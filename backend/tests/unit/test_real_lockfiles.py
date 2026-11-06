"""Real npm lockfile fixtures (Checkpoint D + L1 scope propagation).

Parses and graphs the lockfiles recorded under tests/fixtures/recorded/npm-lockfiles. They are
the evidence that hardening does not break real input: most tests here already pass against the
Checkpoint C parser and must keep passing. Only the tests that use ``ParseLimits`` target the new
API, and they are reached through the module object so each fails on its own today.

The assertions describe structure, not exact package counts, because the transitive versions in
these files were resolved from the registry on the day they were generated.

The L1 scope propagation section (at the bottom of this file) cross-checks graph-derived
``EffectiveScope`` values against npm's own lockfile flags using the following evidence-based
mapping rules:

npm lockfile flag(s)          → acceptable graph EffectiveScope(s)
─────────────────────────────────────────────────────────────────
(no flags)                    → PRODUCTION
dev=true                      → DEVELOPMENT or DEV_OPTIONAL *
optional=true                 → OPTIONAL or DEV_OPTIONAL **
devOptional=true              → DEV_OPTIONAL
peer=true                     → scope inherited from the parent context (see note)

* npm collapses (DEV, REQ) and (DEV, OPT) path states into a single dev=true flag.
  The graph preserves the distinction; a node is DEV_OPTIONAL when it is reachable
  via any optional edge from a dev-only ancestor even if also reachable via (DEV, REQ).

** A node with npm optional=true is OPTIONAL when reached only via optional production
   paths. It may be DEV_OPTIONAL when also reachable via a dev path.

Note on peer=true: npm marks a package peer=true when it was introduced into the
install tree solely to satisfy a peerDependency declaration of another package (not
declared directly in the manifest).  Its effective graph scope is determined entirely
by the scope of the parent package that emits the peer edge, NOT by the peer flag
itself.  In all four fixtures every peer-flagged package is reached via a production
parent, so the graph correctly classifies it as PRODUCTION, not as PEER.
"""

import collections
import hashlib
import json
import re
from pathlib import Path
from typing import Any

import pytest

from deprisk.core import lockfile as lockfile_module
from deprisk.core.graph import build_graph_edges
from deprisk.core.lockfile import LockfileParseError, parse_lockfile
from deprisk.core.scope import EffectiveScope, propagate_scopes

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "recorded" / "npm-lockfiles"

PARSEABLE = ["general-v3", "general-v2", "peer-v3", "flags-v3"]
GENERAL = ["general-v3", "general-v2"]

MANIFEST_FIELDS = {
    "dependencies": "production",
    "devDependencies": "development",
    "optionalDependencies": "optional",
    "peerDependencies": "peer",
}

CANONICAL_PATH = re.compile(r"^(node_modules/(@[^/]+/)?[^/]+)(/node_modules/(@[^/]+/)?[^/]+)*$")


def read_text(name: str) -> str:
    return (FIXTURES / name / "package-lock.json").read_text(encoding="utf-8")


def raw_lock(name: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(read_text(name))
    return data


def manifest_root(name: str) -> set[tuple[str, str, str]]:
    manifest = json.loads((FIXTURES / name / "package.json").read_text(encoding="utf-8"))
    return {
        (dependency, requested_range, scope)
        for field, scope in MANIFEST_FIELDS.items()
        for dependency, requested_range in manifest.get(field, {}).items()
    }


# --- fixture integrity --------------------------------------------------------------------


def test_sha256sums_match_every_fixture_file() -> None:
    listed: dict[str, str] = {}
    for line in (FIXTURES / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines():
        digest, relative = line.split("  ", 1)
        listed[relative] = digest

    on_disk = {
        path.relative_to(FIXTURES).as_posix() for path in FIXTURES.rglob("*") if path.is_file()
    } - {"SHA256SUMS.txt", "PROVENANCE.md"}
    mismatched = [
        relative
        for relative, digest in listed.items()
        if hashlib.sha256((FIXTURES / relative).read_bytes()).hexdigest() != digest
    ]

    assert set(listed) == on_disk
    assert mismatched == []


def test_provenance_document_is_complete() -> None:
    text = (FIXTURES / "PROVENANCE.md").read_text(encoding="utf-8")

    assert "{{" not in text
    assert "SHA256SUMS.txt" in text
    assert "npm" in text


@pytest.mark.parametrize(
    ("name", "version"),
    [
        ("general-v3", 3),
        ("general-v2", 2),
        ("peer-v3", 3),
        ("flags-v3", 3),
        ("workspace-v3", 3),
    ],
)
def test_fixture_lockfile_versions(name: str, version: int) -> None:
    assert raw_lock(name)["lockfileVersion"] == version


def test_flags_fixture_exercises_devOptional_and_peer() -> None:
    packages = raw_lock("flags-v3")["packages"]
    flags = {
        flag for entry in packages.values() for flag in ("devOptional", "peer") if entry.get(flag)
    }

    assert flags == {"devOptional", "peer"}


# --- parsing real lockfiles ---------------------------------------------------------------


@pytest.mark.parametrize("name", PARSEABLE)
def test_every_package_entry_becomes_one_node(name: str) -> None:
    raw = raw_lock(name)["packages"]

    parsed = parse_lockfile(read_text(name))

    assert len(parsed.nodes) == len(raw) - 1
    for node in parsed.nodes:
        entry = raw[node.install_path]
        assert node.version == entry["version"]
        assert node.name == entry.get("name", node.install_path.rsplit("node_modules/", 1)[1])


@pytest.mark.parametrize("name", PARSEABLE)
def test_root_dependencies_match_the_manifest(name: str) -> None:
    parsed = parse_lockfile(read_text(name))

    assert {
        (d.name, d.requested_range, d.scope.value) for d in parsed.root_dependencies
    } == manifest_root(name)
    assert all(d.is_optional for d in parsed.root_dependencies if d.scope.value == "optional")


@pytest.mark.parametrize("name", PARSEABLE)
def test_direct_nodes_are_the_top_level_installs_of_root_dependencies(name: str) -> None:
    raw = raw_lock(name)["packages"]
    parsed = parse_lockfile(read_text(name))
    expected = {
        f"node_modules/{d.name}"
        for d in parsed.root_dependencies
        if f"node_modules/{d.name}" in raw
    }

    assert expected
    assert {node.install_path for node in parsed.nodes if node.is_direct} == expected


@pytest.mark.parametrize("name", PARSEABLE)
def test_no_nested_install_is_marked_direct(name: str) -> None:
    parsed = parse_lockfile(read_text(name))

    assert all("/node_modules/" not in n.install_path for n in parsed.nodes if n.is_direct)


@pytest.mark.parametrize("name", GENERAL)
def test_real_alias_and_scoped_direct_dependencies(name: str) -> None:
    nodes = {node.install_path: node for node in parse_lockfile(read_text(name)).nodes}

    alias = nodes["node_modules/myalias"]
    assert alias.name == "lodash"
    assert alias.is_direct is True

    scoped = nodes["node_modules/@babel/core"]
    assert scoped.name == "@babel/core"
    assert scoped.is_direct is True


def test_v2_and_v3_lockfiles_of_the_same_project_agree_on_their_roots() -> None:
    v2 = parse_lockfile(read_text("general-v2"))
    v3 = parse_lockfile(read_text("general-v3"))

    assert v2.root_dependencies == v3.root_dependencies
    assert {n.install_path for n in v2.nodes if n.is_direct} == {
        n.install_path for n in v3.nodes if n.is_direct
    }


def test_workspace_lockfile_is_rejected_until_workspace_support_exists() -> None:
    """Pins today's policy. Workspace support is a later, separate decision."""
    with pytest.raises(LockfileParseError, match="Linked package entries are not supported yet"):
        parse_lockfile(read_text("workspace-v3"))


# --- the dependency graph of real lockfiles -----------------------------------------------


@pytest.mark.parametrize("name", PARSEABLE)
def test_real_graph_is_consistent_and_deterministic(name: str) -> None:
    parsed = parse_lockfile(read_text(name))
    edges = build_graph_edges(parsed)
    paths = {node.install_path for node in parsed.nodes}

    assert edges
    assert any(edge.parent_path for edge in edges)
    assert all(edge.child_path in paths for edge in edges if edge.child_path is not None)
    assert all(edge.parent_path in paths for edge in edges if edge.parent_path)
    assert edges == build_graph_edges(parsed)
    assert {(e.dependency_name, e.scope.value) for e in edges if e.parent_path == ""} == {
        (d.name, d.scope.value) for d in parsed.root_dependencies
    }


@pytest.mark.parametrize("name", PARSEABLE)
def test_every_declared_dependency_produces_exactly_one_edge(name: str) -> None:
    parsed = parse_lockfile(read_text(name))
    declared = {("", d.name, d.scope) for d in parsed.root_dependencies} | {
        (node.install_path, d.name, d.scope)
        for node in parsed.nodes
        for d in node.declared_dependencies
    }

    edges = build_graph_edges(parsed)

    assert len(edges) == len(declared)
    assert {(e.parent_path, e.dependency_name, e.scope) for e in edges} == declared


@pytest.mark.parametrize("name", GENERAL)
def test_general_graph_leaves_only_optional_dependencies_unresolved(name: str) -> None:
    edges = build_graph_edges(parse_lockfile(read_text(name)))

    assert [e for e in edges if e.resolution.value == "missing"] == []
    assert any(e.resolution.value == "missing_optional" for e in edges)


@pytest.mark.parametrize("name", GENERAL)
def test_general_lockfiles_contain_repeated_package_versions(name: str) -> None:
    groups: dict[tuple[str, str], list[str]] = collections.defaultdict(list)
    for node in parse_lockfile(read_text(name)).nodes:
        groups[(node.name, node.version)].append(node.install_path)

    assert any(len(paths) > 1 for paths in groups.values())


@pytest.mark.parametrize("name", PARSEABLE)
def test_copies_of_one_package_version_keep_separate_paths_and_parents(name: str) -> None:
    """ADR-002 on real data: a parent resolves a package to exactly one install path."""
    parsed = parse_lockfile(read_text(name))
    edges = build_graph_edges(parsed)
    groups: dict[tuple[str, str], list[str]] = collections.defaultdict(list)
    for node in parsed.nodes:
        groups[(node.name, node.version)].append(node.install_path)
    parents_of: dict[str, set[str]] = collections.defaultdict(set)
    for edge in edges:
        if edge.child_path is not None:
            parents_of[edge.child_path].add(edge.parent_path)

    for key, paths in groups.items():
        if len(paths) < 2:
            continue
        seen: set[str] = set()
        for path in paths:
            parents = parents_of[path]
            assert parents, f"{key} at {path} has no incoming edge"
            assert not parents & seen, f"{key} copies share a parent"
            seen |= parents


# --- real lockfiles against the planned hardening rules -----------------------------------


@pytest.mark.parametrize("name", PARSEABLE)
def test_real_lockfiles_satisfy_the_planned_hardening_rules(name: str) -> None:
    """Checks the files themselves, so the new rules cannot reject real npm output."""
    text = read_text(name)
    duplicates: list[str] = []

    def hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        counts = collections.Counter(key for key, _ in pairs)
        duplicates.extend(key for key, count in counts.items() if count > 1)
        return dict(pairs)

    packages = json.loads(text, object_pairs_hook=hook)["packages"]
    entries = [path for path in packages if path]

    assert "" in packages
    assert duplicates == []
    assert [path for path in entries if not CANONICAL_PATH.match(path)] == []
    assert len(text) <= 50_000_000
    assert len(entries) <= 100_000
    assert max(path.count("node_modules/") for path in entries) <= 32
    assert max(len(path) for path in entries) <= 1024


# --- real lockfiles through the new ParseLimits API ---------------------------------------


@pytest.mark.parametrize("name", PARSEABLE)
def test_real_lockfiles_parse_under_the_default_limits(name: str) -> None:
    text = read_text(name)

    limited = parse_lockfile(text, limits=lockfile_module.DEFAULT_PARSE_LIMITS)

    assert limited == parse_lockfile(text)


@pytest.mark.parametrize("name", PARSEABLE)
def test_real_lockfiles_parse_at_their_exact_observed_size(name: str) -> None:
    """The limits are inclusive: a limit equal to what the file needs must be accepted."""
    text = read_text(name)
    entries = [path for path in raw_lock(name)["packages"] if path]
    exact = lockfile_module.ParseLimits(
        max_characters=len(text),
        max_packages=len(entries),
        max_path_segments=max(path.count("node_modules/") for path in entries),
        max_path_length=max(len(path) for path in entries),
    )

    assert len(parse_lockfile(text, limits=exact).nodes) == len(entries)


# --- L1 scope propagation cross-check against real lockfile fixtures ----------
#
# Helper: build a propagation result for a named fixture in one call.


def _propagate(name: str) -> tuple[dict[str, Any], Any]:
    """Return (raw_packages_dict, ScopePropagationResult) for a named fixture."""
    text = read_text(name)
    raw: dict[str, Any] = json.loads(text)["packages"]
    parsed = parse_lockfile(text)
    edges = build_graph_edges(parsed)
    result = propagate_scopes(parsed.nodes, edges)
    return raw, result


# --- L1.1  All parsed nodes appear in the propagation result -----------------


@pytest.mark.parametrize("name", PARSEABLE)
def test_propagation_result_contains_every_parsed_node(name: str) -> None:
    """Every physical installation path produced by the parser must have a
    reachability record in the propagation result."""
    text = read_text(name)
    parsed = parse_lockfile(text)
    edges = build_graph_edges(parsed)
    result = propagate_scopes(parsed.nodes, edges)

    parsed_paths = {node.install_path for node in parsed.nodes}
    result_paths = set(result.nodes.keys())

    assert result_paths == parsed_paths


# --- L1.2  No node is unreachable in the four parseable fixtures -------------


@pytest.mark.parametrize("name", PARSEABLE)
def test_no_node_is_unreachable_in_real_fixtures(name: str) -> None:
    """Every package in the four real fixtures is reachable from the root.
    npm does not record orphaned packages in its lockfile, so zero unreachable
    nodes is the expected and verifiable outcome."""
    _, result = _propagate(name)

    assert result.unreachable_paths == ()


# --- L1.3  No parser-vs-graph disagreements ----------------------------------


@pytest.mark.parametrize("name", PARSEABLE)
def test_no_parser_graph_disagreements_in_real_fixtures(name: str) -> None:
    """The evidence-based disagreement check must produce no contradictions in
    any of the four real lockfile fixtures.  A disagreement requires both
    an explicit parser claim (is_dev=True or PRODUCTION in node.scopes) *and*
    a contradicting graph classification."""
    _, result = _propagate(name)

    assert result.disagreements_with_parser == ()


# --- L1.4  npm no-flag nodes are classified as PRODUCTION --------------------


@pytest.mark.parametrize("name", PARSEABLE)
def test_npm_no_flag_nodes_are_classified_production(name: str) -> None:
    """Packages with no dev/optional/devOptional/peer flag in the lockfile are
    production dependencies.  The graph must classify them as PRODUCTION."""
    raw, result = _propagate(name)

    no_flag_paths = [
        path
        for path, entry in raw.items()
        if path  # skip root ""
        and not entry.get("dev")
        and not entry.get("optional")
        and not entry.get("devOptional")
        and not entry.get("peer")
    ]
    assert no_flag_paths, f"{name}: fixture has no no-flag packages (unexpected)"

    mismatches = [
        (path, result.nodes[path].effective_scope.value)
        for path in no_flag_paths
        if path in result.nodes
        and result.nodes[path].effective_scope is not EffectiveScope.PRODUCTION
    ]
    assert mismatches == [], (
        f"{name}: {len(mismatches)} no-flag node(s) not classified as PRODUCTION: {mismatches}"
    )


# --- L1.5  npm dev=true nodes are classified DEVELOPMENT or DEV_OPTIONAL -----


@pytest.mark.parametrize("name", ["general-v3", "general-v2"])
def test_npm_dev_nodes_are_development_or_dev_optional(name: str) -> None:
    """Packages with dev=true in the lockfile are either DEVELOPMENT or
    DEV_OPTIONAL in the graph.  npm does not distinguish between (DEV, REQ) and
    (DEV, OPT) path states in its flags; the graph preserves the distinction.

    A package is DEV_OPTIONAL (not plain DEVELOPMENT) when it is reachable via
    at least one optional edge from a dev-scope ancestor in addition to any
    required dev paths.  Both are legitimate sub-classifications of dev=true."""
    raw, result = _propagate(name)

    dev_paths = [path for path, entry in raw.items() if path and entry.get("dev")]
    assert dev_paths, f"{name}: fixture has no dev packages (unexpected)"

    acceptable = {EffectiveScope.DEVELOPMENT, EffectiveScope.DEV_OPTIONAL}
    mismatches = [
        (path, result.nodes[path].effective_scope.value)
        for path in dev_paths
        if path in result.nodes and result.nodes[path].effective_scope not in acceptable
    ]
    assert mismatches == [], (
        f"{name}: {len(mismatches)} dev=true node(s) classified outside "
        f"{{DEVELOPMENT, DEV_OPTIONAL}}: {mismatches}"
    )


# --- L1.6  npm optional=true nodes are classified OPTIONAL or DEV_OPTIONAL ---


@pytest.mark.parametrize("name", PARSEABLE)
def test_npm_optional_nodes_are_optional_or_dev_optional(name: str) -> None:
    """Packages with optional=true in the lockfile are either OPTIONAL or
    DEV_OPTIONAL in the graph.  A node with both optional=true and a dev path
    is DEV_OPTIONAL; a node reachable only via optional production paths is
    OPTIONAL."""
    raw, result = _propagate(name)

    opt_paths = [path for path, entry in raw.items() if path and entry.get("optional")]
    if not opt_paths:
        pytest.skip(f"{name}: fixture has no optional-flagged packages")

    acceptable = {EffectiveScope.OPTIONAL, EffectiveScope.DEV_OPTIONAL}
    mismatches = [
        (path, result.nodes[path].effective_scope.value)
        for path in opt_paths
        if path in result.nodes and result.nodes[path].effective_scope not in acceptable
    ]
    assert mismatches == [], (
        f"{name}: {len(mismatches)} optional=true node(s) classified outside "
        f"{{OPTIONAL, DEV_OPTIONAL}}: {mismatches}"
    )


# --- L1.7  npm devOptional=true nodes are classified DEV_OPTIONAL ------------


@pytest.mark.parametrize("name", PARSEABLE)
def test_npm_dev_optional_nodes_are_dev_optional(name: str) -> None:
    """Packages with devOptional=true in the lockfile must be classified as
    DEV_OPTIONAL.  npm sets this flag exactly when a package is simultaneously
    reachable via a dev-required path and an optional production path, which
    is the same condition the graph uses to decide DEV_OPTIONAL."""
    raw, result = _propagate(name)

    dev_opt_paths = [path for path, entry in raw.items() if path and entry.get("devOptional")]
    if not dev_opt_paths:
        pytest.skip(f"{name}: fixture has no devOptional packages")

    mismatches = [
        (path, result.nodes[path].effective_scope.value)
        for path in dev_opt_paths
        if path in result.nodes
        and result.nodes[path].effective_scope is not EffectiveScope.DEV_OPTIONAL
    ]
    assert mismatches == [], (
        f"{name}: {len(mismatches)} devOptional=true node(s) not classified as "
        f"DEV_OPTIONAL: {mismatches}"
    )


# --- L1.8  npm peer=true nodes inherit their parent's scope ------------------


def test_npm_peer_flagged_node_in_flags_v3_is_classified_production() -> None:
    """flags-v3 contains exactly one peer-flagged package: react.
    react is introduced into the install tree by react-dom's peerDependency
    declaration.  react-dom is a root production dependency, so react is reached
    via a (PROD, REQ) path state through that peer edge.

    npm sets peer=true to record *how* the package entered the tree, not what
    deployment scope it carries.  The graph correctly derives PRODUCTION because
    the parent (react-dom) is production.

    This test anchors the peer-flag interpretation so that future changes to the
    classification logic do not silently revert it."""
    raw, result = _propagate("flags-v3")

    peer_paths = [path for path, entry in raw.items() if path and entry.get("peer")]
    assert peer_paths == ["node_modules/react"], (
        f"Expected exactly one peer-flagged package (react) in flags-v3, found: {peer_paths}"
    )

    react_reach = result.nodes["node_modules/react"]
    assert react_reach.effective_scope is EffectiveScope.PRODUCTION, (
        f"react (peer=true, reached via production react-dom) should be PRODUCTION, "
        f"got {react_reach.effective_scope}"
    )
    assert react_reach.is_production is True
    assert "(PROD, REQ)" in react_reach.reached_states


# --- L1.9  peer-v3: all 218 nodes are PRODUCTION (all parents are production) --


def test_peer_v3_all_nodes_are_production() -> None:
    """peer-v3 installs react, react-dom, eslint, and eslint-plugin-react, all as
    root production dependencies.  Every peer edge in this fixture (eslint, acorn,
    react) originates from a production parent, so the entire transitive graph is
    classified PRODUCTION.  Zero nodes should be classified DEV, DEV_OPTIONAL,
    OPTIONAL, PEER, UNKNOWN, or UNREACHABLE."""
    raw, result = _propagate("peer-v3")

    non_prod = [
        (path, r.effective_scope.value)
        for path, r in result.nodes.items()
        if r.effective_scope is not EffectiveScope.PRODUCTION
    ]
    assert non_prod == [], (
        f"peer-v3: expected all 218 nodes PRODUCTION, but {len(non_prod)} are not: {non_prod[:5]}"
    )
    assert len(result.nodes) == 218


# --- L1.10 general-v3 and general-v2 agree on scope distributions ------------


def test_general_v3_and_v2_agree_on_scope_distributions() -> None:
    """The same project was locked at both v2 and v3 format.  Since the resolved
    packages are identical, propagate_scopes must produce the same effective scope
    for every install path in both results."""
    _, result_v3 = _propagate("general-v3")
    _, result_v2 = _propagate("general-v2")

    assert set(result_v3.nodes.keys()) == set(result_v2.nodes.keys())

    def _scope(res: Any, p: str) -> str:
        return res.nodes[p].effective_scope.value  # type: ignore[no-any-return]

    differing = [
        (path, _scope(result_v3, path), _scope(result_v2, path))
        for path in result_v3.nodes
        if result_v3.nodes[path].effective_scope != result_v2.nodes[path].effective_scope
    ]
    assert differing == [], (
        f"general-v3 and general-v2 disagree on scope for {len(differing)} path(s): {differing[:5]}"
    )


# --- L1.11 general-v3 scope count breakdown ----------------------------------


def test_general_v3_scope_count_breakdown() -> None:
    """Pin the exact count of each effective scope in general-v3 so that future
    algorithm changes cannot silently shift classifications.

    Counts were derived from the fixture on the day it was generated and are the
    ground truth for this test run:
      - PRODUCTION  113   (no-flag packages: express, @babel/core, myalias, transitive prod deps)
      - DEVELOPMENT 174   (jest, typescript, and their required transitive deps)
      - DEV_OPTIONAL 54   (dev deps reachable via any optional edge, e.g. @jest/types)
      - OPTIONAL      1   (fsevents, reached only via optional paths)
    """
    _, result = _propagate("general-v3")

    actual = {scope: 0 for scope in EffectiveScope}
    for r in result.nodes.values():
        actual[r.effective_scope] += 1

    assert actual[EffectiveScope.PRODUCTION] == 113
    assert actual[EffectiveScope.DEVELOPMENT] == 174
    assert actual[EffectiveScope.DEV_OPTIONAL] == 54
    assert actual[EffectiveScope.OPTIONAL] == 1
    assert actual[EffectiveScope.PEER] == 0
    assert actual[EffectiveScope.UNKNOWN] == 0
    assert actual[EffectiveScope.UNREACHABLE] == 0
    assert len(result.nodes) == 342


# --- L1.12 general-v3 concrete package spot checks ---------------------------


def test_general_v3_concrete_package_scopes() -> None:
    """Verify effective scopes for a selection of well-known packages in
    general-v3 to anchor the propagation result at the individual-node level.

    express: root production dep → PRODUCTION, (PROD, REQ).
    jest: root dev dep → DEVELOPMENT, (DEV, REQ).
    typescript: root dev dep → DEVELOPMENT, (DEV, REQ).
    myalias (lodash alias): root production dep → PRODUCTION, (PROD, REQ).
    @babel/core: root production dep, also a transitive dev dep →
        still PRODUCTION because (PROD, REQ) dominates (DEV, REQ).
    fsevents: root optional dep + optional dep of jest-haste-map (dev) →
        OPTIONAL because (PROD, OPT) + (DEV, OPT) and (PROD, OPT) dominates.
    """
    _, result = _propagate("general-v3")

    express = result.nodes["node_modules/express"]
    assert express.effective_scope is EffectiveScope.PRODUCTION
    assert express.is_production is True
    assert "(PROD, REQ)" in express.reached_states

    jest = result.nodes["node_modules/jest"]
    assert jest.effective_scope is EffectiveScope.DEVELOPMENT
    assert jest.is_dev is True
    assert "(DEV, REQ)" in jest.reached_states

    typescript = result.nodes["node_modules/typescript"]
    assert typescript.effective_scope is EffectiveScope.DEVELOPMENT
    assert typescript.is_dev is True

    myalias = result.nodes["node_modules/myalias"]
    assert myalias.effective_scope is EffectiveScope.PRODUCTION
    assert myalias.is_production is True

    babel_core = result.nodes["node_modules/@babel/core"]
    assert babel_core.effective_scope is EffectiveScope.PRODUCTION
    assert "(PROD, REQ)" in babel_core.reached_states
    assert "(DEV, REQ)" in babel_core.reached_states  # also a transitive dev dep

    fsevents = result.nodes["node_modules/fsevents"]
    assert fsevents.effective_scope is EffectiveScope.OPTIONAL
    assert "(PROD, OPT)" in fsevents.reached_states
    assert "(DEV, OPT)" in fsevents.reached_states
    assert fsevents.is_optional is True
    assert fsevents.is_production is False


# --- L1.13 flags-v3 concrete package spot checks -----------------------------


def test_flags_v3_concrete_package_scopes() -> None:
    """Verify every node in flags-v3 individually.  flags-v3 is a small fixture
    (20 packages) specifically designed to exercise all npm flag combinations.

    Mapping:
      react-dom, scheduler, loose-envify, js-tokens: no-flag → PRODUCTION
      react (peer=true): reached via production react-dom peer edge → PRODUCTION
      chokidar, anymatch, binary-extensions, fsevents, glob-parent,
      is-binary-path, is-extglob, is-glob, normalize-path,
      picomatch, readdirp: optional=true → OPTIONAL
      braces, fill-range, to-regex-range, is-number: devOptional=true → DEV_OPTIONAL
    """
    _, result = _propagate("flags-v3")

    # Production nodes (no-flag + peer-flagged react)
    for path in (
        "node_modules/react-dom",
        "node_modules/scheduler",
        "node_modules/loose-envify",
        "node_modules/js-tokens",
        "node_modules/react",  # peer=true but parent is production
    ):
        r = result.nodes[path]
        assert r.effective_scope is EffectiveScope.PRODUCTION, (
            f"{path}: expected PRODUCTION, got {r.effective_scope}"
        )
        assert r.is_production is True

    # Optional nodes
    for path in (
        "node_modules/chokidar",
        "node_modules/anymatch",
        "node_modules/binary-extensions",
        "node_modules/fsevents",
        "node_modules/glob-parent",
        "node_modules/is-binary-path",
        "node_modules/is-extglob",
        "node_modules/is-glob",
        "node_modules/normalize-path",
        "node_modules/picomatch",
        "node_modules/readdirp",
    ):
        r = result.nodes[path]
        assert r.effective_scope is EffectiveScope.OPTIONAL, (
            f"{path}: expected OPTIONAL, got {r.effective_scope}"
        )
        assert r.is_optional is True

    # DevOptional nodes
    for path in (
        "node_modules/braces",
        "node_modules/fill-range",
        "node_modules/to-regex-range",
        "node_modules/is-number",
    ):
        r = result.nodes[path]
        assert r.effective_scope is EffectiveScope.DEV_OPTIONAL, (
            f"{path}: expected DEV_OPTIONAL, got {r.effective_scope}"
        )
        assert r.is_dev_optional is True


# --- L1.14 DEV_OPTIONAL nodes in general-v3 carry both DEV and OPT states ---


def test_general_v3_dev_optional_nodes_have_both_dev_and_opt_path_flags() -> None:
    """The 54 DEV_OPTIONAL nodes in general-v3 (e.g. @jest/types, @jest/schemas)
    are reachable via both a required dev path AND an optional dev path.  Every
    one must set both has_development_path=True and has_optional_path=True."""
    _, result = _propagate("general-v3")

    dev_opt_nodes = [
        (path, r)
        for path, r in result.nodes.items()
        if r.effective_scope is EffectiveScope.DEV_OPTIONAL
    ]
    assert len(dev_opt_nodes) == 54

    violations = [
        path for path, r in dev_opt_nodes if not (r.has_development_path and r.has_optional_path)
    ]
    assert violations == [], f"DEV_OPTIONAL nodes missing expected path flags: {violations}"


# --- L1.15 flags-v3 devOptional nodes carry both dev-req and prod-opt states --


def test_flags_v3_dev_optional_nodes_have_correct_path_states() -> None:
    """In flags-v3 the four devOptional packages (braces, fill-range,
    to-regex-range, is-number) are reached via:
      - (DEV, REQ): root dev dep braces → its transitive subtree
      - (PROD, OPT): root optional dep chokidar → its transitive subtree
    Both path states must be present in reached_states for each node."""
    _, result = _propagate("flags-v3")

    for path in (
        "node_modules/braces",
        "node_modules/fill-range",
        "node_modules/to-regex-range",
        "node_modules/is-number",
    ):
        r = result.nodes[path]
        assert "(DEV, REQ)" in r.reached_states, (
            f"{path}: expected (DEV, REQ) in reached_states, got {r.reached_states}"
        )
        assert "(PROD, OPT)" in r.reached_states, (
            f"{path}: expected (PROD, OPT) in reached_states, got {r.reached_states}"
        )


# --- L1.16 propagation result is deterministic across repeated calls ----------


@pytest.mark.parametrize("name", PARSEABLE)
def test_propagation_result_is_deterministic_across_calls(name: str) -> None:
    """Calling propagate_scopes twice on the same parsed lockfile must produce
    identical results (same nodes mapping, same unreachable tuple, same
    disagreements tuple)."""
    text = read_text(name)
    parsed = parse_lockfile(text)
    edges = build_graph_edges(parsed)

    result_a = propagate_scopes(parsed.nodes, edges)
    result_b = propagate_scopes(parsed.nodes, edges)

    assert set(result_a.nodes.keys()) == set(result_b.nodes.keys())
    for path in result_a.nodes:
        assert result_a.nodes[path].effective_scope == result_b.nodes[path].effective_scope
        assert result_a.nodes[path].reached_states == result_b.nodes[path].reached_states
    assert result_a.unreachable_paths == result_b.unreachable_paths
    assert result_a.disagreements_with_parser == result_b.disagreements_with_parser
