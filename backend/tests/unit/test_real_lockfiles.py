"""Real npm lockfile fixtures (Checkpoint D).

Parses and graphs the lockfiles recorded under tests/fixtures/recorded/npm-lockfiles. They are
the evidence that hardening does not break real input: most tests here already pass against the
Checkpoint C parser and must keep passing. Only the tests that use ``ParseLimits`` target the new
API, and they are reached through the module object so each fails on its own today.

The assertions describe structure, not exact package counts, because the transitive versions in
these files were resolved from the registry on the day they were generated.
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
