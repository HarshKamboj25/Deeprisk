"""Tests for DependencyNode.is_dev (Checkpoint D).

Meaning: ``is_dev`` is True only when the evidence shows the package is reachable exclusively
through development dependencies. The rule is: DEVELOPMENT is in ``scopes`` and neither
PRODUCTION nor OPTIONAL is. PEER is ignored, because it describes an edge type and not an
alternative way of being reachable. Conflicting evidence never downgrades a package to
dev-only, so risk is not understated.

``is_dev == False`` does not mean production: a package with no recorded scope is unclassified.
"""

import json
from pathlib import Path
from typing import Any

import pytest

from deprisk.core.lockfile import parse_lockfile
from deprisk.core.models import DependencyNode, DependencyScope

DEV = DependencyScope.DEVELOPMENT
PROD = DependencyScope.PRODUCTION
OPTIONAL = DependencyScope.OPTIONAL
PEER = DependencyScope.PEER

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "recorded" / "npm-lockfiles"


def expected_is_dev(scopes: frozenset[DependencyScope]) -> bool:
    return DEV in scopes and not scopes & {PROD, OPTIONAL}


def parse_one(*, root_fields: tuple[str, ...] = (), flags: tuple[str, ...] = ()) -> DependencyNode:
    """Parse a lockfile with one package, 'p', declared by the root under ``root_fields``."""
    root = {field: {"p": "^1.0.0"} for field in root_fields}
    entry: dict[str, Any] = {"version": "1.0.0", **{flag: True for flag in flags}}
    text = json.dumps({"lockfileVersion": 3, "packages": {"": root, "node_modules/p": entry}})

    (node,) = parse_lockfile(text).nodes
    return node


# --- the truth table ----------------------------------------------------------------------

CASES = [
    # (root fields declaring p, npm flags on the entry, expected scopes, expected is_dev)
    pytest.param((), ("dev",), {DEV}, True, id="dev"),
    pytest.param((), ("optional",), {OPTIONAL}, False, id="optional"),
    pytest.param((), ("devOptional",), {DEV, OPTIONAL}, False, id="devOptional"),
    pytest.param((), ("dev", "optional"), {DEV, OPTIONAL}, False, id="dev-and-optional-flags"),
    pytest.param((), ("peer",), {PEER}, False, id="peer"),
    pytest.param((), ("dev", "peer"), {DEV, PEER}, True, id="dev-and-peer-flags"),
    pytest.param((), (), set(), False, id="no-flags-and-undeclared"),
    pytest.param(("devDependencies",), ("dev",), {DEV}, True, id="root-dev-dependency"),
    pytest.param(("devDependencies",), (), {DEV}, True, id="root-dev-dependency-without-flag"),
    pytest.param(
        ("devDependencies",),
        ("devOptional",),
        {DEV, OPTIONAL},
        False,
        id="root-dev-and-devOptional",
    ),
    pytest.param(
        ("devDependencies",), ("optional",), {DEV, OPTIONAL}, False, id="root-dev-and-optional-flag"
    ),
    pytest.param(
        ("dependencies", "devDependencies"), (), {PROD, DEV}, False, id="prod-and-dev-in-root"
    ),
    pytest.param(
        ("dependencies", "devDependencies"),
        ("dev",),
        {PROD, DEV},
        False,
        id="prod-and-dev-in-root-with-dev-flag",
    ),
    pytest.param(
        ("dependencies",), ("dev",), {PROD, DEV}, False, id="dev-flag-contradicts-root-dependency"
    ),
    pytest.param(
        ("optionalDependencies",),
        ("dev",),
        {OPTIONAL, DEV},
        False,
        id="root-optional-with-dev-flag",
    ),
    pytest.param(("dependencies",), ("peer",), {PROD, PEER}, False, id="root-dependency-peer-flag"),
]


@pytest.mark.parametrize(("root_fields", "flags", "scopes", "expected"), CASES)
def test_is_dev_truth_table(
    root_fields: tuple[str, ...],
    flags: tuple[str, ...],
    scopes: set[DependencyScope],
    expected: bool,
) -> None:
    node = parse_one(root_fields=root_fields, flags=flags)

    assert node.scopes == frozenset(scopes)
    assert node.is_dev is expected


# --- the invariant, over every combination ------------------------------------------------

FLAG_NAMES = ("dev", "optional", "devOptional", "peer")
ROOT_FIELDS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")


def subsets(items: tuple[str, ...]) -> list[tuple[str, ...]]:
    return [
        tuple(item for index, item in enumerate(items) if mask & (1 << index))
        for mask in range(1 << len(items))
    ]


def test_is_dev_is_a_function_of_scopes_for_every_flag_and_declaration_combination() -> None:
    root: dict[str, dict[str, str]] = {field: {} for field in ROOT_FIELDS}
    packages: dict[str, dict[str, Any]] = {}

    for root_fields in subsets(ROOT_FIELDS):
        for flags in subsets(FLAG_NAMES):
            name = f"n{len(packages)}"
            for field in root_fields:
                root[field][name] = "^1.0.0"
            packages[f"node_modules/{name}"] = {
                "version": "1.0.0",
                **{flag: True for flag in flags},
            }

    parsed = parse_lockfile(json.dumps({"lockfileVersion": 3, "packages": {"": root, **packages}}))

    assert len(parsed.nodes) == 256
    offenders = [
        (node.install_path, sorted(scope.value for scope in node.scopes), node.is_dev)
        for node in parsed.nodes
        if node.is_dev != expected_is_dev(node.scopes)
    ]
    assert offenders == []


# --- is_dev describes one install instance ------------------------------------------------


def test_is_dev_is_decided_per_install_instance() -> None:
    text = json.dumps(
        {
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"x": "^2.0.0", "a": "^1.0.0"}},
                "node_modules/x": {"version": "2.0.0"},
                "node_modules/a": {"version": "1.0.0"},
                "node_modules/a/node_modules/x": {"version": "1.0.0", "dev": True},
            },
        }
    )

    nodes = {node.install_path: node for node in parse_lockfile(text).nodes}

    assert nodes["node_modules/x"].is_dev is False
    assert nodes["node_modules/a/node_modules/x"].is_dev is True


# --- real npm lockfiles -------------------------------------------------------------------

REAL_FIXTURES = ["general-v3", "general-v2", "peer-v3", "flags-v3"]


def load_real(name: str) -> tuple[str, dict[str, Any]]:
    text = (FIXTURES / name / "package-lock.json").read_text(encoding="utf-8")
    return text, json.loads(text)["packages"]


@pytest.mark.parametrize("name", REAL_FIXTURES)
def test_is_dev_agrees_with_npm_flags_in_real_lockfiles(name: str) -> None:
    """npm's dev flag means dev-only unless optional or devOptional applies. peer is ignored."""
    text, raw = load_real(name)
    parsed = parse_lockfile(text)

    assert parsed.nodes
    for node in parsed.nodes:
        flagged = {
            flag
            for flag in ("dev", "optional", "devOptional", "peer")
            if raw[node.install_path].get(flag)
        }
        assert node.is_dev is (flagged - {"peer"} == {"dev"}), node.install_path
        assert node.is_dev == expected_is_dev(node.scopes), node.install_path


@pytest.mark.parametrize("name", ["general-v3", "general-v2"])
def test_real_dev_flagged_packages_are_dev(name: str) -> None:
    text, raw = load_real(name)
    dev_paths = {
        path
        for path, entry in raw.items()
        if path and entry.get("dev") and not entry.get("optional") and not entry.get("devOptional")
    }
    nodes = {node.install_path: node for node in parse_lockfile(text).nodes}

    assert dev_paths
    assert all(nodes[path].is_dev for path in dev_paths)


def test_real_devOptional_packages_are_not_dev() -> None:
    text, raw = load_real("flags-v3")
    optional_dev_paths = {path for path, entry in raw.items() if path and entry.get("devOptional")}
    nodes = {node.install_path: node for node in parse_lockfile(text).nodes}

    assert optional_dev_paths
    assert not any(nodes[path].is_dev for path in optional_dev_paths)
    assert all({DEV, OPTIONAL} <= nodes[path].scopes for path in optional_dev_paths)


# --- documentation ------------------------------------------------------------------------


def test_is_dev_field_documents_its_meaning() -> None:
    """Pins the doc-only models.py change planned for Checkpoint D."""
    description = DependencyNode.model_fields["is_dev"].description

    assert description is not None
    assert "development" in description.lower()
    assert "production" in description.lower()
