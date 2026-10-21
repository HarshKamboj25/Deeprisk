"""Tests for what the parser retains: declared dependencies and per-install directness.

The lockfile structures below are synthetic. They follow our current understanding of
the v2/v3 layout, which is still to be checked against real npm output.
"""

import json
from typing import Any

import pytest
from pydantic import ValidationError

from deprisk.core.lockfile import LockfileParseError, parse_lockfile, parse_lockfile_text
from deprisk.core.models import DeclaredDependency, DependencyNode, DependencyScope


def lockfile(root: dict[str, Any], packages: dict[str, dict[str, Any]]) -> str:
    return json.dumps(
        {
            "name": "fixture",
            "lockfileVersion": 3,
            "packages": {"": {"name": "fixture", "version": "1.0.0", **root}, **packages},
        }
    )


def pkg(version: str = "1.0.0", **extra: Any) -> dict[str, Any]:
    return {"version": version, **extra}


def summarize(items: tuple[DeclaredDependency, ...]) -> list[tuple[str, str, str, bool]]:
    return [(d.name, d.requested_range, d.scope.value, d.is_optional) for d in items]


def node_at(nodes: tuple[DependencyNode, ...], install_path: str) -> DependencyNode:
    return next(node for node in nodes if node.install_path == install_path)


# --- models -----------------------------------------------------------------


def test_node_has_no_declared_dependencies_by_default() -> None:
    node = DependencyNode(install_path="node_modules/a", name="a", version="1.0.0")

    assert node.declared_dependencies == ()


def test_declared_dependency_requires_a_name() -> None:
    with pytest.raises(ValidationError):
        DeclaredDependency(name="", requested_range="^1.0.0", scope=DependencyScope.PRODUCTION)


# --- root dependencies ---------------------------------------------------------


def test_root_dependencies_carry_range_and_scope() -> None:
    text = lockfile(
        {
            "dependencies": {"a": "^1.0.0"},
            "devDependencies": {"d": "^2.0.0"},
            "optionalDependencies": {"o": "^3.0.0"},
            "peerDependencies": {"p": "^4.0.0"},
        },
        {},
    )

    parsed = parse_lockfile(text)

    assert summarize(parsed.root_dependencies) == [
        ("a", "^1.0.0", "production", False),
        ("d", "^2.0.0", "development", False),
        ("o", "^3.0.0", "optional", True),
        ("p", "^4.0.0", "peer", False),
    ]


def test_name_in_two_root_fields_gives_one_entry_per_scope() -> None:
    text = lockfile(
        {"dependencies": {"a": "^1.0.0"}, "devDependencies": {"a": "^1.0.0"}},
        {},
    )

    parsed = parse_lockfile(text)

    assert summarize(parsed.root_dependencies) == [
        ("a", "^1.0.0", "development", False),
        ("a", "^1.0.0", "production", False),
    ]


def test_optional_root_peer_is_marked_optional() -> None:
    text = lockfile(
        {
            "peerDependencies": {"react": "^18.0.0"},
            "peerDependenciesMeta": {"react": {"optional": True}},
        },
        {},
    )

    parsed = parse_lockfile(text)

    assert summarize(parsed.root_dependencies) == [("react", "^18.0.0", "peer", True)]


# --- per-package declared dependencies (G1) ---------------------------------------


def test_package_declared_dependencies_are_retained() -> None:
    text = lockfile(
        {"dependencies": {"a": "^1.0.0"}},
        {
            "node_modules/a": pkg(
                dependencies={"b": "^1.0.0"},
                optionalDependencies={"fsevents": "^2.0.0"},
                peerDependencies={"react": "^18.0.0", "left-pad": "^1.0.0"},
                peerDependenciesMeta={"react": {"optional": True}},
            )
        },
    )

    node = node_at(parse_lockfile(text).nodes, "node_modules/a")

    assert summarize(node.declared_dependencies) == [
        ("b", "^1.0.0", "production", False),
        ("fsevents", "^2.0.0", "optional", True),
        ("left-pad", "^1.0.0", "peer", False),
        ("react", "^18.0.0", "peer", True),
    ]


def test_package_without_dependencies_has_none() -> None:
    text = lockfile({}, {"node_modules/a": pkg()})

    assert node_at(parse_lockfile(text).nodes, "node_modules/a").declared_dependencies == ()


def test_declared_dependencies_do_not_depend_on_json_key_order() -> None:
    forward = lockfile(
        {"dependencies": {"a": "^1.0.0", "b": "^1.0.0"}},
        {"node_modules/a": pkg(dependencies={"x": "1", "y": "2"})},
    )
    backward = lockfile(
        {"dependencies": {"b": "^1.0.0", "a": "^1.0.0"}},
        {"node_modules/a": pkg(dependencies={"y": "2", "x": "1"})},
    )

    assert parse_lockfile(forward) == parse_lockfile(backward)


# --- direct dependencies are decided per install path (C4) ---------------------------


def test_nested_copy_of_a_root_dependency_is_not_direct() -> None:
    """Regression for C4: every copy sharing a root dependency's name was marked direct."""
    text = lockfile(
        {"dependencies": {"x": "^2.0.0"}},
        {
            "node_modules/x": pkg("2.0.0"),
            "node_modules/other": pkg("1.0.0"),
            "node_modules/other/node_modules/x": pkg("1.0.0"),
        },
    )

    nodes = parse_lockfile(text).nodes

    top = node_at(nodes, "node_modules/x")
    nested = node_at(nodes, "node_modules/other/node_modules/x")
    assert top.is_direct is True
    assert top.scopes == {DependencyScope.PRODUCTION}
    assert nested.is_direct is False
    assert nested.scopes == frozenset()


def test_scoped_root_dependency_is_direct_but_its_nested_copy_is_not() -> None:
    text = lockfile(
        {"dependencies": {"@demo/scoped": "^1.0.0"}},
        {
            "node_modules/@demo/scoped": pkg(),
            "node_modules/a": pkg(),
            "node_modules/a/node_modules/@demo/scoped": pkg("0.9.0"),
        },
    )

    nodes = parse_lockfile(text).nodes

    assert node_at(nodes, "node_modules/@demo/scoped").is_direct is True
    assert node_at(nodes, "node_modules/a/node_modules/@demo/scoped").is_direct is False


def test_path_like_root_dependency_key_does_not_make_a_nested_install_direct() -> None:
    """A malformed root key such as 'a/node_modules/x' must not mark a nested install direct."""
    text = lockfile(
        {"dependencies": {"a/node_modules/x": "^1.0.0"}},
        {
            "node_modules/a": pkg(),
            "node_modules/a/node_modules/x": pkg(),
        },
    )

    nodes = parse_lockfile(text).nodes

    assert node_at(nodes, "node_modules/a/node_modules/x").is_direct is False
    assert node_at(nodes, "node_modules/a").is_direct is False


def test_dev_root_dependency_marks_only_the_top_level_install() -> None:
    text = lockfile(
        {"devDependencies": {"d": "^1.0.0"}},
        {
            "node_modules/d": pkg(dev=True),
            "node_modules/a": pkg(),
            "node_modules/a/node_modules/d": pkg("0.1.0"),
        },
    )

    nodes = parse_lockfile(text).nodes

    assert node_at(nodes, "node_modules/d").scopes == {DependencyScope.DEVELOPMENT}
    assert node_at(nodes, "node_modules/a/node_modules/d").is_direct is False


def test_alias_install_is_direct_by_install_path() -> None:
    """Regression for the alias risk: root declares the alias, the entry names the package."""
    text = lockfile(
        {"dependencies": {"myalias": "npm:real@^1.0.0"}},
        {"node_modules/myalias": pkg(name="real")},
    )

    node = node_at(parse_lockfile(text).nodes, "node_modules/myalias")

    assert node.name == "real"
    assert node.is_direct is True


# --- malformed declared dependencies ------------------------------------------------------


def test_root_field_must_be_an_object() -> None:
    with pytest.raises(LockfileParseError, match="Root field 'dependencies' must be an object"):
        parse_lockfile(lockfile({"dependencies": ["a"]}, {}))


def test_package_field_must_be_an_object() -> None:
    text = lockfile({}, {"node_modules/a": pkg(dependencies=["b"])})

    with pytest.raises(LockfileParseError, match="node_modules/a field 'dependencies'"):
        parse_lockfile(text)


def test_requested_range_must_be_a_string() -> None:
    text = lockfile({}, {"node_modules/a": pkg(dependencies={"b": 1})})

    with pytest.raises(LockfileParseError, match="range for 'b'.*must be a string"):
        parse_lockfile(text)


def test_empty_dependency_name_is_rejected() -> None:
    text = lockfile({"dependencies": {"": "^1.0.0"}}, {})

    with pytest.raises(LockfileParseError, match="invalid dependency name"):
        parse_lockfile(text)


# --- compatibility -------------------------------------------------------------------------


def test_parse_lockfile_text_returns_the_same_nodes() -> None:
    text = lockfile({"dependencies": {"a": "^1.0.0"}}, {"node_modules/a": pkg()})

    assert parse_lockfile_text(text) == list(parse_lockfile(text).nodes)
