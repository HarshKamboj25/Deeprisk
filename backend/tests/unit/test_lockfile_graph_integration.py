"""End to end: lockfile text -> parser -> graph edges, with no test doubles.

The lockfile structures are synthetic and follow our current understanding of the v2/v3
layout, which is still to be checked against real npm output.
"""

import json
from typing import Any

from deprisk.core.graph import build_dependency_edges, build_graph_edges
from deprisk.core.lockfile import parse_lockfile, parse_lockfile_text
from deprisk.core.models import ROOT_INSTALL_PATH, DependencyEdge, DependencyScope


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


def edges_for(text: str) -> list[DependencyEdge]:
    return build_graph_edges(parse_lockfile(text))


def summarize(edges: list[DependencyEdge]) -> list[tuple[str, str, str | None, str]]:
    return [(e.parent_path, e.dependency_name, e.child_path, e.resolution.value) for e in edges]


def test_nested_edges_are_produced_from_the_lockfile() -> None:
    """Regression for G1: nested edges could never exist while the parser dropped them."""
    text = lockfile(
        {"dependencies": {"a": "^1.0.0"}},
        {
            "node_modules/a": pkg(dependencies={"b": "^1.0.0"}),
            "node_modules/a/node_modules/b": pkg(),
        },
    )

    assert summarize(edges_for(text)) == [
        (ROOT_INSTALL_PATH, "a", "node_modules/a", "resolved"),
        ("node_modules/a", "b", "node_modules/a/node_modules/b", "resolved"),
    ]


def test_scoped_root_dependency_resolves_end_to_end() -> None:
    text = lockfile(
        {"dependencies": {"@demo/scoped": "^1.0.0"}},
        {"node_modules/@demo/scoped": pkg()},
    )

    assert summarize(edges_for(text)) == [
        (ROOT_INSTALL_PATH, "@demo/scoped", "node_modules/@demo/scoped", "resolved"),
    ]


def test_root_dependency_binds_to_the_top_level_install_end_to_end() -> None:
    text = lockfile(
        {"dependencies": {"x": "^2.0.0"}},
        {
            "node_modules/a": pkg(),
            "node_modules/a/node_modules/x": pkg("1.0.0"),
            "node_modules/x": pkg("2.0.0"),
        },
    )

    assert summarize(edges_for(text)) == [
        (ROOT_INSTALL_PATH, "x", "node_modules/x", "resolved"),
    ]


def test_same_name_and_version_at_two_paths_keep_distinct_parents() -> None:
    """ADR-002 required test, with real parser output."""
    text = lockfile(
        {"dependencies": {"a": "^1.0.0", "c": "^1.0.0"}},
        {
            "node_modules/a": pkg(dependencies={"b": "^1.0.0"}),
            "node_modules/a/node_modules/b": pkg("1.0.0"),
            "node_modules/c": pkg(dependencies={"b": "^1.0.0"}),
            "node_modules/c/node_modules/b": pkg("1.0.0"),
        },
    )

    parsed = parse_lockfile(text)
    edges = build_graph_edges(parsed)

    b_nodes = [node for node in parsed.nodes if node.name == "b"]
    assert len(b_nodes) == 2
    assert {(node.name, node.version) for node in b_nodes} == {("b", "1.0.0")}
    assert [(e.parent_path, e.child_path) for e in edges if e.dependency_name == "b"] == [
        ("node_modules/a", "node_modules/a/node_modules/b"),
        ("node_modules/c", "node_modules/c/node_modules/b"),
    ]


def test_missing_root_dependencies_are_retained_with_their_scope() -> None:
    text = lockfile(
        {
            "dependencies": {"ghost": "^1.0.0"},
            "optionalDependencies": {"fsevents": "^2.0.0"},
        },
        {},
    )

    edges = edges_for(text)

    assert summarize(edges) == [
        (ROOT_INSTALL_PATH, "fsevents", None, "missing_optional"),
        (ROOT_INSTALL_PATH, "ghost", None, "missing"),
    ]
    assert edges[0].scope is DependencyScope.OPTIONAL
    assert edges[0].is_optional is True
    assert edges[1].scope is DependencyScope.PRODUCTION


def test_missing_optional_nested_dependency_is_retained() -> None:
    text = lockfile(
        {"dependencies": {"a": "^1.0.0"}},
        {"node_modules/a": pkg(optionalDependencies={"fsevents": "^2.0.0"})},
    )

    assert summarize(edges_for(text)) == [
        (ROOT_INSTALL_PATH, "a", "node_modules/a", "resolved"),
        ("node_modules/a", "fsevents", None, "missing_optional"),
    ]


def test_peer_edges_carry_scope_and_optionality() -> None:
    text = lockfile(
        {"dependencies": {"a": "^1.0.0"}},
        {
            "node_modules/a": pkg(
                peerDependencies={"react": "^18.0.0", "vue": "^3.0.0"},
                peerDependenciesMeta={"vue": {"optional": True}},
            ),
            "node_modules/react": pkg("18.0.0", peer=True),
        },
    )

    peer_edges = [e for e in edges_for(text) if e.scope is DependencyScope.PEER]

    assert [(e.dependency_name, e.resolution.value, e.is_optional) for e in peer_edges] == [
        ("react", "resolved", False),
        ("vue", "missing_optional", True),
    ]


def test_dev_root_dependency_edge_has_development_scope() -> None:
    text = lockfile(
        {"devDependencies": {"d": "^1.0.0"}},
        {"node_modules/d": pkg(dev=True)},
    )

    (edge,) = edges_for(text)

    assert edge.scope is DependencyScope.DEVELOPMENT
    assert edge.resolution.value == "resolved"


def test_alias_root_dependency_resolves_by_directory_name() -> None:
    text = lockfile(
        {"dependencies": {"myalias": "npm:real@^1.0.0"}},
        {"node_modules/myalias": pkg(name="real")},
    )

    parsed = parse_lockfile(text)

    assert summarize(build_graph_edges(parsed)) == [
        (ROOT_INSTALL_PATH, "myalias", "node_modules/myalias", "resolved"),
    ]
    assert parsed.nodes[0].name == "real"


def test_edges_do_not_depend_on_json_key_order() -> None:
    forward = lockfile(
        {"dependencies": {"a": "^1.0.0", "c": "^1.0.0"}},
        {
            "node_modules/a": pkg(dependencies={"b": "^1.0.0", "ghost": "^1.0.0"}),
            "node_modules/a/node_modules/b": pkg(),
            "node_modules/c": pkg(),
        },
    )
    backward = lockfile(
        {"dependencies": {"c": "^1.0.0", "a": "^1.0.0"}},
        {
            "node_modules/c": pkg(),
            "node_modules/a/node_modules/b": pkg(),
            "node_modules/a": pkg(dependencies={"ghost": "^1.0.0", "b": "^1.0.0"}),
        },
    )

    assert edges_for(forward) == edges_for(backward)


def test_name_only_entry_point_still_works() -> None:
    """Compatibility: root dependencies given as name -> range, scope unknown."""
    text = lockfile(
        {"dependencies": {"a": "^1.0.0"}},
        {"node_modules/a": pkg(dependencies={"b": "^1.0.0"}), "node_modules/b": pkg()},
    )

    edges = build_dependency_edges(parse_lockfile_text(text), {"a": "^1.0.0"})

    assert summarize(edges) == [
        (ROOT_INSTALL_PATH, "a", "node_modules/a", "resolved"),
        ("node_modules/a", "b", "node_modules/b", "resolved"),
    ]
    assert edges[0].scope is DependencyScope.UNKNOWN
