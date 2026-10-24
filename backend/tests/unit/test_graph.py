"""Tests for dependency-edge construction (ADR-002: install-path identity)."""

import pytest

from deprisk.core import graph
from deprisk.core.graph import GraphBuildError, build_dependency_edges
from deprisk.core.models import (
    ROOT_INSTALL_PATH,
    DependencyEdge,
    DependencyNode,
    DependencyScope,
)

Declared = tuple[str, str, DependencyScope, bool]


def node(install_path: str, name: str, version: str = "1.0.0") -> DependencyNode:
    return DependencyNode(install_path=install_path, name=name, version=version)


def declare(monkeypatch: pytest.MonkeyPatch, declared: dict[str, list[Declared]]) -> None:
    """Stand in for parser metadata. The parser does not retain declared dependencies yet."""

    def fake(parent: DependencyNode) -> list[Declared]:
        return declared.get(parent.install_path, [])

    monkeypatch.setattr(graph, "_declared_dependencies", fake)


def summarize(edges: list[DependencyEdge]) -> list[tuple[str, str, str | None, str]]:
    return [(e.parent_path, e.dependency_name, e.child_path, e.resolution.value) for e in edges]


def prod(name: str, requested_range: str = "^1.0.0") -> Declared:
    return (name, requested_range, DependencyScope.PRODUCTION, False)


# --- root dependencies ------------------------------------------------------


def test_empty_graph_has_no_edges() -> None:
    assert build_dependency_edges([], {}) == []


def test_root_dependency_resolves_to_top_level_install() -> None:
    edges = build_dependency_edges(
        [node("node_modules/example", "example")],
        {"example": "^1.0.0"},
    )

    assert summarize(edges) == [
        (ROOT_INSTALL_PATH, "example", "node_modules/example", "resolved"),
    ]
    assert edges[0].requested_range == "^1.0.0"


def test_scoped_root_dependency_is_resolved() -> None:
    """Regression for C2: scoped root dependencies were silently dropped."""
    edges = build_dependency_edges(
        [node("node_modules/@demo/scoped", "@demo/scoped", "2.0.0")],
        {"@demo/scoped": "^2.0.0"},
    )

    assert summarize(edges) == [
        (ROOT_INSTALL_PATH, "@demo/scoped", "node_modules/@demo/scoped", "resolved"),
    ]


@pytest.mark.parametrize("reverse_nodes", [False, True])
def test_root_dependency_prefers_top_level_over_nested_copy(reverse_nodes: bool) -> None:
    """Regression for C3: 'node_modules/a/node_modules/x' sorted before 'node_modules/x'."""
    nodes = [
        node("node_modules/a/node_modules/x", "x", "1.0.0"),
        node("node_modules/x", "x", "2.0.0"),
    ]
    if reverse_nodes:
        nodes.reverse()

    edges = build_dependency_edges(nodes, {"x": "^2.0.0"})

    assert summarize(edges) == [(ROOT_INSTALL_PATH, "x", "node_modules/x", "resolved")]


def test_root_dependency_is_not_bound_to_a_nested_only_copy() -> None:
    edges = build_dependency_edges(
        [node("node_modules/a/node_modules/x", "x")],
        {"x": "^1.0.0"},
    )

    assert summarize(edges) == [(ROOT_INSTALL_PATH, "x", None, "missing")]


def test_scoped_root_dependency_is_not_bound_to_a_nested_only_copy() -> None:
    edges = build_dependency_edges(
        [node("node_modules/a/node_modules/@demo/scoped", "@demo/scoped")],
        {"@demo/scoped": "^1.0.0"},
    )

    assert summarize(edges) == [(ROOT_INSTALL_PATH, "@demo/scoped", None, "missing")]


def test_missing_root_dependency_is_retained_with_its_range() -> None:
    edges = build_dependency_edges([], {"ghost": "^3.0.0"})

    assert summarize(edges) == [(ROOT_INSTALL_PATH, "ghost", None, "missing")]
    assert edges[0].requested_range == "^3.0.0"
    assert edges[0].is_optional is False


# --- nested resolution and install-path identity ----------------------------


def test_multiple_installed_versions_stay_distinct(monkeypatch: pytest.MonkeyPatch) -> None:
    nodes = [
        node("node_modules/example", "example", "2.0.0"),
        node("node_modules/other", "other", "1.0.0"),
        node("node_modules/other/node_modules/example", "example", "1.0.0"),
    ]
    declare(monkeypatch, {"node_modules/other": [prod("example", "^1.0.0")]})

    edges = build_dependency_edges(nodes, {"example": "^2.0.0", "other": "^1.0.0"})

    assert summarize(edges) == [
        (ROOT_INSTALL_PATH, "example", "node_modules/example", "resolved"),
        (ROOT_INSTALL_PATH, "other", "node_modules/other", "resolved"),
        (
            "node_modules/other",
            "example",
            "node_modules/other/node_modules/example",
            "resolved",
        ),
    ]


def test_same_name_and_version_at_two_paths_keep_distinct_parents(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ADR-002 required test: b@1.0.0 at two paths must not be merged."""
    nodes = [
        node("node_modules/a", "a"),
        node("node_modules/a/node_modules/b", "b", "1.0.0"),
        node("node_modules/c", "c"),
        node("node_modules/c/node_modules/b", "b", "1.0.0"),
    ]
    declare(
        monkeypatch,
        {
            "node_modules/a": [prod("b")],
            "node_modules/c": [prod("b")],
        },
    )

    edges = build_dependency_edges(nodes, {"a": "^1.0.0", "c": "^1.0.0"})

    b_edges = [edge for edge in edges if edge.dependency_name == "b"]
    assert [(e.parent_path, e.child_path) for e in b_edges] == [
        ("node_modules/a", "node_modules/a/node_modules/b"),
        ("node_modules/c", "node_modules/c/node_modules/b"),
    ]


def test_nested_resolution_prefers_nearest_install(monkeypatch: pytest.MonkeyPatch) -> None:
    nodes = [
        node("node_modules/a", "a"),
        node("node_modules/a/node_modules/b", "b"),
        node("node_modules/a/node_modules/c", "c", "1.0.0"),
        node("node_modules/c", "c", "2.0.0"),
    ]
    declare(monkeypatch, {"node_modules/a/node_modules/b": [prod("c")]})

    edges = build_dependency_edges(nodes, {})

    assert summarize(edges) == [
        (
            "node_modules/a/node_modules/b",
            "c",
            "node_modules/a/node_modules/c",
            "resolved",
        ),
    ]


def test_nested_resolution_walks_up_to_top_level(monkeypatch: pytest.MonkeyPatch) -> None:
    nodes = [
        node("node_modules/a", "a"),
        node("node_modules/a/node_modules/b", "b"),
        node("node_modules/c", "c"),
    ]
    declare(monkeypatch, {"node_modules/a/node_modules/b": [prod("c")]})

    edges = build_dependency_edges(nodes, {})

    assert summarize(edges) == [
        ("node_modules/a/node_modules/b", "c", "node_modules/c", "resolved"),
    ]


def test_scoped_parent_resolves_children(monkeypatch: pytest.MonkeyPatch) -> None:
    nodes = [
        node("node_modules/@s/a", "@s/a"),
        node("node_modules/@s/a/node_modules/b", "b"),
        node("node_modules/@s/a/node_modules/@t/d", "@t/d"),
        node("node_modules/c", "c"),
    ]
    declare(
        monkeypatch,
        {"node_modules/@s/a": [prod("b"), prod("@t/d"), prod("c")]},
    )

    edges = build_dependency_edges(nodes, {})

    assert summarize(edges) == [
        ("node_modules/@s/a", "@t/d", "node_modules/@s/a/node_modules/@t/d", "resolved"),
        ("node_modules/@s/a", "b", "node_modules/@s/a/node_modules/b", "resolved"),
        ("node_modules/@s/a", "c", "node_modules/c", "resolved"),
    ]


# --- unresolved edges ---------------------------------------------------------


def test_missing_nested_dependency_is_retained(monkeypatch: pytest.MonkeyPatch) -> None:
    declare(monkeypatch, {"node_modules/a": [prod("ghost", "^9.0.0")]})

    edges = build_dependency_edges([node("node_modules/a", "a")], {})

    assert summarize(edges) == [("node_modules/a", "ghost", None, "missing")]
    assert edges[0].requested_range == "^9.0.0"
    assert edges[0].is_optional is False


def test_missing_optional_dependency_is_retained(monkeypatch: pytest.MonkeyPatch) -> None:
    """ADR-002 required test: an optional dependency that is absent is missing_optional."""
    declare(
        monkeypatch,
        {"node_modules/a": [("fsevents", "^2.0.0", DependencyScope.OPTIONAL, True)]},
    )

    edges = build_dependency_edges([node("node_modules/a", "a")], {})

    assert summarize(edges) == [("node_modules/a", "fsevents", None, "missing_optional")]
    assert edges[0].is_optional is True
    assert edges[0].scope is DependencyScope.OPTIONAL


def test_two_missing_dependencies_of_one_parent_are_not_collapsed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    declare(monkeypatch, {"node_modules/a": [prod("ghost-one"), prod("ghost-two")]})

    edges = build_dependency_edges([node("node_modules/a", "a")], {})

    assert [e.dependency_name for e in edges] == ["ghost-one", "ghost-two"]


# --- ordering -------------------------------------------------------------------


def _mixed_graph(monkeypatch: pytest.MonkeyPatch, *, reverse: bool) -> list[DependencyEdge]:
    nodes = [
        node("node_modules/a", "a"),
        node("node_modules/alpha", "alpha"),
    ]
    declared: list[Declared] = [
        prod("zeta"),
        prod("alpha"),
        ("mid", "^1.0.0", DependencyScope.OPTIONAL, True),
        prod("beta"),
    ]
    root = {"a": "^1.0.0", "ghost-root": "^1.0.0"}

    if reverse:
        nodes.reverse()
        declared.reverse()
        root = dict(reversed(list(root.items())))

    declare(monkeypatch, {"node_modules/a": declared})
    return build_dependency_edges(nodes, root)


def test_resolved_and_unresolved_edges_sort_without_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """child_path may be None; sorting must never compare None with a string."""
    edges = _mixed_graph(monkeypatch, reverse=False)

    assert summarize(edges) == [
        (ROOT_INSTALL_PATH, "a", "node_modules/a", "resolved"),
        (ROOT_INSTALL_PATH, "ghost-root", None, "missing"),
        ("node_modules/a", "alpha", "node_modules/alpha", "resolved"),
        ("node_modules/a", "beta", None, "missing"),
        ("node_modules/a", "mid", None, "missing_optional"),
        ("node_modules/a", "zeta", None, "missing"),
    ]


def test_edge_order_is_independent_of_input_order(monkeypatch: pytest.MonkeyPatch) -> None:
    forward = _mixed_graph(monkeypatch, reverse=False)
    backward = _mixed_graph(monkeypatch, reverse=True)

    assert forward == backward


# --- invalid input --------------------------------------------------------------


def test_duplicate_install_paths_are_rejected() -> None:
    nodes = [
        node("node_modules/example", "example", "1.0.0"),
        node("node_modules/example", "example", "2.0.0"),
    ]

    with pytest.raises(GraphBuildError, match="Duplicate installation paths"):
        build_dependency_edges(nodes, {})
