"""Synthetic unit tests for L1 graph scope propagation.

Tests the propagation contract and effective deployment scope derivation
across production, development, optional, peer, unknown, and unreachable nodes.
"""

from typing import Any  # noqa: I001

import pytest
from pydantic import ValidationError

from deprisk.core.models import (
    ROOT_INSTALL_PATH,
    DependencyEdge,
    DependencyNode,
    DependencyScope,
    EdgeResolution,
)
from deprisk.core.scope import (
    EffectiveScope,
    NodeReachability,
    ScopePropagationResult,
    propagate_scopes,
)


def _node(
    install_path: str,
    name: str | None = None,
    version: str = "1.0.0",
    **kwargs: Any,
) -> DependencyNode:
    """Helper to create a DependencyNode with default name derived from path."""
    if name is None:
        name = install_path.rsplit("node_modules/", 1)[-1]
    return DependencyNode(install_path=install_path, name=name, version=version, **kwargs)


def _edge(
    parent_path: str,
    child_path: str | None,
    dependency_name: str,
    scope: DependencyScope = DependencyScope.PRODUCTION,
    is_optional: bool = False,
    resolution: EdgeResolution = EdgeResolution.RESOLVED,
    requested_range: str = "^1.0.0",
) -> DependencyEdge:
    """Helper to create a DependencyEdge."""
    return DependencyEdge(
        parent_path=parent_path,
        child_path=child_path,
        dependency_name=dependency_name,
        requested_range=requested_range,
        scope=scope,
        is_optional=is_optional,
        resolution=resolution,
    )


# --- 1. Production Propagation ------------------------------------------------


def test_direct_production_dependency_propagates_production() -> None:
    node_a = _node("node_modules/a")
    edge_a = _edge(ROOT_INSTALL_PATH, "node_modules/a", "a", scope=DependencyScope.PRODUCTION)

    result = propagate_scopes([node_a], [edge_a])

    reach = result.nodes["node_modules/a"]
    assert reach.effective_scope is EffectiveScope.PRODUCTION
    assert reach.is_production is True
    assert reach.is_dev is False
    assert reach.is_optional is False
    assert reach.is_dev_optional is False
    assert reach.is_peer is False
    assert reach.is_unreachable is False
    assert reach.has_production_path is True
    assert reach.has_development_path is False
    assert reach.has_optional_path is False
    assert reach.has_required_path is True
    assert reach.reached_states == frozenset({"(PROD, REQ)"})


def test_transitive_production_chain_propagates_production() -> None:
    nodes = [_node("node_modules/a"), _node("node_modules/b"), _node("node_modules/c")]
    edges = [
        _edge(ROOT_INSTALL_PATH, "node_modules/a", "a", scope=DependencyScope.PRODUCTION),
        _edge("node_modules/a", "node_modules/b", "b", scope=DependencyScope.PRODUCTION),
        _edge("node_modules/b", "node_modules/c", "c", scope=DependencyScope.PRODUCTION),
    ]

    result = propagate_scopes(nodes, edges)

    for path in ("node_modules/a", "node_modules/b", "node_modules/c"):
        reach = result.nodes[path]
        assert reach.effective_scope is EffectiveScope.PRODUCTION
        assert reach.is_production is True
        assert reach.reached_states == frozenset({"(PROD, REQ)"})


# --- 2. Development Propagation -----------------------------------------------


def test_direct_development_dependency_propagates_development() -> None:
    node_dev = _node("node_modules/dev-tool")
    edge_dev = _edge(
        ROOT_INSTALL_PATH, "node_modules/dev-tool", "dev-tool", scope=DependencyScope.DEVELOPMENT
    )

    result = propagate_scopes([node_dev], [edge_dev])

    reach = result.nodes["node_modules/dev-tool"]
    assert reach.effective_scope is EffectiveScope.DEVELOPMENT
    assert reach.is_production is False
    assert reach.is_dev is True
    assert reach.is_optional is False
    assert reach.is_dev_optional is False
    assert reach.is_peer is False
    assert reach.has_development_path is True
    assert reach.has_production_path is False
    assert reach.reached_states == frozenset({"(DEV, REQ)"})


def test_transitive_production_edge_under_development_remains_development() -> None:
    nodes = [_node("node_modules/dev-tool"), _node("node_modules/dep-of-dev")]
    edges = [
        _edge(
            ROOT_INSTALL_PATH,
            "node_modules/dev-tool",
            "dev-tool",
            scope=DependencyScope.DEVELOPMENT,
        ),
        _edge(
            "node_modules/dev-tool",
            "node_modules/dep-of-dev",
            "dep-of-dev",
            scope=DependencyScope.PRODUCTION,
        ),
    ]

    result = propagate_scopes(nodes, edges)

    reach = result.nodes["node_modules/dep-of-dev"]
    assert reach.effective_scope is EffectiveScope.DEVELOPMENT
    assert reach.is_production is False
    assert reach.is_dev is True
    assert reach.reached_states == frozenset({"(DEV, REQ)"})


# --- 3. Production Precedence over Development --------------------------------


def test_production_dominates_development_in_mixed_paths() -> None:
    nodes = [
        _node("node_modules/prod-tool"),
        _node("node_modules/dev-tool"),
        _node("node_modules/shared"),
    ]
    edges = [
        _edge(
            ROOT_INSTALL_PATH,
            "node_modules/prod-tool",
            "prod-tool",
            scope=DependencyScope.PRODUCTION,
        ),
        _edge(
            ROOT_INSTALL_PATH,
            "node_modules/dev-tool",
            "dev-tool",
            scope=DependencyScope.DEVELOPMENT,
        ),
        _edge(
            "node_modules/prod-tool",
            "node_modules/shared",
            "shared",
            scope=DependencyScope.PRODUCTION,
        ),
        _edge(
            "node_modules/dev-tool",
            "node_modules/shared",
            "shared",
            scope=DependencyScope.PRODUCTION,
        ),
    ]

    result = propagate_scopes(nodes, edges)

    reach = result.nodes["node_modules/shared"]
    assert reach.effective_scope is EffectiveScope.PRODUCTION
    assert reach.is_production is True
    assert reach.is_dev is False
    assert reach.has_production_path is True
    assert reach.has_development_path is True
    assert reach.reached_states == frozenset({"(PROD, REQ)", "(DEV, REQ)"})


# --- 4. Optional and DEV_OPTIONAL Paths ----------------------------------------


def test_direct_root_optional_dependency_becomes_optional() -> None:
    node_opt = _node("node_modules/opt-pkg")
    edge_opt = _edge(
        ROOT_INSTALL_PATH,
        "node_modules/opt-pkg",
        "opt-pkg",
        scope=DependencyScope.OPTIONAL,
        is_optional=True,
    )

    result = propagate_scopes([node_opt], [edge_opt])

    reach = result.nodes["node_modules/opt-pkg"]
    assert reach.effective_scope is EffectiveScope.OPTIONAL
    assert reach.is_production is False
    assert reach.is_optional is True
    assert reach.is_dev is False
    assert reach.has_optional_path is True
    assert reach.reached_states == frozenset({"(PROD, OPT)"})


def test_optional_edge_under_production_becomes_optional() -> None:
    nodes = [_node("node_modules/prod-pkg"), _node("node_modules/opt-child")]
    edges = [
        _edge(
            ROOT_INSTALL_PATH,
            "node_modules/prod-pkg",
            "prod-pkg",
            scope=DependencyScope.PRODUCTION,
        ),
        _edge(
            "node_modules/prod-pkg",
            "node_modules/opt-child",
            "opt-child",
            scope=DependencyScope.OPTIONAL,
            is_optional=True,
        ),
    ]

    result = propagate_scopes(nodes, edges)

    reach = result.nodes["node_modules/opt-child"]
    assert reach.effective_scope is EffectiveScope.OPTIONAL
    assert reach.is_production is False
    assert reach.is_optional is True
    assert reach.has_optional_path is True
    assert reach.reached_states == frozenset({"(PROD, OPT)"})


def test_transitive_production_edge_under_optional_remains_optional() -> None:
    nodes = [
        _node("node_modules/opt-root"),
        _node("node_modules/opt-child"),
    ]
    edges = [
        _edge(
            ROOT_INSTALL_PATH,
            "node_modules/opt-root",
            "opt-root",
            scope=DependencyScope.OPTIONAL,
            is_optional=True,
        ),
        _edge(
            "node_modules/opt-root",
            "node_modules/opt-child",
            "opt-child",
            scope=DependencyScope.PRODUCTION,
        ),
    ]

    result = propagate_scopes(nodes, edges)

    reach = result.nodes["node_modules/opt-child"]
    assert reach.effective_scope is EffectiveScope.OPTIONAL
    assert reach.is_production is False
    assert reach.is_optional is True
    assert reach.has_optional_path is True
    assert reach.reached_states == frozenset({"(PROD, OPT)"})


def test_production_required_beats_production_optional_for_effective_scope() -> None:
    nodes = [
        _node("node_modules/req-parent"),
        _node("node_modules/opt-parent"),
        _node("node_modules/shared-target"),
    ]
    edges = [
        _edge(
            ROOT_INSTALL_PATH,
            "node_modules/req-parent",
            "req-parent",
            scope=DependencyScope.PRODUCTION,
        ),
        _edge(
            ROOT_INSTALL_PATH,
            "node_modules/opt-parent",
            "opt-parent",
            scope=DependencyScope.OPTIONAL,
            is_optional=True,
        ),
        _edge(
            "node_modules/req-parent",
            "node_modules/shared-target",
            "shared-target",
            scope=DependencyScope.PRODUCTION,
        ),
        _edge(
            "node_modules/opt-parent",
            "node_modules/shared-target",
            "shared-target",
            scope=DependencyScope.PRODUCTION,
        ),
    ]

    result = propagate_scopes(nodes, edges)

    reach = result.nodes["node_modules/shared-target"]
    assert reach.effective_scope is EffectiveScope.PRODUCTION
    assert reach.is_production is True
    assert reach.is_optional is False
    assert reach.has_required_path is True
    assert reach.has_optional_path is True
    assert reach.reached_states == frozenset({"(PROD, REQ)", "(PROD, OPT)"})


def test_optional_edge_under_development_becomes_dev_optional() -> None:
    nodes = [_node("node_modules/dev-parent"), _node("node_modules/dev-opt-child")]
    edges = [
        _edge(
            ROOT_INSTALL_PATH,
            "node_modules/dev-parent",
            "dev-parent",
            scope=DependencyScope.DEVELOPMENT,
        ),
        _edge(
            "node_modules/dev-parent",
            "node_modules/dev-opt-child",
            "dev-opt-child",
            scope=DependencyScope.OPTIONAL,
            is_optional=True,
        ),
    ]

    result = propagate_scopes(nodes, edges)

    reach = result.nodes["node_modules/dev-opt-child"]
    assert reach.effective_scope is EffectiveScope.DEV_OPTIONAL
    assert reach.is_production is False
    assert reach.is_dev is False
    assert reach.is_optional is True
    assert reach.is_dev_optional is True
    assert reach.has_development_path is True
    assert reach.has_optional_path is True
    assert reach.reached_states == frozenset({"(DEV, OPT)"})


def test_development_and_optional_paths_combine_to_dev_optional() -> None:
    nodes = [
        _node("node_modules/dev-parent"),
        _node("node_modules/opt-parent"),
        _node("node_modules/shared"),
    ]
    edges = [
        _edge(
            ROOT_INSTALL_PATH,
            "node_modules/dev-parent",
            "dev-parent",
            scope=DependencyScope.DEVELOPMENT,
        ),
        _edge(
            ROOT_INSTALL_PATH,
            "node_modules/opt-parent",
            "opt-parent",
            scope=DependencyScope.OPTIONAL,
            is_optional=True,
        ),
        _edge(
            "node_modules/dev-parent",
            "node_modules/shared",
            "shared",
            scope=DependencyScope.PRODUCTION,
        ),
        _edge(
            "node_modules/opt-parent",
            "node_modules/shared",
            "shared",
            scope=DependencyScope.PRODUCTION,
        ),
    ]

    result = propagate_scopes(nodes, edges)

    reach = result.nodes["node_modules/shared"]
    assert reach.effective_scope is EffectiveScope.DEV_OPTIONAL
    assert reach.is_production is False
    assert reach.is_dev is False
    assert reach.is_optional is True
    assert reach.is_dev_optional is True
    assert reach.has_development_path is True
    assert reach.has_optional_path is True
    assert reach.reached_states == frozenset({"(DEV, REQ)", "(PROD, OPT)"})


# --- 5. Peer and Optional-Peer Behavior ---------------------------------------


def test_peer_edge_from_production_parent_becomes_production() -> None:
    nodes = [_node("node_modules/prod-host"), _node("node_modules/peer-target")]
    edges = [
        _edge(
            ROOT_INSTALL_PATH,
            "node_modules/prod-host",
            "prod-host",
            scope=DependencyScope.PRODUCTION,
        ),
        _edge(
            "node_modules/prod-host",
            "node_modules/peer-target",
            "peer-target",
            scope=DependencyScope.PEER,
            is_optional=False,
        ),
    ]

    result = propagate_scopes(nodes, edges)

    reach = result.nodes["node_modules/peer-target"]
    assert reach.effective_scope is EffectiveScope.PRODUCTION
    assert reach.is_production is True
    assert reach.reached_states == frozenset({"(PROD, REQ)"})


def test_peer_edge_from_development_parent_becomes_development() -> None:
    nodes = [_node("node_modules/dev-host"), _node("node_modules/peer-target")]
    edges = [
        _edge(
            ROOT_INSTALL_PATH,
            "node_modules/dev-host",
            "dev-host",
            scope=DependencyScope.DEVELOPMENT,
        ),
        _edge(
            "node_modules/dev-host",
            "node_modules/peer-target",
            "peer-target",
            scope=DependencyScope.PEER,
            is_optional=False,
        ),
    ]

    result = propagate_scopes(nodes, edges)

    reach = result.nodes["node_modules/peer-target"]
    assert reach.effective_scope is EffectiveScope.DEVELOPMENT
    assert reach.is_dev is True
    assert reach.is_production is False
    assert reach.reached_states == frozenset({"(DEV, REQ)"})


def test_optional_peer_from_production_parent_becomes_optional() -> None:
    nodes = [_node("node_modules/prod-host"), _node("node_modules/opt-peer")]
    edges = [
        _edge(
            ROOT_INSTALL_PATH,
            "node_modules/prod-host",
            "prod-host",
            scope=DependencyScope.PRODUCTION,
        ),
        _edge(
            "node_modules/prod-host",
            "node_modules/opt-peer",
            "opt-peer",
            scope=DependencyScope.PEER,
            is_optional=True,
        ),
    ]

    result = propagate_scopes(nodes, edges)

    reach = result.nodes["node_modules/opt-peer"]
    assert reach.effective_scope is EffectiveScope.OPTIONAL
    assert reach.is_production is False
    assert reach.is_optional is True
    assert reach.reached_states == frozenset({"(PROD, OPT)"})


def test_optional_peer_from_development_parent_becomes_dev_optional() -> None:
    nodes = [_node("node_modules/dev-host"), _node("node_modules/dev-opt-peer")]
    edges = [
        _edge(
            ROOT_INSTALL_PATH,
            "node_modules/dev-host",
            "dev-host",
            scope=DependencyScope.DEVELOPMENT,
        ),
        _edge(
            "node_modules/dev-host",
            "node_modules/dev-opt-peer",
            "dev-opt-peer",
            scope=DependencyScope.PEER,
            is_optional=True,
        ),
    ]

    result = propagate_scopes(nodes, edges)

    reach = result.nodes["node_modules/dev-opt-peer"]
    assert reach.effective_scope is EffectiveScope.DEV_OPTIONAL
    assert reach.is_dev_optional is True
    assert reach.is_dev is False
    assert reach.is_optional is True
    assert reach.reached_states == frozenset({"(DEV, OPT)"})


def test_standalone_root_peer_dependency_becomes_peer() -> None:
    node_peer = _node("node_modules/root-peer")
    edge_peer = _edge(
        ROOT_INSTALL_PATH,
        "node_modules/root-peer",
        "root-peer",
        scope=DependencyScope.PEER,
        is_optional=False,
    )

    result = propagate_scopes([node_peer], [edge_peer])

    reach = result.nodes["node_modules/root-peer"]
    assert reach.effective_scope is EffectiveScope.PEER
    assert reach.is_peer is True
    assert reach.is_production is False
    assert reach.is_dev is False
    assert reach.reached_states == frozenset({"(PEER, REQ)"})


def test_optional_root_peer_dependency_becomes_peer() -> None:
    node_peer = _node("node_modules/root-opt-peer")
    edge_peer = _edge(
        ROOT_INSTALL_PATH,
        "node_modules/root-opt-peer",
        "root-opt-peer",
        scope=DependencyScope.PEER,
        is_optional=True,
    )

    result = propagate_scopes([node_peer], [edge_peer])

    reach = result.nodes["node_modules/root-opt-peer"]
    assert reach.effective_scope is EffectiveScope.PEER
    assert reach.is_peer is True
    assert reach.is_optional is True
    assert reach.reached_states == frozenset({"(PEER, OPT)"})


def test_transitive_production_edge_under_peer_remains_peer() -> None:
    nodes = [_node("node_modules/root-peer"), _node("node_modules/peer-child")]
    edges = [
        _edge(
            ROOT_INSTALL_PATH,
            "node_modules/root-peer",
            "root-peer",
            scope=DependencyScope.PEER,
            is_optional=False,
        ),
        _edge(
            "node_modules/root-peer",
            "node_modules/peer-child",
            "peer-child",
            scope=DependencyScope.PRODUCTION,
        ),
    ]

    result = propagate_scopes(nodes, edges)

    reach = result.nodes["node_modules/peer-child"]
    assert reach.effective_scope is EffectiveScope.PEER
    assert reach.is_peer is True
    assert reach.reached_states == frozenset({"(PEER, REQ)"})


# --- 6. UNKNOWN Scope Handling ------------------------------------------------


def test_root_unknown_dependency_becomes_unknown() -> None:
    node_unk = _node("node_modules/unk-pkg")
    edge_unk = _edge(
        ROOT_INSTALL_PATH, "node_modules/unk-pkg", "unk-pkg", scope=DependencyScope.UNKNOWN
    )

    result = propagate_scopes([node_unk], [edge_unk])

    reach = result.nodes["node_modules/unk-pkg"]
    assert reach.effective_scope is EffectiveScope.UNKNOWN
    assert reach.is_production is False
    assert reach.is_dev is False
    assert reach.reached_states == frozenset({"(UNKNOWN, REQ)"})


def test_transitive_production_edge_under_unknown_remains_unknown() -> None:
    nodes = [_node("node_modules/unk-root"), _node("node_modules/unk-child")]
    edges = [
        _edge(
            ROOT_INSTALL_PATH, "node_modules/unk-root", "unk-root", scope=DependencyScope.UNKNOWN
        ),
        _edge(
            "node_modules/unk-root",
            "node_modules/unk-child",
            "unk-child",
            scope=DependencyScope.PRODUCTION,
        ),
    ]

    result = propagate_scopes(nodes, edges)

    reach = result.nodes["node_modules/unk-child"]
    assert reach.effective_scope is EffectiveScope.UNKNOWN
    assert reach.is_production is False
    assert reach.is_dev is False
    assert reach.reached_states == frozenset({"(UNKNOWN, REQ)"})


def test_optional_edge_under_unknown_becomes_unknown_optional() -> None:
    nodes = [_node("node_modules/unk-root"), _node("node_modules/unk-opt-child")]
    edges = [
        _edge(
            ROOT_INSTALL_PATH, "node_modules/unk-root", "unk-root", scope=DependencyScope.UNKNOWN
        ),
        _edge(
            "node_modules/unk-root",
            "node_modules/unk-opt-child",
            "unk-opt-child",
            scope=DependencyScope.OPTIONAL,
            is_optional=True,
        ),
    ]

    result = propagate_scopes(nodes, edges)

    reach = result.nodes["node_modules/unk-opt-child"]
    assert reach.effective_scope is EffectiveScope.UNKNOWN
    assert reach.is_production is False
    assert reach.is_dev is False
    assert reach.is_optional is True
    assert reach.has_optional_path is True
    assert reach.reached_states == frozenset({"(UNKNOWN, OPT)"})


def test_unknown_and_development_paths_remain_unknown() -> None:
    nodes = [
        _node("node_modules/unk-parent"),
        _node("node_modules/dev-parent"),
        _node("node_modules/shared"),
    ]
    edges = [
        _edge(
            ROOT_INSTALL_PATH,
            "node_modules/unk-parent",
            "unk-parent",
            scope=DependencyScope.UNKNOWN,
        ),
        _edge(
            ROOT_INSTALL_PATH,
            "node_modules/dev-parent",
            "dev-parent",
            scope=DependencyScope.DEVELOPMENT,
        ),
        _edge(
            "node_modules/unk-parent",
            "node_modules/shared",
            "shared",
            scope=DependencyScope.PRODUCTION,
        ),
        _edge(
            "node_modules/dev-parent",
            "node_modules/shared",
            "shared",
            scope=DependencyScope.PRODUCTION,
        ),
    ]

    result = propagate_scopes(nodes, edges)

    reach = result.nodes["node_modules/shared"]
    assert reach.effective_scope is EffectiveScope.UNKNOWN
    assert reach.is_dev is False
    assert reach.is_production is False
    assert reach.reached_states == frozenset({"(UNKNOWN, REQ)", "(DEV, REQ)"})


def test_production_dominates_unknown_path() -> None:
    nodes = [
        _node("node_modules/prod-parent"),
        _node("node_modules/unk-parent"),
        _node("node_modules/shared"),
    ]
    edges = [
        _edge(
            ROOT_INSTALL_PATH,
            "node_modules/prod-parent",
            "prod-parent",
            scope=DependencyScope.PRODUCTION,
        ),
        _edge(
            ROOT_INSTALL_PATH,
            "node_modules/unk-parent",
            "unk-parent",
            scope=DependencyScope.UNKNOWN,
        ),
        _edge(
            "node_modules/prod-parent",
            "node_modules/shared",
            "shared",
            scope=DependencyScope.PRODUCTION,
        ),
        _edge(
            "node_modules/unk-parent",
            "node_modules/shared",
            "shared",
            scope=DependencyScope.PRODUCTION,
        ),
    ]

    result = propagate_scopes(nodes, edges)

    reach = result.nodes["node_modules/shared"]
    assert reach.effective_scope is EffectiveScope.PRODUCTION
    assert reach.is_production is True
    assert reach.is_dev is False
    assert reach.reached_states == frozenset({"(PROD, REQ)", "(UNKNOWN, REQ)"})


def test_development_edge_under_unknown_req_remains_unknown_req() -> None:
    nodes = [_node("node_modules/unk-root"), _node("node_modules/unk-dev-child")]
    edges = [
        _edge(
            ROOT_INSTALL_PATH, "node_modules/unk-root", "unk-root", scope=DependencyScope.UNKNOWN
        ),
        _edge(
            "node_modules/unk-root",
            "node_modules/unk-dev-child",
            "unk-dev-child",
            scope=DependencyScope.DEVELOPMENT,
            is_optional=False,
        ),
    ]

    result = propagate_scopes(nodes, edges)

    reach = result.nodes["node_modules/unk-dev-child"]
    assert reach.effective_scope is EffectiveScope.UNKNOWN
    assert reach.is_production is False
    assert reach.is_dev is False
    assert reach.is_optional is False
    assert reach.reached_states == frozenset({"(UNKNOWN, REQ)"})


def test_optional_development_edge_under_unknown_req_becomes_unknown_opt() -> None:
    nodes = [_node("node_modules/unk-root"), _node("node_modules/unk-opt-dev-child")]
    edges = [
        _edge(
            ROOT_INSTALL_PATH, "node_modules/unk-root", "unk-root", scope=DependencyScope.UNKNOWN
        ),
        _edge(
            "node_modules/unk-root",
            "node_modules/unk-opt-dev-child",
            "unk-opt-dev-child",
            scope=DependencyScope.DEVELOPMENT,
            is_optional=True,
        ),
    ]

    result = propagate_scopes(nodes, edges)

    reach = result.nodes["node_modules/unk-opt-dev-child"]
    assert reach.effective_scope is EffectiveScope.UNKNOWN
    assert reach.is_production is False
    assert reach.is_dev is False
    assert reach.is_optional is True
    assert reach.has_optional_path is True
    assert reach.reached_states == frozenset({"(UNKNOWN, OPT)"})


def test_development_edge_under_unknown_opt_remains_unknown_opt() -> None:
    nodes = [
        _node("node_modules/unk-root"),
        _node("node_modules/unk-opt-parent"),
        _node("node_modules/unk-opt-dev-child"),
    ]
    edges = [
        _edge(
            ROOT_INSTALL_PATH, "node_modules/unk-root", "unk-root", scope=DependencyScope.UNKNOWN
        ),
        _edge(
            "node_modules/unk-root",
            "node_modules/unk-opt-parent",
            "unk-opt-parent",
            scope=DependencyScope.OPTIONAL,
            is_optional=True,
        ),
        _edge(
            "node_modules/unk-opt-parent",
            "node_modules/unk-opt-dev-child",
            "unk-opt-dev-child",
            scope=DependencyScope.DEVELOPMENT,
            is_optional=False,
        ),
    ]

    result = propagate_scopes(nodes, edges)

    reach = result.nodes["node_modules/unk-opt-dev-child"]
    assert reach.effective_scope is EffectiveScope.UNKNOWN
    assert reach.is_production is False
    assert reach.is_dev is False
    assert reach.is_optional is True
    assert reach.has_optional_path is True
    assert reach.reached_states == frozenset({"(UNKNOWN, OPT)"})


def test_unknown_optional_and_development_paths_remain_unknown() -> None:
    nodes = [
        _node("node_modules/unk-parent"),
        _node("node_modules/dev-parent"),
        _node("node_modules/shared"),
    ]
    edges = [
        _edge(
            ROOT_INSTALL_PATH,
            "node_modules/unk-parent",
            "unk-parent",
            scope=DependencyScope.UNKNOWN,
        ),
        _edge(
            ROOT_INSTALL_PATH,
            "node_modules/dev-parent",
            "dev-parent",
            scope=DependencyScope.DEVELOPMENT,
        ),
        _edge(
            "node_modules/unk-parent",
            "node_modules/shared",
            "shared",
            scope=DependencyScope.OPTIONAL,
            is_optional=True,
        ),
        _edge(
            "node_modules/dev-parent",
            "node_modules/shared",
            "shared",
            scope=DependencyScope.PRODUCTION,
        ),
    ]

    result = propagate_scopes(nodes, edges)

    reach = result.nodes["node_modules/shared"]
    assert reach.effective_scope is EffectiveScope.UNKNOWN
    assert reach.is_dev is False
    assert reach.is_dev_optional is False
    assert reach.is_production is False
    assert reach.is_optional is True
    assert reach.has_optional_path is True
    assert reach.reached_states == frozenset({"(UNKNOWN, OPT)", "(DEV, REQ)"})


# --- 7. Unreachable Nodes -----------------------------------------------------


def test_unreachable_node_is_classified_as_unreachable() -> None:
    node_reachable = _node("node_modules/a")
    node_orphan = _node("node_modules/orphan")
    edge_a = _edge(ROOT_INSTALL_PATH, "node_modules/a", "a", scope=DependencyScope.PRODUCTION)

    result = propagate_scopes([node_reachable, node_orphan], [edge_a])

    reach = result.nodes["node_modules/orphan"]
    assert reach.effective_scope is EffectiveScope.UNREACHABLE
    assert reach.is_unreachable is True
    assert reach.is_production is False
    assert reach.is_dev is False
    assert reach.is_optional is False
    assert reach.is_peer is False
    assert reach.reached_states == frozenset()
    assert result.unreachable_paths == ("node_modules/orphan",)


# --- 8. Missing Edges ---------------------------------------------------------


def test_missing_required_edge_terminates_traversal_cleanly() -> None:
    node_a = _node("node_modules/a")
    edges = [
        _edge(ROOT_INSTALL_PATH, "node_modules/a", "a", scope=DependencyScope.PRODUCTION),
        _edge(
            "node_modules/a",
            None,
            "missing-child",
            scope=DependencyScope.PRODUCTION,
            resolution=EdgeResolution.MISSING,
        ),
    ]

    result = propagate_scopes([node_a], edges)

    reach = result.nodes["node_modules/a"]
    assert reach.effective_scope is EffectiveScope.PRODUCTION
    assert len(result.nodes) == 1


def test_missing_optional_edge_terminates_traversal_cleanly() -> None:
    node_a = _node("node_modules/a")
    edges = [
        _edge(ROOT_INSTALL_PATH, "node_modules/a", "a", scope=DependencyScope.PRODUCTION),
        _edge(
            "node_modules/a",
            None,
            "missing-opt-child",
            scope=DependencyScope.OPTIONAL,
            is_optional=True,
            resolution=EdgeResolution.MISSING_OPTIONAL,
        ),
    ]

    result = propagate_scopes([node_a], edges)

    reach = result.nodes["node_modules/a"]
    assert reach.effective_scope is EffectiveScope.PRODUCTION
    assert len(result.nodes) == 1


# --- 9. Multiple Physical Installations ---------------------------------------


def test_multiple_physical_installations_compute_independent_scopes() -> None:
    top_helper = _node("node_modules/helper", name="helper")
    nested_helper = _node("node_modules/dev-tool/node_modules/helper", name="helper")
    dev_tool = _node("node_modules/dev-tool", name="dev-tool")

    nodes = [top_helper, dev_tool, nested_helper]
    edges = [
        _edge(ROOT_INSTALL_PATH, "node_modules/helper", "helper", scope=DependencyScope.PRODUCTION),
        _edge(
            ROOT_INSTALL_PATH,
            "node_modules/dev-tool",
            "dev-tool",
            scope=DependencyScope.DEVELOPMENT,
        ),
        _edge(
            "node_modules/dev-tool",
            "node_modules/dev-tool/node_modules/helper",
            "helper",
            scope=DependencyScope.PRODUCTION,
        ),
    ]

    result = propagate_scopes(nodes, edges)

    top_reach = result.nodes["node_modules/helper"]
    nested_reach = result.nodes["node_modules/dev-tool/node_modules/helper"]

    assert top_reach.effective_scope is EffectiveScope.PRODUCTION
    assert top_reach.is_production is True
    assert top_reach.is_dev is False

    assert nested_reach.effective_scope is EffectiveScope.DEVELOPMENT
    assert nested_reach.is_production is False
    assert nested_reach.is_dev is True


# --- 10. Cycles and Termination -----------------------------------------------


def test_cyclic_dependency_graph_terminates_deterministically() -> None:
    node_a = _node("node_modules/a")
    node_b = _node("node_modules/b")
    nodes = [node_a, node_b]
    edges = [
        _edge(ROOT_INSTALL_PATH, "node_modules/a", "a", scope=DependencyScope.PRODUCTION),
        _edge("node_modules/a", "node_modules/b", "b", scope=DependencyScope.PRODUCTION),
        _edge("node_modules/b", "node_modules/a", "a", scope=DependencyScope.PRODUCTION),
    ]

    result = propagate_scopes(nodes, edges)

    assert result.nodes["node_modules/a"].effective_scope is EffectiveScope.PRODUCTION
    assert result.nodes["node_modules/b"].effective_scope is EffectiveScope.PRODUCTION


# --- 11. Immutability & Contract Enforcement ----------------------------------


def test_result_and_nested_collections_are_genuinely_immutable() -> None:
    node_a = _node("node_modules/a")
    edge_a = _edge(ROOT_INSTALL_PATH, "node_modules/a", "a", scope=DependencyScope.PRODUCTION)

    result = propagate_scopes([node_a], [edge_a])

    assert isinstance(result, ScopePropagationResult)

    # 1. Top-level result model is frozen
    with pytest.raises((ValidationError, TypeError)):
        result.unreachable_paths = ("tampered",)  # type: ignore[misc]

    # 2. Nested dictionary/mapping cannot be mutated
    with pytest.raises(TypeError):
        result.nodes["node_modules/a"] = NodeReachability(  # type: ignore[index]
            install_path="node_modules/a",
            effective_scope=EffectiveScope.DEVELOPMENT,
            is_production=False,
            is_dev=True,
            is_optional=False,
            is_dev_optional=False,
            is_peer=False,
            is_unreachable=False,
            reached_states=frozenset(),
            has_production_path=False,
            has_development_path=True,
            has_optional_path=False,
            has_required_path=True,
        )

    with pytest.raises(TypeError):
        del result.nodes["node_modules/a"]  # type: ignore[attr-defined]

    # 3. NodeReachability is frozen
    reach = result.nodes["node_modules/a"]
    with pytest.raises((ValidationError, TypeError)):
        reach.is_production = False  # type: ignore[misc]

    # 4. reached_states is an immutable frozenset
    assert isinstance(reach.reached_states, frozenset)
    assert isinstance(result.unreachable_paths, tuple)
    assert isinstance(result.disagreements_with_parser, tuple)


def test_original_nodes_and_edges_remain_unmutated() -> None:
    node_a = _node(
        "node_modules/a",
        scopes=frozenset({DependencyScope.DEVELOPMENT}),
        is_dev=True,
    )
    edge_a = _edge(ROOT_INSTALL_PATH, "node_modules/a", "a", scope=DependencyScope.PRODUCTION)

    propagate_scopes([node_a], [edge_a])

    # Node remains untouched as parsed evidence
    assert node_a.is_dev is True
    assert node_a.scopes == frozenset({DependencyScope.DEVELOPMENT})
    assert edge_a.scope is DependencyScope.PRODUCTION


# --- 12. Disagreement Detection -----------------------------------------------


def test_unclassified_node_resolved_to_development_is_not_disagreement() -> None:
    """An unclassified node (is_dev=False, scopes=empty) resolved to DEVELOPMENT
    is NOT a disagreement because is_dev=False means unclassified, not production."""
    node_a = _node("node_modules/a", is_dev=False, scopes=frozenset())
    edge_a = _edge(
        ROOT_INSTALL_PATH,
        "node_modules/a",
        "a",
        scope=DependencyScope.DEVELOPMENT,
    )

    result = propagate_scopes([node_a], [edge_a])

    reach = result.nodes["node_modules/a"]
    assert reach.effective_scope is EffectiveScope.DEVELOPMENT
    assert reach.is_dev is True
    assert result.disagreements_with_parser == ()


def test_parser_dev_claim_contradicted_by_graph_production_is_disagreement() -> None:
    """When parser explicitly claims is_dev=True but graph proves PRODUCTION,
    it is flagged as a disagreement."""
    node_a = _node(
        "node_modules/a",
        is_dev=True,
        scopes=frozenset({DependencyScope.DEVELOPMENT}),
    )
    edge_a = _edge(
        ROOT_INSTALL_PATH,
        "node_modules/a",
        "a",
        scope=DependencyScope.PRODUCTION,
    )

    result = propagate_scopes([node_a], [edge_a])

    reach = result.nodes["node_modules/a"]
    assert reach.effective_scope is EffectiveScope.PRODUCTION
    assert reach.is_production is True
    assert result.disagreements_with_parser == ("node_modules/a",)


def test_parser_production_scope_contradicted_by_graph_development_is_disagreement() -> None:
    """When parser explicitly recorded PRODUCTION scope but graph proves DEVELOPMENT,
    it is flagged as a disagreement."""
    node_a = _node(
        "node_modules/a",
        is_dev=False,
        scopes=frozenset({DependencyScope.PRODUCTION}),
    )
    edge_a = _edge(
        ROOT_INSTALL_PATH,
        "node_modules/a",
        "a",
        scope=DependencyScope.DEVELOPMENT,
    )

    result = propagate_scopes([node_a], [edge_a])

    reach = result.nodes["node_modules/a"]
    assert reach.effective_scope is EffectiveScope.DEVELOPMENT
    assert reach.is_dev is True
    assert result.disagreements_with_parser == ("node_modules/a",)


def test_optional_and_peer_nodes_without_contradiction_have_no_disagreements() -> None:
    """OPTIONAL, DEV_OPTIONAL, and PEER nodes without contradictory parser evidence
    do not produce disagreements."""
    node_opt = _node(
        "node_modules/opt",
        is_dev=False,
        scopes=frozenset({DependencyScope.OPTIONAL}),
    )
    node_parent_dev = _node(
        "node_modules/parent-dev",
        is_dev=True,
        scopes=frozenset({DependencyScope.DEVELOPMENT}),
    )
    node_dev_opt = _node(
        "node_modules/dev-opt",
        is_dev=True,
        scopes=frozenset({DependencyScope.DEVELOPMENT, DependencyScope.OPTIONAL}),
    )
    node_peer = _node(
        "node_modules/peer",
        is_dev=False,
        scopes=frozenset({DependencyScope.PEER}),
    )

    nodes = [node_opt, node_parent_dev, node_dev_opt, node_peer]
    edges = [
        _edge(
            ROOT_INSTALL_PATH,
            "node_modules/opt",
            "opt",
            scope=DependencyScope.OPTIONAL,
            is_optional=True,
        ),
        _edge(
            ROOT_INSTALL_PATH,
            "node_modules/parent-dev",
            "parent-dev",
            scope=DependencyScope.DEVELOPMENT,
        ),
        _edge(
            "node_modules/parent-dev",
            "node_modules/dev-opt",
            "dev-opt",
            scope=DependencyScope.OPTIONAL,
            is_optional=True,
        ),
        _edge(
            ROOT_INSTALL_PATH,
            "node_modules/peer",
            "peer",
            scope=DependencyScope.PEER,
        ),
    ]

    result = propagate_scopes(nodes, edges)

    assert result.nodes["node_modules/opt"].effective_scope is EffectiveScope.OPTIONAL
    assert result.nodes["node_modules/dev-opt"].effective_scope is EffectiveScope.DEV_OPTIONAL
    assert result.nodes["node_modules/peer"].effective_scope is EffectiveScope.PEER
    assert result.disagreements_with_parser == ()


def test_unknown_and_unreachable_nodes_have_no_false_disagreements() -> None:
    """UNKNOWN and UNREACHABLE classifications do not trigger production/development
    disagreements in the absence of contradictions."""
    node_unknown = _node("node_modules/unknown", is_dev=False, scopes=frozenset())
    node_orphan = _node("node_modules/orphan", is_dev=False, scopes=frozenset())
    node_dev_orphan = _node(
        "node_modules/dev-orphan",
        is_dev=True,
        scopes=frozenset({DependencyScope.DEVELOPMENT}),
    )

    nodes = [node_unknown, node_orphan, node_dev_orphan]
    edges = [
        _edge(ROOT_INSTALL_PATH, "node_modules/unknown", "unknown", scope=DependencyScope.UNKNOWN),
    ]

    result = propagate_scopes(nodes, edges)

    assert result.nodes["node_modules/unknown"].effective_scope is EffectiveScope.UNKNOWN
    assert result.nodes["node_modules/orphan"].effective_scope is EffectiveScope.UNREACHABLE
    assert result.nodes["node_modules/dev-orphan"].effective_scope is EffectiveScope.UNREACHABLE
    assert result.disagreements_with_parser == ()


def test_multiple_disagreements_are_sorted_deterministically() -> None:
    """Multiple disagreements are returned in deterministically sorted order."""
    node_z = _node("node_modules/z", is_dev=True)
    node_a = _node("node_modules/a", is_dev=True)
    edges = [
        _edge(ROOT_INSTALL_PATH, "node_modules/z", "z", scope=DependencyScope.PRODUCTION),
        _edge(ROOT_INSTALL_PATH, "node_modules/a", "a", scope=DependencyScope.PRODUCTION),
    ]

    result = propagate_scopes([node_z, node_a], edges)

    assert result.disagreements_with_parser == ("node_modules/a", "node_modules/z")
