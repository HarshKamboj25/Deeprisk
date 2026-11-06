"""Transitive scope propagation and effective deployment scope derivation."""

import collections
from collections.abc import Mapping, Sequence
from enum import StrEnum
from types import MappingProxyType
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, PlainSerializer, PlainValidator

from deprisk.core.models import (
    ROOT_INSTALL_PATH,
    DependencyEdge,
    DependencyNode,
    DependencyScope,
)


class EffectiveScope(StrEnum):
    """Mutually exclusive deployment classification derived from graph reachability."""

    PRODUCTION = "production"
    DEVELOPMENT = "development"
    OPTIONAL = "optional"
    DEV_OPTIONAL = "dev_optional"
    PEER = "peer"
    UNKNOWN = "unknown"
    UNREACHABLE = "unreachable"


class NodeReachability(BaseModel):
    """Graph reachability facts and derived scope for one physical installation."""

    model_config = ConfigDict(frozen=True)

    install_path: str = Field(min_length=1)
    effective_scope: EffectiveScope
    is_production: bool
    is_dev: bool
    is_optional: bool
    is_dev_optional: bool
    is_peer: bool
    is_unreachable: bool
    reached_states: frozenset[str]
    has_production_path: bool
    has_development_path: bool
    has_optional_path: bool
    has_required_path: bool


def _validate_mapping_proxy(value: object) -> MappingProxyType[str, NodeReachability]:
    if isinstance(value, MappingProxyType):
        return value
    if isinstance(value, Mapping):
        return MappingProxyType(dict(value))
    raise TypeError(f"Expected a Mapping, got {type(value).__name__}")


ImmutableNodesMapping = Annotated[
    MappingProxyType[str, NodeReachability],
    PlainValidator(_validate_mapping_proxy),
    PlainSerializer(lambda v: dict(v)),
]


class ScopePropagationResult(BaseModel):
    """Scan-level scope propagation output."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    nodes: ImmutableNodesMapping
    unreachable_paths: tuple[str, ...] = ()
    disagreements_with_parser: tuple[str, ...] = ()


def _initial_root_state(scope: DependencyScope, is_optional: bool) -> str:
    """Determine the path state introduced by a root dependency edge."""
    if scope is DependencyScope.PRODUCTION:
        return "(PROD, REQ)"
    if scope is DependencyScope.DEVELOPMENT:
        return "(DEV, REQ)"
    if scope is DependencyScope.OPTIONAL:
        return "(PROD, OPT)"
    if scope is DependencyScope.PEER:
        return "(PEER, OPT)" if is_optional else "(PEER, REQ)"
    if scope is DependencyScope.UNKNOWN:
        return "(UNKNOWN, OPT)" if is_optional else "(UNKNOWN, REQ)"
    return "(UNKNOWN, REQ)"


def _transition_state(parent_state: str, edge_scope: DependencyScope, is_optional: bool) -> str:
    """Compute the resulting child path state along a dependency edge."""
    if parent_state.startswith("(PROD,"):
        env = "PROD"
    elif parent_state.startswith("(DEV,"):
        env = "DEV"
    elif parent_state.startswith("(PEER,"):
        env = "PEER"
    else:
        env = "UNKNOWN"

    parent_opt = "OPT" if parent_state.endswith(", OPT)") else "REQ"

    child_opt = "OPT" if (edge_scope is DependencyScope.OPTIONAL or is_optional) else parent_opt

    if env == "UNKNOWN":
        child_env = "UNKNOWN"
    elif edge_scope in (DependencyScope.PRODUCTION, DependencyScope.OPTIONAL, DependencyScope.PEER):
        child_env = env
    elif edge_scope is DependencyScope.DEVELOPMENT:
        child_env = "DEV"
    else:
        child_env = env

    return f"({child_env}, {child_opt})"


def _classify_effective_scope(states: frozenset[str]) -> EffectiveScope:
    """Derive mutually exclusive effective deployment scope from reachability states."""
    if not states:
        return EffectiveScope.UNREACHABLE
    if "(PROD, REQ)" in states:
        return EffectiveScope.PRODUCTION
    if "(UNKNOWN, REQ)" in states or "(UNKNOWN, OPT)" in states:
        return EffectiveScope.UNKNOWN
    if "(DEV, REQ)" in states and ("(PROD, OPT)" in states or "(DEV, OPT)" in states):
        return EffectiveScope.DEV_OPTIONAL
    if "(PROD, OPT)" in states:
        return EffectiveScope.OPTIONAL
    if "(DEV, OPT)" in states:
        return EffectiveScope.DEV_OPTIONAL
    if "(DEV, REQ)" in states:
        return EffectiveScope.DEVELOPMENT
    if "(PEER, REQ)" in states or "(PEER, OPT)" in states:
        return EffectiveScope.PEER
    return EffectiveScope.UNKNOWN


def propagate_scopes(
    nodes: Sequence[DependencyNode],
    edges: Sequence[DependencyEdge],
) -> ScopePropagationResult:
    """Propagate dependency scopes through the graph and compute effective deployment scopes."""
    node_by_path = {node.install_path: node for node in nodes}
    reached: dict[str, set[str]] = {node.install_path: set() for node in nodes}

    outgoing: dict[str, list[DependencyEdge]] = collections.defaultdict(list)
    for edge in edges:
        outgoing[edge.parent_path].append(edge)

    worklist: collections.deque[tuple[str, str]] = collections.deque()

    # Seed worklist with root dependencies (parent_path == ROOT_INSTALL_PATH)
    for root_edge in outgoing.get(ROOT_INSTALL_PATH, []):
        if root_edge.child_path is None or root_edge.child_path not in node_by_path:
            continue
        init_state = _initial_root_state(root_edge.scope, root_edge.is_optional)
        if init_state not in reached[root_edge.child_path]:
            reached[root_edge.child_path].add(init_state)
            worklist.append((root_edge.child_path, init_state))

    # Propagate across edges using a worklist algorithm
    while worklist:
        curr_path, curr_state = worklist.popleft()
        for edge in outgoing.get(curr_path, []):
            if edge.child_path is None or edge.child_path not in node_by_path:
                continue
            next_state = _transition_state(curr_state, edge.scope, edge.is_optional)
            if next_state not in reached[edge.child_path]:
                reached[edge.child_path].add(next_state)
                worklist.append((edge.child_path, next_state))

    node_results: dict[str, NodeReachability] = {}
    unreachable_paths: list[str] = []
    disagreements: list[str] = []

    for install_path, node in node_by_path.items():
        states = frozenset(reached[install_path])
        effective_scope = _classify_effective_scope(states)

        has_prod = any(s.startswith("(PROD,") for s in states)
        has_dev = any(s.startswith("(DEV,") for s in states)
        has_opt = any(s.endswith(", OPT)") for s in states)
        has_req = any(s.endswith(", REQ)") for s in states)

        is_production = effective_scope is EffectiveScope.PRODUCTION
        is_dev = effective_scope is EffectiveScope.DEVELOPMENT
        is_optional = has_opt and not is_production
        is_dev_optional = effective_scope is EffectiveScope.DEV_OPTIONAL
        is_peer = effective_scope is EffectiveScope.PEER
        is_unreachable = effective_scope is EffectiveScope.UNREACHABLE

        if is_unreachable:
            unreachable_paths.append(install_path)

        reachability = NodeReachability(
            install_path=install_path,
            effective_scope=effective_scope,
            is_production=is_production,
            is_dev=is_dev,
            is_optional=is_optional,
            is_dev_optional=is_dev_optional,
            is_peer=is_peer,
            is_unreachable=is_unreachable,
            reached_states=states,
            has_production_path=has_prod,
            has_development_path=has_dev,
            has_optional_path=has_opt,
            has_required_path=has_req,
        )
        node_results[install_path] = reachability

        # Evidence-based contradiction detection:
        # 1. Parser positively asserted dev-only (node.is_dev=True), but graph
        #    proves unconditional production.
        # 2. Parser explicitly recorded production scope
        #    (DependencyScope.PRODUCTION in node.scopes), but graph proves dev-only.
        is_disagreement = (node.is_dev and is_production) or (
            DependencyScope.PRODUCTION in node.scopes and is_dev
        )
        if is_disagreement:
            disagreements.append(install_path)

    return ScopePropagationResult(
        nodes=MappingProxyType(node_results),
        unreachable_paths=tuple(sorted(unreachable_paths)),
        disagreements_with_parser=tuple(sorted(disagreements)),
    )
