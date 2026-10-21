"""Dependency graph construction from parsed npm lockfile entries."""

from deprisk.core.lockfile import LockfileParseError
from deprisk.core.models import (
    ROOT_INSTALL_PATH,
    DependencyEdge,
    DependencyNode,
    DependencyScope,
    EdgeResolution,
)


def build_dependency_edges(
    nodes: list[DependencyNode],
    root_dependencies: dict[str, str],
) -> list[DependencyEdge]:
    """Build parent-to-child edges using npm's nested node_modules layout.

    Every declared dependency produces one edge. A dependency that cannot be found is
    kept as an unresolved edge instead of being dropped.
    """
    by_path = {node.install_path: node for node in nodes}
    if len(by_path) != len(nodes):
        raise LockfileParseError("Duplicate installation paths found")

    edges: list[DependencyEdge] = []

    # Direct dependencies resolve exactly like any other lookup, starting at the root.
    for name, requested_range in root_dependencies.items():
        child = _resolve_child(ROOT_INSTALL_PATH, name, by_path)
        edges.append(
            _make_edge(
                parent_path=ROOT_INSTALL_PATH,
                dependency_name=name,
                requested_range=requested_range,
                scope=_scope_for_root_dependency(name),
                is_optional=False,
                child=child,
            )
        )

    # Resolve declared child dependencies using Node.js lookup rules.
    for parent in nodes:
        declared = _declared_dependencies(parent)

        for child_name, requested_range, scope, is_optional in declared:
            child = _resolve_child(parent.install_path, child_name, by_path)
            edges.append(
                _make_edge(
                    parent_path=parent.install_path,
                    dependency_name=child_name,
                    requested_range=requested_range,
                    scope=scope,
                    is_optional=is_optional,
                    child=child,
                )
            )

    # A parent declares each dependency name once per scope, and resolution is
    # deterministic, so this key identifies an edge even when child_path is None.
    unique = {(edge.parent_path, edge.dependency_name, edge.scope): edge for edge in edges}

    return sorted(unique.values(), key=_edge_sort_key)


def _make_edge(
    *,
    parent_path: str,
    dependency_name: str,
    requested_range: str,
    scope: DependencyScope,
    is_optional: bool,
    child: DependencyNode | None,
) -> DependencyEdge:
    """Create a resolved edge, or an unresolved one when no install was found."""
    if child is not None:
        resolution = EdgeResolution.RESOLVED
        child_path = child.install_path
    else:
        resolution = EdgeResolution.MISSING_OPTIONAL if is_optional else EdgeResolution.MISSING
        child_path = None

    return DependencyEdge(
        parent_path=parent_path,
        child_path=child_path,
        dependency_name=dependency_name,
        requested_range=requested_range,
        scope=scope,
        is_optional=is_optional,
        resolution=resolution,
    )


def _edge_sort_key(edge: DependencyEdge) -> tuple[str, str, str, str]:
    """Total ordering that never compares None with a string."""
    return (
        edge.parent_path,
        edge.dependency_name,
        edge.scope.value,
        edge.child_path or "",
    )


def _resolve_child(
    parent_path: str,
    child_name: str,
    by_path: dict[str, DependencyNode],
) -> DependencyNode | None:
    """Resolve the nearest installed copy of a child package."""
    current = parent_path

    while True:
        candidate_path = f"{current}/node_modules/{child_name}".lstrip("/")
        candidate = by_path.get(candidate_path)

        if candidate is not None:
            return candidate

        if not current:
            return by_path.get(f"node_modules/{child_name}")

        marker = "/node_modules/"
        index = current.rfind(marker)
        current = "" if index < 0 else current[:index]


def _declared_dependencies(
    node: DependencyNode,
) -> list[tuple[str, str, DependencyScope, bool]]:
    """Placeholder until parser metadata retains declared dependencies."""
    return []


def _scope_for_root_dependency(name: str) -> DependencyScope:
    """Return the fallback scope for a root dependency."""
    return DependencyScope.UNKNOWN
