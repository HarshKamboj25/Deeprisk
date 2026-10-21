"""Dependency graph construction from parsed npm lockfile entries."""

from collections import defaultdict

from deprisk.core.lockfile import LockfileParseError
from deprisk.core.models import DependencyEdge, DependencyNode, DependencyScope


def build_dependency_edges(
    nodes: list[DependencyNode],
    root_dependencies: dict[str, str],
) -> list[DependencyEdge]:
    """Build parent-to-child edges using npm's nested node_modules layout."""
    by_path = {node.install_path: node for node in nodes}
    if len(by_path) != len(nodes):
        raise LockfileParseError("Duplicate installation paths found")

    children_by_parent: dict[str, list[DependencyNode]] = defaultdict(list)
    for node in nodes:
        parent_path = _parent_install_path(node.install_path)
        children_by_parent[parent_path].append(node)

    edges: list[DependencyEdge] = []

    # Direct dependencies are children of the root project.
    for name, requested_range in root_dependencies.items():
        candidates = [node for node in children_by_parent[""] if node.name == name]
        if not candidates:
            continue

        node = sorted(candidates, key=lambda item: item.install_path)[0]
        edges.append(
            DependencyEdge(
                parent_path="",
                child_path=node.install_path,
                dependency_name=name,
                requested_range=requested_range,
                scope=_scope_for_root_dependency(name),
            )
        )

    # Resolve declared child dependencies using Node.js lookup rules.
    for parent in nodes:
        declared = _declared_dependencies(parent)

        for child_name, requested_range, scope, is_optional in declared:
            candidate = _resolve_child(
                parent.install_path,
                child_name,
                by_path,
            )
            if candidate is None:
                continue

            edges.append(
                DependencyEdge(
                    parent_path=parent.install_path,
                    child_path=candidate.install_path,
                    dependency_name=child_name,
                    requested_range=requested_range,
                    scope=scope,
                    is_optional=is_optional,
                )
            )

    unique = {(edge.parent_path, edge.child_path, edge.scope): edge for edge in edges}

    return sorted(
        unique.values(),
        key=lambda edge: (
            edge.parent_path,
            edge.child_path,
            edge.scope.value,
        ),
    )


def _parent_install_path(install_path: str) -> str:
    """Return the package installation path containing this node."""
    parts = install_path.split("/")

    if len(parts) <= 2:
        return ""
    if parts[-2] == "node_modules":
        return ""

    return "/".join(parts[:-2])


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
