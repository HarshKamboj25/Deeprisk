"""Safe parser for npm package-lock.json v2 and v3."""

import json
from collections.abc import Mapping
from typing import Any

from deprisk.core.models import (
    DeclaredDependency,
    DependencyNode,
    DependencyScope,
    ParsedLockfile,
)


class LockfileParseError(ValueError):
    """Raised when an npm lockfile is invalid or unsupported."""


# (lockfile field, scope, is_optional)
_DependencyFields = tuple[tuple[str, DependencyScope, bool], ...]

_ROOT_DEPENDENCY_FIELDS: _DependencyFields = (
    ("dependencies", DependencyScope.PRODUCTION, False),
    ("devDependencies", DependencyScope.DEVELOPMENT, False),
    ("optionalDependencies", DependencyScope.OPTIONAL, True),
    ("peerDependencies", DependencyScope.PEER, False),
)

_PACKAGE_DEPENDENCY_FIELDS: _DependencyFields = (
    ("dependencies", DependencyScope.PRODUCTION, False),
    ("optionalDependencies", DependencyScope.OPTIONAL, True),
    ("peerDependencies", DependencyScope.PEER, False),
)


def _package_name_from_path(install_path: str) -> str:
    marker = "node_modules/"
    index = install_path.rfind(marker)

    if index < 0:
        raise LockfileParseError(f"Cannot derive package name from install path: {install_path}")

    tail = install_path[index + len(marker) :]
    parts = tail.split("/")

    if not parts[0]:
        raise LockfileParseError(f"Empty package name in path: {install_path}")

    if parts[0].startswith("@"):
        if len(parts) < 2 or not parts[1]:
            raise LockfileParseError(f"Invalid scoped package path: {install_path}")
        return f"{parts[0]}/{parts[1]}"

    return parts[0]


def _is_optional_peer(peer_meta: Any, name: str) -> bool:
    """Interpret peerDependenciesMeta. Its exact lockfile shape is not yet verified."""
    if not isinstance(peer_meta, Mapping):
        return False
    info = peer_meta.get(name)
    return isinstance(info, Mapping) and info.get("optional") is True


def _read_declared_dependencies(
    label: str,
    entry: Mapping[str, Any],
    fields: _DependencyFields,
) -> tuple[DeclaredDependency, ...]:
    """Read declared dependencies from one lockfile entry, in a deterministic order."""
    peer_meta = entry.get("peerDependenciesMeta")
    declared: list[DeclaredDependency] = []

    for field, scope, is_optional in fields:
        value = entry.get(field)
        if value is None:
            continue
        if not isinstance(value, Mapping):
            raise LockfileParseError(f"{label} field {field!r} must be an object")

        for name, requested_range in value.items():
            if not isinstance(name, str) or not name:
                raise LockfileParseError(f"{label} field {field!r} has an invalid dependency name")
            if not isinstance(requested_range, str):
                raise LockfileParseError(
                    f"{label} range for {name!r} in {field!r} must be a string"
                )

            declared.append(
                DeclaredDependency(
                    name=name,
                    requested_range=requested_range,
                    scope=scope,
                    is_optional=is_optional
                    or (scope is DependencyScope.PEER and _is_optional_peer(peer_meta, name)),
                )
            )

    return tuple(sorted(declared, key=lambda item: (item.name, item.scope.value)))


def _top_level_key(install_path: str) -> str | None:
    """Return the package key if the path is a top-level install, else None."""
    if "/node_modules/" in install_path:
        return None
    return install_path.removeprefix("node_modules/")


def parse_lockfile(content: str) -> ParsedLockfile:
    """Parse an npm lockfile v2 or v3 into nodes and declared dependencies."""
    try:
        data: Any = json.loads(content)
    except json.JSONDecodeError as exc:
        raise LockfileParseError(f"Invalid JSON: {exc.msg}") from exc

    if not isinstance(data, Mapping):
        raise LockfileParseError("Lockfile root must be a JSON object")

    lockfile_version = data.get("lockfileVersion")
    if lockfile_version not in (2, 3):
        raise LockfileParseError(
            f"Unsupported lockfileVersion: {lockfile_version!r}; expected 2 or 3"
        )

    packages = data.get("packages")
    if not isinstance(packages, Mapping):
        raise LockfileParseError("Lockfile must contain a packages object")

    root = packages.get("", {})
    if not isinstance(root, Mapping):
        raise LockfileParseError("Root package entry must be an object")

    root_dependencies = _read_declared_dependencies("Root", root, _ROOT_DEPENDENCY_FIELDS)

    direct_scopes: dict[str, set[DependencyScope]] = {}
    for declared in root_dependencies:
        direct_scopes.setdefault(declared.name, set()).add(declared.scope)

    nodes: list[DependencyNode] = []

    for install_path, entry in packages.items():
        if install_path == "":
            continue

        if not isinstance(install_path, str) or not install_path.startswith("node_modules/"):
            raise LockfileParseError(f"Unsupported package installation path: {install_path!r}")

        if not isinstance(entry, Mapping):
            raise LockfileParseError(f"Package entry must be an object: {install_path}")

        # Workspace/link entries can omit versions. Do not silently invent one.
        if entry.get("link") is True:
            raise LockfileParseError(
                f"Linked package entries are not supported yet: {install_path}"
            )

        name = entry.get("name") or _package_name_from_path(install_path)
        version = entry.get("version")

        if not isinstance(name, str) or not name:
            raise LockfileParseError(f"Invalid package name: {install_path}")
        if not isinstance(version, str) or not version:
            raise LockfileParseError(f"Missing package version: {install_path}")

        # Direct means "installed at node_modules/<root dependency key>". Nested copies
        # that merely share a name with a root dependency are not direct.
        top_level_key = _top_level_key(install_path)
        is_direct = top_level_key is not None and top_level_key in direct_scopes
        scopes = set(direct_scopes[top_level_key]) if is_direct and top_level_key else set()

        if entry.get("dev") is True:
            scopes.add(DependencyScope.DEVELOPMENT)
        if entry.get("optional") is True:
            scopes.add(DependencyScope.OPTIONAL)
        if entry.get("devOptional") is True:
            scopes.update({DependencyScope.DEVELOPMENT, DependencyScope.OPTIONAL})
        if entry.get("peer") is True:
            scopes.add(DependencyScope.PEER)

        nodes.append(
            DependencyNode(
                install_path=install_path,
                name=name,
                version=version,
                scopes=frozenset(scopes),
                is_direct=is_direct,
                is_dev=entry.get("dev") is True,
                declared_dependencies=_read_declared_dependencies(
                    f"Package {install_path}", entry, _PACKAGE_DEPENDENCY_FIELDS
                ),
            )
        )

    return ParsedLockfile(
        nodes=tuple(sorted(nodes, key=lambda node: node.install_path)),
        root_dependencies=root_dependencies,
    )


def parse_lockfile_text(content: str) -> list[DependencyNode]:
    """Parse installed package entries from an npm lockfile v2 or v3."""
    return list(parse_lockfile(content).nodes)
