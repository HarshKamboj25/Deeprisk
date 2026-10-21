"""Safe parser for npm package-lock.json v2 and v3."""

import json
from collections.abc import Mapping
from typing import Any

from deprisk.core.models import DependencyNode, DependencyScope


class LockfileParseError(ValueError):
    """Raised when an npm lockfile is invalid or unsupported."""


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


def parse_lockfile_text(content: str) -> list[DependencyNode]:
    """Parse installed package entries from an npm lockfile v2 or v3."""
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

    direct_scopes: dict[str, set[DependencyScope]] = {}
    scope_fields = (
        ("dependencies", DependencyScope.PRODUCTION),
        ("devDependencies", DependencyScope.DEVELOPMENT),
        ("optionalDependencies", DependencyScope.OPTIONAL),
        ("peerDependencies", DependencyScope.PEER),
    )

    for field, scope in scope_fields:
        declared = root.get(field, {})
        if declared is None:
            continue
        if not isinstance(declared, Mapping):
            raise LockfileParseError(f"Root field {field!r} must be an object")
        for name in declared:
            if isinstance(name, str) and name:
                direct_scopes.setdefault(name, set()).add(scope)

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

        scopes = set(direct_scopes.get(name, set()))

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
                is_direct=name in direct_scopes,
                is_dev=entry.get("dev") is True,
            )
        )

    return sorted(nodes, key=lambda node: node.install_path)
