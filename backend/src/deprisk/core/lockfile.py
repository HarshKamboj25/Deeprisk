"""Safe parser for npm package-lock.json v2 and v3."""

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from deprisk.core.models import (
    DeclaredDependency,
    DependencyNode,
    DependencyScope,
    ParsedLockfile,
)
from deprisk.core.package_source import classify_package_source


class LockfileParseError(ValueError):
    """Raised when an npm lockfile is invalid or unsupported."""


@dataclass(frozen=True, slots=True)
class ParseLimits:
    """Upper bounds that keep a hostile lockfile from exhausting memory or time.

    The defaults are hypotheses, set far above anything seen in real lockfiles, and are
    meant to be re-evaluated in the performance evaluation. Overriding one limit keeps
    the other defaults.
    """

    max_characters: int = 50_000_000
    max_packages: int = 100_000
    max_path_segments: int = 32
    max_path_length: int = 1024

    def __post_init__(self) -> None:
        for name in ("max_characters", "max_packages", "max_path_segments", "max_path_length"):
            if getattr(self, name) < 1:
                raise ValueError(f"{name} must be at least 1")


DEFAULT_PARSE_LIMITS = ParseLimits()


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


def _is_valid_name_part(part: str) -> bool:
    """A package name or scope: not empty, not "." or "..", no separators or control characters."""
    return (
        bool(part)
        and part not in {".", ".."}
        and not any(ch == "\\" or ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in part)
    )


def _is_valid_package_name(name: str) -> bool:
    """True for 'name' and '@scope/name'. Any other shape is not a package name."""
    if name.startswith("@"):
        parts = name[1:].split("/")
        return len(parts) == 2 and all(_is_valid_name_part(part) for part in parts)
    return "/" not in name and _is_valid_name_part(name)


def _package_names_in_path(install_path: str, limits: ParseLimits) -> list[str]:
    """Return the package names along an install path, nearest the root first.

    A valid path is 'node_modules/<name>' repeated, where <name> is 'pkg' or '@scope/pkg'.
    Anything else, including workspace paths such as 'packages/app', is rejected.
    """
    shown = _describe(install_path)
    if len(install_path) > limits.max_path_length:
        raise LockfileParseError(
            f"Install path exceeds the path length limit ({limits.max_path_length}): {shown}"
        )

    parts = install_path.split("/")
    names: list[str] = []
    index = 0
    while index < len(parts):
        if parts[index] != "node_modules" or index + 1 >= len(parts):
            raise LockfileParseError(f"Unsupported package installation path: {shown}")
        index += 1
        name = parts[index]
        if name.startswith("@"):
            if index + 1 >= len(parts):
                raise LockfileParseError(f"Invalid scoped package path: {shown}")
            name = f"{name}/{parts[index + 1]}"
            index += 1
        index += 1
        if not _is_valid_package_name(name):
            raise LockfileParseError(f"Invalid package name in install path: {shown}")
        names.append(name)
        if len(names) > limits.max_path_segments:
            raise LockfileParseError(
                f"Install path exceeds the path depth limit ({limits.max_path_segments}): {shown}"
            )
    return names


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
                    f"{label} range for {_describe(name)} in {field!r} must be a string"
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


def _is_development_only(scopes: set[DependencyScope]) -> bool:
    """True when development is the only way the package is reachable.

    A production or optional scope means a non-development path exists, so conflicting
    evidence never downgrades a package to dev-only. PEER describes an edge type, not
    another way of being reachable, and is ignored.
    """
    non_development = {DependencyScope.PRODUCTION, DependencyScope.OPTIONAL}
    return DependencyScope.DEVELOPMENT in scopes and not scopes & non_development


def _top_level_key(install_path: str) -> str | None:
    """Return the package key if the path is a top-level install, else None."""
    if "/node_modules/" in install_path:
        return None
    return install_path.removeprefix("node_modules/")


def _describe(value: str) -> str:
    """Quote a value from an untrusted file for an error message, without echoing huge text."""
    return repr(value if len(value) <= 80 else value[:77] + "...")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build a JSON object, refusing duplicate keys instead of silently keeping the last."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise LockfileParseError(f"Duplicate JSON key: {_describe(key)}")
        result[key] = value
    return result



def _parse_v1_lockfile(
    data: Mapping[str, Any],
    limits: ParseLimits,
    manifest_content: str | None,
) -> ParsedLockfile:
    """Parse the nested dependency tree used by npm lockfile v1."""
    dependencies = data.get("dependencies", {})
    if dependencies is None:
        dependencies = {}
    if not isinstance(dependencies, Mapping):
        raise LockfileParseError("npm v1 lockfile dependencies must be an object")

    root_dependencies: tuple[DeclaredDependency, ...]
    if manifest_content is not None:
        if len(manifest_content) > limits.max_characters:
            raise LockfileParseError("package.json exceeds the character limit")
        try:
            manifest = json.loads(manifest_content, object_pairs_hook=_reject_duplicate_keys)
        except (json.JSONDecodeError, RecursionError) as exc:
            raise LockfileParseError("Invalid or deeply nested package.json") from exc
        if not isinstance(manifest, Mapping):
            raise LockfileParseError("package.json root must be a JSON object")
        root_dependencies = _read_declared_dependencies(
            "Manifest", manifest, _ROOT_DEPENDENCY_FIELDS
        )
    else:
        # Without a manifest, top-level lockfile entries are only best-effort roots.
        fallback: list[DeclaredDependency] = []
        for name, entry in dependencies.items():
            if not isinstance(name, str) or not _is_valid_package_name(name):
                raise LockfileParseError("Invalid top-level dependency name in npm v1 lockfile")
            if not isinstance(entry, Mapping):
                raise LockfileParseError(f"Package entry must be an object: {name}")
            version = entry.get("version")
            fallback.append(
                DeclaredDependency(
                    name=name,
                    requested_range=version if isinstance(version, str) else "*",
                    scope=DependencyScope.UNKNOWN,
                )
            )
        root_dependencies = tuple(sorted(fallback, key=lambda item: item.name))

    direct_scopes: dict[str, set[DependencyScope]] = {}
    for declared in root_dependencies:
        direct_scopes.setdefault(declared.name, set()).add(declared.scope)

    nodes: list[DependencyNode] = []
    seen_paths: set[str] = set()
    stack: list[tuple[str, Mapping[str, Any]]] = [
        (f"node_modules/{name}", entry)
        for name, entry in reversed(list(dependencies.items()))
        if isinstance(name, str) and isinstance(entry, Mapping)
    ]

    if len(dependencies) > limits.max_packages:
        raise LockfileParseError(f"Lockfile exceeds the package limit ({limits.max_packages})")

    while stack:
        install_path, entry = stack.pop()
        path_names = _package_names_in_path(install_path, limits)

        if install_path in seen_paths:
            raise LockfileParseError(f"Duplicate package installation path: {install_path}")
        seen_paths.add(install_path)

        if len(seen_paths) > limits.max_packages:
            raise LockfileParseError(f"Lockfile exceeds the package limit ({limits.max_packages})")

        name = path_names[-1]
        version = entry.get("version")
        if not isinstance(version, str) or not version:
            raise LockfileParseError(f"Missing package version: {install_path}")

        requires = entry.get("requires", {})
        if not isinstance(requires, Mapping):
            raise LockfileParseError(f"Invalid requires metadata: {install_path}")

        declared_dependencies: list[DeclaredDependency] = []
        for child_name, requested_range in requires.items():
            if not isinstance(child_name, str) or not _is_valid_package_name(child_name):
                raise LockfileParseError(f"Invalid required dependency name: {install_path}")
            if not isinstance(requested_range, str):
                raise LockfileParseError(f"Invalid required dependency range: {install_path}")
            declared_dependencies.append(
                DeclaredDependency(
                    name=child_name,
                    requested_range=requested_range,
                    scope=DependencyScope.PRODUCTION,
                )
            )

        scopes = (
            set(direct_scopes.get(name, set()))
            if "/node_modules/" not in install_path
            else set()
        )

        if entry.get("dev") is True:
            scopes.add(DependencyScope.DEVELOPMENT)
        if entry.get("optional") is True:
            scopes.add(DependencyScope.OPTIONAL)

        resolved = entry.get("resolved")
        integrity = entry.get("integrity")
        has_install_script = entry.get("hasInstallScript", False)
        if resolved is not None and not isinstance(resolved, str):
            raise LockfileParseError(f"Invalid resolved metadata: {install_path}")
        if integrity is not None and not isinstance(integrity, str):
            raise LockfileParseError(f"Invalid integrity metadata: {install_path}")
        if not isinstance(has_install_script, bool):
            raise LockfileParseError(f"Invalid hasInstallScript metadata: {install_path}")

        nodes.append(
            DependencyNode(
                install_path=install_path,
                name=name,
                version=version,
                scopes=frozenset(scopes),
                is_direct="/node_modules/" not in install_path and name in direct_scopes,
                is_dev=_is_development_only(scopes),
                declared_dependencies=tuple(
                    sorted(declared_dependencies, key=lambda item: item.name)
                ),
                source_type=classify_package_source(resolved),
                resolved=resolved,
                integrity=integrity,
                has_install_script=has_install_script,
            )
        )

        children = entry.get("dependencies", {})
        if not isinstance(children, Mapping):
            raise LockfileParseError(f"Invalid nested dependencies: {install_path}")
        for child_name, child_entry in reversed(list(children.items())):
            if not isinstance(child_name, str) or not _is_valid_package_name(child_name):
                raise LockfileParseError(f"Invalid nested package name: {install_path}")
            if not isinstance(child_entry, Mapping):
                raise LockfileParseError(f"Package entry must be an object: {install_path}")
            child_path = f"{install_path}/node_modules/{child_name}"
            stack.append((child_path, child_entry))

    return ParsedLockfile(
        nodes=tuple(sorted(nodes, key=lambda node: node.install_path)),
        root_dependencies=root_dependencies,
    )


def parse_lockfile(
    content: str,
    limits: ParseLimits = DEFAULT_PARSE_LIMITS,
    *,
    manifest_content: str | None = None,
) -> ParsedLockfile:
    """Parse npm lockfiles v1, v2 and v3 into nodes and declared dependencies."""
    if len(content) > limits.max_characters:
        raise LockfileParseError(f"Lockfile exceeds the character limit ({limits.max_characters})")
    try:
        data: Any = json.loads(content, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise LockfileParseError(f"Invalid JSON: {exc.msg}") from exc
    except RecursionError as exc:
        raise LockfileParseError("Lockfile JSON is nested too deeply") from exc

    if not isinstance(data, Mapping):
        raise LockfileParseError("Lockfile root must be a JSON object")

    lockfile_version = data.get("lockfileVersion")
    if lockfile_version == 1:
        return _parse_v1_lockfile(data, limits, manifest_content)

    if lockfile_version not in (2, 3):
        raise LockfileParseError(
            f"Unsupported lockfileVersion: {_describe(str(lockfile_version))}; expected 1, 2 or 3"
        )

    packages = data.get("packages")
    if not isinstance(packages, Mapping):
        raise LockfileParseError("Lockfile must contain a packages object")

    if "" not in packages:
        raise LockfileParseError("Lockfile has no root package entry")
    if len(packages) - 1 > limits.max_packages:
        raise LockfileParseError(f"Lockfile exceeds the package limit ({limits.max_packages})")
    root = packages[""]
    if not isinstance(root, Mapping):
        raise LockfileParseError("Root package entry must be an object")

    # Reject npm workspace links before validating installation paths.
    # This makes rejection independent of JSON object entry order.
    for install_path, entry in packages.items():
        if install_path and isinstance(entry, Mapping) and entry.get("link") is True:
            raise LockfileParseError(
                f"Linked package entries are not supported yet: {install_path}"
            )

    root_dependencies = _read_declared_dependencies("Root", root, _ROOT_DEPENDENCY_FIELDS)

    direct_scopes: dict[str, set[DependencyScope]] = {}
    for declared in root_dependencies:
        direct_scopes.setdefault(declared.name, set()).add(declared.scope)

    nodes: list[DependencyNode] = []

    for install_path, entry in packages.items():
        if install_path == "":
            continue

        path_names = _package_names_in_path(install_path, limits)

        if not isinstance(entry, Mapping):
            raise LockfileParseError(f"Package entry must be an object: {install_path}")

        # Workspace/link entries can omit versions. Do not silently invent one.
        if entry.get("link") is True:
            raise LockfileParseError(
                f"Linked package entries are not supported yet: {install_path}"
            )

        name = entry["name"] if "name" in entry else path_names[-1]
        version = entry.get("version")

        if not isinstance(name, str) or not _is_valid_package_name(name):
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

        resolved = entry.get("resolved")
        integrity = entry.get("integrity")
        has_install_script = entry.get("hasInstallScript", False)

        if resolved is not None and not isinstance(resolved, str):
            raise LockfileParseError(f"Invalid resolved metadata: {install_path}")
        if integrity is not None and not isinstance(integrity, str):
            raise LockfileParseError(f"Invalid integrity metadata: {install_path}")
        if not isinstance(has_install_script, bool):
            raise LockfileParseError(f"Invalid hasInstallScript metadata: {install_path}")

        nodes.append(
            DependencyNode(
                install_path=install_path,
                name=name,
                version=version,
                scopes=frozenset(scopes),
                is_direct=is_direct,
                is_dev=_is_development_only(scopes),
                declared_dependencies=_read_declared_dependencies(
                    f"Package {install_path}", entry, _PACKAGE_DEPENDENCY_FIELDS
                ),
                source_type=classify_package_source(resolved),
                resolved=resolved,
                integrity=integrity,
                has_install_script=has_install_script,
            )
        )

    return ParsedLockfile(
        nodes=tuple(sorted(nodes, key=lambda node: node.install_path)),
        root_dependencies=root_dependencies,
    )


def parse_lockfile_text(
    content: str, limits: ParseLimits = DEFAULT_PARSE_LIMITS
) -> list[DependencyNode]:
    """Parse installed package entries from an npm lockfile v2 or v3."""
    return list(parse_lockfile(content, limits).nodes)
