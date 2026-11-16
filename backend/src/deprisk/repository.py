"""Safe ingestion of local npm repositories."""

from dataclasses import dataclass
from pathlib import Path

from deprisk.core.lockfile import DEFAULT_PARSE_LIMITS, ParseLimits


class RepositoryScanError(ValueError):
    """Raised when a local repository cannot be safely inspected."""


@dataclass(frozen=True, slots=True)
class RepositoryLockfile:
    """A validated local repository lockfile and its contents."""

    repository_path: Path
    lockfile_path: Path
    content: str
    repository_name: str | None = None
    repository_url: str | None = None
    manifest_content: str | None = None


def load_repository_lockfile(
    repository_path: str | Path,
    limits: ParseLimits = DEFAULT_PARSE_LIMITS,
) -> RepositoryLockfile:
    """Locate and safely read package-lock.json from a local repository."""

    try:
        root = Path(repository_path).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise RepositoryScanError(
            f"Repository path does not exist or cannot be resolved: {repository_path}"
        ) from exc

    if not root.is_dir():
        raise RepositoryScanError(f"Repository path is not a directory: {root}")

    lockfile = root / "package-lock.json"

    try:
        resolved_lockfile = lockfile.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise RepositoryScanError(
            f"Repository does not contain a readable package-lock.json: {root}"
        ) from exc

    if not resolved_lockfile.is_relative_to(root):
        raise RepositoryScanError("package-lock.json resolves outside the repository directory")

    if not resolved_lockfile.is_file():
        raise RepositoryScanError("package-lock.json is not a regular file")

    try:
        file_size = resolved_lockfile.stat().st_size
    except OSError as exc:
        raise RepositoryScanError("Unable to inspect package-lock.json size") from exc

    if file_size > limits.max_characters:
        raise RepositoryScanError(
            f"package-lock.json exceeds the size limit ({limits.max_characters})"
        )

    try:
        content = resolved_lockfile.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise RepositoryScanError("package-lock.json is not valid UTF-8") from exc
    except OSError as exc:
        raise RepositoryScanError("Unable to read package-lock.json") from exc

    if len(content) > limits.max_characters:
        raise RepositoryScanError(
            f"package-lock.json exceeds the character limit ({limits.max_characters})"
        )

    manifest_content: str | None = None
    manifest_path = root / "package.json"

    if manifest_path.exists() or manifest_path.is_symlink():
        try:
            resolved_manifest = manifest_path.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise RepositoryScanError("Unable to resolve package.json") from exc

        if not resolved_manifest.is_relative_to(root):
            raise RepositoryScanError("package.json resolves outside the repository directory")
        if not resolved_manifest.is_file():
            raise RepositoryScanError("package.json is not a regular file")

        try:
            manifest_size = resolved_manifest.stat().st_size
            if manifest_size > limits.max_characters:
                raise RepositoryScanError(
                    f"package.json exceeds the size limit ({limits.max_characters})"
                )
            manifest_content = resolved_manifest.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise RepositoryScanError("package.json is not valid UTF-8") from exc
        except OSError as exc:
            raise RepositoryScanError("Unable to read package.json") from exc

        if len(manifest_content) > limits.max_characters:
            raise RepositoryScanError(
                f"package.json exceeds the character limit ({limits.max_characters})"
            )

    return RepositoryLockfile(
        repository_path=root,
        lockfile_path=resolved_lockfile,
        content=content,
        manifest_content=manifest_content,
    )
