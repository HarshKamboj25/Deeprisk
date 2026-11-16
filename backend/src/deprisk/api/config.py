"""Security configuration for the DepRisk API."""

import os
from pathlib import Path


class WorkspaceConfigurationError(ValueError):
    """Raised when the local scan workspace is invalid."""


def get_workspace_root() -> Path:
    """Return the configured, existing local scan workspace."""

    configured_root = os.environ.get("DEPRISK_WORKSPACE_ROOT")

    if not configured_root:
        raise WorkspaceConfigurationError(
            "Local scanning is disabled. Configure DEPRISK_WORKSPACE_ROOT."
        )

    try:
        root = Path(configured_root).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise WorkspaceConfigurationError(
            "The configured scan workspace does not exist or cannot be resolved."
        ) from exc

    if not root.is_dir():
        raise WorkspaceConfigurationError("The configured scan workspace must be a directory.")

    return root


def resolve_local_repository_path(repository_path: str) -> Path:
    """Resolve a repository path and enforce the configured workspace boundary."""

    root = get_workspace_root()
    candidate = Path(repository_path).expanduser()

    if not candidate.is_absolute():
        candidate = root / candidate

    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise WorkspaceConfigurationError(
            "The requested repository does not exist or cannot be resolved."
        ) from exc

    if not resolved.is_relative_to(root):
        raise WorkspaceConfigurationError(
            "The requested repository is outside the configured workspace."
        )

    if not resolved.is_dir():
        raise WorkspaceConfigurationError("The requested repository must be a directory.")

    return resolved
