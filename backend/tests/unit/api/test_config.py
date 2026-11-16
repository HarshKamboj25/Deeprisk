"""Tests for API workspace security configuration."""

from pathlib import Path

import pytest

from deprisk.api.config import (
    WorkspaceConfigurationError,
    get_workspace_root,
    resolve_local_repository_path,
)


def test_workspace_configuration_is_required(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("DEPRISK_WORKSPACE_ROOT", raising=False)

    with pytest.raises(WorkspaceConfigurationError, match="Local scanning is disabled"):
        get_workspace_root()


def test_workspace_root_must_exist(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    missing = tmp_path / "missing"
    monkeypatch.setenv("DEPRISK_WORKSPACE_ROOT", str(missing))

    with pytest.raises(WorkspaceConfigurationError, match="does not exist"):
        get_workspace_root()


def test_workspace_root_must_be_a_directory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    file_path = tmp_path / "not-a-directory"
    file_path.write_text("content", encoding="utf-8")
    monkeypatch.setenv("DEPRISK_WORKSPACE_ROOT", str(file_path))

    with pytest.raises(WorkspaceConfigurationError, match="must be a directory"):
        get_workspace_root()


def test_resolves_repository_inside_workspace(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    repository = workspace / "project"
    repository.mkdir(parents=True)
    monkeypatch.setenv("DEPRISK_WORKSPACE_ROOT", str(workspace))

    resolved = resolve_local_repository_path("project")

    assert resolved == repository.resolve()


def test_rejects_repository_outside_workspace(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    workspace.mkdir()
    outside.mkdir()
    monkeypatch.setenv("DEPRISK_WORKSPACE_ROOT", str(workspace))

    with pytest.raises(WorkspaceConfigurationError, match="outside"):
        resolve_local_repository_path(str(outside))


def test_rejects_nonexistent_repository(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setenv("DEPRISK_WORKSPACE_ROOT", str(workspace))

    with pytest.raises(WorkspaceConfigurationError, match="does not exist"):
        resolve_local_repository_path("missing")


def test_rejects_file_instead_of_repository_directory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    file_path = workspace / "not-a-directory"
    file_path.write_text("content", encoding="utf-8")
    monkeypatch.setenv("DEPRISK_WORKSPACE_ROOT", str(workspace))

    with pytest.raises(WorkspaceConfigurationError, match="must be a directory"):
        resolve_local_repository_path("not-a-directory")


def test_rejects_symlink_escape(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    workspace.mkdir()
    outside.mkdir()
    link = workspace / "linked-project"

    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation is not permitted on this system")

    monkeypatch.setenv("DEPRISK_WORKSPACE_ROOT", str(workspace))

    with pytest.raises(WorkspaceConfigurationError, match="outside"):
        resolve_local_repository_path("linked-project")
