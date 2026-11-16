from pathlib import Path

import pytest

from deprisk.core.lockfile import ParseLimits
from deprisk.repository import (
    RepositoryScanError,
    load_repository_lockfile,
)


def make_repository(tmp_path: Path, content: str = '{"lockfileVersion": 3}') -> Path:
    (tmp_path / "package-lock.json").write_text(content, encoding="utf-8")
    return tmp_path


def test_loads_repository_lockfile(tmp_path: Path) -> None:
    root = make_repository(tmp_path)

    result = load_repository_lockfile(root)

    assert result.repository_path == root.resolve()
    assert result.lockfile_path == (root / "package-lock.json").resolve()
    assert result.content == '{"lockfileVersion": 3}'


def test_rejects_missing_repository(tmp_path: Path) -> None:
    with pytest.raises(RepositoryScanError, match="does not exist"):
        load_repository_lockfile(tmp_path / "missing")


def test_rejects_file_as_repository_path(tmp_path: Path) -> None:
    file_path = tmp_path / "not-a-directory"
    file_path.write_text("content", encoding="utf-8")

    with pytest.raises(RepositoryScanError, match="not a directory"):
        load_repository_lockfile(file_path)


def test_rejects_missing_lockfile(tmp_path: Path) -> None:
    with pytest.raises(RepositoryScanError, match="package-lock.json"):
        load_repository_lockfile(tmp_path)


def test_rejects_oversized_lockfile(tmp_path: Path) -> None:
    root = make_repository(tmp_path, '{"lockfileVersion": 3}')

    with pytest.raises(RepositoryScanError, match="size limit"):
        load_repository_lockfile(root, ParseLimits(max_characters=5))


def test_rejects_invalid_utf8_lockfile(tmp_path: Path) -> None:
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_bytes(b"\xff\xfe\xfa")

    with pytest.raises(RepositoryScanError, match="valid UTF-8"):
        load_repository_lockfile(tmp_path)


def test_rejects_lockfile_symlink_outside_repository(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()

    outside = tmp_path / "outside.json"
    outside.write_text('{"lockfileVersion": 3}', encoding="utf-8")

    link = root / "package-lock.json"

    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation is not permitted on this system")

    with pytest.raises(RepositoryScanError, match="outside the repository"):
        load_repository_lockfile(root)


def test_rejects_lockfile_directory(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").mkdir()

    with pytest.raises(RepositoryScanError, match="regular file"):
        load_repository_lockfile(tmp_path)
