import asyncio
import tarfile
from io import BytesIO
from pathlib import Path

import pytest

from deprisk.core.lockfile import LockfileParseError
from deprisk.github_repository import GitHubRepositoryError
from deprisk.scan import analyze_local_repository, scan_github_repository
from deprisk.vulnerability.osv_service import OSVLookupResult

FIXTURES = (
    "flags-v3",
    "general-v2",
    "general-v3",
    "peer-v3",
)

FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures" / "recorded" / "npm-lockfiles"


@pytest.mark.parametrize("fixture_name", FIXTURES)
def test_analyzes_supported_recorded_lockfiles(fixture_name: str) -> None:
    repository = FIXTURE_ROOT / fixture_name

    result = analyze_local_repository(repository)

    assert result.repository.repository_path == repository.resolve()
    assert result.repository.lockfile_path.name == "package-lock.json"
    assert result.parsed_lockfile.nodes
    assert result.edges
    assert result.scope_result.nodes
    assert result.candidate_selection.decisions

    node_paths = {node.install_path for node in result.parsed_lockfile.nodes}
    assert set(result.scope_result.nodes) == node_paths

    assert all(candidate.install_paths for candidate in result.candidate_selection.candidates)


def test_rejects_unsupported_workspace_fixture() -> None:
    repository = FIXTURE_ROOT / "workspace-v3"

    with pytest.raises(LockfileParseError):
        analyze_local_repository(repository)


def test_analysis_is_deterministic() -> None:
    repository = FIXTURE_ROOT / "general-v3"

    first = analyze_local_repository(repository)
    second = analyze_local_repository(repository)

    assert first.edges == second.edges
    assert first.scope_result == second.scope_result
    assert first.candidate_selection == second.candidate_selection


def _make_github_test_tarball() -> bytes:
    fixture = FIXTURE_ROOT / "general-v3" / "package-lock.json"
    lockfile_content = fixture.read_bytes()
    buffer = BytesIO()

    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        root = tarfile.TarInfo("sample-repo/")
        root.type = tarfile.DIRTYPE
        archive.addfile(root)

        lockfile = tarfile.TarInfo("sample-repo/package-lock.json")
        lockfile.size = len(lockfile_content)
        archive.addfile(lockfile, BytesIO(lockfile_content))

    return buffer.getvalue()


class _EmptyOSVService:
    async def lookup(self, candidates):
        return OSVLookupResult()


def test_github_scan_uses_real_extraction_and_preserves_identity(
    monkeypatch,
) -> None:
    archive = _make_github_test_tarball()

    async def fake_download(repository_url: str) -> bytes:
        assert repository_url == "https://github.com/example/sample-repo"
        return archive

    monkeypatch.setattr(
        "deprisk.scan.download_github_repository_tarball",
        fake_download,
    )

    result = asyncio.run(
        scan_github_repository(
            "https://github.com/example/sample-repo",
            _EmptyOSVService(),
        )
    )

    assert result.analysis.repository.repository_name == "sample-repo"
    assert result.analysis.repository.repository_url == "https://github.com/example/sample-repo"
    assert result.analysis.parsed_lockfile.nodes
    assert not result.analysis.repository.repository_path.exists()


def test_github_scan_rejects_invalid_url_before_download(monkeypatch) -> None:
    def unexpected_download(*args, **kwargs):
        raise AssertionError("Download must not run for an invalid URL")

    monkeypatch.setattr(
        "deprisk.scan.download_github_repository_tarball",
        unexpected_download,
    )

    with pytest.raises(GitHubRepositoryError):
        asyncio.run(
            scan_github_repository(
                "https://example.com/attacker/repository",
                _EmptyOSVService(),
            )
        )


def test_github_scan_propagates_download_failure(monkeypatch) -> None:
    async def failing_download(repository_url: str) -> bytes:
        raise GitHubRepositoryError("Simulated download failure")

    monkeypatch.setattr(
        "deprisk.scan.download_github_repository_tarball",
        failing_download,
    )

    with pytest.raises(GitHubRepositoryError, match="Simulated download failure"):
        asyncio.run(
            scan_github_repository(
                "https://github.com/example/sample-repo",
                _EmptyOSVService(),
            )
        )


def test_github_scan_cleans_temporary_directory_after_scan_failure(
    monkeypatch,
) -> None:
    archive = _make_github_test_tarball()
    captured_paths = []

    async def fake_download(repository_url: str) -> bytes:
        return archive

    async def failing_scan(repository_path, osv_service, enrichment_service=None):
        captured_paths.append(repository_path)
        raise RuntimeError("Simulated analysis failure")

    monkeypatch.setattr(
        "deprisk.scan.download_github_repository_tarball",
        fake_download,
    )
    monkeypatch.setattr(
        "deprisk.scan.scan_local_repository",
        failing_scan,
    )

    with pytest.raises(RuntimeError, match="Simulated analysis failure"):
        asyncio.run(
            scan_github_repository(
                "https://github.com/example/sample-repo",
                _EmptyOSVService(),
            )
        )

    assert len(captured_paths) == 1
    assert not captured_paths[0].exists()
