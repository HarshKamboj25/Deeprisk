"""Tests for DepRisk API scan registration and job execution."""

import asyncio
from pathlib import Path
from runpy import run_path
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from deprisk.api.config import WorkspaceConfigurationError
from deprisk.api.schemas import GitHubScanRequest, LocalScanRequest
from deprisk.api.services import execute_scan_job, register_scan
from deprisk.persistence.base import Base
from deprisk.persistence.models import Repository, ScanStatus
from deprisk.persistence.store import ScanPersistence

report_helpers = run_path(Path(__file__).resolve().parents[1] / "test_report.py")
make_scan_result = report_helpers["make_scan_result"]


async def create_test_database(tmp_path):
    """Create an isolated temporary SQLite database."""

    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'api_scan_test.db'}")

    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(
        engine,
        expire_on_commit=False,
    )

    return engine, session_factory


def install_fake_services(monkeypatch):
    """Replace external vulnerability clients with inert test services."""

    monkeypatch.setattr(
        "deprisk.api.services.build_scanner_services",
        lambda client: SimpleNamespace(
            osv_service=object(),
            enrichment_service=object(),
        ),
    )


def test_scan_registration_persists_pending_without_execution(
    tmp_path,
    monkeypatch,
):
    async def scenario():
        workspace = tmp_path / "workspace"
        repository_path = workspace / "sample-project"
        workspace.mkdir()
        repository_path.mkdir()

        monkeypatch.setenv("DEPRISK_WORKSPACE_ROOT", str(workspace))

        engine, session_factory = await create_test_database(tmp_path)

        try:
            result = await register_scan(
                session_factory,
                LocalScanRequest(
                    source_type="local",
                    repository_path="sample-project",
                ),
            )

            assert result.status == ScanStatus.PENDING

            async with session_factory() as session:
                scan = await ScanPersistence.get_scan(
                    session,
                    scan_id=result.scan_id,
                )
                repository = await session.get(Repository, result.repository_id)

                assert scan.status == ScanStatus.PENDING.value
                assert scan.started_at is None
                assert scan.finished_at is None
                assert repository is not None
                assert repository.name == "sample-project"

        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_local_scan_job_success_persists_complete_report(
    tmp_path,
    monkeypatch,
):
    async def scenario():
        workspace = tmp_path / "workspace"
        repository_path = workspace / "sample-project"
        workspace.mkdir()
        repository_path.mkdir()

        monkeypatch.setenv("DEPRISK_WORKSPACE_ROOT", str(workspace))

        fixture_root = tmp_path / "report-fixture"
        fixture_root.mkdir()
        scan_result = make_scan_result(fixture_root)

        engine, session_factory = await create_test_database(tmp_path)

        async def fake_scan(received_path, osv_service, enrichment_service):
            assert received_path == repository_path.resolve()
            assert osv_service is not None
            assert enrichment_service is not None
            return scan_result

        monkeypatch.setattr(
            "deprisk.api.services.scan_local_repository",
            fake_scan,
        )
        install_fake_services(monkeypatch)

        try:
            submission = await register_scan(
                session_factory,
                LocalScanRequest(
                    source_type="local",
                    repository_path="sample-project",
                ),
            )

            assert submission.status == ScanStatus.PENDING

            await execute_scan_job(session_factory, submission.scan_id)

            async with session_factory() as session:
                scan = await ScanPersistence.get_scan(
                    session,
                    scan_id=submission.scan_id,
                )
                report = await ScanPersistence.get_report(
                    session,
                    scan_id=submission.scan_id,
                )

                assert scan.status == ScanStatus.SUCCEEDED.value
                assert scan.started_at is not None
                assert scan.finished_at is not None
                assert report is not None
                assert report.report_data["schema_version"] == report.schema_version
                assert report.report_data["dependencies"]

        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_local_scanner_failure_records_failure_without_report(
    tmp_path,
    monkeypatch,
):
    async def scenario():
        workspace = tmp_path / "workspace"
        repository_path = workspace / "failed-project"
        workspace.mkdir()
        repository_path.mkdir()

        monkeypatch.setenv("DEPRISK_WORKSPACE_ROOT", str(workspace))

        engine, session_factory = await create_test_database(tmp_path)

        async def failing_scan(repository_path, osv_service, enrichment_service):
            raise httpx.ConnectError("secret connection details")

        monkeypatch.setattr(
            "deprisk.api.services.scan_local_repository",
            failing_scan,
        )
        install_fake_services(monkeypatch)

        try:
            submission = await register_scan(
                session_factory,
                LocalScanRequest(
                    source_type="local",
                    repository_path="failed-project",
                ),
            )

            await execute_scan_job(session_factory, submission.scan_id)

            async with session_factory() as session:
                scan = await ScanPersistence.get_scan(
                    session,
                    scan_id=submission.scan_id,
                )
                report = await ScanPersistence.get_report(
                    session,
                    scan_id=submission.scan_id,
                )

                assert scan.status == ScanStatus.FAILED.value
                assert scan.finished_at is not None
                assert scan.error_message == "Scan failed (ConnectError)."
                assert "secret" not in scan.error_message
                assert report is None

        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_github_scan_job_uses_canonical_repository_url(
    tmp_path,
    monkeypatch,
):
    async def scenario():
        fixture_root = tmp_path / "report-fixture"
        fixture_root.mkdir()
        scan_result = make_scan_result(fixture_root)

        engine, session_factory = await create_test_database(tmp_path)
        received_urls = []

        async def fake_scan(repository_url, osv_service, enrichment_service):
            received_urls.append(repository_url)
            return scan_result

        monkeypatch.setattr(
            "deprisk.api.services.scan_github_repository",
            fake_scan,
        )
        install_fake_services(monkeypatch)

        try:
            submission = await register_scan(
                session_factory,
                GitHubScanRequest(
                    source_type="github",
                    repository_url="https://github.com/example/sample-repo",
                ),
            )

            assert submission.status == ScanStatus.PENDING

            await execute_scan_job(session_factory, submission.scan_id)

            assert received_urls == ["https://github.com/example/sample-repo"]

            async with session_factory() as session:
                repository = await session.get(
                    Repository,
                    submission.repository_id,
                )
                scan = await ScanPersistence.get_scan(
                    session,
                    scan_id=submission.scan_id,
                )
                report = await ScanPersistence.get_report(
                    session,
                    scan_id=submission.scan_id,
                )

                assert repository is not None
                assert repository.name == "sample-repo"
                assert repository.canonical_source == ("https://github.com/example/sample-repo")
                assert scan.status == ScanStatus.SUCCEEDED.value
                assert report is not None

        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_local_repository_outside_workspace_is_rejected(
    tmp_path,
    monkeypatch,
):
    async def scenario():
        workspace = tmp_path / "workspace"
        outside_repository = tmp_path / "outside-project"
        workspace.mkdir()
        outside_repository.mkdir()

        monkeypatch.setenv("DEPRISK_WORKSPACE_ROOT", str(workspace))

        engine, session_factory = await create_test_database(tmp_path)

        try:
            with pytest.raises(
                WorkspaceConfigurationError,
                match="outside the configured workspace",
            ):
                await register_scan(
                    session_factory,
                    LocalScanRequest(
                        source_type="local",
                        repository_path=str(outside_repository),
                    ),
                )

            async with session_factory() as session:
                repositories = await session.execute(select(Repository))
                assert repositories.scalars().all() == []

        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_recover_scans_fails_interrupted_jobs_and_returns_pending_jobs(
    tmp_path,
    monkeypatch,
):
    async def scenario():
        from deprisk.api.services import recover_scans
        from deprisk.persistence.models import Scan, ScanStatus
        from deprisk.persistence.store import ScanPersistence

        workspace = tmp_path / "workspace"
        repository_path = workspace / "recovery-project"
        workspace.mkdir()
        repository_path.mkdir()

        monkeypatch.setenv("DEPRISK_WORKSPACE_ROOT", str(workspace))

        engine, session_factory = await create_test_database(tmp_path)

        try:
            pending = await register_scan(
                session_factory,
                LocalScanRequest(
                    source_type="local",
                    repository_path="recovery-project",
                ),
            )

            interrupted = await register_scan(
                session_factory,
                LocalScanRequest(
                    source_type="local",
                    repository_path="recovery-project",
                ),
            )

            async with session_factory() as session, session.begin():
                await ScanPersistence.mark_running(
                    session,
                    scan_id=interrupted.scan_id,
                )

            pending_ids = await recover_scans(session_factory)

            assert pending.scan_id in pending_ids
            assert interrupted.scan_id not in pending_ids

            async with session_factory() as session:
                pending_scan = await ScanPersistence.get_scan(
                    session,
                    scan_id=pending.scan_id,
                )
                interrupted_scan = await ScanPersistence.get_scan(
                    session,
                    scan_id=interrupted.scan_id,
                )

                assert pending_scan.status == ScanStatus.PENDING.value
                assert interrupted_scan.status == ScanStatus.FAILED.value
                assert interrupted_scan.finished_at is not None
                assert interrupted_scan.error_message == (
                    "Scan interrupted by previous application process."
                )

                all_scans = (
                    (await session.execute(select(Scan).order_by(Scan.created_at))).scalars().all()
                )

                assert len(all_scans) == 2

        finally:
            await engine.dispose()

    asyncio.run(scenario())
