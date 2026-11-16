"""Tests for DepRisk scan persistence operations."""

import asyncio
from pathlib import Path
from runpy import run_path

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from deprisk.persistence.base import Base
from deprisk.persistence.models import (
    Repository,
    RepositorySourceType,
    Scan,
    ScanStatus,
)
from deprisk.persistence.store import (
    InvalidScanTransitionError,
    ScanNotFoundError,
    ScanPersistence,
)
from deprisk.report import build_repository_report

report_helpers = run_path(Path(__file__).resolve().parents[1] / "test_report.py")
make_scan_result = report_helpers["make_scan_result"]


def test_successful_scan_lifecycle_persists_report(tmp_path):
    async def scenario():
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'successful_scan.db'}")
        session_factory = async_sessionmaker(
            engine,
            expire_on_commit=False,
        )

        try:
            async with engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)

            async with session_factory() as session, session.begin():
                repository = await ScanPersistence.get_or_create_repository(
                    session,
                    name="sample-project",
                    source_type=RepositorySourceType.LOCAL,
                    canonical_source="C:/projects/sample-project",
                )
                repository_id = repository.id

                duplicate = await ScanPersistence.get_or_create_repository(
                    session,
                    name="renamed-project",
                    source_type=RepositorySourceType.LOCAL,
                    canonical_source="C:/projects/sample-project",
                )

                assert duplicate.id == repository_id
                assert duplicate.name == "sample-project"

                scan = await ScanPersistence.create_scan(
                    session,
                    repository_id=repository_id,
                )
                scan_id = scan.id

                assert scan.status == ScanStatus.PENDING.value

                running_scan = await ScanPersistence.mark_running(
                    session,
                    scan_id=scan_id,
                )
                assert running_scan.status == ScanStatus.RUNNING.value
                assert running_scan.started_at is not None

                report = build_repository_report(make_scan_result(tmp_path))

                snapshot = await ScanPersistence.complete_scan(
                    session,
                    scan_id=scan_id,
                    report=report,
                )

                assert snapshot.schema_version == report.schema_version
                assert snapshot.report_data == report.model_dump(mode="json")

                assert running_scan.status == ScanStatus.SUCCEEDED.value
                assert running_scan.finished_at is not None

            async with session_factory() as session:
                persisted_scan = await ScanPersistence.get_scan(
                    session,
                    scan_id=scan_id,
                )
                persisted_report = await ScanPersistence.get_report(
                    session,
                    scan_id=scan_id,
                )

                assert persisted_scan.status == ScanStatus.SUCCEEDED.value
                assert persisted_report is not None
                assert persisted_report.report_data == report.model_dump(mode="json")

        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_failed_scan_records_error_without_report(tmp_path):
    async def scenario():
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'failed_scan.db'}")
        session_factory = async_sessionmaker(
            engine,
            expire_on_commit=False,
        )

        try:
            async with engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)

            async with session_factory() as session, session.begin():
                repository = await ScanPersistence.get_or_create_repository(
                    session,
                    name="failed-project",
                    source_type=RepositorySourceType.LOCAL,
                    canonical_source="C:/projects/failed-project",
                )
                scan = await ScanPersistence.create_scan(
                    session,
                    repository_id=repository.id,
                )
                scan_id = scan.id

                failed_scan = await ScanPersistence.fail_scan(
                    session,
                    scan_id=scan_id,
                    error_message="Repository scan failed.",
                )

                assert failed_scan.status == ScanStatus.FAILED.value
                assert failed_scan.finished_at is not None
                assert failed_scan.error_message == "Repository scan failed."

                assert (
                    await ScanPersistence.get_report(
                        session,
                        scan_id=scan_id,
                    )
                    is None
                )

                with pytest.raises(InvalidScanTransitionError):
                    await ScanPersistence.mark_running(
                        session,
                        scan_id=scan_id,
                    )

                with pytest.raises(InvalidScanTransitionError):
                    await ScanPersistence.fail_scan(
                        session,
                        scan_id=scan_id,
                        error_message="Second failure.",
                    )

            async with session_factory() as session:
                persisted_scan = await ScanPersistence.get_scan(
                    session,
                    scan_id=scan_id,
                )
                assert persisted_scan.status == ScanStatus.FAILED.value

                with pytest.raises(ScanNotFoundError):
                    await ScanPersistence.get_scan(
                        session,
                        scan_id=__import__("uuid").uuid4(),
                    )

        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_scan_and_repository_creation_roll_back_together(tmp_path):
    async def scenario():
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'rollback_scan.db'}")
        session_factory = async_sessionmaker(
            engine,
            expire_on_commit=False,
        )

        try:
            async with engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)

            with pytest.raises(RuntimeError, match="simulate transaction failure"):
                async with session_factory() as session, session.begin():
                    repository = await ScanPersistence.get_or_create_repository(
                        session,
                        name="rollback-project",
                        source_type=RepositorySourceType.LOCAL,
                        canonical_source="C:/projects/rollback-project",
                    )
                    await ScanPersistence.create_scan(
                        session,
                        repository_id=repository.id,
                    )
                    raise RuntimeError("simulate transaction failure")

            async with session_factory() as session:
                repositories = await session.execute(select(Repository))
                scans = await session.execute(select(Scan))

                assert repositories.scalars().all() == []
                assert scans.scalars().all() == []

        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_concurrent_repository_registration_creates_one_record(tmp_path):
    async def scenario():
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'concurrent_repository.db'}")
        session_factory = async_sessionmaker(
            engine,
            expire_on_commit=False,
        )

        try:
            async with engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)

            ready = asyncio.Event()
            ready_count = 0

            async def register_repository(name):
                nonlocal ready_count

                async with session_factory() as session, session.begin():
                    ready_count += 1

                    if ready_count == 2:
                        ready.set()

                    await ready.wait()

                    repository = await ScanPersistence.get_or_create_repository(
                        session,
                        name=name,
                        source_type=RepositorySourceType.LOCAL,
                        canonical_source="C:/projects/concurrent-project",
                    )

                    return repository.id, repository.name

            first, second = await asyncio.gather(
                register_repository("first-registration"),
                register_repository("second-registration"),
            )

            assert first[0] == second[0]
            assert first[1] == second[1]

            async with session_factory() as session:
                repositories = (await session.scalars(select(Repository))).all()

                assert len(repositories) == 1
                assert repositories[0].id == first[0]
                assert repositories[0].canonical_source == ("C:/projects/concurrent-project")
                assert repositories[0].name in {
                    "first-registration",
                    "second-registration",
                }

        finally:
            await engine.dispose()

    asyncio.run(scenario())
