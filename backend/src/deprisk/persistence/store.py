"""Database operations for DepRisk repositories, scans, and reports."""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession

from deprisk.persistence.models import (
    Repository,
    RepositorySourceType,
    Scan,
    ScanReport,
    ScanStatus,
)
from deprisk.report import RepositoryReport


class PersistenceError(Exception):
    """Base exception for persistence operations."""


class ScanNotFoundError(PersistenceError):
    """Raised when a requested scan does not exist."""


class InvalidScanTransitionError(PersistenceError):
    """Raised when a scan lifecycle transition is invalid."""


class ScanPersistence:
    """Perform persistence operations without owning transaction commits."""

    @staticmethod
    async def get_or_create_repository(
        session: AsyncSession,
        *,
        name: str,
        source_type: RepositorySourceType,
        canonical_source: str,
    ) -> Repository:
        """Atomically register a repository or return its existing record."""

        dialect_name = session.get_bind().dialect.name
        insert_statement: Any

        if dialect_name == "sqlite":
            insert_statement = sqlite_insert(Repository)
        elif dialect_name == "postgresql":
            insert_statement = postgresql_insert(Repository)
        else:
            raise PersistenceError(
                f"Unsupported database dialect for repository registration: {dialect_name}."
            )

        insert_statement = insert_statement.values(
            name=name,
            source_type=source_type.value,
            canonical_source=canonical_source,
        ).on_conflict_do_nothing(
            index_elements=[
                Repository.source_type,
                Repository.canonical_source,
            ],
        )

        await session.execute(insert_statement)

        statement = select(Repository).where(
            Repository.source_type == source_type.value,
            Repository.canonical_source == canonical_source,
        )
        result = await session.execute(statement)
        repository = result.scalar_one_or_none()

        if repository is None:
            raise PersistenceError("Repository registration did not produce a record.")

        return repository

    @staticmethod
    async def create_scan(
        session: AsyncSession,
        *,
        repository_id: UUID,
    ) -> Scan:
        """Create a scan in the pending state."""

        scan = Scan(
            repository_id=repository_id,
            status=ScanStatus.PENDING.value,
        )
        session.add(scan)
        await session.flush()
        return scan

    @staticmethod
    async def get_scan(
        session: AsyncSession,
        *,
        scan_id: UUID,
    ) -> Scan:
        """Retrieve a scan or raise a domain-specific error."""

        result = await session.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()

        if scan is None:
            raise ScanNotFoundError(f"Scan not found: {scan_id}")

        return scan

    @staticmethod
    async def mark_running(
        session: AsyncSession,
        *,
        scan_id: UUID,
    ) -> Scan:
        """Move a pending scan into the running state."""

        scan = await ScanPersistence.get_scan(session, scan_id=scan_id)

        if scan.status != ScanStatus.PENDING.value:
            raise InvalidScanTransitionError(f"Cannot start scan in state '{scan.status}'.")

        scan.status = ScanStatus.RUNNING.value
        scan.started_at = datetime.now(UTC)

        await session.flush()
        return scan

    @staticmethod
    async def complete_scan(
        session: AsyncSession,
        *,
        scan_id: UUID,
        report: RepositoryReport,
    ) -> ScanReport:
        """Atomically prepare a successful scan and its report snapshot.

        The caller must commit both changes in the same transaction.
        """

        scan = await ScanPersistence.get_scan(session, scan_id=scan_id)

        if scan.status != ScanStatus.RUNNING.value:
            raise InvalidScanTransitionError(f"Cannot complete scan in state '{scan.status}'.")

        report_snapshot = ScanReport(
            scan_id=scan.id,
            schema_version=report.schema_version,
            report_data=report.model_dump(mode="json"),
        )

        scan.status = ScanStatus.SUCCEEDED.value
        scan.finished_at = datetime.now(UTC)
        session.add(report_snapshot)

        await session.flush()
        return report_snapshot

    @staticmethod
    async def fail_scan(
        session: AsyncSession,
        *,
        scan_id: UUID,
        error_message: str,
    ) -> Scan:
        """Record a scan failure without creating a report."""

        scan = await ScanPersistence.get_scan(session, scan_id=scan_id)

        if scan.status not in {
            ScanStatus.PENDING.value,
            ScanStatus.RUNNING.value,
        }:
            raise InvalidScanTransitionError(f"Cannot fail scan in state '{scan.status}'.")

        scan.status = ScanStatus.FAILED.value
        scan.finished_at = datetime.now(UTC)
        scan.error_message = error_message[:2000]

        await session.flush()
        return scan

    @staticmethod
    async def get_report(
        session: AsyncSession,
        *,
        scan_id: UUID,
    ) -> ScanReport | None:
        """Retrieve the persisted report snapshot for a scan."""

        result = await session.execute(select(ScanReport).where(ScanReport.scan_id == scan_id))
        return result.scalar_one_or_none()
