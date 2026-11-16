"""Application services for registering and executing repository scans."""

import logging
from dataclasses import dataclass
from uuid import UUID

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from deprisk.api.config import resolve_local_repository_path
from deprisk.api.schemas import GitHubScanRequest, LocalScanRequest
from deprisk.github_repository import parse_github_repository_url
from deprisk.persistence.models import (
    Repository,
    RepositorySourceType,
    Scan,
    ScanStatus,
)
from deprisk.persistence.store import ScanPersistence
from deprisk.report import build_repository_report
from deprisk.scan import scan_github_repository, scan_local_repository
from deprisk.scanner_services import build_scanner_services

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ScanSubmissionResult:
    """Identifiers and initial status returned after scan registration."""

    scan_id: UUID
    repository_id: UUID
    status: ScanStatus


async def register_scan(
    session_factory: async_sessionmaker[AsyncSession],
    request: LocalScanRequest | GitHubScanRequest,
) -> ScanSubmissionResult:
    """Validate and persist a pending scan without executing it."""

    if isinstance(request, LocalScanRequest):
        repository_path = resolve_local_repository_path(request.repository_path)
        repository_name = repository_path.name
        source_type = RepositorySourceType.LOCAL
        canonical_source = str(repository_path)
    else:
        github_repository = parse_github_repository_url(request.repository_url)
        repository_name = github_repository.repository
        source_type = RepositorySourceType.GITHUB
        canonical_source = github_repository.canonical_url

    async with session_factory() as session, session.begin():
        repository = await ScanPersistence.get_or_create_repository(
            session,
            name=repository_name,
            source_type=source_type,
            canonical_source=canonical_source,
        )
        scan = await ScanPersistence.create_scan(
            session,
            repository_id=repository.id,
        )

        result = ScanSubmissionResult(
            scan_id=scan.id,
            repository_id=repository.id,
            status=ScanStatus.PENDING,
        )

    return result


async def recover_scans(
    session_factory: async_sessionmaker[AsyncSession],
) -> list[UUID]:
    """Fail interrupted jobs and return pending scans for re-queuing."""

    async with session_factory() as session, session.begin():
        running_result = await session.execute(
            select(Scan.id).where(Scan.status == ScanStatus.RUNNING.value)
        )
        interrupted_scan_ids = list(running_result.scalars().all())

        for scan_id in interrupted_scan_ids:
            await ScanPersistence.fail_scan(
                session,
                scan_id=scan_id,
                error_message="Scan interrupted by previous application process.",
            )

        pending_result = await session.execute(
            select(Scan.id)
            .where(Scan.status == ScanStatus.PENDING.value)
            .order_by(Scan.created_at, Scan.id)
        )
        pending_scan_ids = list(pending_result.scalars().all())

    return pending_scan_ids


async def execute_scan_job(
    session_factory: async_sessionmaker[AsyncSession],
    scan_id: UUID,
) -> None:
    """Execute a persisted pending scan and save its result."""

    async with session_factory() as session, session.begin():
        scan = await ScanPersistence.get_scan(session, scan_id=scan_id)

        if scan.status != ScanStatus.PENDING.value:
            return

        repository = await session.get(Repository, scan.repository_id)

        if repository is None:
            await ScanPersistence.fail_scan(
                session,
                scan_id=scan_id,
                error_message="Scan failed (RepositoryNotFound).",
            )
            return

        source_type = RepositorySourceType(repository.source_type)
        canonical_source = repository.canonical_source

        await ScanPersistence.mark_running(
            session,
            scan_id=scan_id,
        )

    try:
        if source_type == RepositorySourceType.LOCAL:
            repository_path = resolve_local_repository_path(canonical_source)
        else:
            github_repository = parse_github_repository_url(canonical_source)
            canonical_source = github_repository.canonical_url
            repository_path = None

        async with httpx.AsyncClient() as client:
            services = build_scanner_services(client)

            if source_type == RepositorySourceType.LOCAL:
                if repository_path is None:
                    raise RuntimeError("Local repository path was not resolved.")
                result = await scan_local_repository(
                    repository_path,
                    services.osv_service,
                    services.enrichment_service,
                )
            else:
                result = await scan_github_repository(
                    canonical_source,
                    services.osv_service,
                    services.enrichment_service,
                )

        report = build_repository_report(result)

    except Exception as exc:
        logger.exception("Scan execution failed for scan %s", scan_id)
        error_message = f"Scan failed ({type(exc).__name__})."

        async with session_factory() as session, session.begin():
            await ScanPersistence.fail_scan(
                session,
                scan_id=scan_id,
                error_message=error_message,
            )

        return

    async with session_factory() as session, session.begin():
        await ScanPersistence.complete_scan(
            session,
            scan_id=scan_id,
            report=report,
        )

