"""Versioned REST endpoints for DepRisk."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from deprisk.api.config import WorkspaceConfigurationError, get_workspace_root
from deprisk.api.dependencies import get_session
from deprisk.api.schemas import (
    RepositoryResponse,
    ScanCreateRequest,
    ScanCreateResponse,
    ScanHistoryItem,
    ScanHistoryResponse,
    ScanReportResponse,
    ScanStatusResponse,
)
from deprisk.api.services import register_scan
from deprisk.api.worker import WorkerPoolError
from deprisk.github_repository import GitHubRepositoryError
from deprisk.persistence.models import Repository, Scan
from deprisk.persistence.store import (
    ScanNotFoundError,
    ScanPersistence,
)

router = APIRouter(prefix="/api/v1", tags=["DepRisk"])

@router.get("/configuration")
async def get_api_configuration() -> dict[str, object]:
    """Expose safe, read-only local workspace configuration."""

    try:
        workspace_root = get_workspace_root()
    except WorkspaceConfigurationError:
        return {
            "local_scanning_enabled": False,
            "workspace_root": None,
        }

    return {
        "local_scanning_enabled": True,
        "workspace_root": str(workspace_root),
    }


@router.post(
    "/scans",
    response_model=ScanCreateResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def create_scan(
    payload: ScanCreateRequest,
    request: Request,
) -> ScanCreateResponse:
    """Register a repository scan and queue it for background execution."""

    session_factory = request.app.state.session_factory

    try:
        result = await register_scan(session_factory, payload)
    except WorkspaceConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except GitHubRepositoryError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc

    try:
        request.app.state.worker_pool.submit(result.scan_id)
    except WorkerPoolError as exc:
        async with session_factory() as session, session.begin():
            await ScanPersistence.fail_scan(
                session,
                scan_id=result.scan_id,
                error_message="Scan was not accepted by the worker pool.",
            )

        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Scan queue is unavailable or full. Please retry later.",
        ) from exc

    return ScanCreateResponse(
        scan_id=result.scan_id,
        repository_id=result.repository_id,
        status="pending",
    )


@router.get(
    "/scans",
    response_model=ScanHistoryResponse,
)
async def list_scan_history(
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    status_filter: Annotated[
        str | None,
        Query(alias="status", pattern="^(pending|running|succeeded|failed)$"),
    ] = None,
    repository_id: UUID | None = None,
    search: str | None = Query(default=None, min_length=1, max_length=255),
) -> ScanHistoryResponse:
    """List persisted scans with repository details and pagination."""

    filters = []

    if status_filter is not None:
        filters.append(Scan.status == status_filter)

    if repository_id is not None:
        filters.append(Scan.repository_id == repository_id)

    if search is not None:
        search_term = search.strip()

        if search_term:
            filters.append(Repository.name.ilike(f"%{search_term}%"))

    count_statement = (
        select(func.count())
        .select_from(Scan)
        .join(Repository, Scan.repository_id == Repository.id)
        .where(*filters)
    )

    total = await session.scalar(count_statement)

    history_statement = (
        select(Scan, Repository)
        .join(Repository, Scan.repository_id == Repository.id)
        .where(*filters)
        .order_by(Scan.created_at.desc(), Scan.id.desc())
        .offset(offset)
        .limit(limit)
    )

    result = await session.execute(history_statement)
    rows = result.all()

    items = [
        ScanHistoryItem(
            id=scan.id,
            repository_id=scan.repository_id,
            repository_name=repository.name,
            source_type=repository.source_type,
            status=scan.status,
            started_at=scan.started_at,
            finished_at=scan.finished_at,
            error_message=scan.error_message,
            created_at=scan.created_at,
        )
        for scan, repository in rows
    ]

    return ScanHistoryResponse(
        items=items,
        total=total or 0,
        limit=limit,
        offset=offset,
    )

@router.get(
    "/scans/{scan_id}",
    response_model=ScanStatusResponse,
)
async def get_scan_status(
    scan_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> ScanStatusResponse:
    """Retrieve the persisted status of a scan."""

    try:
        scan = await ScanPersistence.get_scan(
            session,
            scan_id=scan_id,
        )
    except ScanNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found.",
        ) from exc

    return ScanStatusResponse(
        id=scan.id,
        repository_id=scan.repository_id,
        status=scan.status,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        error_message=scan.error_message,
        created_at=scan.created_at,
    )


@router.get(
    "/scans/{scan_id}/report",
    response_model=ScanReportResponse,
)
async def get_scan_report(
    scan_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> ScanReportResponse:
    """Retrieve the immutable report snapshot for a completed scan."""

    try:
        await ScanPersistence.get_scan(
            session,
            scan_id=scan_id,
        )
    except ScanNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found.",
        ) from exc

    report = await ScanPersistence.get_report(
        session,
        scan_id=scan_id,
    )

    if report is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No report is available for this scan.",
        )

    return ScanReportResponse(
        scan_id=report.scan_id,
        schema_version=report.schema_version,
        report=report.report_data,
        created_at=report.created_at,
    )


@router.get(
    "/repositories",
    response_model=list[RepositoryResponse],
)
async def list_repositories(
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[RepositoryResponse]:
    """List registered repositories, newest first."""

    statement = select(Repository).order_by(Repository.created_at.desc())
    result = await session.execute(statement)
    repositories = result.scalars().all()

    return [
        RepositoryResponse(
            id=repository.id,
            name=repository.name,
            source_type=repository.source_type,
            canonical_source=repository.canonical_source,
            created_at=repository.created_at,
        )
        for repository in repositories
    ]
