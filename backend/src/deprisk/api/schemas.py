"""Request and response schemas for the DepRisk API."""

from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class LocalScanRequest(BaseModel):
    """Request to scan a repository inside the configured workspace."""

    model_config = ConfigDict(extra="forbid")

    source_type: Literal["local"]
    repository_path: str = Field(min_length=1, max_length=4096)


class GitHubScanRequest(BaseModel):
    """Request to scan a public GitHub repository."""

    model_config = ConfigDict(extra="forbid")

    source_type: Literal["github"]
    repository_url: str = Field(min_length=1, max_length=2048)


ScanCreateRequest = Annotated[
    LocalScanRequest | GitHubScanRequest,
    Field(discriminator="source_type"),
]


class ScanCreateResponse(BaseModel):
    """Response returned after a scan has been accepted for execution."""

    scan_id: UUID
    repository_id: UUID
    status: Literal["pending"]


class ScanStatusResponse(BaseModel):
    """Persisted scan lifecycle information."""

    id: UUID
    repository_id: UUID
    status: Literal["pending", "running", "succeeded", "failed"]
    started_at: datetime | None
    finished_at: datetime | None
    error_message: str | None
    created_at: datetime


class RepositoryResponse(BaseModel):
    """Persisted repository identity."""

    id: UUID
    name: str
    source_type: Literal["local", "github"]
    canonical_source: str
    created_at: datetime


class ScanHistoryItem(BaseModel):
    """One scan history entry with its repository identity."""

    id: UUID
    repository_id: UUID
    repository_name: str
    source_type: Literal["local", "github"]
    status: Literal["pending", "running", "succeeded", "failed"]
    started_at: datetime | None
    finished_at: datetime | None
    error_message: str | None
    created_at: datetime


class ScanHistoryResponse(BaseModel):
    """Paginated scan history response."""

    items: list[ScanHistoryItem]
    total: int
    limit: int
    offset: int

class ScanReportResponse(BaseModel):
    """Complete persisted report snapshot."""

    scan_id: UUID
    schema_version: str
    report: dict[str, Any]
    created_at: datetime
