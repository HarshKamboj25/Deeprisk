"""Relational persistence models for DepRisk scans and report snapshots."""

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from deprisk.persistence.base import REPORT_JSON_TYPE, Base


class RepositorySourceType(StrEnum):
    LOCAL = "local"
    GITHUB = "github"


class ScanStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class Repository(Base):
    """A repository registered for security scanning."""

    __tablename__ = "repositories"
    __table_args__ = (
        UniqueConstraint(
            "source_type",
            "canonical_source",
            name="uq_repository_source_identity",
        ),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    source_type: Mapped[str] = mapped_column(String(20), nullable=False)
    canonical_source: Mapped[str] = mapped_column(String(2048), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    scans: Mapped[list["Scan"]] = relationship(
        back_populates="repository",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class Scan(Base):
    """One execution of the DepRisk scanning pipeline."""

    __tablename__ = "scans"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    repository_id: Mapped[UUID] = mapped_column(
        ForeignKey("repositories.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(20),
        default=ScanStatus.PENDING.value,
        nullable=False,
        index=True,
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    error_message: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    repository: Mapped["Repository"] = relationship(back_populates="scans")
    report: Mapped["ScanReport | None"] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        passive_deletes=True,
        uselist=False,
    )


class ScanReport(Base):
    """Immutable JSON snapshot produced by a successful scan."""

    __tablename__ = "scan_reports"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    scan_id: Mapped[UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    schema_version: Mapped[str] = mapped_column(String(32), nullable=False)
    report_data: Mapped[dict[str, Any]] = mapped_column(REPORT_JSON_TYPE, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    scan: Mapped["Scan"] = relationship(back_populates="report")
