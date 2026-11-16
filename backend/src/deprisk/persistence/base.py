"""Shared SQLAlchemy base and portable database types."""

from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base class for all DepRisk persistence models."""


REPORT_JSON_TYPE = JSON().with_variant(JSONB(), "postgresql")
"""Portable JSON type using native JSONB on PostgreSQL."""
