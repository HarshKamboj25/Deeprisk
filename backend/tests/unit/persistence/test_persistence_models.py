"""Tests for DepRisk persistence model metadata."""

import asyncio

from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import create_async_engine

from deprisk.persistence.base import Base
from deprisk.persistence.models import Repository, Scan, ScanReport


def test_persistence_tables_create_in_sqlite(tmp_path):
    database_path = tmp_path / "test_deprisk.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{database_path}")

    async def create_and_inspect():
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

            def inspect_schema(sync_connection):
                inspector = inspect(sync_connection)
                return {
                    "tables": set(inspector.get_table_names()),
                    "columns": {
                        table: {column["name"] for column in inspector.get_columns(table)}
                        for table in (
                            "repositories",
                            "scans",
                            "scan_reports",
                        )
                    },
                }

            return await connection.run_sync(inspect_schema)

    try:
        schema = asyncio.run(create_and_inspect())
    finally:
        asyncio.run(engine.dispose())

    assert schema["tables"] == {
        "repositories",
        "scans",
        "scan_reports",
    }
    assert "canonical_source" in schema["columns"]["repositories"]
    assert "status" in schema["columns"]["scans"]
    assert "report_data" in schema["columns"]["scan_reports"]


def test_models_share_the_expected_metadata():
    assert Repository.metadata is Base.metadata
    assert Scan.metadata is Base.metadata
    assert ScanReport.metadata is Base.metadata
