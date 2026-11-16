"""Tests for async database configuration."""

import asyncio

import pytest
from sqlalchemy import text

from deprisk.persistence.database import (
    create_database_engine,
    create_session_factory,
    get_database_url,
)


def test_default_database_url(monkeypatch):
    monkeypatch.delenv("DEPRISK_DATABASE_URL", raising=False)

    assert get_database_url() == "sqlite+aiosqlite:///./deprisk.db"


def test_database_url_uses_environment_variable(monkeypatch):
    expected = "sqlite+aiosqlite:///./custom.db"
    monkeypatch.setenv("DEPRISK_DATABASE_URL", expected)

    assert get_database_url() == expected


def test_unsupported_database_driver_is_rejected():
    with pytest.raises(ValueError, match="Unsupported database driver"):
        create_database_engine("mysql+aiomysql://localhost/deprisk")


def test_sqlite_foreign_keys_are_enabled(tmp_path):
    async def scenario():
        engine = create_database_engine(f"sqlite+aiosqlite:///{tmp_path / 'foreign_keys.db'}")

        try:
            async with engine.connect() as connection:
                result = await connection.execute(text("PRAGMA foreign_keys"))
                assert result.scalar_one() == 1
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_session_factory_uses_async_sessions():
    async def scenario():
        engine = create_database_engine("sqlite+aiosqlite:///./session_factory_test.db")

        try:
            factory = create_session_factory(engine)

            async with factory() as session:
                assert session.is_active
        finally:
            await engine.dispose()

    asyncio.run(scenario())
