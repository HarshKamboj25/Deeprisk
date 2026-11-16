"""Async database engine and session configuration."""

import os
from typing import Any

from sqlalchemy import event
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

DEFAULT_DATABASE_URL = "sqlite+aiosqlite:///./deprisk.db"

SUPPORTED_DRIVERS = {
    "sqlite+aiosqlite",
    "postgresql+asyncpg",
}


def get_database_url() -> str:
    """Return the configured database URL."""

    return os.environ.get(
        "DEPRISK_DATABASE_URL",
        DEFAULT_DATABASE_URL,
    )


def create_database_engine(
    database_url: str | None = None,
    *,
    echo: bool = False,
) -> AsyncEngine:
    """Create an async engine for a supported database driver."""

    url = database_url or get_database_url()
    parsed_url = make_url(url)

    if parsed_url.drivername not in SUPPORTED_DRIVERS:
        raise ValueError("Unsupported database driver. Use sqlite+aiosqlite or postgresql+asyncpg.")

    engine = create_async_engine(
        url,
        echo=echo,
        pool_pre_ping=parsed_url.get_backend_name() == "postgresql",
    )

    if parsed_url.get_backend_name() == "sqlite":

        @event.listens_for(engine.sync_engine, "connect")
        def enable_sqlite_foreign_keys(
            dbapi_connection: Any,
            connection_record: Any,
        ) -> None:
            """Enable foreign-key enforcement for SQLite connections."""

            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine


def create_session_factory(
    engine: AsyncEngine,
) -> async_sessionmaker[AsyncSession]:
    """Create sessions that retain loaded objects after commits."""

    return async_sessionmaker(
        engine,
        expire_on_commit=False,
    )
