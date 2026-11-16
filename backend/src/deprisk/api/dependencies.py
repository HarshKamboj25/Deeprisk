"""FastAPI dependencies for database access."""

from collections.abc import AsyncIterator

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    """Provide one database session for the lifetime of a request."""

    session_factory = request.app.state.session_factory

    async with session_factory() as session:
        yield session
