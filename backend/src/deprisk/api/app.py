"""FastAPI application entry point for DepRisk."""

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from functools import partial

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from deprisk.api.routes import router
from deprisk.api.services import execute_scan_job, recover_scans
from deprisk.api.worker import ScanWorkerPool
from deprisk.persistence.database import (
    create_database_engine,
    create_session_factory,
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Manage database and background worker resources."""

    engine = create_database_engine()
    session_factory = create_session_factory(engine)

    app.state.engine = engine
    app.state.session_factory = session_factory

    worker_pool = ScanWorkerPool(
        partial(execute_scan_job, session_factory),
        worker_count=int(os.getenv("DEPRISK_WORKER_COUNT", "2")),
    )
    app.state.worker_pool = worker_pool

    try:
        await worker_pool.start()

        pending_scan_ids = await recover_scans(session_factory)

        for scan_id in pending_scan_ids:
            await worker_pool.submit_wait(scan_id)

        yield

    finally:
        await worker_pool.stop()
        await engine.dispose()


app = FastAPI(
    title="DepRisk API",
    description="Explainable software supply-chain vulnerability prioritization.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        origin.strip()
        for origin in os.getenv("DEPRISK_CORS_ORIGINS", "").split(",")
        if origin.strip()
    ] + [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)
app.include_router(router)


@app.get("/health", tags=["Health"])
async def health_check() -> dict[str, str]:
    """Return the API process liveness status."""

    return {"status": "ok"}


@app.get("/health/ready", tags=["Health"])
async def readiness_check() -> dict[str, str]:
    """Return readiness after verifying database connectivity."""

    try:
        async with app.state.session_factory() as session:
            await session.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database is unavailable.",
        ) from exc

    return {
        "status": "ok",
        "database": "ok",
    }
