"""HTTP integration tests for the DepRisk API."""

import asyncio
from pathlib import Path
from runpy import run_path
from types import SimpleNamespace
from uuid import UUID

import httpx
from sqlalchemy import select

from deprisk.api.app import app
from deprisk.persistence.base import Base
from deprisk.persistence.database import create_database_engine
from deprisk.persistence.models import Repository, Scan, ScanReport

report_helpers = run_path(Path(__file__).resolve().parents[1] / "test_report.py")
make_scan_result = report_helpers["make_scan_result"]


async def wait_for_terminal_status(client, scan_id):
    """Poll until a background scan reaches a terminal state."""

    for _ in range(500):
        response = await client.get(f"/api/v1/scans/{scan_id}")
        assert response.status_code == 200

        scan_status = response.json()["status"]
        if scan_status in {"succeeded", "failed"}:
            return response

        await asyncio.sleep(0.01)

    raise AssertionError(f"Scan {scan_id} did not finish within 5 seconds.")


async def api_transport(tmp_path, monkeypatch):
    """Create an HTTP transport backed by an isolated SQLite database."""

    database_url = f"sqlite+aiosqlite:///{tmp_path / 'api_http_test.db'}"
    engine = create_database_engine(database_url)

    monkeypatch.setattr(
        "deprisk.api.app.create_database_engine",
        lambda: engine,
    )

    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    return httpx.ASGITransport(app=app)


def test_health_endpoint_works_with_lifespan(tmp_path, monkeypatch):
    async def scenario():
        transport = await api_transport(tmp_path, monkeypatch)

        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(
                transport=transport,
                base_url="http://test",
            ) as client,
        ):
            response = await client.get("/health")

            assert response.status_code == 200
            assert response.json() == {"status": "ok"}
            assert hasattr(app.state, "engine")
            assert hasattr(app.state, "session_factory")

    asyncio.run(scenario())


def test_invalid_scan_request_returns_422(tmp_path, monkeypatch):
    async def scenario():
        transport = await api_transport(tmp_path, monkeypatch)

        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(
                transport=transport,
                base_url="http://test",
            ) as client,
        ):
            response = await client.post(
                "/api/v1/scans",
                json={
                    "source_type": "local",
                    "repository_url": "https://github.com/example/demo",
                },
            )

            assert response.status_code == 422

    asyncio.run(scenario())


def test_missing_scan_returns_404(tmp_path, monkeypatch):
    async def scenario():
        transport = await api_transport(tmp_path, monkeypatch)

        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(
                transport=transport,
                base_url="http://test",
            ) as client,
        ):
            response = await client.get("/api/v1/scans/00000000-0000-0000-0000-000000000001")

            assert response.status_code == 404
            assert response.json()["detail"] == "Scan not found."

    asyncio.run(scenario())


def test_http_local_scan_persists_and_returns_report(
    tmp_path,
    monkeypatch,
):
    async def scenario():
        workspace = tmp_path / "workspace"
        repository_path = workspace / "sample-project"
        workspace.mkdir()
        repository_path.mkdir()

        monkeypatch.setenv("DEPRISK_WORKSPACE_ROOT", str(workspace))

        fixture_root = tmp_path / "report-fixture"
        fixture_root.mkdir()
        scan_result = make_scan_result(fixture_root)

        async def fake_scan(received_path, osv_service, enrichment_service):
            assert received_path == repository_path.resolve()
            assert osv_service is not None
            assert enrichment_service is not None
            return scan_result

        monkeypatch.setattr(
            "deprisk.api.services.scan_local_repository",
            fake_scan,
        )
        monkeypatch.setattr(
            "deprisk.api.services.build_scanner_services",
            lambda client: SimpleNamespace(
                osv_service=object(),
                enrichment_service=object(),
            ),
        )

        transport = await api_transport(tmp_path, monkeypatch)

        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(
                transport=transport,
                base_url="http://test",
            ) as client,
        ):
            create_response = await client.post(
                "/api/v1/scans",
                json={
                    "source_type": "local",
                    "repository_path": "sample-project",
                },
            )

            assert create_response.status_code == 202

            created = create_response.json()
            scan_id = created["scan_id"]
            repository_id = created["repository_id"]

            assert created["status"] == "pending"

            await wait_for_terminal_status(client, scan_id)
            status_response = await client.get(f"/api/v1/scans/{scan_id}")

            assert status_response.status_code == 200

            status = status_response.json()
            assert status["id"] == scan_id
            assert status["repository_id"] == repository_id
            assert status["status"] == "succeeded"
            assert status["started_at"] is not None
            assert status["finished_at"] is not None

            report_response = await client.get(f"/api/v1/scans/{scan_id}/report")

            assert report_response.status_code == 200

            report_payload = report_response.json()
            assert report_payload["scan_id"] == scan_id
            assert report_payload["schema_version"]
            assert report_payload["report"]["dependencies"]

            repositories_response = await client.get("/api/v1/repositories")

            assert repositories_response.status_code == 200

            repositories = repositories_response.json()
            assert len(repositories) == 1
            assert repositories[0]["id"] == repository_id
            assert repositories[0]["name"] == "sample-project"

            async with app.state.session_factory() as session:
                persisted_scan = await session.get(
                    Scan,
                    UUID(scan_id),
                )
                persisted_report = await session.scalar(
                    select(ScanReport).where(ScanReport.scan_id == UUID(scan_id))
                )
                persisted_repository = await session.get(
                    Repository,
                    UUID(repository_id),
                )

                assert persisted_scan is not None
                assert persisted_report is not None
                assert persisted_repository is not None
                assert persisted_report.report_data["dependencies"]

    asyncio.run(scenario())


def test_http_failed_scan_is_persisted_without_exposing_internal_error(
    tmp_path,
    monkeypatch,
):
    async def scenario():
        workspace = tmp_path / "workspace"
        repository_path = workspace / "sample-project"
        workspace.mkdir()
        repository_path.mkdir()

        monkeypatch.setenv("DEPRISK_WORKSPACE_ROOT", str(workspace))

        async def failing_scan(received_path, osv_service, enrichment_service):
            raise RuntimeError("SECRET_TOKEN=internal-sensitive-detail")

        monkeypatch.setattr(
            "deprisk.api.services.scan_local_repository",
            failing_scan,
        )
        monkeypatch.setattr(
            "deprisk.api.services.build_scanner_services",
            lambda client: SimpleNamespace(
                osv_service=object(),
                enrichment_service=object(),
            ),
        )

        transport = await api_transport(tmp_path, monkeypatch)

        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(
                transport=transport,
                base_url="http://test",
            ) as client,
        ):
            create_response = await client.post(
                "/api/v1/scans",
                json={
                    "source_type": "local",
                    "repository_path": "sample-project",
                },
            )

            assert create_response.status_code == 202

            created = create_response.json()
            scan_id = created["scan_id"]

            assert created["status"] == "pending"

            await wait_for_terminal_status(client, scan_id)
            status_response = await client.get(f"/api/v1/scans/{scan_id}")

            assert status_response.status_code == 200

            status = status_response.json()
            assert status["status"] == "failed"
            assert status["started_at"] is not None
            assert status["finished_at"] is not None
            assert status["error_message"] == "Scan failed (RuntimeError)."
            assert "SECRET_TOKEN" not in status["error_message"]
            assert "internal-sensitive-detail" not in status["error_message"]

            report_response = await client.get(f"/api/v1/scans/{scan_id}/report")

            assert report_response.status_code == 404
            assert report_response.json()["detail"] == "No report is available for this scan."

            async with app.state.session_factory() as session:
                persisted_scan = await session.get(
                    Scan,
                    UUID(scan_id),
                )
                persisted_report = await session.scalar(
                    select(ScanReport).where(ScanReport.scan_id == UUID(scan_id))
                )

                assert persisted_scan is not None
                assert persisted_scan.status == "failed"
                assert persisted_scan.error_message == "Scan failed (RuntimeError)."
                assert persisted_report is None

    asyncio.run(scenario())


def test_local_scan_without_workspace_configuration_returns_400(
    tmp_path,
    monkeypatch,
):
    async def scenario():
        monkeypatch.delenv("DEPRISK_WORKSPACE_ROOT", raising=False)

        transport = await api_transport(tmp_path, monkeypatch)

        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(
                transport=transport,
                base_url="http://test",
            ) as client,
        ):
            response = await client.post(
                "/api/v1/scans",
                json={
                    "source_type": "local",
                    "repository_path": "sample-project",
                },
            )

            assert response.status_code == 400
            assert response.json()["detail"] == (
                "Local scanning is disabled. Configure DEPRISK_WORKSPACE_ROOT."
            )

    asyncio.run(scenario())


def test_invalid_github_repository_url_returns_422(
    tmp_path,
    monkeypatch,
):
    async def scenario():
        transport = await api_transport(tmp_path, monkeypatch)

        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(
                transport=transport,
                base_url="http://test",
            ) as client,
        ):
            response = await client.post(
                "/api/v1/scans",
                json={
                    "source_type": "github",
                    "repository_url": "https://example.com/not-a-github-repository",
                },
            )

            assert response.status_code == 422
            assert response.json()["detail"]

            async with app.state.session_factory() as session:
                repositories = (await session.scalars(select(Repository))).all()
                scans = (await session.scalars(select(Scan))).all()

                assert repositories == []
                assert scans == []

    asyncio.run(scenario())


def test_readiness_endpoint_confirms_database_connectivity(
    tmp_path,
    monkeypatch,
):
    async def scenario():
        transport = await api_transport(tmp_path, monkeypatch)

        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(
                transport=transport,
                base_url="http://test",
            ) as client,
        ):
            response = await client.get("/health/ready")

            assert response.status_code == 200
            assert response.json() == {
                "status": "ok",
                "database": "ok",
            }

    asyncio.run(scenario())


def test_readiness_endpoint_returns_503_without_exposing_database_error(
    tmp_path,
    monkeypatch,
):
    from sqlalchemy.exc import SQLAlchemyError

    class FailingSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc_value, traceback):
            return False

        async def execute(self, statement):
            raise SQLAlchemyError("SECRET_DATABASE_PASSWORD=internal-sensitive-detail")

    async def scenario():
        transport = await api_transport(tmp_path, monkeypatch)

        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(
                transport=transport,
                base_url="http://test",
            ) as client,
        ):
            monkeypatch.setattr(
                app.state,
                "session_factory",
                lambda: FailingSession(),
            )

            response = await client.get("/health/ready")

            assert response.status_code == 503
            assert response.json() == {"detail": "Database is unavailable."}
            assert "SECRET_DATABASE_PASSWORD" not in response.text
            assert "internal-sensitive-detail" not in response.text

    asyncio.run(scenario())


def test_http_queue_rejection_marks_scan_failed(
    tmp_path,
    monkeypatch,
):
    from deprisk.api.worker import WorkerPoolError

    async def scenario():
        workspace = tmp_path / "workspace"
        repository_path = workspace / "sample-project"
        workspace.mkdir()
        repository_path.mkdir()

        monkeypatch.setenv("DEPRISK_WORKSPACE_ROOT", str(workspace))

        transport = await api_transport(tmp_path, monkeypatch)

        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(
                transport=transport,
                base_url="http://test",
            ) as client,
        ):

            def reject_submission(scan_id):
                raise WorkerPoolError("Internal queue capacity detail.")

            monkeypatch.setattr(
                app.state.worker_pool,
                "submit",
                reject_submission,
            )

            response = await client.post(
                "/api/v1/scans",
                json={
                    "source_type": "local",
                    "repository_path": "sample-project",
                },
            )

            assert response.status_code == 503
            assert response.json() == {
                "detail": "Scan queue is unavailable or full. Please retry later."
            }

            async with app.state.session_factory() as session:
                scans = (await session.scalars(select(Scan))).all()

                assert len(scans) == 1
                assert scans[0].status == "failed"
                assert scans[0].finished_at is not None
                assert scans[0].error_message == ("Scan was not accepted by the worker pool.")

    asyncio.run(scenario())


def test_application_startup_recovers_pending_scans_and_fails_interrupted_scans(
    tmp_path,
    monkeypatch,
):
    from deprisk.persistence.database import create_session_factory
    from deprisk.persistence.models import RepositorySourceType, ScanStatus
    from deprisk.persistence.store import ScanPersistence

    async def scenario():
        engine = create_database_engine(f"sqlite+aiosqlite:///{tmp_path / 'startup_recovery.db'}")

        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

        session_factory = create_session_factory(engine)

        try:
            async with session_factory() as session, session.begin():
                repository = await ScanPersistence.get_or_create_repository(
                    session,
                    name="recovery-project",
                    source_type=RepositorySourceType.LOCAL,
                    canonical_source=str(tmp_path),
                )

                pending_scan = await ScanPersistence.create_scan(
                    session,
                    repository_id=repository.id,
                )
                interrupted_scan = await ScanPersistence.create_scan(
                    session,
                    repository_id=repository.id,
                )

                await ScanPersistence.mark_running(
                    session,
                    scan_id=interrupted_scan.id,
                )

                pending_id = pending_scan.id
                interrupted_id = interrupted_scan.id

            processed_ids = []
            processed_event = asyncio.Event()

            async def fake_execute_scan_job(received_factory, scan_id):
                processed_ids.append(scan_id)
                processed_event.set()

            monkeypatch.setattr(
                "deprisk.api.app.create_database_engine",
                lambda: engine,
            )
            monkeypatch.setattr(
                "deprisk.api.app.execute_scan_job",
                fake_execute_scan_job,
            )

            async with app.router.lifespan_context(app):
                await asyncio.wait_for(
                    processed_event.wait(),
                    timeout=2,
                )

                assert processed_ids == [pending_id]

                async with app.state.session_factory() as session:
                    recovered_pending = await ScanPersistence.get_scan(
                        session,
                        scan_id=pending_id,
                    )
                    recovered_interrupted = await ScanPersistence.get_scan(
                        session,
                        scan_id=interrupted_id,
                    )

                    assert recovered_pending.status == ScanStatus.PENDING.value
                    assert recovered_interrupted.status == ScanStatus.FAILED.value
                    assert recovered_interrupted.finished_at is not None
                    assert recovered_interrupted.error_message == (
                        "Scan interrupted by previous application process."
                    )

        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_configuration_endpoint_returns_workspace_details(tmp_path, monkeypatch):
    async def scenario():
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        monkeypatch.setenv("DEPRISK_WORKSPACE_ROOT", str(workspace))

        transport = await api_transport(tmp_path, monkeypatch)

        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(
                transport=transport,
                base_url="http://test",
            ) as client,
        ):
            response = await client.get("/api/v1/configuration")

            assert response.status_code == 200
            assert response.json() == {
                "local_scanning_enabled": True,
                "workspace_root": str(workspace.resolve()),
            }

    asyncio.run(scenario())


def test_configuration_endpoint_reports_disabled_local_scanning(
    tmp_path,
    monkeypatch,
):
    async def scenario():
        monkeypatch.delenv("DEPRISK_WORKSPACE_ROOT", raising=False)

        transport = await api_transport(tmp_path, monkeypatch)

        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(
                transport=transport,
                base_url="http://test",
            ) as client,
        ):
            response = await client.get("/api/v1/configuration")

            assert response.status_code == 200
            assert response.json() == {
                "local_scanning_enabled": False,
                "workspace_root": None,
            }

    asyncio.run(scenario())

def test_scan_history_supports_filters_and_pagination(tmp_path, monkeypatch):
    async def scenario():
        transport = await api_transport(tmp_path, monkeypatch)

        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(
                transport=transport,
                base_url="http://test",
            ) as client,
        ):
            async with app.state.session_factory() as session, session.begin():
                alpha = Repository(
                    name="alpha-project",
                    source_type="local",
                    canonical_source=str(tmp_path / "alpha-project"),
                )
                beta = Repository(
                    name="beta-project",
                    source_type="github",
                    canonical_source="https://github.com/example/beta-project",
                )
                session.add_all([alpha, beta])
                await session.flush()

                session.add_all([
                    Scan(repository_id=alpha.id, status="succeeded"),
                    Scan(repository_id=alpha.id, status="failed"),
                    Scan(repository_id=beta.id, status="pending"),
                ])

                alpha_id = alpha.id
                beta_id = beta.id

            response = await client.get("/api/v1/scans")

            assert response.status_code == 200
            payload = response.json()
            assert payload["total"] == 3
            assert payload["limit"] == 20
            assert payload["offset"] == 0
            assert len(payload["items"]) == 3

            for item in payload["items"]:
                assert item["id"]
                assert item["repository_id"]
                assert item["repository_name"] in {
                    "alpha-project",
                    "beta-project",
                }
                assert item["source_type"] in {"local", "github"}
                assert item["status"] in {
                    "pending",
                    "running",
                    "succeeded",
                    "failed",
                }
                assert item["created_at"]

            failed_response = await client.get(
                "/api/v1/scans",
                params={"status": "failed"},
            )

            assert failed_response.status_code == 200
            failed_payload = failed_response.json()
            assert failed_payload["total"] == 1
            assert failed_payload["items"][0]["status"] == "failed"

            search_response = await client.get(
                "/api/v1/scans",
                params={"search": "beta"},
            )

            assert search_response.status_code == 200
            search_payload = search_response.json()
            assert search_payload["total"] == 1
            assert search_payload["items"][0]["repository_name"] == "beta-project"

            repository_response = await client.get(
                "/api/v1/scans",
                params={"repository_id": str(alpha_id)},
            )

            assert repository_response.status_code == 200
            repository_payload = repository_response.json()
            assert repository_payload["total"] == 2
            assert all(
                item["repository_id"] == str(alpha_id)
                for item in repository_payload["items"]
            )

            pagination_response = await client.get(
                "/api/v1/scans",
                params={"limit": 1, "offset": 1},
            )

            assert pagination_response.status_code == 200
            pagination_payload = pagination_response.json()
            assert pagination_payload["total"] == 3
            assert pagination_payload["limit"] == 1
            assert pagination_payload["offset"] == 1
            assert len(pagination_payload["items"]) == 1

            invalid_status_response = await client.get(
                "/api/v1/scans",
                params={"status": "unknown"},
            )

            assert invalid_status_response.status_code == 422

            invalid_limit_response = await client.get(
                "/api/v1/scans",
                params={"limit": 101},
            )

            assert invalid_limit_response.status_code == 422

            assert beta_id is not None

    asyncio.run(scenario())


def test_scan_history_returns_empty_collection(tmp_path, monkeypatch):
    async def scenario():
        transport = await api_transport(tmp_path, monkeypatch)

        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(
                transport=transport,
                base_url="http://test",
            ) as client,
        ):
            response = await client.get("/api/v1/scans")

            assert response.status_code == 200
            assert response.json() == {
                "items": [],
                "total": 0,
                "limit": 20,
                "offset": 0,
            }

    asyncio.run(scenario())