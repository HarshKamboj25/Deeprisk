import asyncio

import httpx
import pytest

from deprisk.vulnerability.enrichment_models import (
    IntelligenceStatus,
)
from deprisk.vulnerability.epss_client import EPSSClient


def test_fetches_and_normalizes_epss_record() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["cve"] == "CVE-2021-44228"
        return httpx.Response(
            200,
            json={
                "data": [
                    {
                        "cve": "CVE-2021-44228",
                        "epss": "0.999990000",
                        "percentile": "1.000000000",
                        "date": "2026-11-05",
                    }
                ]
            },
        )

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            result = await EPSSClient(client=http).get_score("cve-2021-44228")

        assert result.availability.status is IntelligenceStatus.AVAILABLE
        assert result.record is not None
        assert result.record.cve == "CVE-2021-44228"
        assert result.record.epss == pytest.approx(0.99999)
        assert result.record.percentile == 1.0
        assert result.record.score_date == "2026-11-05"

    asyncio.run(run())


def test_missing_cve_returns_not_found() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": []})

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            result = await EPSSClient(client=http).get_score("CVE-2026-1234")

        assert result.record is None
        assert result.availability.status is IntelligenceStatus.NOT_FOUND

    asyncio.run(run())


def test_http_failure_returns_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": "Bad request"})

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            result = await EPSSClient(
                client=http,
                max_retries=0,
            ).get_score("CVE-2026-1234")

        assert result.record is None
        assert result.availability.status is IntelligenceStatus.UNAVAILABLE

    asyncio.run(run())


def test_malformed_response_returns_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"unexpected": []})

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            result = await EPSSClient(client=http).get_score("CVE-2026-1234")

        assert result.record is None
        assert result.availability.status is IntelligenceStatus.UNAVAILABLE

    asyncio.run(run())


def test_invalid_epss_score_returns_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": [
                    {
                        "cve": "CVE-2026-1234",
                        "epss": "1.5",
                        "percentile": "0.5",
                        "date": "2026-11-05",
                    }
                ]
            },
        )

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            result = await EPSSClient(client=http).get_score("CVE-2026-1234")

        assert result.record is None
        assert result.availability.status is IntelligenceStatus.UNAVAILABLE

    asyncio.run(run())


def test_invalid_cve_is_rejected_before_request() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        pytest.fail("Invalid CVE must not trigger an HTTP request")

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            with pytest.raises(ValueError, match="valid CVE"):
                await EPSSClient(client=http).get_score("../invalid")

    asyncio.run(run())


def test_retries_transient_server_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0

    async def no_sleep(delay: float) -> None:
        return None

    monkeypatch.setattr(
        "deprisk.vulnerability.epss_client.asyncio.sleep",
        no_sleep,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1

        if attempts == 1:
            return httpx.Response(503)

        return httpx.Response(
            200,
            json={
                "data": [
                    {
                        "cve": "CVE-2026-1234",
                        "epss": "0.5",
                        "percentile": "0.8",
                        "date": "2026-11-05",
                    }
                ]
            },
        )

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            result = await EPSSClient(
                client=http,
                max_retries=1,
            ).get_score("CVE-2026-1234")

        assert result.availability.status is IntelligenceStatus.AVAILABLE

    asyncio.run(run())
    assert attempts == 2


def test_repeated_lookup_uses_cache() -> None:
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1

        return httpx.Response(200, json={"data": []})

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            client = EPSSClient(client=http)
            first = await client.get_score("CVE-2026-1234")
            second = await client.get_score("CVE-2026-1234")

        assert first == second

    asyncio.run(run())
    assert requests == 1


def test_unavailable_result_is_not_cached() -> None:
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1

        if requests == 1:
            return httpx.Response(503)

        return httpx.Response(200, json={"data": []})

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            client = EPSSClient(client=http, max_retries=0)
            first = await client.get_score("CVE-2026-1234")
            second = await client.get_score("CVE-2026-1234")

        assert first.availability.status is IntelligenceStatus.UNAVAILABLE
        assert second.availability.status is IntelligenceStatus.NOT_FOUND

    asyncio.run(run())
    assert requests == 2


def test_expired_cache_entry_is_refetched() -> None:
    current_time = 100.0
    requests = 0

    def clock() -> float:
        return current_time

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(200, json={"data": []})

    async def run() -> None:
        nonlocal current_time

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            client = EPSSClient(
                client=http,
                cache_ttl_seconds=5,
                clock=clock,
            )

            await client.get_score("CVE-2026-1234")
            current_time += 6
            await client.get_score("CVE-2026-1234")

    asyncio.run(run())
    assert requests == 2


def test_epss_client_parses_actual_captured_log4shell_response() -> None:
    import json
    from pathlib import Path

    root = Path(__file__).resolve().parents[3]
    sample_path = root / "eval" / "spikes" / "e1" / "epss_log4shell.json"
    sample = json.loads(sample_path.read_text(encoding="utf-8"))
    payload = sample["response"]

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["cve"] == "CVE-2021-44228"
        return httpx.Response(200, json=payload)

    async def scenario() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
            client = EPSSClient(client=http_client)
            result = await client.get_score("CVE-2021-44228")

        assert result.availability.status is IntelligenceStatus.AVAILABLE
        assert result.record is not None
        assert result.record.cve == "CVE-2021-44228"
        assert result.record.epss == pytest.approx(0.99999)
        assert result.record.percentile == 1.0
        assert result.record.score_date == "2026-11-05"

    asyncio.run(scenario())
