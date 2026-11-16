import asyncio

import httpx
import pytest

from deprisk.vulnerability.enrichment_models import IntelligenceStatus
from deprisk.vulnerability.kev_client import KEVClient


def make_record(cve: str = "CVE-2021-44228") -> dict[str, object]:
    return {
        "cveID": cve,
        "vendorProject": "Apache",
        "product": "Log4j2",
        "vulnerabilityName": "Remote Code Execution Vulnerability",
        "dateAdded": "2021-12-10",
        "shortDescription": "Example vulnerability.",
        "requiredAction": "Apply available updates.",
        "dueDate": "2021-12-24",
        "knownRansomwareCampaignUse": "Known",
        "forensicTriage": "No",
        "notes": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        "cwes": ["CWE-20", "CWE-400"],
    }


def make_catalog(*records: dict[str, object]) -> dict[str, object]:
    return {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2026.11.04",
        "dateReleased": "2026-11-04T20:00:05.774Z",
        "count": len(records),
        "vulnerabilities": list(records),
    }


def test_fetches_and_parses_catalog() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert "known_exploited_vulnerabilities.json" in str(request.url)
        return httpx.Response(200, json=make_catalog(make_record()))

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            catalog = await KEVClient(client=http).get_catalog()

        assert catalog.catalog_version == "2026.11.04"
        assert catalog.count == 1
        assert catalog.vulnerabilities[0].cve_id == "CVE-2021-44228"

    asyncio.run(run())


def test_lookup_finds_cve_in_catalog() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=make_catalog(make_record()))

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            result = await KEVClient(client=http).lookup("cve-2021-44228")

        assert result.availability.status is IntelligenceStatus.AVAILABLE
        assert result.record is not None
        assert result.record.vendor_project == "Apache"
        assert result.record.known_ransomware_campaign_use == "Known"
        assert result.catalog_version == "2026.11.04"

    asyncio.run(run())


def test_lookup_returns_not_found_for_absent_cve() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=make_catalog(make_record()))

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            result = await KEVClient(client=http).lookup("CVE-2026-1234")

        assert result.record is None
        assert result.availability.status is IntelligenceStatus.NOT_FOUND
        assert result.catalog_version == "2026.11.04"

    asyncio.run(run())


def test_empty_cve_is_rejected() -> None:
    async def run() -> None:
        async with httpx.AsyncClient() as http:
            with pytest.raises(ValueError, match="cannot be empty"):
                await KEVClient(client=http).lookup("   ")

    asyncio.run(run())


def test_catalog_is_downloaded_only_once_when_cached() -> None:
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(200, json=make_catalog(make_record()))

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            client = KEVClient(client=http)
            await client.lookup("CVE-2021-44228")
            await client.lookup("CVE-2021-44228")
            await client.lookup("CVE-2026-1234")

    asyncio.run(run())
    assert requests == 1


def test_catalog_count_mismatch_is_rejected() -> None:
    payload = make_catalog(make_record())
    payload["count"] = 2

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            client = KEVClient(client=http)
            with pytest.raises(ValueError, match="count does not match"):
                await client.get_catalog()

    asyncio.run(run())


def test_http_failure_returns_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            result = await KEVClient(
                client=http,
                max_retries=0,
            ).lookup("CVE-2021-44228")

        assert result.record is None
        assert result.availability.status is IntelligenceStatus.UNAVAILABLE

    asyncio.run(run())


def test_malformed_catalog_returns_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"unexpected": "payload"})

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            result = await KEVClient(client=http).lookup("CVE-2021-44228")

        assert result.record is None
        assert result.availability.status is IntelligenceStatus.UNAVAILABLE

    asyncio.run(run())


def test_retries_transient_server_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0

    async def no_sleep(delay: float) -> None:
        return None

    monkeypatch.setattr(
        "deprisk.vulnerability.kev_client.asyncio.sleep",
        no_sleep,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1

        if attempts == 1:
            return httpx.Response(503)

        return httpx.Response(200, json=make_catalog(make_record()))

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            result = await KEVClient(
                client=http,
                max_retries=1,
            ).lookup("CVE-2021-44228")

        assert result.availability.status is IntelligenceStatus.AVAILABLE

    asyncio.run(run())
    assert attempts == 2


def test_force_refresh_downloads_new_catalog() -> None:
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1

        version = "2026.11.04" if requests == 1 else "2026.11.05"
        payload = make_catalog(make_record())
        payload["catalogVersion"] = version

        return httpx.Response(200, json=payload)

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            client = KEVClient(client=http)
            first = await client.get_catalog()
            second = await client.get_catalog(force_refresh=True)

        assert first.catalog_version == "2026.11.04"
        assert second.catalog_version == "2026.11.05"

    asyncio.run(run())
    assert requests == 2


def test_expired_catalog_cache_is_refetched() -> None:
    current_time = 100.0
    requests = 0

    def clock() -> float:
        return current_time

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(200, json=make_catalog(make_record()))

    async def run() -> None:
        nonlocal current_time

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            client = KEVClient(
                client=http,
                cache_ttl_seconds=5,
                clock=clock,
            )

            await client.get_catalog()
            current_time += 6
            await client.get_catalog()

    asyncio.run(run())
    assert requests == 2


def test_kev_client_parses_actual_captured_catalog() -> None:
    import json
    from pathlib import Path

    root = Path(__file__).resolve().parents[3]
    sample_path = root / "eval" / "spikes" / "e1" / "cisa_kev_catalog.json"
    sample = json.loads(sample_path.read_text(encoding="utf-8"))
    payload = sample["response"]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    async def scenario() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
            client = KEVClient(client=http_client)
            catalog = await client.get_catalog()

        assert catalog.catalog_version == "2026.11.04"
        assert catalog.count == 1768
        assert len(catalog.vulnerabilities) == 1768
        assert catalog.vulnerabilities[0].cve_id == "CVE-2024-27834"
        assert catalog.vulnerabilities[0].vendor_project == "Apple"

    asyncio.run(scenario())
