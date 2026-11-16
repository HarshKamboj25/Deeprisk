"""Tests for the NVD vulnerability intelligence client."""

import asyncio
import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from deprisk.vulnerability.enrichment_models import IntelligenceStatus
from deprisk.vulnerability.nvd_client import NVDClient


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def make_metric(
    version: str,
    source: str = "nvd@nist.gov",
    metric_type: str = "Primary",
    score: float = 8.0,
) -> dict[str, Any]:
    return {
        "source": source,
        "type": metric_type,
        "cvssData": {
            "version": version,
            "vectorString": f"CVSS:{version}/AV:N/AC:L",
            "baseScore": score,
            "baseSeverity": "HIGH",
        },
        "exploitabilityScore": 3.0,
        "impactScore": 4.0,
    }


def make_payload(
    cve: str = "CVE-2021-44228",
    metrics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve,
                    "metrics": metrics or {},
                }
            }
        ],
    }


def make_client(
    payload: dict[str, Any],
    **kwargs: Any,
) -> NVDClient:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return NVDClient(client=http_client, **kwargs)


def test_nvd_client_parses_actual_captured_log4shell_response() -> None:
    root = Path(__file__).resolve().parents[3]
    sample_path = root / "eval" / "spikes" / "e1" / "nvd_log4shell.json"
    sample = json.loads(sample_path.read_text(encoding="utf-8"))
    payload = sample["response"]

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    async def scenario() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
            client = NVDClient(client=http_client)
            result = await client.get_cvss("CVE-2021-44228")

        assert result.availability.status == IntelligenceStatus.AVAILABLE
        assert result.record is not None
        assert result.record.cve_id == "CVE-2021-44228"
        assert result.record.cvss_version == "3.1"
        assert result.record.source == "nvd@nist.gov"
        assert result.record.metric_type == "Primary"
        assert result.record.base_score == 10.0
        assert result.record.base_severity == "CRITICAL"
        assert result.record.exploitability_score == 3.9
        assert result.record.impact_score == 6.0

    run(scenario())


def test_nvd_client_prefers_cvss_4_over_older_versions() -> None:
    payload = make_payload(
        metrics={
            "cvssMetricV40": [make_metric("4.0", score=9.5)],
            "cvssMetricV31": [make_metric("3.1", score=10.0)],
            "cvssMetricV2": [make_metric("2.0", score=9.3)],
        }
    )

    async def scenario() -> None:
        client = make_client(payload)
        result = await client.get_cvss("CVE-2021-44228")
        assert result.record is not None
        assert result.record.cvss_version == "4.0"
        assert result.record.base_score == 9.5

    run(scenario())


@pytest.mark.parametrize(
    ("version", "metric_key"),
    [
        ("3.1", "cvssMetricV31"),
        ("3.0", "cvssMetricV30"),
        ("2.0", "cvssMetricV2"),
    ],
)
def test_nvd_client_selects_available_cvss_version(
    version: str,
    metric_key: str,
) -> None:
    payload = make_payload(metrics={metric_key: [make_metric(version)]})

    async def scenario() -> None:
        client = make_client(payload)
        result = await client.get_cvss("CVE-2021-44228")
        assert result.record is not None
        assert result.record.cvss_version == version

    run(scenario())


def test_nvd_client_prefers_primary_metric() -> None:
    payload = make_payload(
        metrics={
            "cvssMetricV31": [
                make_metric(
                    "3.1",
                    source="secondary.example",
                    metric_type="Secondary",
                    score=7.0,
                ),
                make_metric(
                    "3.1",
                    source="nvd@nist.gov",
                    metric_type="Primary",
                    score=10.0,
                ),
            ]
        }
    )

    async def scenario() -> None:
        client = make_client(payload)
        result = await client.get_cvss("CVE-2021-44228")
        assert result.record is not None
        assert result.record.source == "nvd@nist.gov"
        assert result.record.metric_type == "Primary"
        assert result.record.base_score == 10.0

    run(scenario())


def test_nvd_client_selects_source_deterministically() -> None:
    payload = make_payload(
        metrics={
            "cvssMetricV31": [
                make_metric("3.1", source="z-source", score=7.0),
                make_metric("3.1", source="a-source", score=8.0),
            ]
        }
    )

    async def scenario() -> None:
        client = make_client(payload)
        result = await client.get_cvss("CVE-2021-44228")
        assert result.record is not None
        assert result.record.source == "a-source"

    run(scenario())


def test_nvd_client_returns_not_found_when_cve_is_absent() -> None:
    payload = {"vulnerabilities": []}

    async def scenario() -> None:
        client = make_client(payload)
        result = await client.get_cvss("CVE-2021-44228")
        assert result.availability.status == IntelligenceStatus.NOT_FOUND
        assert result.record is None

    run(scenario())


def test_nvd_client_returns_not_found_when_cvss_is_absent() -> None:
    payload = make_payload(metrics={"ssvcV203": []})

    async def scenario() -> None:
        client = make_client(payload)
        result = await client.get_cvss("CVE-2021-44228")
        assert result.availability.status == IntelligenceStatus.NOT_FOUND
        assert result.record is None

    run(scenario())


def test_nvd_client_rejects_invalid_cve_before_request() -> None:
    async def scenario() -> None:
        client = NVDClient()
        with pytest.raises(ValueError, match="valid CVE"):
            await client.get_cvss("not-a-cve")

    run(scenario())


def test_nvd_client_returns_unavailable_for_malformed_payload() -> None:
    payload: dict[str, Any] = {"unexpected": []}

    async def scenario() -> None:
        client = make_client(payload)
        result = await client.get_cvss("CVE-2021-44228")
        assert result.availability.status == IntelligenceStatus.UNAVAILABLE
        assert result.record is None

    run(scenario())


def test_nvd_client_returns_unavailable_for_http_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    async def scenario() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
            client = NVDClient(client=http_client, max_retries=0)
            result = await client.get_cvss("CVE-2021-44228")

        assert result.availability.status == IntelligenceStatus.UNAVAILABLE
        assert result.record is None

    run(scenario())


def test_nvd_client_caches_successful_results() -> None:
    request_count = 0
    payload = make_payload(metrics={"cvssMetricV31": [make_metric("3.1")]})

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1
        return httpx.Response(200, json=payload)

    async def scenario() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
            client = NVDClient(client=http_client)
            first = await client.get_cvss("CVE-2021-44228")
            second = await client.get_cvss("CVE-2021-44228")

        assert first == second
        assert request_count == 1

    run(scenario())


def test_nvd_client_does_not_cache_unavailable_results() -> None:
    request_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1
        return httpx.Response(503)

    async def scenario() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
            client = NVDClient(client=http_client, max_retries=0)
            await client.get_cvss("CVE-2021-44228")
            await client.get_cvss("CVE-2021-44228")

        assert request_count == 2

    run(scenario())


def test_nvd_client_sends_api_key_when_configured() -> None:
    received_headers: list[str | None] = []
    payload = make_payload(metrics={"cvssMetricV31": [make_metric("3.1")]})

    def handler(request: httpx.Request) -> httpx.Response:
        received_headers.append(request.headers.get("apiKey"))
        return httpx.Response(200, json=payload)

    async def scenario() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
            client = NVDClient(client=http_client, api_key="test-api-key")
            await client.get_cvss("CVE-2021-44228")

        assert received_headers == ["test-api-key"]

    run(scenario())
