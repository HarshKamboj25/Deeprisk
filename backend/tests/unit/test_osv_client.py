import asyncio

import httpx
import pytest
from pydantic import ValidationError

from deprisk.vulnerability.osv_client import OSVClient
from deprisk.vulnerability.registry_candidates import RegistryQueryCandidate


def make_candidate(name: str = "lodash", version: str = "4.17.20"):
    return RegistryQueryCandidate(
        package_name=name,
        package_version=version,
        install_paths=(f"node_modules/{name}",),
    )


def test_batch_query_sends_candidates_and_parses_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/querybatch"
        assert request.method == "POST"
        payload = request.read()
        assert b"lodash" in payload
        assert b"4.17.20" in payload
        return httpx.Response(
            200,
            json={"results": [{"vulns": [{"id": "GHSA-example"}]}]},
        )

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            result = await OSVClient(client=http).query_batch([make_candidate()])
        assert len(result.results) == 1
        assert result.results[0].vulns[0].id == "GHSA-example"

    asyncio.run(run())


def test_empty_candidates_skip_network_request() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        pytest.fail("Network request should not be made")

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            result = await OSVClient(client=http).query_batch([])
        assert result.results == ()

    asyncio.run(run())


def test_batch_response_count_mismatch_is_rejected() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"results": []})

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            with pytest.raises(ValueError, match="count does not match"):
                await OSVClient(client=http).query_batch([make_candidate()])

    asyncio.run(run())


def test_http_errors_are_not_silently_ignored() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": "Bad request"})

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            with pytest.raises(httpx.HTTPStatusError):
                await OSVClient(client=http, max_retries=0).query_batch([make_candidate()])

    asyncio.run(run())


def test_retries_transient_server_error(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts = 0

    async def no_sleep(delay: float) -> None:
        return None

    monkeypatch.setattr("deprisk.vulnerability.osv_client.asyncio.sleep", no_sleep)

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return httpx.Response(503)
        return httpx.Response(200, json={"results": [{"vulns": []}]})

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            result = await OSVClient(client=http, max_retries=1).query_batch([make_candidate()])
        assert result.results == (result.results[0],)

    asyncio.run(run())
    assert attempts == 2


def test_fetches_complete_advisory() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == "/v1/vulns/GHSA-example"
        return httpx.Response(
            200,
            json={
                "id": "GHSA-example",
                "summary": "Example vulnerability",
                "aliases": ["CVE-2026-1234"],
                "affected": [
                    {
                        "package": {"ecosystem": "npm", "name": "lodash"},
                        "ranges": [],
                        "versions": [],
                    }
                ],
            },
        )

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            advisory = await OSVClient(client=http).get_advisory("GHSA-example")
        assert advisory.id == "GHSA-example"
        assert advisory.summary == "Example vulnerability"
        assert advisory.aliases == ("CVE-2026-1234",)

    asyncio.run(run())


def test_empty_advisory_id_is_rejected() -> None:
    async def run() -> None:
        async with httpx.AsyncClient() as http:
            with pytest.raises(ValueError, match="cannot be empty"):
                await OSVClient(client=http).get_advisory("   ")

    asyncio.run(run())


def test_advisory_not_found_raises_http_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": "Not found"})

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            with pytest.raises(httpx.HTTPStatusError):
                await OSVClient(client=http, max_retries=0).get_advisory("GHSA-missing")

    asyncio.run(run())


def test_malformed_advisory_response_is_rejected() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"summary": "Missing advisory ID"})

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            with pytest.raises(ValidationError):
                await OSVClient(client=http).get_advisory("GHSA-example")

    asyncio.run(run())


def test_retries_advisory_fetch_after_server_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0

    async def no_sleep(delay: float) -> None:
        return None

    monkeypatch.setattr("deprisk.vulnerability.osv_client.asyncio.sleep", no_sleep)

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return httpx.Response(503)
        return httpx.Response(200, json={"id": "GHSA-example"})

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            advisory = await OSVClient(client=http, max_retries=1).get_advisory("GHSA-example")
        assert advisory.id == "GHSA-example"

    asyncio.run(run())
    assert attempts == 2


def test_repeated_batch_query_uses_cache() -> None:
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(200, json={"results": [{"vulns": []}]})

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            client = OSVClient(client=http)
            first = await client.query_batch([make_candidate()])
            second = await client.query_batch([make_candidate()])
        assert first == second

    asyncio.run(run())
    assert requests == 1


def test_batch_query_fetches_only_uncached_candidates() -> None:
    requests: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        import json

        payload = json.loads(request.content)
        requests.append(payload)
        return httpx.Response(
            200,
            json={"results": [{"vulns": []} for _ in payload["queries"]]},
        )

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            client = OSVClient(client=http)
            await client.query_batch([make_candidate("lodash")])
            await client.query_batch([make_candidate("lodash"), make_candidate("axios")])

    asyncio.run(run())
    assert len(requests) == 2
    assert len(requests[0]["queries"]) == 1
    assert len(requests[1]["queries"]) == 1
    assert requests[1]["queries"][0]["package"]["name"] == "axios"


def test_expired_batch_cache_entry_is_refetched() -> None:
    current_time = 100.0
    requests = 0

    def clock() -> float:
        return current_time

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(200, json={"results": [{"vulns": []}]})

    async def run() -> None:
        nonlocal current_time
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            client = OSVClient(
                client=http,
                cache_ttl_seconds=5,
                clock=clock,
            )
            await client.query_batch([make_candidate()])
            current_time += 6
            await client.query_batch([make_candidate()])

    asyncio.run(run())
    assert requests == 2


def test_repeated_advisory_fetch_uses_cache() -> None:
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(200, json={"id": "GHSA-example"})

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            client = OSVClient(client=http)
            first = await client.get_advisory("GHSA-example")
            second = await client.get_advisory("GHSA-example")
        assert first == second

    asyncio.run(run())


@pytest.mark.parametrize(
    "advisory_id",
    [
        "GHSA-35jh-r3h4-6jhm",
        "CVE-2026-1234",
        "PYSEC-2026-123",
        "RUSTSEC-2026-0001",
    ],
)
def test_valid_advisory_ids_are_accepted(advisory_id: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == f"/v1/vulns/{advisory_id}"
        return httpx.Response(200, json={"id": advisory_id})

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            advisory = await OSVClient(client=http).get_advisory(advisory_id)

        assert advisory.id == advisory_id

    asyncio.run(run())


@pytest.mark.parametrize(
    "advisory_id",
    [
        "../GHSA-example",
        "GHSA-example/extra",
        "GHSA-example?admin=true",
        "GHSA-example#fragment",
        "GHSA example",
        "%2e%2e%2f",
        "GHSA-example\\extra",
    ],
)
def test_invalid_advisory_ids_are_rejected_before_request(
    advisory_id: str,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        pytest.fail("Invalid advisory ID must be rejected before HTTP request")

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            with pytest.raises(ValueError, match="invalid characters"):
                await OSVClient(client=http).get_advisory(advisory_id)

    asyncio.run(run())
