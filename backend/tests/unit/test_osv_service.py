"""Tests for the OSV vulnerability orchestration service."""

import asyncio

import httpx

from deprisk.vulnerability.osv_client import OSVClient
from deprisk.vulnerability.osv_service import OSVVulnerabilityService
from deprisk.vulnerability.registry_candidates import RegistryQueryCandidate


def candidate(name: str, version: str, *paths: str) -> RegistryQueryCandidate:
    return RegistryQueryCandidate(
        package_name=name,
        package_version=version,
        install_paths=tuple(paths),
    )


def test_lookup_hydrates_shared_advisory_once_and_preserves_package_paths() -> None:
    detail_requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/querybatch":
            return httpx.Response(
                200,
                json={
                    "results": [
                        {"vulns": [{"id": "GHSA-shared"}]},
                        {"vulns": [{"id": "GHSA-shared"}]},
                    ]
                },
            )

        if request.url.path == "/v1/vulns/GHSA-shared":
            detail_requests.append(request.url.path)
            return httpx.Response(
                200,
                json={
                    "id": "GHSA-shared",
                    "summary": "Shared advisory",
                    "aliases": ["CVE-2026-1234"],
                    "database_specific": {"severity": "HIGH"},
                },
            )

        return httpx.Response(404)

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            service = OSVVulnerabilityService(OSVClient(client=http))
            result = await service.lookup(
                [
                    candidate("lodash", "4.17.20", "node_modules/lodash"),
                    candidate(
                        "lodash",
                        "4.17.20",
                        "node_modules/app/node_modules/lodash",
                    ),
                ]
            )

        assert len(result.package_results) == 2
        assert len(result.advisories) == 1
        assert len(result.normalized_advisories) == 1
        assert len(result.findings) == 2
        assert len(result.alias_groups) == 1

        assert result.findings[0].affected_install_paths == ("node_modules/lodash",)
        assert result.findings[1].affected_install_paths == (
            "node_modules/app/node_modules/lodash",
        )
        assert all(finding.advisory.advisory_id == "GHSA-shared" for finding in result.findings)

    asyncio.run(run())
    assert detail_requests == ["/v1/vulns/GHSA-shared"]


def test_lookup_hydrates_multiple_advisories_and_groups_aliases() -> None:
    detail_ids: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/querybatch":
            return httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "vulns": [
                                {"id": "GHSA-one"},
                                {"id": "GHSA-two"},
                            ]
                        }
                    ]
                },
            )

        advisory_id = request.url.path.rsplit("/", 1)[-1]
        detail_ids.append(advisory_id)

        aliases = {
            "GHSA-one": ["CVE-2026-1234"],
            "GHSA-two": ["CVE-2026-1234"],
        }

        return httpx.Response(
            200,
            json={
                "id": advisory_id,
                "summary": f"Summary for {advisory_id}",
                "aliases": aliases[advisory_id],
            },
        )

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            service = OSVVulnerabilityService(OSVClient(client=http))
            result = await service.lookup([candidate("lodash", "4.17.20", "node_modules/lodash")])

        assert len(result.advisories) == 2
        assert len(result.findings) == 2
        assert len(result.alias_groups) == 1
        assert result.alias_groups[0].advisory_ids == (
            "GHSA-one",
            "GHSA-two",
        )
        assert result.alias_groups[0].aliases == ("CVE-2026-1234",)

    asyncio.run(run())
    assert detail_ids == ["GHSA-one", "GHSA-two"]


def test_lookup_with_no_candidates_skips_network() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("No request should be made")

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            service = OSVVulnerabilityService(OSVClient(client=http))
            result = await service.lookup([])

        assert result.package_results == ()
        assert result.advisories == ()
        assert result.normalized_advisories == ()
        assert result.alias_groups == ()
        assert result.findings == ()

    asyncio.run(run())
