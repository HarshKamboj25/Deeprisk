"""End-to-end tests for source-aware OSV vulnerability lookup."""

import asyncio
import json

import httpx

from deprisk.core.models import DependencyNode, PackageSourceType
from deprisk.vulnerability.osv_client import OSVClient
from deprisk.vulnerability.osv_service import OSVVulnerabilityService
from deprisk.vulnerability.osv_version_matcher import VersionMatchStatus
from deprisk.vulnerability.registry_candidates import select_registry_candidates
from deprisk.vulnerability.source_eligibility import SourceEligibilityStatus


def make_node(
    install_path: str,
    name: str,
    source_type: PackageSourceType,
    resolved: str | None,
    version: str = "1.2.3",
) -> DependencyNode:
    return DependencyNode(
        install_path=install_path,
        name=name,
        version=version,
        source_type=source_type,
        resolved=resolved,
    )


def test_source_eligibility_flows_through_to_osv_lookup() -> None:
    nodes = [
        make_node(
            "node_modules/lodash",
            "lodash",
            PackageSourceType.REGISTRY,
            "https://registry.npmjs.org/lodash/-/lodash-1.2.3.tgz",
        ),
        make_node(
            "node_modules/git-package",
            "git-package",
            PackageSourceType.GIT,
            "git+https://github.com/acme/git-package.git",
        ),
        make_node(
            "node_modules/local-package",
            "local-package",
            PackageSourceType.FILE,
            "file:../local-package",
        ),
        make_node(
            "node_modules/url-package",
            "url-package",
            PackageSourceType.URL,
            "https://example.com/url-package.tgz",
        ),
        make_node(
            "node_modules/unknown-package",
            "unknown-package",
            PackageSourceType.UNKNOWN,
            None,
        ),
    ]

    selection = select_registry_candidates(nodes)

    assert len(selection.candidates) == 1
    assert selection.candidates[0].package_name == "lodash"
    assert selection.candidates[0].package_version == "1.2.3"
    assert selection.candidates[0].install_paths == ("node_modules/lodash",)

    decisions_by_path = {decision.install_path: decision for decision in selection.decisions}

    assert decisions_by_path["node_modules/lodash"].status is SourceEligibilityStatus.ELIGIBLE
    assert decisions_by_path["node_modules/git-package"].status is (
        SourceEligibilityStatus.INELIGIBLE
    )
    assert decisions_by_path["node_modules/local-package"].status is (
        SourceEligibilityStatus.INELIGIBLE
    )
    assert decisions_by_path["node_modules/url-package"].status is (
        SourceEligibilityStatus.INELIGIBLE
    )
    assert decisions_by_path["node_modules/unknown-package"].status is (
        SourceEligibilityStatus.UNKNOWN
    )

    batch_payloads: list[dict[str, object]] = []
    detail_requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path == "/v1/querybatch":
            batch_payloads.append(json.loads(request.content))
            return httpx.Response(
                200,
                json={"results": [{"vulns": [{"id": "GHSA-lodash"}]}]},
            )

        if request.method == "GET" and request.url.path == "/v1/vulns/GHSA-lodash":
            detail_requests.append(request.url.path)
            return httpx.Response(
                200,
                json={
                    "id": "GHSA-lodash",
                    "summary": "Test lodash vulnerability",
                    "affected": [
                        {
                            "package": {
                                "ecosystem": "npm",
                                "name": "lodash",
                            },
                            "ranges": [
                                {
                                    "type": "SEMVER",
                                    "events": [
                                        {"introduced": "0"},
                                        {"fixed": "2.0.0"},
                                    ],
                                }
                            ],
                            "versions": [],
                        }
                    ],
                },
            )

        return httpx.Response(404)

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            service = OSVVulnerabilityService(OSVClient(client=http))
            result = await service.lookup(selection.candidates)

        assert len(batch_payloads) == 1
        assert batch_payloads[0] == {
            "queries": [
                {
                    "package": {
                        "name": "lodash",
                        "ecosystem": "npm",
                    },
                    "version": "1.2.3",
                }
            ]
        }

        assert detail_requests == ["/v1/vulns/GHSA-lodash"]
        assert len(result.package_results) == 1
        assert len(result.advisories) == 1
        assert len(result.match_decisions) == 1
        assert result.match_decisions[0].status is VersionMatchStatus.AFFECTED

        assert len(result.findings) == 1
        assert result.findings[0].package_name == "lodash"
        assert result.findings[0].affected_install_paths == ("node_modules/lodash",)

    asyncio.run(run())
