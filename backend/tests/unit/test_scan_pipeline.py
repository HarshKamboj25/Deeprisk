import asyncio
from types import SimpleNamespace
from typing import cast

from deprisk.core.models import AdvisoryReference, VulnerabilityFinding
from deprisk.scan import RepositoryAnalysis, scan_local_repository
from deprisk.vulnerability.enrichment_models import EnrichmentResult, FindingEnrichment
from deprisk.vulnerability.enrichment_service import VulnerabilityEnrichmentService
from deprisk.vulnerability.osv_aliases import OSVAliasGroup
from deprisk.vulnerability.osv_service import (
    OSVLookupResult,
    OSVVulnerabilityService,
)
from deprisk.vulnerability.registry_candidates import RegistryQueryCandidate


class FakeOSVService:
    def __init__(self, result: OSVLookupResult) -> None:
        self.result = result
        self.received_candidates: tuple[RegistryQueryCandidate, ...] | None = None

    async def lookup(
        self,
        candidates: tuple[RegistryQueryCandidate, ...],
    ) -> OSVLookupResult:
        self.received_candidates = tuple(candidates)
        return self.result


def make_analysis(
    candidates: tuple[RegistryQueryCandidate, ...],
) -> RepositoryAnalysis:
    return cast(
        RepositoryAnalysis,
        SimpleNamespace(candidate_selection=SimpleNamespace(candidates=candidates)),
    )


def test_scan_pipeline_aggregates_osv_findings(monkeypatch) -> None:
    async def run_test() -> None:
        candidate = RegistryQueryCandidate(
            package_name="lodash",
            package_version="4.17.20",
            install_paths=(
                "node_modules/lodash",
                "packages/app/node_modules/lodash",
            ),
        )

        advisory_one = AdvisoryReference(
            advisory_id="GHSA-one",
            aliases=("CVE-2026-1234",),
        )
        advisory_two = AdvisoryReference(
            advisory_id="GHSA-two",
            aliases=("CVE-2026-1234",),
        )

        findings = (
            VulnerabilityFinding(
                package_name="lodash",
                package_version="4.17.20",
                advisory=advisory_one,
                affected_install_paths=("node_modules/lodash",),
            ),
            VulnerabilityFinding(
                package_name="lodash",
                package_version="4.17.20",
                advisory=advisory_two,
                affected_install_paths=("packages/app/node_modules/lodash",),
            ),
        )

        alias_group = OSVAliasGroup(
            canonical_id="GHSA-one",
            advisory_ids=("GHSA-one", "GHSA-two"),
            aliases=("CVE-2026-1234",),
        )

        osv_result = OSVLookupResult(
            findings=findings,
            alias_groups=(alias_group,),
        )

        analysis = make_analysis((candidate,))
        service = FakeOSVService(osv_result)

        monkeypatch.setattr(
            "deprisk.scan.analyze_local_repository",
            lambda _: analysis,
        )

        result = await scan_local_repository(
            "fake-repository",
            cast(OSVVulnerabilityService, service),
        )

        assert service.received_candidates == (candidate,)
        assert result.analysis is analysis
        assert result.osv_result is osv_result
        assert len(result.aggregated_findings) == 1

        aggregated = result.aggregated_findings[0]

        assert aggregated.package.name == "lodash"
        assert aggregated.package.version == "4.17.20"
        assert aggregated.advisory_ids == ("GHSA-one", "GHSA-two")
        assert aggregated.affected_install_paths == (
            "node_modules/lodash",
            "packages/app/node_modules/lodash",
        )

    asyncio.run(run_test())


def test_scan_pipeline_handles_no_registry_candidates(monkeypatch) -> None:
    async def run_test() -> None:
        analysis = make_analysis(())
        service = FakeOSVService(OSVLookupResult())

        monkeypatch.setattr(
            "deprisk.scan.analyze_local_repository",
            lambda _: analysis,
        )

        result = await scan_local_repository(
            "fake-repository",
            cast(OSVVulnerabilityService, service),
        )

        assert service.received_candidates == ()
        assert result.osv_result == OSVLookupResult()
        assert result.aggregated_findings == ()

    asyncio.run(run_test())


def test_scan_pipeline_runs_enrichment_after_aggregation(monkeypatch) -> None:
    async def run_test() -> None:
        candidate = RegistryQueryCandidate(
            package_name="lodash",
            package_version="4.17.20",
            install_paths=("node_modules/lodash",),
        )

        finding = VulnerabilityFinding(
            package_name="lodash",
            package_version="4.17.20",
            advisory=AdvisoryReference(
                advisory_id="GHSA-one",
                aliases=("CVE-2026-1234",),
            ),
            affected_install_paths=("node_modules/lodash",),
        )

        analysis = make_analysis((candidate,))
        alias_group = OSVAliasGroup(
            canonical_id="GHSA-one",
            advisory_ids=("GHSA-one",),
            aliases=("CVE-2026-1234",),
        )
        osv_result = OSVLookupResult(
            findings=(finding,),
            alias_groups=(alias_group,),
        )
        osv_service = FakeOSVService(osv_result)

        class FakeEnrichmentService:
            def __init__(self) -> None:
                self.received_findings = None

            async def enrich(self, findings):
                self.received_findings = tuple(findings)
                return EnrichmentResult(
                    finding_results=(
                        FindingEnrichment(
                            canonical_advisory_id="GHSA-one",
                            package_name="lodash",
                            package_version="4.17.20",
                            cve_ids=("CVE-2026-1234",),
                        ),
                    )
                )

        enrichment_service = FakeEnrichmentService()

        monkeypatch.setattr(
            "deprisk.scan.analyze_local_repository",
            lambda _: analysis,
        )

        result = await scan_local_repository(
            "fake-repository",
            cast(OSVVulnerabilityService, osv_service),
            cast(VulnerabilityEnrichmentService, enrichment_service),
        )

        assert len(result.aggregated_findings) == 1
        assert enrichment_service.received_findings == result.aggregated_findings
        assert result.enrichment_result.finding_results[0].cve_ids == ("CVE-2026-1234",)

    asyncio.run(run_test())


def test_scan_pipeline_defaults_to_empty_enrichment(monkeypatch) -> None:
    async def run_test() -> None:
        analysis = make_analysis(())
        service = FakeOSVService(OSVLookupResult())

        monkeypatch.setattr(
            "deprisk.scan.analyze_local_repository",
            lambda _: analysis,
        )

        result = await scan_local_repository(
            "fake-repository",
            cast(OSVVulnerabilityService, service),
        )

        assert result.enrichment_result == EnrichmentResult()
        assert result.aggregated_findings == ()

    asyncio.run(run_test())
