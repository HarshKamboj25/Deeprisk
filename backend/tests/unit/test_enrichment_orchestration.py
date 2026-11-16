import asyncio

from deprisk.core.models import AdvisoryReference
from deprisk.vulnerability.enrichment_models import (
    EnrichmentResult,
    EPSSRecord,
    EPSSResult,
    FindingEnrichment,
    IntelligenceSource,
    IntelligenceStatus,
    KEVResult,
    NVDRecord,
    NVDResult,
    SourceAvailability,
)
from deprisk.vulnerability.enrichment_service import (
    VulnerabilityEnrichmentService,
)
from deprisk.vulnerability.finding_aggregator import (
    AggregatedFinding,
    PackageVersion,
)


def make_finding(
    advisory_id: str,
    cve_ids: tuple[str, ...],
) -> AggregatedFinding:
    return AggregatedFinding(
        package=PackageVersion(
            ecosystem="npm",
            name="example-package",
            version="1.0.0",
        ),
        canonical_advisory_id=advisory_id,
        advisory_ids=(advisory_id,),
        advisories=(
            AdvisoryReference(
                advisory_id=advisory_id,
                aliases=cve_ids,
            ),
        ),
        aliases=cve_ids,
        affected_install_paths=("node_modules/example-package",),
    )


def make_availability(
    source: IntelligenceSource,
    status: IntelligenceStatus = IntelligenceStatus.AVAILABLE,
    reason: str | None = None,
) -> SourceAvailability:
    return SourceAvailability(
        source=source,
        status=status,
        reason=reason,
    )


class FakeEPSSClient:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def get_score(self, cve: str) -> EPSSResult:
        self.calls.append(cve)
        return EPSSResult(
            availability=make_availability(IntelligenceSource.EPSS),
            record=EPSSRecord(
                cve=cve,
                epss=0.95,
                percentile=0.99,
                score_date="2026-11-07",
            ),
        )


class FakeKEVClient:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def lookup(self, cve: str) -> KEVResult:
        self.calls.append(cve)
        return KEVResult(
            availability=make_availability(IntelligenceSource.CISA_KEV),
        )


class FakeNVDClient:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def get_cvss(self, cve: str) -> NVDResult:
        self.calls.append(cve)
        return NVDResult(
            availability=make_availability(IntelligenceSource.NVD),
            record=NVDRecord(
                cve_id=cve,
                cvss_version="3.1",
                source="nvd@nist.gov",
                metric_type="Primary",
                vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                base_score=9.8,
                base_severity="CRITICAL",
            ),
        )


def test_enriches_cve_using_all_three_sources() -> None:
    async def scenario() -> None:
        epss = FakeEPSSClient()
        kev = FakeKEVClient()
        nvd = FakeNVDClient()

        service = VulnerabilityEnrichmentService(
            epss_client=epss,
            kev_client=kev,
            nvd_client=nvd,
        )

        result = await service.enrich((make_finding("GHSA-example", ("CVE-2021-44228",)),))

        assert isinstance(result, EnrichmentResult)
        assert len(result.cve_results) == 1

        enrichment = result.cve_results[0]
        assert enrichment.cve_id == "CVE-2021-44228"
        assert enrichment.epss.record is not None
        assert enrichment.kev.availability.status == IntelligenceStatus.AVAILABLE
        assert enrichment.nvd.record is not None

        assert epss.calls == ["CVE-2021-44228"]
        assert kev.calls == ["CVE-2021-44228"]
        assert nvd.calls == ["CVE-2021-44228"]

    asyncio.run(scenario())


def test_deduplicates_cves_across_findings() -> None:
    async def scenario() -> None:
        epss = FakeEPSSClient()
        kev = FakeKEVClient()
        nvd = FakeNVDClient()

        service = VulnerabilityEnrichmentService(
            epss_client=epss,
            kev_client=kev,
            nvd_client=nvd,
        )

        findings = (
            make_finding("GHSA-first", ("CVE-2021-44228",)),
            make_finding("GHSA-second", ("CVE-2021-44228",)),
        )

        result = await service.enrich(findings)

        assert len(result.cve_results) == 1
        assert len(result.finding_results) == 2
        assert epss.calls == ["CVE-2021-44228"]
        assert kev.calls == ["CVE-2021-44228"]
        assert nvd.calls == ["CVE-2021-44228"]

    asyncio.run(scenario())


def test_preserves_finding_to_cve_associations() -> None:
    async def scenario() -> None:
        service = VulnerabilityEnrichmentService(
            epss_client=FakeEPSSClient(),
            kev_client=FakeKEVClient(),
            nvd_client=FakeNVDClient(),
        )

        findings = (
            make_finding("GHSA-first", ("CVE-2021-44228",)),
            make_finding("GHSA-second", ("CVE-2021-45046",)),
        )

        result = await service.enrich(findings)

        assert result.finding_results == (
            FindingEnrichment(
                canonical_advisory_id="GHSA-first",
                package_name="example-package",
                package_version="1.0.0",
                cve_ids=("CVE-2021-44228",),
            ),
            FindingEnrichment(
                canonical_advisory_id="GHSA-second",
                package_name="example-package",
                package_version="1.0.0",
                cve_ids=("CVE-2021-45046",),
            ),
        )

    asyncio.run(scenario())


def test_returns_deterministically_sorted_cve_results() -> None:
    async def scenario() -> None:
        service = VulnerabilityEnrichmentService(
            epss_client=FakeEPSSClient(),
            kev_client=FakeKEVClient(),
            nvd_client=FakeNVDClient(),
        )

        findings = (
            make_finding("GHSA-z", ("CVE-2022-22965",)),
            make_finding("GHSA-a", ("CVE-2021-44228",)),
        )

        result = await service.enrich(findings)

        assert [item.cve_id for item in result.cve_results] == [
            "CVE-2021-44228",
            "CVE-2022-22965",
        ]

    asyncio.run(scenario())


def test_isolates_failure_of_one_intelligence_source() -> None:
    class FailingNVDClient:
        async def get_cvss(self, cve: str) -> NVDResult:
            raise RuntimeError("NVD service unavailable")

    async def scenario() -> None:
        epss = FakeEPSSClient()
        kev = FakeKEVClient()

        service = VulnerabilityEnrichmentService(
            epss_client=epss,
            kev_client=kev,
            nvd_client=FailingNVDClient(),
        )

        result = await service.enrich((make_finding("GHSA-example", ("CVE-2021-44228",)),))

        enrichment = result.cve_results[0]

        assert enrichment.epss.record is not None
        assert enrichment.kev.availability.status == IntelligenceStatus.AVAILABLE
        assert enrichment.nvd.availability.status == IntelligenceStatus.UNAVAILABLE
        assert enrichment.nvd.record is None

    asyncio.run(scenario())


def test_handles_empty_findings_without_api_calls() -> None:
    async def scenario() -> None:
        epss = FakeEPSSClient()
        kev = FakeKEVClient()
        nvd = FakeNVDClient()

        service = VulnerabilityEnrichmentService(
            epss_client=epss,
            kev_client=kev,
            nvd_client=nvd,
        )

        result = await service.enrich(())

        assert result == EnrichmentResult()
        assert not epss.calls
        assert not kev.calls
        assert not nvd.calls

    asyncio.run(scenario())


def test_respects_configured_concurrency_limit() -> None:
    class TrackingEPSSClient:
        def __init__(self) -> None:
            self.active = 0
            self.maximum_active = 0

        async def get_score(self, cve: str) -> EPSSResult:
            self.active += 1
            self.maximum_active = max(self.maximum_active, self.active)
            try:
                await asyncio.sleep(0.02)
                return EPSSResult(
                    availability=make_availability(IntelligenceSource.EPSS),
                )
            finally:
                self.active -= 1

    async def scenario() -> None:
        epss = TrackingEPSSClient()

        service = VulnerabilityEnrichmentService(
            epss_client=epss,
            kev_client=FakeKEVClient(),
            nvd_client=FakeNVDClient(),
            max_concurrency=2,
        )

        findings = tuple(
            make_finding(
                f"GHSA-{index}",
                (f"CVE-2021-{index + 1000}",),
            )
            for index in range(6)
        )

        result = await service.enrich(findings)

        assert len(result.cve_results) == 6
        assert epss.maximum_active <= 2
        assert epss.maximum_active >= 2

    asyncio.run(scenario())


def test_marks_unexpected_epss_failure_unavailable() -> None:
    class FailingEPSSClient:
        async def get_score(self, cve: str) -> EPSSResult:
            raise RuntimeError("EPSS unavailable")

    async def scenario() -> None:
        service = VulnerabilityEnrichmentService(
            epss_client=FailingEPSSClient(),
            kev_client=FakeKEVClient(),
            nvd_client=FakeNVDClient(),
        )

        result = await service.enrich((make_finding("GHSA-example", ("CVE-2021-44228",)),))

        enrichment = result.cve_results[0]
        assert enrichment.epss.availability.status == IntelligenceStatus.UNAVAILABLE
        assert enrichment.epss.record is None
        assert enrichment.kev.availability.status == IntelligenceStatus.AVAILABLE

    asyncio.run(scenario())
