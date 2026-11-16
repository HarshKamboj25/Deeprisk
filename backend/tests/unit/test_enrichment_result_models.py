from deprisk.vulnerability.enrichment_models import (
    CVEEnrichment,
    EnrichmentResult,
    EPSSResult,
    FindingEnrichment,
    IntelligenceSource,
    IntelligenceStatus,
    KEVResult,
    NVDResult,
    SourceAvailability,
)


def make_availability(source: IntelligenceSource) -> SourceAvailability:
    return SourceAvailability(
        source=source,
        status=IntelligenceStatus.NOT_FOUND,
        reason="No matching record",
    )


def test_cve_enrichment_combines_three_intelligence_sources() -> None:
    result = CVEEnrichment(
        cve_id="CVE-2021-44228",
        epss=EPSSResult(
            availability=make_availability(IntelligenceSource.EPSS),
        ),
        kev=KEVResult(
            availability=make_availability(IntelligenceSource.CISA_KEV),
        ),
        nvd=NVDResult(
            availability=make_availability(IntelligenceSource.NVD),
        ),
    )

    assert result.cve_id == "CVE-2021-44228"
    assert result.epss.record is None
    assert result.kev.record is None
    assert result.nvd.record is None


def test_finding_enrichment_preserves_cve_associations() -> None:
    result = FindingEnrichment(
        canonical_advisory_id="GHSA-example",
        package_name="lodash",
        package_version="4.17.20",
        cve_ids=("CVE-2021-44228", "CVE-2021-45046"),
    )

    assert result.cve_ids == ("CVE-2021-44228", "CVE-2021-45046")


def test_finding_enrichment_allows_no_cve_aliases() -> None:
    result = FindingEnrichment(
        canonical_advisory_id="GHSA-example",
        package_name="lodash",
        package_version="4.17.20",
    )

    assert result.cve_ids == ()


def test_enrichment_result_defaults_to_empty_collections() -> None:
    result = EnrichmentResult()

    assert result.cve_results == ()
    assert result.finding_results == ()


def test_enrichment_result_preserves_cve_and_finding_results() -> None:
    cve_result = CVEEnrichment(
        cve_id="CVE-2021-44228",
        epss=EPSSResult(
            availability=make_availability(IntelligenceSource.EPSS),
        ),
        kev=KEVResult(
            availability=make_availability(IntelligenceSource.CISA_KEV),
        ),
        nvd=NVDResult(
            availability=make_availability(IntelligenceSource.NVD),
        ),
    )

    finding_result = FindingEnrichment(
        canonical_advisory_id="GHSA-example",
        package_name="lodash",
        package_version="4.17.20",
        cve_ids=("CVE-2021-44228",),
    )

    result = EnrichmentResult(
        cve_results=(cve_result,),
        finding_results=(finding_result,),
    )

    assert len(result.cve_results) == 1
    assert len(result.finding_results) == 1
    assert result.finding_results[0].cve_ids == ("CVE-2021-44228",)
