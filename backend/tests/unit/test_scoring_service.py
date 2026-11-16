import pytest

from deprisk.core.models import AdvisoryReference, AdvisorySeverity
from deprisk.core.scope import (
    EffectiveScope,
    NodeReachability,
    ScopePropagationResult,
)
from deprisk.vulnerability.enrichment_models import (
    CVEEnrichment,
    EnrichmentResult,
    EPSSRecord,
    EPSSResult,
    FindingEnrichment,
    IntelligenceSource,
    IntelligenceStatus,
    KEVRecord,
    KEVResult,
    NVDRecord,
    NVDResult,
    SourceAvailability,
)
from deprisk.vulnerability.finding_aggregator import (
    AggregatedFinding,
    PackageVersion,
)
from deprisk.vulnerability.scoring_models import (
    ScoreInterval,
    ScoringVersion,
    SeveritySource,
    TriStateStatus,
    UnitInterval,
)


def make_finding(
    severity: AdvisorySeverity = AdvisorySeverity.HIGH,
    affected_paths: tuple[str, ...] = ("node_modules/example-package",),
    cve_ids: tuple[str, ...] = ("CVE-2021-44228",),
) -> AggregatedFinding:
    advisory = AdvisoryReference(
        advisory_id="GHSA-example",
        aliases=cve_ids,
        severity=severity,
    )
    return AggregatedFinding(
        package=PackageVersion(
            ecosystem="npm",
            name="example-package",
            version="1.0.0",
        ),
        canonical_advisory_id="GHSA-example",
        advisory_ids=("GHSA-example",),
        advisories=(advisory,),
        aliases=cve_ids,
        affected_install_paths=affected_paths,
    )


def make_availability(
    source: IntelligenceSource,
    status: IntelligenceStatus,
) -> SourceAvailability:
    return SourceAvailability(source=source, status=status)


def make_cve_enrichment(
    cve_id: str = "CVE-2021-44228",
    *,
    epss_status: IntelligenceStatus = IntelligenceStatus.AVAILABLE,
    epss_probability: float | None = 0.25,
    kev_status: IntelligenceStatus = IntelligenceStatus.AVAILABLE,
    ransomware_use: str = "Unknown",
    nvd_status: IntelligenceStatus = IntelligenceStatus.AVAILABLE,
    cvss_score: float | None = 7.5,
    cvss_version: str = "3.1",
) -> CVEEnrichment:
    epss_record = (
        EPSSRecord(
            cve=cve_id,
            epss=epss_probability,
            percentile=0.75,
            score_date="2026-11-09",
        )
        if epss_status is IntelligenceStatus.AVAILABLE and epss_probability is not None
        else None
    )
    kev_record = (
        KEVRecord(
            cveID=cve_id,
            vendorProject="Example Vendor",
            product="Example Product",
            vulnerabilityName="Example Vulnerability",
            dateAdded="2026-01-01",
            shortDescription="Test vulnerability.",
            requiredAction="Apply the available update.",
            dueDate="2026-02-01",
            knownRansomwareCampaignUse=ransomware_use,
        )
        if kev_status is IntelligenceStatus.AVAILABLE
        else None
    )
    nvd_record = (
        NVDRecord(
            cve_id=cve_id,
            cvss_version=cvss_version,
            source="nvd@nist.gov",
            metric_type="Primary",
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            base_score=cvss_score,
            base_severity="HIGH",
        )
        if nvd_status is IntelligenceStatus.AVAILABLE and cvss_score is not None
        else None
    )

    return CVEEnrichment(
        cve_id=cve_id,
        epss=EPSSResult(
            availability=make_availability(IntelligenceSource.EPSS, epss_status),
            record=epss_record,
        ),
        kev=KEVResult(
            availability=make_availability(IntelligenceSource.CISA_KEV, kev_status),
            record=kev_record,
        ),
        nvd=NVDResult(
            availability=make_availability(IntelligenceSource.NVD, nvd_status),
            record=nvd_record,
        ),
    )


def make_scope_result(
    paths: tuple[str, ...] = ("node_modules/example-package",),
    scope: EffectiveScope = EffectiveScope.PRODUCTION,
) -> ScopePropagationResult:
    states_by_scope = {
        EffectiveScope.PRODUCTION: {"(PROD, REQ)"},
        EffectiveScope.PEER: {"(PEER, REQ)"},
        EffectiveScope.UNKNOWN: {"(UNKNOWN, REQ)"},
        EffectiveScope.OPTIONAL: {"(PROD, OPT)"},
        EffectiveScope.DEV_OPTIONAL: {"(DEV, OPT)"},
        EffectiveScope.DEVELOPMENT: {"(DEV, REQ)"},
        EffectiveScope.UNREACHABLE: set(),
    }
    states = frozenset(states_by_scope[scope])

    nodes = {
        path: NodeReachability(
            install_path=path,
            effective_scope=scope,
            is_production=scope is EffectiveScope.PRODUCTION,
            is_dev=scope is EffectiveScope.DEVELOPMENT,
            is_optional=scope is EffectiveScope.OPTIONAL,
            is_dev_optional=scope is EffectiveScope.DEV_OPTIONAL,
            is_peer=scope is EffectiveScope.PEER,
            is_unreachable=scope is EffectiveScope.UNREACHABLE,
            reached_states=states,
            has_production_path=any(s.startswith("(PROD,") for s in states),
            has_development_path=any(s.startswith("(DEV,") for s in states),
            has_optional_path=any(s.endswith(", OPT)") for s in states),
            has_required_path=any(s.endswith(", REQ)") for s in states),
        )
        for path in paths
    }
    return ScopePropagationResult(nodes=nodes)


def make_enrichment_result(
    *cves: CVEEnrichment,
    canonical_advisory_id: str = "GHSA-example",
    package_name: str = "example-package",
    package_version: str = "1.0.0",
) -> EnrichmentResult:
    return EnrichmentResult(
        cve_results=tuple(cves),
        finding_results=(
            FindingEnrichment(
                canonical_advisory_id=canonical_advisory_id,
                package_name=package_name,
                package_version=package_version,
                cve_ids=tuple(cve.cve_id for cve in cves),
            ),
        ),
    )


# Scoring service behavior tests


def test_nvd_cvss_is_used_as_base_severity() -> None:
    from deprisk.vulnerability.scoring_service import score_finding

    finding = make_finding()
    enrichment = make_enrichment_result(make_cve_enrichment())
    scopes = make_scope_result()

    result = score_finding(finding, enrichment, scopes)

    assert result.scoring_version is ScoringVersion.V1
    assert result.governing_cve_id == "CVE-2021-44228"

    cve = result.contributing_cves[0]
    assert cve.severity_source is SeveritySource.NVD_CVSS
    assert cve.cvss_score == 7.5
    assert cve.cvss_version == "3.1"
    assert cve.base_severity == ScoreInterval(
        lower=75.0,
        nominal=75.0,
        upper=75.0,
    )


def test_advisory_severity_is_used_when_nvd_is_unavailable() -> None:
    from deprisk.vulnerability.scoring_service import score_finding

    finding = make_finding(severity=AdvisorySeverity.HIGH)
    enrichment = make_enrichment_result(
        make_cve_enrichment(
            nvd_status=IntelligenceStatus.UNAVAILABLE,
            cvss_score=None,
        )
    )
    scopes = make_scope_result()

    result = score_finding(finding, enrichment, scopes)

    cve = result.contributing_cves[0]
    assert cve.severity_source is SeveritySource.ADVISORY_SEVERITY_FALLBACK
    assert cve.cvss_score is None
    assert cve.cvss_version is None
    assert cve.cvss_status is IntelligenceStatus.UNAVAILABLE
    assert cve.base_severity == ScoreInterval(
        lower=70.0,
        nominal=79.95,
        upper=89.9,
    )


def test_kev_membership_and_ransomware_are_independent() -> None:
    from deprisk.vulnerability.scoring_service import score_finding

    finding = make_finding()
    enrichment = make_enrichment_result(make_cve_enrichment(ransomware_use="Unknown"))

    result = score_finding(finding, enrichment, make_scope_result())
    cve = result.contributing_cves[0]

    assert cve.is_in_kev is TriStateStatus.POSITIVE
    assert cve.known_ransomware_campaign_use is TriStateStatus.UNKNOWN


def test_known_ransomware_campaign_maps_to_positive() -> None:
    from deprisk.vulnerability.scoring_service import score_finding

    finding = make_finding()
    enrichment = make_enrichment_result(make_cve_enrichment(ransomware_use="Known"))

    result = score_finding(finding, enrichment, make_scope_result())
    cve = result.contributing_cves[0]

    assert cve.is_in_kev is TriStateStatus.POSITIVE
    assert cve.known_ransomware_campaign_use is TriStateStatus.POSITIVE


def test_absent_kev_record_does_not_prove_no_ransomware_use() -> None:
    from deprisk.vulnerability.scoring_service import score_finding

    finding = make_finding()
    enrichment = make_enrichment_result(
        make_cve_enrichment(kev_status=IntelligenceStatus.NOT_FOUND)
    )

    result = score_finding(finding, enrichment, make_scope_result())
    cve = result.contributing_cves[0]

    assert cve.is_in_kev is TriStateStatus.NEGATIVE
    assert cve.known_ransomware_campaign_use is TriStateStatus.UNKNOWN


def test_available_epss_probability_is_preserved() -> None:
    from deprisk.vulnerability.scoring_service import score_finding

    enrichment = make_enrichment_result(make_cve_enrichment(epss_probability=0.25))

    result = score_finding(
        make_finding(),
        enrichment,
        make_scope_result(),
    )
    cve = result.contributing_cves[0]

    assert cve.epss_status is IntelligenceStatus.AVAILABLE
    assert cve.epss_probability == 0.25
    assert cve.epss_upper_bound_is_hypothetical is False


def test_unavailable_epss_remains_unknown() -> None:
    from deprisk.vulnerability.scoring_service import score_finding

    enrichment = make_enrichment_result(
        make_cve_enrichment(
            epss_status=IntelligenceStatus.UNAVAILABLE,
            epss_probability=None,
        )
    )

    result = score_finding(
        make_finding(),
        enrichment,
        make_scope_result(),
    )
    cve = result.contributing_cves[0]

    assert cve.epss_status is IntelligenceStatus.UNAVAILABLE
    assert cve.epss_probability is None
    assert cve.epss_upper_bound_is_hypothetical is True
    assert IntelligenceSource.EPSS in result.missing_sources


@pytest.mark.parametrize(
    ("scope", "expected"),
    [
        (EffectiveScope.PRODUCTION, 1.00),
        (EffectiveScope.PEER, 1.00),
        (EffectiveScope.OPTIONAL, 0.70),
        (EffectiveScope.DEV_OPTIONAL, 0.35),
        (EffectiveScope.DEVELOPMENT, 0.30),
    ],
)
def test_fixed_scope_exposure_multipliers(
    scope: EffectiveScope,
    expected: float,
) -> None:
    from deprisk.vulnerability.scoring_service import score_finding

    result = score_finding(
        make_finding(),
        make_enrichment_result(make_cve_enrichment()),
        make_scope_result(scope=scope),
    )

    assert result.governing_scope is scope
    assert result.exposure_multiplier == UnitInterval(
        lower=expected,
        nominal=expected,
        upper=expected,
    )


def test_unknown_scope_preserves_exposure_uncertainty() -> None:
    from deprisk.vulnerability.scoring_service import score_finding

    result = score_finding(
        make_finding(),
        make_enrichment_result(make_cve_enrichment()),
        make_scope_result(scope=EffectiveScope.UNKNOWN),
    )

    assert result.governing_scope is EffectiveScope.UNKNOWN
    assert result.exposure_multiplier.lower == 0.30
    assert result.exposure_multiplier.upper == 1.00
    assert result.exposure_multiplier.lower <= result.exposure_multiplier.nominal
    assert result.exposure_multiplier.nominal <= result.exposure_multiplier.upper


def test_unreachable_dependency_has_zero_operational_risk() -> None:
    from deprisk.vulnerability.scoring_service import score_finding

    result = score_finding(
        make_finding(),
        make_enrichment_result(make_cve_enrichment()),
        make_scope_result(scope=EffectiveScope.UNREACHABLE),
    )

    assert result.is_unreachable is True
    assert result.governing_scope is EffectiveScope.UNREACHABLE
    assert result.exposure_multiplier == UnitInterval(
        lower=0.0,
        nominal=0.0,
        upper=0.0,
    )
    assert result.risk_interval == ScoreInterval(
        lower=0.0,
        nominal=0.0,
        upper=0.0,
    )


def make_mixed_scope_result(
    path_scopes: dict[str, EffectiveScope],
) -> ScopePropagationResult:
    nodes = {}
    for path, scope in path_scopes.items():
        single_path_result = make_scope_result((path,), scope)
        nodes[path] = single_path_result.nodes[path]
    return ScopePropagationResult(nodes=nodes)


def test_production_path_wins_over_development_path() -> None:
    from deprisk.vulnerability.scoring_service import score_finding

    paths = ("node_modules/example-package", "node_modules/other/example-package")
    scopes = make_mixed_scope_result(
        {
            paths[0]: EffectiveScope.DEVELOPMENT,
            paths[1]: EffectiveScope.PRODUCTION,
        }
    )

    result = score_finding(
        make_finding(affected_paths=paths),
        make_enrichment_result(make_cve_enrichment()),
        scopes,
    )

    assert result.governing_scope is EffectiveScope.PRODUCTION
    assert result.exposure_multiplier == UnitInterval(lower=1.0, nominal=1.0, upper=1.0)


def test_optional_path_wins_over_development_path() -> None:
    from deprisk.vulnerability.scoring_service import score_finding

    paths = ("node_modules/example-package", "node_modules/other/example-package")
    scopes = make_mixed_scope_result(
        {
            paths[0]: EffectiveScope.DEVELOPMENT,
            paths[1]: EffectiveScope.OPTIONAL,
        }
    )

    result = score_finding(
        make_finding(affected_paths=paths),
        make_enrichment_result(make_cve_enrichment()),
        scopes,
    )

    assert result.governing_scope is EffectiveScope.OPTIONAL
    assert result.exposure_multiplier == UnitInterval(lower=0.70, nominal=0.70, upper=0.70)


def test_reachable_production_path_wins_over_unreachable_path() -> None:
    from deprisk.vulnerability.scoring_service import score_finding

    paths = ("node_modules/example-package", "node_modules/other/example-package")
    scopes = make_mixed_scope_result(
        {
            paths[0]: EffectiveScope.UNREACHABLE,
            paths[1]: EffectiveScope.PRODUCTION,
        }
    )

    result = score_finding(
        make_finding(affected_paths=paths),
        make_enrichment_result(make_cve_enrichment()),
        scopes,
    )

    assert result.is_unreachable is False
    assert result.governing_scope is EffectiveScope.PRODUCTION


def test_multiple_cves_are_assessed_independently() -> None:
    from deprisk.vulnerability.scoring_service import score_finding

    finding = make_finding(
        cve_ids=("CVE-2021-44228", "CVE-2022-22965"),
    )
    enrichment = make_enrichment_result(
        make_cve_enrichment(
            "CVE-2021-44228",
            cvss_score=9.8,
        ),
        make_cve_enrichment(
            "CVE-2022-22965",
            cvss_score=5.0,
        ),
    )

    result = score_finding(finding, enrichment, make_scope_result())

    assert len(result.contributing_cves) == 2
    assert {cve.cve_id for cve in result.contributing_cves} == {
        "CVE-2021-44228",
        "CVE-2022-22965",
    }
    assert result.contributing_cves[0].base_severity.nominal == 98.0
    assert result.contributing_cves[1].base_severity.nominal == 50.0


def test_highest_upper_risk_cve_becomes_governing_cve() -> None:
    from deprisk.vulnerability.scoring_service import score_finding

    finding = make_finding(
        cve_ids=("CVE-2021-44228", "CVE-2022-22965"),
    )
    enrichment = make_enrichment_result(
        make_cve_enrichment("CVE-2021-44228", cvss_score=5.0),
        make_cve_enrichment("CVE-2022-22965", cvss_score=9.8),
    )

    result = score_finding(finding, enrichment, make_scope_result())

    assert result.governing_cve_id == "CVE-2022-22965"
    assert len(result.contributing_cves) == 2


def test_governing_cve_uses_nominal_risk_as_tie_breaker() -> None:
    from deprisk.vulnerability.scoring_service import score_finding

    finding = make_finding(
        cve_ids=("CVE-2021-44228", "CVE-2022-22965"),
    )
    enrichment = make_enrichment_result(
        make_cve_enrichment("CVE-2021-44228", cvss_score=8.0),
        make_cve_enrichment(
            "CVE-2022-22965",
            cvss_score=8.0,
            ransomware_use="Known",
        ),
    )

    result = score_finding(finding, enrichment, make_scope_result())

    assessments = {cve.cve_id: cve for cve in result.contributing_cves}
    first = assessments["CVE-2021-44228"].operational_risk
    second = assessments["CVE-2022-22965"].operational_risk

    assert first.upper == second.upper
    assert second.nominal > first.nominal
    assert result.governing_cve_id == "CVE-2022-22965"


def test_missing_finding_enrichment_is_rejected() -> None:
    from deprisk.vulnerability.scoring_service import score_finding

    finding = make_finding()
    unrelated_enrichment = make_enrichment_result(
        make_cve_enrichment(),
        canonical_advisory_id="GHSA-unrelated",
    )

    with pytest.raises(ValueError):
        score_finding(
            finding,
            unrelated_enrichment,
            make_scope_result(),
        )


def test_missing_cve_enrichment_is_rejected() -> None:
    from deprisk.vulnerability.scoring_service import score_finding

    finding = make_finding(
        cve_ids=("CVE-2021-44228", "CVE-2022-22965"),
    )
    incomplete_enrichment = make_enrichment_result(
        make_cve_enrichment("CVE-2021-44228"),
    )

    with pytest.raises(ValueError):
        score_finding(
            finding,
            incomplete_enrichment,
            make_scope_result(),
        )
