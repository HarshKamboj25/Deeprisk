"""Unit tests for Risk Scoring v1 domain models."""

import pytest
from pydantic import ValidationError

from deprisk.core.models import FindingEvidence
from deprisk.core.scope import EffectiveScope
from deprisk.vulnerability.enrichment_models import (
    IntelligenceSource,
    IntelligenceStatus,
)
from deprisk.vulnerability.scoring_models import (
    CVEAssessment,
    FindingRiskAssessmentV1,
    RepositoryRiskSummary,
    RiskDistribution,
    ScoreInterval,
    ScoringVersion,
    SeveritySource,
    TriStateStatus,
    UnitInterval,
)

# --- Helpers -----------------------------------------------------------------


def _score_interval(
    lower: float = 10.0, nominal: float = 50.0, upper: float = 90.0
) -> ScoreInterval:
    return ScoreInterval(lower=lower, nominal=nominal, upper=upper)


def _unit_interval(lower: float = 0.1, nominal: float = 0.5, upper: float = 0.9) -> UnitInterval:
    return UnitInterval(lower=lower, nominal=nominal, upper=upper)


def _cve_assessment(
    cve_id: str = "CVE-2024-1234",
    base_severity: ScoreInterval | None = None,
    severity_source: SeveritySource = SeveritySource.NVD_CVSS,
    cvss_score: float | None = 7.5,
    cvss_version: str | None = "3.1",
    cvss_status: IntelligenceStatus = IntelligenceStatus.AVAILABLE,
    epss_status: IntelligenceStatus = IntelligenceStatus.AVAILABLE,
    epss_probability: float | None = 0.25,
    epss_percentile: float | None = 0.80,
    epss_upper_bound_is_hypothetical: bool = False,
    kev_status: IntelligenceStatus = IntelligenceStatus.AVAILABLE,
    is_in_kev: TriStateStatus = TriStateStatus.POSITIVE,
    known_ransomware_campaign_use: TriStateStatus = TriStateStatus.UNKNOWN,
    threat_factor: UnitInterval | None = None,
    unattenuated_severity: ScoreInterval | None = None,
    operational_risk: ScoreInterval | None = None,
    evidence: tuple[FindingEvidence, ...] = (),
) -> CVEAssessment:
    return CVEAssessment(
        cve_id=cve_id,
        base_severity=base_severity or _score_interval(75.0, 75.0, 75.0),
        severity_source=severity_source,
        cvss_score=cvss_score,
        cvss_version=cvss_version,
        cvss_status=cvss_status,
        epss_status=epss_status,
        epss_probability=epss_probability,
        epss_percentile=epss_percentile,
        epss_upper_bound_is_hypothetical=epss_upper_bound_is_hypothetical,
        kev_status=kev_status,
        is_in_kev=is_in_kev,
        known_ransomware_campaign_use=known_ransomware_campaign_use,
        threat_factor=threat_factor or _unit_interval(0.2, 0.4, 0.6),
        unattenuated_severity=unattenuated_severity or _score_interval(75.0, 80.0, 85.0),
        operational_risk=operational_risk or _score_interval(75.0, 80.0, 85.0),
        evidence=evidence,
    )


# --- 1. ScoreInterval Tests --------------------------------------------------


def test_score_interval_valid_bounds() -> None:
    interval = ScoreInterval(lower=10.0, nominal=50.0, upper=90.0)
    assert interval.lower == 10.0
    assert interval.nominal == 50.0
    assert interval.upper == 90.0


def test_score_interval_collapsed_boundary_values() -> None:
    zero_interval = ScoreInterval(lower=0.0, nominal=0.0, upper=0.0)
    assert zero_interval.lower == 0.0
    assert zero_interval.nominal == 0.0
    assert zero_interval.upper == 0.0

    hundred_interval = ScoreInterval(lower=100.0, nominal=100.0, upper=100.0)
    assert hundred_interval.lower == 100.0
    assert hundred_interval.nominal == 100.0
    assert hundred_interval.upper == 100.0


def test_score_interval_rejects_negative_lower() -> None:
    with pytest.raises(ValidationError):
        ScoreInterval(lower=-0.1, nominal=50.0, upper=90.0)


def test_score_interval_rejects_upper_exceeding_one_hundred() -> None:
    with pytest.raises(ValidationError):
        ScoreInterval(lower=10.0, nominal=50.0, upper=100.1)


def test_score_interval_rejects_nominal_less_than_lower() -> None:
    with pytest.raises(ValidationError, match="ScoreInterval ordering violated"):
        ScoreInterval(lower=50.0, nominal=40.0, upper=60.0)


def test_score_interval_rejects_upper_less_than_nominal() -> None:
    with pytest.raises(ValidationError, match="ScoreInterval ordering violated"):
        ScoreInterval(lower=10.0, nominal=50.0, upper=40.0)


def test_score_interval_is_frozen() -> None:
    interval = ScoreInterval(lower=10.0, nominal=50.0, upper=90.0)
    with pytest.raises(ValidationError):
        interval.lower = 20.0  # type: ignore[misc]


# --- 2. UnitInterval Tests ---------------------------------------------------


def test_unit_interval_valid_bounds() -> None:
    interval = UnitInterval(lower=0.1, nominal=0.5, upper=0.9)
    assert interval.lower == 0.1
    assert interval.nominal == 0.5
    assert interval.upper == 0.9


def test_unit_interval_collapsed_boundary_values() -> None:
    zero = UnitInterval(lower=0.0, nominal=0.0, upper=0.0)
    assert zero.lower == 0.0
    assert zero.nominal == 0.0
    assert zero.upper == 0.0

    one = UnitInterval(lower=1.0, nominal=1.0, upper=1.0)
    assert one.lower == 1.0
    assert one.nominal == 1.0
    assert one.upper == 1.0


def test_unit_interval_rejects_negative_lower() -> None:
    with pytest.raises(ValidationError):
        UnitInterval(lower=-0.01, nominal=0.5, upper=0.9)


def test_unit_interval_rejects_upper_exceeding_one() -> None:
    with pytest.raises(ValidationError):
        UnitInterval(lower=0.1, nominal=0.5, upper=1.01)


def test_unit_interval_rejects_nominal_less_than_lower() -> None:
    with pytest.raises(ValidationError, match="UnitInterval ordering violated"):
        UnitInterval(lower=0.5, nominal=0.4, upper=0.6)


def test_unit_interval_rejects_upper_less_than_nominal() -> None:
    with pytest.raises(ValidationError, match="UnitInterval ordering violated"):
        UnitInterval(lower=0.1, nominal=0.5, upper=0.4)


def test_unit_interval_is_frozen() -> None:
    interval = UnitInterval(lower=0.1, nominal=0.5, upper=0.9)
    with pytest.raises(ValidationError):
        interval.lower = 0.2  # type: ignore[misc]


# --- 3. EPSS Status and Hypothetical Flag Consistency ------------------------


def test_epss_available_valid_combination() -> None:
    assessment = _cve_assessment(
        epss_status=IntelligenceStatus.AVAILABLE,
        epss_probability=0.42,
        epss_percentile=0.91,
        epss_upper_bound_is_hypothetical=False,
    )
    assert assessment.epss_probability == 0.42
    assert assessment.epss_percentile == 0.91
    assert assessment.epss_upper_bound_is_hypothetical is False


def test_epss_available_rejects_missing_probability() -> None:
    with pytest.raises(
        ValidationError,
        match="epss_probability is required when epss_status is AVAILABLE",
    ):
        _cve_assessment(
            epss_status=IntelligenceStatus.AVAILABLE,
            epss_probability=None,
            epss_upper_bound_is_hypothetical=False,
        )


def test_epss_available_rejects_hypothetical_true() -> None:
    with pytest.raises(
        ValidationError,
        match="epss_upper_bound_is_hypothetical must be False when epss_status is AVAILABLE",
    ):
        _cve_assessment(
            epss_status=IntelligenceStatus.AVAILABLE,
            epss_probability=0.42,
            epss_upper_bound_is_hypothetical=True,
        )


@pytest.mark.parametrize(
    "status",
    [
        IntelligenceStatus.NOT_FOUND,
        IntelligenceStatus.UNAVAILABLE,
        IntelligenceStatus.NOT_REQUESTED,
    ],
)
def test_epss_missing_valid_combination(status: IntelligenceStatus) -> None:
    assessment = _cve_assessment(
        epss_status=status,
        epss_probability=None,
        epss_percentile=None,
        epss_upper_bound_is_hypothetical=True,
    )
    assert assessment.epss_status is status
    assert assessment.epss_probability is None
    assert assessment.epss_upper_bound_is_hypothetical is True


@pytest.mark.parametrize(
    "status",
    [
        IntelligenceStatus.NOT_FOUND,
        IntelligenceStatus.UNAVAILABLE,
        IntelligenceStatus.NOT_REQUESTED,
    ],
)
def test_epss_missing_rejects_hypothetical_false(status: IntelligenceStatus) -> None:
    with pytest.raises(
        ValidationError,
        match=f"epss_upper_bound_is_hypothetical must be True when epss_status is {status}",
    ):
        _cve_assessment(
            epss_status=status,
            epss_probability=None,
            epss_upper_bound_is_hypothetical=False,
        )


@pytest.mark.parametrize(
    "status",
    [
        IntelligenceStatus.NOT_FOUND,
        IntelligenceStatus.UNAVAILABLE,
        IntelligenceStatus.NOT_REQUESTED,
    ],
)
def test_epss_missing_rejects_non_none_probability(
    status: IntelligenceStatus,
) -> None:
    with pytest.raises(
        ValidationError,
        match=f"epss_probability must be None when epss_status is {status}",
    ):
        _cve_assessment(
            epss_status=status,
            epss_probability=0.05,
            epss_upper_bound_is_hypothetical=True,
        )


# --- 4. Tri-State KEV and Ransomware Tests -----------------------------------


@pytest.mark.parametrize("status", list(TriStateStatus))
def test_kev_status_and_ransomware_accepts_all_tristates(
    status: TriStateStatus,
) -> None:
    kev_status = {
        TriStateStatus.POSITIVE: IntelligenceStatus.AVAILABLE,
        TriStateStatus.NEGATIVE: IntelligenceStatus.NOT_FOUND,
        TriStateStatus.UNKNOWN: IntelligenceStatus.UNAVAILABLE,
    }[status]

    assessment = _cve_assessment(
        kev_status=kev_status,
        is_in_kev=status,
        known_ransomware_campaign_use=status,
    )
    assert assessment.is_in_kev is status
    assert assessment.known_ransomware_campaign_use is status


def test_ransomware_defaults_to_unknown() -> None:
    assessment = CVEAssessment(
        cve_id="CVE-2024-9999",
        base_severity=_score_interval(50.0, 50.0, 50.0),
        severity_source=SeveritySource.NVD_CVSS,
        cvss_score=5.0,
        cvss_version="3.1",
        cvss_status=IntelligenceStatus.AVAILABLE,
        epss_status=IntelligenceStatus.NOT_FOUND,
        epss_probability=None,
        epss_upper_bound_is_hypothetical=True,
        kev_status=IntelligenceStatus.UNAVAILABLE,
        is_in_kev=TriStateStatus.UNKNOWN,
        threat_factor=_unit_interval(0.0, 0.2, 0.4),
        unattenuated_severity=_score_interval(50.0, 55.0, 60.0),
        operational_risk=_score_interval(50.0, 55.0, 60.0),
    )
    assert assessment.known_ransomware_campaign_use is TriStateStatus.UNKNOWN


@pytest.mark.parametrize(
    ("kev_status", "is_in_kev"),
    [
        (IntelligenceStatus.AVAILABLE, TriStateStatus.POSITIVE),
        (IntelligenceStatus.NOT_FOUND, TriStateStatus.NEGATIVE),
        (IntelligenceStatus.UNAVAILABLE, TriStateStatus.UNKNOWN),
        (IntelligenceStatus.NOT_REQUESTED, TriStateStatus.UNKNOWN),
    ],
)
def test_kev_status_accepts_consistent_tristate(
    kev_status: IntelligenceStatus,
    is_in_kev: TriStateStatus,
) -> None:
    assessment = _cve_assessment(
        kev_status=kev_status,
        is_in_kev=is_in_kev,
    )
    assert assessment.kev_status is kev_status
    assert assessment.is_in_kev is is_in_kev


@pytest.mark.parametrize(
    ("kev_status", "is_in_kev"),
    [
        (IntelligenceStatus.AVAILABLE, TriStateStatus.NEGATIVE),
        (IntelligenceStatus.AVAILABLE, TriStateStatus.UNKNOWN),
        (IntelligenceStatus.NOT_FOUND, TriStateStatus.POSITIVE),
        (IntelligenceStatus.NOT_FOUND, TriStateStatus.UNKNOWN),
        (IntelligenceStatus.UNAVAILABLE, TriStateStatus.POSITIVE),
        (IntelligenceStatus.UNAVAILABLE, TriStateStatus.NEGATIVE),
        (IntelligenceStatus.NOT_REQUESTED, TriStateStatus.POSITIVE),
        (IntelligenceStatus.NOT_REQUESTED, TriStateStatus.NEGATIVE),
    ],
)
def test_kev_status_rejects_inconsistent_tristate(
    kev_status: IntelligenceStatus,
    is_in_kev: TriStateStatus,
) -> None:
    with pytest.raises(ValidationError, match="KEV"):
        _cve_assessment(
            kev_status=kev_status,
            is_in_kev=is_in_kev,
        )


# --- 5. Severity Provenance Tests --------------------------------------------


@pytest.mark.parametrize("version", ["4.0", "3.1", "3.0", "2.0"])
def test_severity_provenance_accepts_supported_cvss_versions(version: str) -> None:
    assessment = _cve_assessment(
        cvss_version=version,
        cvss_score=7.5,
        base_severity=_score_interval(75.0, 75.0, 75.0),
    )
    assert assessment.cvss_version == version


@pytest.mark.parametrize("version", [None, "", "5.0", "3.2"])
def test_severity_provenance_rejects_unsupported_cvss_versions(
    version: str | None,
) -> None:
    with pytest.raises(ValidationError, match="cvss_version"):
        _cve_assessment(cvss_version=version)


def test_severity_provenance_nvd_rejects_mismatched_base_severity() -> None:
    with pytest.raises(ValidationError, match="base_severity"):
        _cve_assessment(
            cvss_score=7.5,
            cvss_version="3.1",
            base_severity=_score_interval(70.0, 75.0, 80.0),
        )


def test_severity_provenance_fallback_rejects_cvss_version() -> None:
    with pytest.raises(ValidationError, match="cvss_version"):
        _cve_assessment(
            severity_source=SeveritySource.ADVISORY_SEVERITY_FALLBACK,
            cvss_score=None,
            cvss_version="3.1",
            cvss_status=IntelligenceStatus.NOT_FOUND,
            base_severity=_score_interval(70.0, 79.95, 89.9),
        )


def test_severity_provenance_nvd_cvss() -> None:
    assessment = _cve_assessment(
        severity_source=SeveritySource.NVD_CVSS,
        cvss_score=9.8,
        cvss_version="3.1",
        base_severity=_score_interval(98.0, 98.0, 98.0),
    )
    assert assessment.severity_source is SeveritySource.NVD_CVSS
    assert assessment.cvss_score == 9.8
    assert assessment.cvss_version == "3.1"
    assert assessment.base_severity.lower == 98.0
    assert assessment.base_severity.upper == 98.0


def test_severity_provenance_advisory_fallback_interval() -> None:
    # High severity bracket: [70.0, 89.9]
    high_bracket = _score_interval(lower=70.0, nominal=79.95, upper=89.9)
    assessment = _cve_assessment(
        severity_source=SeveritySource.ADVISORY_SEVERITY_FALLBACK,
        cvss_score=None,
        cvss_version=None,
        cvss_status=IntelligenceStatus.NOT_FOUND,
        base_severity=high_bracket,
    )
    assert assessment.severity_source is SeveritySource.ADVISORY_SEVERITY_FALLBACK
    assert assessment.cvss_score is None
    assert assessment.cvss_version is None
    assert assessment.base_severity.lower == 70.0
    assert assessment.base_severity.upper == 89.9


def test_severity_provenance_nvd_cvss_rejects_none_score() -> None:
    with pytest.raises(
        ValidationError,
        match="cvss_score is required when severity_source is NVD_CVSS",
    ):
        _cve_assessment(
            severity_source=SeveritySource.NVD_CVSS,
            cvss_score=None,
            cvss_status=IntelligenceStatus.AVAILABLE,
        )


def test_severity_provenance_nvd_cvss_rejects_non_available_status() -> None:
    with pytest.raises(
        ValidationError,
        match="cvss_status must be AVAILABLE when severity_source is NVD_CVSS",
    ):
        _cve_assessment(
            severity_source=SeveritySource.NVD_CVSS,
            cvss_score=8.0,
            cvss_status=IntelligenceStatus.NOT_FOUND,
        )


def test_severity_provenance_fallback_rejects_cvss_score() -> None:
    with pytest.raises(
        ValidationError,
        match="cvss_score must be None when severity_source is ADVISORY_SEVERITY_FALLBACK",
    ):
        _cve_assessment(
            severity_source=SeveritySource.ADVISORY_SEVERITY_FALLBACK,
            cvss_score=7.5,
            cvss_status=IntelligenceStatus.NOT_FOUND,
        )


def test_severity_provenance_fallback_rejects_available_cvss_status() -> None:
    with pytest.raises(
        ValidationError,
        match="cvss_status cannot be AVAILABLE when severity_source is ADVISORY_SEVERITY_FALLBACK",
    ):
        _cve_assessment(
            severity_source=SeveritySource.ADVISORY_SEVERITY_FALLBACK,
            cvss_score=None,
            cvss_version=None,
            cvss_status=IntelligenceStatus.AVAILABLE,
        )


# --- 6. Nested Multi-CVE Finding Assessment Tests ----------------------------


def test_finding_risk_assessment_with_governing_and_contributing_cves() -> None:
    cve_1 = _cve_assessment(
        cve_id="CVE-2024-0001",
        cvss_score=9.8,
        base_severity=_score_interval(98.0, 98.0, 98.0),
    )
    cve_2 = _cve_assessment(
        cve_id="CVE-2024-0002",
        cvss_score=5.0,
        base_severity=_score_interval(50.0, 50.0, 50.0),
    )

    finding = FindingRiskAssessmentV1(
        governing_cve_id="CVE-2024-0001",
        risk_interval=_score_interval(70.0, 85.0, 98.0),
        unattenuated_severity=_score_interval(98.0, 98.0, 100.0),
        governing_scope=EffectiveScope.PRODUCTION,
        exposure_multiplier=_unit_interval(1.0, 1.0, 1.0),
        is_unreachable=False,
        affected_install_paths=("node_modules/example",),
        contributing_cves=(cve_1, cve_2),
        missing_sources=(),
        evidence=(
            FindingEvidence(
                kind="governing_cve",
                description="Governing CVE-2024-0001 chosen by highest upper risk bound.",
            ),
        ),
    )

    assert finding.scoring_version is ScoringVersion.V1
    assert finding.governing_cve_id == "CVE-2024-0001"
    assert len(finding.contributing_cves) == 2
    assert finding.contributing_cves[0].cve_id == "CVE-2024-0001"
    assert finding.contributing_cves[1].cve_id == "CVE-2024-0002"
    assert finding.evidence[0].kind == "governing_cve"


def test_finding_risk_assessment_rejects_governing_cve_not_in_contributing_cves() -> None:
    cve_1 = _cve_assessment(cve_id="CVE-2024-0001")

    with pytest.raises(
        ValidationError,
        match="governing_cve_id 'CVE-2024-9999' not found in contributing_cves",
    ):
        FindingRiskAssessmentV1(
            governing_cve_id="CVE-2024-9999",
            risk_interval=_score_interval(10.0, 20.0, 30.0),
            unattenuated_severity=_score_interval(10.0, 20.0, 30.0),
            governing_scope=EffectiveScope.PRODUCTION,
            exposure_multiplier=_unit_interval(1.0, 1.0, 1.0),
            affected_install_paths=("node_modules/example",),
            contributing_cves=(cve_1,),
        )


def test_finding_risk_assessment_supports_zero_cves() -> None:
    finding = FindingRiskAssessmentV1(
        governing_cve_id=None,
        risk_interval=_score_interval(30.0, 45.0, 60.0),
        unattenuated_severity=_score_interval(40.0, 50.0, 60.0),
        governing_scope=EffectiveScope.DEVELOPMENT,
        exposure_multiplier=_unit_interval(0.3, 0.3, 0.3),
        is_unreachable=False,
        affected_install_paths=("node_modules/ghsa-only",),
        contributing_cves=(),
        missing_sources=(IntelligenceSource.EPSS, IntelligenceSource.CISA_KEV),
    )
    assert finding.governing_cve_id is None
    assert finding.contributing_cves == ()
    assert len(finding.missing_sources) == 2


@pytest.mark.parametrize(
    ("scope", "exposure"),
    [
        (EffectiveScope.PRODUCTION, 1.0),
        (EffectiveScope.PEER, 1.0),
        (EffectiveScope.OPTIONAL, 0.70),
        (EffectiveScope.DEV_OPTIONAL, 0.35),
        (EffectiveScope.DEVELOPMENT, 0.30),
    ],
)
def test_scope_exposure_mapping_accepts_fixed_values(
    scope: EffectiveScope, exposure: float
) -> None:
    finding = FindingRiskAssessmentV1(
        governing_cve_id=None,
        risk_interval=_score_interval(10.0, 20.0, 30.0),
        unattenuated_severity=_score_interval(40.0, 50.0, 60.0),
        governing_scope=scope,
        exposure_multiplier=_unit_interval(exposure, exposure, exposure),
        affected_install_paths=("node_modules/example",),
    )
    assert finding.governing_scope is scope
    assert finding.exposure_multiplier.nominal == exposure


def test_scope_exposure_mapping_accepts_unknown_interval() -> None:
    finding = FindingRiskAssessmentV1(
        governing_cve_id=None,
        risk_interval=_score_interval(10.0, 20.0, 30.0),
        unattenuated_severity=_score_interval(40.0, 50.0, 60.0),
        governing_scope=EffectiveScope.UNKNOWN,
        exposure_multiplier=_unit_interval(0.30, 0.65, 1.00),
        affected_install_paths=("node_modules/example",),
    )
    assert finding.governing_scope is EffectiveScope.UNKNOWN


@pytest.mark.parametrize(
    ("scope", "exposure"),
    [
        (EffectiveScope.PRODUCTION, 0.70),
        (EffectiveScope.PEER, 0.35),
        (EffectiveScope.OPTIONAL, 1.00),
        (EffectiveScope.DEV_OPTIONAL, 0.30),
        (EffectiveScope.DEVELOPMENT, 0.70),
    ],
)
def test_scope_exposure_mapping_rejects_incorrect_fixed_values(
    scope: EffectiveScope, exposure: float
) -> None:
    with pytest.raises(ValidationError, match="exposure_multiplier"):
        FindingRiskAssessmentV1(
            governing_cve_id=None,
            risk_interval=_score_interval(10.0, 20.0, 30.0),
            unattenuated_severity=_score_interval(40.0, 50.0, 60.0),
            governing_scope=scope,
            exposure_multiplier=_unit_interval(exposure, exposure, exposure),
            affected_install_paths=("node_modules/example",),
        )


def test_unknown_scope_rejects_exposure_outside_policy_bounds() -> None:
    with pytest.raises(ValidationError, match="exposure_multiplier"):
        FindingRiskAssessmentV1(
            governing_cve_id=None,
            risk_interval=_score_interval(10.0, 20.0, 30.0),
            unattenuated_severity=_score_interval(40.0, 50.0, 60.0),
            governing_scope=EffectiveScope.UNKNOWN,
            exposure_multiplier=_unit_interval(0.20, 0.50, 0.90),
            affected_install_paths=("node_modules/example",),
        )


def test_finding_risk_assessment_requires_governing_cve_when_contributing_cves_exist() -> None:
    cve_1 = _cve_assessment(cve_id="CVE-2024-0001")
    with pytest.raises(
        ValidationError,
        match="governing_cve_id is required when contributing_cves is non-empty",
    ):
        FindingRiskAssessmentV1(
            governing_cve_id=None,
            risk_interval=_score_interval(10.0, 20.0, 30.0),
            unattenuated_severity=_score_interval(10.0, 20.0, 30.0),
            governing_scope=EffectiveScope.PRODUCTION,
            exposure_multiplier=_unit_interval(1.0, 1.0, 1.0),
            affected_install_paths=("node_modules/example",),
            contributing_cves=(cve_1,),
        )


def test_finding_risk_assessment_rejects_governing_cve_when_contributing_cves_empty() -> None:
    with pytest.raises(
        ValidationError,
        match="governing_cve_id must be None when contributing_cves is empty",
    ):
        FindingRiskAssessmentV1(
            governing_cve_id="CVE-2024-0001",
            risk_interval=_score_interval(10.0, 20.0, 30.0),
            unattenuated_severity=_score_interval(10.0, 20.0, 30.0),
            governing_scope=EffectiveScope.PRODUCTION,
            exposure_multiplier=_unit_interval(1.0, 1.0, 1.0),
            affected_install_paths=("node_modules/example",),
            contributing_cves=(),
        )


# --- 7. Serialization & Deserialization --------------------------------------


def test_cve_assessment_serialization_roundtrip() -> None:
    cve = _cve_assessment()
    raw = cve.model_dump(mode="json")

    assert raw["cve_id"] == "CVE-2024-1234"
    assert raw["severity_source"] == "nvd_cvss"
    assert raw["is_in_kev"] == "positive"
    assert raw["epss_upper_bound_is_hypothetical"] is False

    reconstructed = CVEAssessment.model_validate(raw)
    assert reconstructed == cve


def test_finding_risk_assessment_serialization_roundtrip() -> None:
    cve = _cve_assessment()
    finding = FindingRiskAssessmentV1(
        governing_cve_id=cve.cve_id,
        risk_interval=_score_interval(20.0, 40.0, 60.0),
        unattenuated_severity=_score_interval(50.0, 60.0, 70.0),
        governing_scope=EffectiveScope.OPTIONAL,
        exposure_multiplier=_unit_interval(0.7, 0.7, 0.7),
        is_unreachable=False,
        affected_install_paths=("node_modules/pkg",),
        contributing_cves=(cve,),
        missing_sources=(IntelligenceSource.NVD,),
    )

    raw = finding.model_dump(mode="json")
    assert raw["governing_scope"] == "optional"
    assert raw["scoring_version"] == "v1"

    reconstructed = FindingRiskAssessmentV1.model_validate(raw)
    assert reconstructed == finding


def test_repository_risk_summary_serialization_roundtrip() -> None:
    distribution = RiskDistribution(
        critical=2,
        high=5,
        medium=10,
        low=3,
        inactive_unreachable=1,
    )
    summary = RepositoryRiskSummary(
        peak_risk_interval=_score_interval(70.0, 85.0, 95.0),
        distribution=distribution,
        high_uncertainty_count=2,
    )

    raw = summary.model_dump(mode="json")
    assert raw["distribution"]["critical"] == 2
    assert raw["distribution"]["inactive_unreachable"] == 1
    assert raw["high_uncertainty_count"] == 2

    reconstructed = RepositoryRiskSummary.model_validate(raw)
    assert reconstructed == summary


@pytest.mark.parametrize(
    "field",
    ["critical", "high", "medium", "low", "inactive_unreachable"],
)
def test_risk_distribution_rejects_negative_value_for_every_count(
    field: str,
) -> None:
    values = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "inactive_unreachable": 0,
    }
    values[field] = -1

    with pytest.raises(ValidationError):
        RiskDistribution(**values)


def test_risk_distribution_is_frozen() -> None:
    distribution = RiskDistribution(
        critical=1,
        high=2,
        medium=3,
        low=4,
        inactive_unreachable=5,
    )
    with pytest.raises(ValidationError):
        distribution.critical = 10  # type: ignore[misc]


def test_repository_risk_summary_is_frozen() -> None:
    summary = RepositoryRiskSummary(
        peak_risk_interval=_score_interval(70.0, 80.0, 90.0),
        distribution=RiskDistribution(
            critical=1,
            high=2,
            medium=3,
            low=4,
            inactive_unreachable=0,
        ),
        high_uncertainty_count=2,
    )
    with pytest.raises(ValidationError):
        summary.high_uncertainty_count = 5  # type: ignore[misc]


def test_finding_risk_assessment_is_frozen() -> None:
    finding = FindingRiskAssessmentV1(
        governing_cve_id=None,
        risk_interval=_score_interval(20.0, 30.0, 40.0),
        unattenuated_severity=_score_interval(30.0, 40.0, 50.0),
        governing_scope=EffectiveScope.OPTIONAL,
        exposure_multiplier=_unit_interval(0.7, 0.7, 0.7),
        is_unreachable=False,
        affected_install_paths=("node_modules/example",),
        contributing_cves=(),
    )
    with pytest.raises(ValidationError):
        finding.is_unreachable = True  # type: ignore[misc]


# --- 8. Boundary Cases from Design -------------------------------------------


def test_maximum_severity_saturation_boundary() -> None:
    """When base severity is 100, headroom is 0, so threat-adjusted and operational
    risk collapse to 100 on both bounds when exposure is 1.0."""
    cve = _cve_assessment(
        cvss_score=10.0,
        base_severity=_score_interval(100.0, 100.0, 100.0),
        threat_factor=_unit_interval(0.0, 0.5, 1.0),
        unattenuated_severity=_score_interval(100.0, 100.0, 100.0),
        operational_risk=_score_interval(100.0, 100.0, 100.0),
    )
    assert cve.operational_risk.lower == 100.0
    assert cve.operational_risk.nominal == 100.0
    assert cve.operational_risk.upper == 100.0
    assert cve.threat_factor.lower < cve.threat_factor.upper


def test_unreachable_dependency_boundary_preserves_intrinsic_severity() -> None:
    """Unreachable dependency has operational risk 0.0, but unattenuated severity
    remains visible."""
    finding = FindingRiskAssessmentV1(
        governing_cve_id=None,
        risk_interval=_score_interval(0.0, 0.0, 0.0),
        unattenuated_severity=_score_interval(90.0, 95.0, 98.0),
        governing_scope=EffectiveScope.UNREACHABLE,
        exposure_multiplier=_unit_interval(0.0, 0.0, 0.0),
        is_unreachable=True,
        affected_install_paths=("node_modules/orphan",),
        contributing_cves=(),
    )
    assert finding.is_unreachable is True
    assert finding.risk_interval.lower == 0.0
    assert finding.risk_interval.upper == 0.0
    assert finding.unattenuated_severity.lower == 90.0
    assert finding.unattenuated_severity.upper == 98.0


def test_risk_distribution_rejects_negative_counts() -> None:
    with pytest.raises(ValidationError):
        RiskDistribution(
            critical=-1,
            high=0,
            medium=0,
            low=0,
            inactive_unreachable=0,
        )


# --- 9. Unreachable Consistency Negative Tests -------------------------------


def test_unreachable_finding_rejects_non_unreachable_scope() -> None:
    with pytest.raises(
        ValidationError,
        match="is_unreachable=True requires governing_scope to be EffectiveScope.UNREACHABLE",
    ):
        FindingRiskAssessmentV1(
            governing_cve_id=None,
            risk_interval=_score_interval(0.0, 0.0, 0.0),
            unattenuated_severity=_score_interval(90.0, 95.0, 98.0),
            governing_scope=EffectiveScope.PRODUCTION,
            exposure_multiplier=_unit_interval(0.0, 0.0, 0.0),
            is_unreachable=True,
            affected_install_paths=("node_modules/orphan",),
            contributing_cves=(),
        )


def test_unreachable_finding_rejects_non_zero_exposure_multiplier() -> None:
    with pytest.raises(
        ValidationError,
        match="is_unreachable=True requires exposure_multiplier to be exactly zero",
    ):
        FindingRiskAssessmentV1(
            governing_cve_id=None,
            risk_interval=_score_interval(0.0, 0.0, 0.0),
            unattenuated_severity=_score_interval(90.0, 95.0, 98.0),
            governing_scope=EffectiveScope.UNREACHABLE,
            exposure_multiplier=_unit_interval(0.0, 0.1, 0.2),
            is_unreachable=True,
            affected_install_paths=("node_modules/orphan",),
            contributing_cves=(),
        )


def test_unreachable_finding_rejects_non_zero_risk_interval() -> None:
    with pytest.raises(
        ValidationError,
        match="is_unreachable=True requires risk_interval to be exactly zero",
    ):
        FindingRiskAssessmentV1(
            governing_cve_id=None,
            risk_interval=_score_interval(0.0, 5.0, 10.0),
            unattenuated_severity=_score_interval(90.0, 95.0, 98.0),
            governing_scope=EffectiveScope.UNREACHABLE,
            exposure_multiplier=_unit_interval(0.0, 0.0, 0.0),
            is_unreachable=True,
            affected_install_paths=("node_modules/orphan",),
            contributing_cves=(),
        )


def test_non_unreachable_finding_rejects_unreachable_scope() -> None:
    with pytest.raises(
        ValidationError,
        match="is_unreachable=False cannot have governing_scope as EffectiveScope.UNREACHABLE",
    ):
        FindingRiskAssessmentV1(
            governing_cve_id=None,
            risk_interval=_score_interval(0.0, 0.0, 0.0),
            unattenuated_severity=_score_interval(90.0, 95.0, 98.0),
            governing_scope=EffectiveScope.UNREACHABLE,
            exposure_multiplier=_unit_interval(0.0, 0.0, 0.0),
            is_unreachable=False,
            affected_install_paths=("node_modules/orphan",),
            contributing_cves=(),
        )
