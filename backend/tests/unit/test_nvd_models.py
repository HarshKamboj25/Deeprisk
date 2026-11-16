import pytest
from pydantic import ValidationError

from deprisk.vulnerability.enrichment_models import (
    IntelligenceSource,
    IntelligenceStatus,
    NVDRecord,
    NVDResult,
    SourceAvailability,
)


def make_record(**overrides: object) -> NVDRecord:
    data: dict[str, object] = {
        "cve_id": "CVE-2021-44228",
        "cvss_version": "3.1",
        "source": "nvd@nist.gov",
        "metric_type": "Primary",
        "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "base_score": 10.0,
        "base_severity": "CRITICAL",
        "exploitability_score": 3.9,
        "impact_score": 6.0,
    }
    data.update(overrides)
    return NVDRecord.model_validate(data)


@pytest.mark.parametrize("version", ["4.0", "3.1", "3.0", "2.0"])
def test_nvd_record_accepts_supported_cvss_versions(version: str) -> None:
    record = make_record(cvss_version=version)
    assert record.cvss_version == version


def test_nvd_record_preserves_metric_metadata() -> None:
    record = make_record()
    assert record.source == "nvd@nist.gov"
    assert record.metric_type == "Primary"
    assert record.base_score == 10.0
    assert record.base_severity == "CRITICAL"


@pytest.mark.parametrize("score", [0.0, 10.0, 5.5])
def test_nvd_record_accepts_valid_base_scores(score: float) -> None:
    assert make_record(base_score=score).base_score == score


@pytest.mark.parametrize("score", [-0.1, 10.1])
def test_nvd_record_rejects_out_of_range_base_scores(score: float) -> None:
    with pytest.raises(ValidationError):
        make_record(base_score=score)


def test_nvd_record_allows_missing_optional_metadata() -> None:
    record = make_record(
        base_severity=None,
        exploitability_score=None,
        impact_score=None,
    )
    assert record.base_severity is None
    assert record.exploitability_score is None
    assert record.impact_score is None


@pytest.mark.parametrize(
    "field",
    ["cve_id", "cvss_version", "source", "metric_type", "vector_string"],
)
def test_nvd_record_rejects_empty_required_strings(field: str) -> None:
    with pytest.raises(ValidationError):
        make_record(**{field: ""})


def test_nvd_result_supports_available_record() -> None:
    result = NVDResult(
        availability=SourceAvailability(
            source=IntelligenceSource.NVD,
            status=IntelligenceStatus.AVAILABLE,
        ),
        record=make_record(),
    )
    assert result.record is not None
    assert result.availability.status == IntelligenceStatus.AVAILABLE


def test_nvd_result_supports_missing_cvss_without_zero_score() -> None:
    result = NVDResult(
        availability=SourceAvailability(
            source=IntelligenceSource.NVD,
            status=IntelligenceStatus.NOT_FOUND,
            reason="No CVSS metrics available",
        ),
        record=None,
    )
    assert result.record is None
    assert result.availability.status == IntelligenceStatus.NOT_FOUND
