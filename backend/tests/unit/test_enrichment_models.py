import pytest
from pydantic import ValidationError

from deprisk.vulnerability.enrichment_models import (
    EPSSRecord,
    EPSSResult,
    IntelligenceSource,
    IntelligenceStatus,
    SourceAvailability,
)


def test_valid_epss_record_accepts_decimal_values() -> None:
    record = EPSSRecord(
        cve="CVE-2021-44228",
        epss="0.999990000",
        percentile="1.000000000",
        score_date="2026-11-05",
    )

    assert record.epss == pytest.approx(0.99999)
    assert record.percentile == 1.0


@pytest.mark.parametrize("score", [-0.01, 1.01])
def test_epss_score_rejects_values_outside_range(score: float) -> None:
    with pytest.raises(ValidationError):
        EPSSRecord(
            cve="CVE-2026-1234",
            epss=score,
            percentile=0.5,
            score_date="2026-11-05",
        )


def test_epss_result_can_represent_missing_record() -> None:
    result = EPSSResult(
        availability=SourceAvailability(
            source=IntelligenceSource.EPSS,
            status=IntelligenceStatus.NOT_FOUND,
            reason="No matching CVE record returned by EPSS.",
        ),
        record=None,
    )

    assert result.record is None
    assert result.availability.status is IntelligenceStatus.NOT_FOUND


def test_unavailable_source_is_not_treated_as_zero_risk() -> None:
    result = EPSSResult(
        availability=SourceAvailability(
            source=IntelligenceSource.EPSS,
            status=IntelligenceStatus.UNAVAILABLE,
            reason="EPSS service timed out.",
        ),
    )

    assert result.record is None
    assert result.availability.status is IntelligenceStatus.UNAVAILABLE


def test_not_requested_source_is_explicit() -> None:
    availability = SourceAvailability(
        source=IntelligenceSource.NVD,
        status=IntelligenceStatus.NOT_REQUESTED,
    )

    assert availability.status is IntelligenceStatus.NOT_REQUESTED


def test_enrichment_models_are_immutable() -> None:
    record = EPSSRecord(
        cve="CVE-2021-44228",
        epss=0.9,
        percentile=0.99,
        score_date="2026-11-05",
    )

    with pytest.raises(ValidationError):
        record.epss = 0.1  # type: ignore[misc]


def test_unknown_upstream_fields_are_preserved() -> None:
    availability = SourceAvailability(
        source=IntelligenceSource.EPSS,
        status=IntelligenceStatus.AVAILABLE,
        upstream_field="future-schema-value",
    )

    assert availability.model_extra == {"upstream_field": "future-schema-value"}
