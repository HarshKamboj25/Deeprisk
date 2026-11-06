"""Tests for OSV advisory normalization."""

import json
from pathlib import Path

import pytest

from deprisk.core.models import AdvisorySeverity
from deprisk.vulnerability.osv_models import OSVAdvisory
from deprisk.vulnerability.osv_normalizer import normalize_osv_advisory


def make_advisory(**overrides: object) -> OSVAdvisory:
    values: dict[str, object] = {
        "id": "GHSA-example",
        "summary": "Example vulnerability",
        "aliases": ["CVE-2026-1234"],
        "database_specific": {"severity": "HIGH"},
        "severity": [
            {
                "type": "CVSS_V3",
                "score": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
            }
        ],
    }
    values.update(overrides)
    return OSVAdvisory.model_validate(values)


def test_normalizes_high_severity_and_aliases() -> None:
    result = normalize_osv_advisory(make_advisory())

    assert result.advisory_id == "GHSA-example"
    assert result.aliases == ("CVE-2026-1234",)
    assert result.summary == "Example vulnerability"
    assert result.severity is AdvisorySeverity.HIGH
    assert result.source == "OSV"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("CRITICAL", AdvisorySeverity.CRITICAL),
        ("HIGH", AdvisorySeverity.HIGH),
        ("MODERATE", AdvisorySeverity.MEDIUM),
        ("MEDIUM", AdvisorySeverity.MEDIUM),
        ("LOW", AdvisorySeverity.LOW),
        ("unknown-value", AdvisorySeverity.UNKNOWN),
    ],
)
def test_maps_database_severity(raw: str, expected: AdvisorySeverity) -> None:
    advisory = make_advisory(database_specific={"severity": raw})
    assert normalize_osv_advisory(advisory).severity is expected


def test_missing_severity_defaults_to_unknown() -> None:
    advisory = make_advisory(database_specific={}, severity=[])
    assert normalize_osv_advisory(advisory).severity is AdvisorySeverity.UNKNOWN


def test_cvss_vector_is_not_mistaken_for_numeric_score() -> None:
    result = normalize_osv_advisory(make_advisory())

    assert result.cvss_score is None


def test_duplicate_and_self_aliases_are_removed() -> None:
    advisory = make_advisory(
        aliases=["CVE-2026-1234", "CVE-2026-1234", "GHSA-example", " CVE-2026-5678 "]
    )
    assert normalize_osv_advisory(advisory).aliases == (
        "CVE-2026-1234",
        "CVE-2026-5678",
    )


def test_normalizes_captured_osv_advisory() -> None:
    path = (
        Path(__file__).resolve().parents[3]
        / "eval"
        / "spikes"
        / "e1"
        / "osv_vulnerability_detail.json"
    )
    capture = json.loads(path.read_text(encoding="utf-8"))
    advisory = OSVAdvisory.model_validate(capture["response"])

    result = normalize_osv_advisory(advisory)

    assert result.advisory_id == "GHSA-35jh-r3h4-6jhm"
    assert result.aliases == ("CVE-2021-23337",)
    assert result.severity is AdvisorySeverity.HIGH
    assert result.cvss_score is None
