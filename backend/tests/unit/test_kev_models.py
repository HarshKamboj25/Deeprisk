import pytest
from pydantic import ValidationError

from deprisk.vulnerability.enrichment_models import (
    IntelligenceSource,
    IntelligenceStatus,
    KEVCatalog,
    KEVRecord,
    KEVResult,
    SourceAvailability,
)


def make_kev_record(**overrides: object) -> dict[str, object]:
    record: dict[str, object] = {
        "cveID": "CVE-2021-44228",
        "vendorProject": "Apache",
        "product": "Log4j2",
        "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
        "dateAdded": "2021-12-10",
        "shortDescription": "Remote code execution vulnerability.",
        "requiredAction": "Apply available updates.",
        "dueDate": "2021-12-24",
        "knownRansomwareCampaignUse": "Known",
        "forensicTriage": "No",
        "notes": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        "cwes": ["CWE-20", "CWE-400", "CWE-502"],
    }
    record.update(overrides)
    return record


def test_kev_record_parses_cisa_field_names() -> None:
    record = KEVRecord.model_validate(make_kev_record())

    assert record.cve_id == "CVE-2021-44228"
    assert record.vendor_project == "Apache"
    assert record.product == "Log4j2"
    assert record.known_ransomware_campaign_use == "Known"
    assert record.cwes == ("CWE-20", "CWE-400", "CWE-502")


def test_kev_record_allows_missing_optional_cwes() -> None:
    data = make_kev_record()
    data.pop("cwes")

    record = KEVRecord.model_validate(data)

    assert record.cwes == ()


def test_unknown_ransomware_value_is_preserved() -> None:
    record = KEVRecord.model_validate(make_kev_record(knownRansomwareCampaignUse="Unknown"))

    assert record.known_ransomware_campaign_use == "Unknown"


def test_kev_catalog_parses_metadata_and_records() -> None:
    catalog = KEVCatalog.model_validate(
        {
            "title": "CISA Catalog of Known Exploited Vulnerabilities",
            "catalogVersion": "2026.11.04",
            "dateReleased": "2026-11-04T20:00:05.774Z",
            "count": 1,
            "vulnerabilities": [make_kev_record()],
        }
    )

    assert catalog.catalog_version == "2026.11.04"
    assert catalog.count == 1
    assert len(catalog.vulnerabilities) == 1


def test_kev_catalog_preserves_unknown_upstream_fields() -> None:
    catalog = KEVCatalog.model_validate(
        {
            "title": "CISA Catalog",
            "catalogVersion": "2026.11.04",
            "dateReleased": "2026-11-04T20:00:05.774Z",
            "count": 0,
            "vulnerabilities": [],
            "futureField": "preserved",
        }
    )

    assert catalog.model_extra == {"futureField": "preserved"}


def test_kev_result_represents_catalog_absence() -> None:
    result = KEVResult(
        availability=SourceAvailability(
            source=IntelligenceSource.CISA_KEV,
            status=IntelligenceStatus.NOT_FOUND,
            reason="CVE not present in the catalog.",
        ),
        record=None,
        catalog_version="2026.11.04",
    )

    assert result.record is None
    assert result.availability.status is IntelligenceStatus.NOT_FOUND


def test_kev_record_rejects_missing_cve_id() -> None:
    data = make_kev_record()
    data.pop("cveID")

    with pytest.raises(ValidationError):
        KEVRecord.model_validate(data)
