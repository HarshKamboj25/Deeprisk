import pytest
from pydantic import ValidationError

from deprisk.vulnerability.osv_models import (
    OSVAdvisory,
    OSVAffectedPackage,
    OSVBatchResponse,
    OSVQueryResponse,
)


def test_parses_batch_response() -> None:
    response = OSVBatchResponse.model_validate(
        {"results": [{"vulns": [{"id": "GHSA-example"}]}, {"vulns": []}]}
    )
    assert len(response.results) == 2
    assert response.results[0].vulns[0].id == "GHSA-example"


def test_parses_single_query_response() -> None:
    response = OSVQueryResponse.model_validate(
        {"vulns": [{"id": "GHSA-example", "aliases": ["CVE-2026-1234"]}]}
    )
    assert response.vulns[0].aliases == ("CVE-2026-1234",)


def test_preserves_affected_package_ranges_and_events() -> None:
    affected = OSVAffectedPackage.model_validate(
        {
            "package": {"ecosystem": "npm", "name": "lodash"},
            "ranges": [
                {
                    "type": "SEMVER",
                    "events": [{"introduced": "0"}, {"fixed": "4.17.21"}],
                }
            ],
        }
    )
    assert affected.package.name == "lodash"
    assert affected.ranges[0].events[0].introduced == "0"
    assert affected.ranges[0].events[1].fixed == "4.17.21"


def test_preserves_multiple_ecosystems() -> None:
    advisory = OSVAdvisory.model_validate(
        {
            "id": "GHSA-example",
            "affected": [
                {"package": {"ecosystem": "npm", "name": "lodash"}},
                {"package": {"ecosystem": "RubyGems", "name": "lodash-rails"}},
            ],
        }
    )
    assert [item.package.ecosystem for item in advisory.affected] == [
        "npm",
        "RubyGems",
    ]


def test_rejects_advisory_without_id() -> None:
    with pytest.raises(ValidationError):
        OSVAdvisory.model_validate({"summary": "Missing advisory ID"})


def test_models_are_immutable() -> None:
    advisory = OSVAdvisory(id="GHSA-example")
    with pytest.raises((ValidationError, TypeError)):
        advisory.id = "GHSA-changed"
