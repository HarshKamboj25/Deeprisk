import pytest

from deprisk.vulnerability.osv_aliases import group_advisories_by_alias
from deprisk.vulnerability.osv_models import OSVAdvisory


def advisory(identifier: str, *aliases: str) -> OSVAdvisory:
    return OSVAdvisory(id=identifier, aliases=aliases)


def test_groups_advisories_with_shared_alias() -> None:
    groups = group_advisories_by_alias(
        [
            advisory("GHSA-one", "CVE-2026-1234"),
            advisory("GHSA-two", "CVE-2026-1234"),
        ]
    )

    assert len(groups) == 1
    assert groups[0].advisory_ids == ("GHSA-one", "GHSA-two")
    assert groups[0].canonical_id == "GHSA-one"


def test_groups_transitive_alias_relationships() -> None:
    groups = group_advisories_by_alias(
        [
            advisory("GHSA-one", "CVE-2026-1234"),
            advisory("CVE-2026-1234", "GHSA-two"),
            advisory("GHSA-two", "CVE-2026-5678"),
        ]
    )

    assert len(groups) == 1
    assert groups[0].advisory_ids == ("CVE-2026-1234", "GHSA-one", "GHSA-two")
    assert groups[0].aliases == ("CVE-2026-5678",)


def test_keeps_unrelated_advisories_separate() -> None:
    groups = group_advisories_by_alias(
        [
            advisory("GHSA-one", "CVE-2026-1234"),
            advisory("GHSA-two", "CVE-2026-5678"),
        ]
    )

    assert len(groups) == 2


def test_grouping_is_deterministic() -> None:
    items = [
        advisory("GHSA-z", "CVE-2026-1234"),
        advisory("GHSA-a", "CVE-2026-1234"),
        advisory("GHSA-independent"),
    ]

    assert group_advisories_by_alias(items) == group_advisories_by_alias(list(reversed(items)))


def test_duplicate_advisory_ids_are_rejected() -> None:
    with pytest.raises(ValueError, match="Duplicate advisory ID"):
        group_advisories_by_alias(
            [
                advisory("GHSA-one", "CVE-2026-1234"),
                advisory("GHSA-one", "CVE-2026-5678"),
            ]
        )


def test_empty_input_returns_no_groups() -> None:
    assert group_advisories_by_alias([]) == ()


def test_preserves_all_aliases() -> None:
    groups = group_advisories_by_alias([advisory("GHSA-one", "CVE-2026-1234", "CVE-2026-5678")])

    assert groups[0].aliases == ("CVE-2026-1234", "CVE-2026-5678")
