from deprisk.core.models import AdvisoryReference, VulnerabilityFinding
from deprisk.vulnerability.finding_aggregator import aggregate_findings
from deprisk.vulnerability.osv_aliases import OSVAliasGroup


def make_finding(
    advisory_id: str,
    package_name: str = "lodash",
    package_version: str = "4.17.20",
    paths: tuple[str, ...] = ("node_modules/lodash",),
) -> VulnerabilityFinding:
    advisory = AdvisoryReference(
        advisory_id=advisory_id,
        aliases=("CVE-2026-1234",),
    )
    return VulnerabilityFinding(
        package_name=package_name,
        package_version=package_version,
        advisory=advisory,
        affected_install_paths=paths,
    )


def make_alias_group(
    canonical_id: str,
    advisory_ids: tuple[str, ...],
) -> OSVAliasGroup:
    return OSVAliasGroup(
        canonical_id=canonical_id,
        advisory_ids=advisory_ids,
        aliases=("CVE-2026-1234",),
    )


def test_alias_related_findings_are_aggregated() -> None:
    findings = (
        make_finding("GHSA-one", paths=("node_modules/lodash",)),
        make_finding(
            "GHSA-two",
            paths=("node_modules/app/node_modules/lodash",),
        ),
    )
    groups = (make_alias_group("GHSA-one", ("GHSA-one", "GHSA-two")),)

    result = aggregate_findings(findings, groups)

    assert len(result) == 1
    assert result[0].canonical_advisory_id == "GHSA-one"
    assert result[0].advisory_ids == ("GHSA-one", "GHSA-two")
    assert result[0].aliases == ("CVE-2026-1234",)
    assert result[0].affected_install_paths == (
        "node_modules/app/node_modules/lodash",
        "node_modules/lodash",
    )


def test_different_alias_groups_remain_separate() -> None:
    findings = (
        make_finding("GHSA-one"),
        make_finding("GHSA-two"),
    )
    groups = (
        make_alias_group("GHSA-one", ("GHSA-one",)),
        make_alias_group("GHSA-two", ("GHSA-two",)),
    )

    result = aggregate_findings(findings, groups)

    assert len(result) == 2
    assert {item.canonical_advisory_id for item in result} == {
        "GHSA-one",
        "GHSA-two",
    }


def test_different_package_versions_remain_separate() -> None:
    findings = (
        make_finding("GHSA-one", package_version="4.17.20"),
        make_finding("GHSA-one", package_version="4.17.21"),
    )
    groups = (make_alias_group("GHSA-one", ("GHSA-one",)),)

    result = aggregate_findings(findings, groups)

    assert len(result) == 2
    assert {item.package.version for item in result} == {
        "4.17.20",
        "4.17.21",
    }


def test_duplicate_advisory_findings_merge_install_paths() -> None:
    findings = (
        make_finding("GHSA-one", paths=("node_modules/lodash",)),
        make_finding("GHSA-one", paths=("packages/app/node_modules/lodash",)),
    )
    groups = (make_alias_group("GHSA-one", ("GHSA-one",)),)

    result = aggregate_findings(findings, groups)

    assert len(result) == 1
    assert result[0].advisory_ids == ("GHSA-one",)
    assert len(result[0].advisories) == 1
    assert result[0].affected_install_paths == (
        "node_modules/lodash",
        "packages/app/node_modules/lodash",
    )


def test_missing_alias_group_raises_value_error() -> None:
    findings = (make_finding("GHSA-missing"),)

    try:
        aggregate_findings(findings, ())
    except ValueError as error:
        assert "No alias group found" in str(error)
    else:
        raise AssertionError("Expected ValueError for missing alias group")


def test_duplicate_advisory_membership_raises_value_error() -> None:
    findings = (make_finding("GHSA-one"),)
    groups = (
        make_alias_group("GHSA-one", ("GHSA-one",)),
        make_alias_group("GHSA-two", ("GHSA-one", "GHSA-two")),
    )

    try:
        aggregate_findings(findings, groups)
    except ValueError as error:
        assert "multiple alias groups" in str(error)
    else:
        raise AssertionError("Expected ValueError for duplicate membership")


def test_empty_inputs_return_empty_tuple() -> None:
    assert aggregate_findings((), ()) == ()
