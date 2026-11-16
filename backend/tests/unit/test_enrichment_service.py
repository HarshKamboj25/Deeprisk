from deprisk.core.models import AdvisoryReference
from deprisk.vulnerability.enrichment_service import extract_finding_cves
from deprisk.vulnerability.finding_aggregator import (
    AggregatedFinding,
    PackageVersion,
)


def make_finding(
    advisory_id: str,
    aliases: tuple[str, ...] = (),
) -> AggregatedFinding:
    return AggregatedFinding(
        package=PackageVersion(
            ecosystem="npm",
            name="example-package",
            version="1.0.0",
        ),
        canonical_advisory_id=advisory_id,
        advisory_ids=(advisory_id,),
        advisories=(AdvisoryReference(advisory_id=advisory_id, aliases=aliases),),
        aliases=aliases,
        affected_install_paths=("node_modules/example-package",),
    )


def test_extracts_cve_from_advisory_aliases() -> None:
    finding = make_finding(
        "GHSA-example",
        ("CVE-2021-44228",),
    )

    result = extract_finding_cves((finding,))

    assert result[0].cve_ids == ("CVE-2021-44228",)


def test_extracts_cve_from_advisory_id() -> None:
    finding = make_finding("CVE-2021-44228")

    result = extract_finding_cves((finding,))

    assert result[0].cve_ids == ("CVE-2021-44228",)


def test_normalizes_lowercase_cve_identifier() -> None:
    finding = make_finding(
        "GHSA-example",
        ("cve-2021-44228",),
    )

    result = extract_finding_cves((finding,))

    assert result[0].cve_ids == ("CVE-2021-44228",)


def test_deduplicates_repeated_cve_aliases() -> None:
    finding = make_finding(
        "GHSA-example",
        ("CVE-2021-44228", "CVE-2021-44228"),
    )

    result = extract_finding_cves((finding,))

    assert result[0].cve_ids == ("CVE-2021-44228",)


def test_ignores_non_cve_identifiers() -> None:
    finding = make_finding(
        "GHSA-example",
        ("GHSA-another", "OSV-2024-1234"),
    )

    result = extract_finding_cves((finding,))

    assert result[0].cve_ids == ()


def test_sorts_multiple_cves_deterministically() -> None:
    finding = make_finding(
        "GHSA-example",
        ("CVE-2021-45046", "CVE-2021-44228"),
    )

    result = extract_finding_cves((finding,))

    assert result[0].cve_ids == (
        "CVE-2021-44228",
        "CVE-2021-45046",
    )


def test_preserves_finding_identity() -> None:
    finding = make_finding(
        "GHSA-example",
        ("CVE-2021-44228",),
    )

    result = extract_finding_cves((finding,))

    assert result[0].canonical_advisory_id == "GHSA-example"
    assert result[0].package_name == "example-package"
    assert result[0].package_version == "1.0.0"


def test_handles_empty_findings() -> None:
    assert extract_finding_cves(()) == ()


def test_extracts_unique_cves_across_multiple_findings() -> None:
    from deprisk.vulnerability.enrichment_service import extract_unique_cves

    first = make_finding(
        "GHSA-first",
        ("CVE-2021-44228", "CVE-2021-45046"),
    )
    second = make_finding(
        "GHSA-second",
        ("CVE-2021-44228", "CVE-2022-22965"),
    )

    finding_results = extract_finding_cves((first, second))

    assert extract_unique_cves(finding_results) == (
        "CVE-2021-44228",
        "CVE-2021-45046",
        "CVE-2022-22965",
    )


def test_extract_unique_cves_handles_empty_results() -> None:
    from deprisk.vulnerability.enrichment_service import extract_unique_cves

    assert extract_unique_cves(()) == ()
