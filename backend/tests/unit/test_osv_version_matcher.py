"""Tests for conservative OSV affected-version matching."""

import json
from pathlib import Path

from deprisk.vulnerability.osv_models import OSVAdvisory
from deprisk.vulnerability.osv_version_matcher import (
    VersionMatchStatus,
    match_affected_version,
)


def make_advisory(
    package_name: str = "lodash",
    ecosystem: str = "npm",
    versions: list[str] | None = None,
    ranges: list[dict[str, object]] | None = None,
) -> OSVAdvisory:
    return OSVAdvisory.model_validate(
        {
            "id": "GHSA-example",
            "affected": [
                {
                    "package": {
                        "name": package_name,
                        "ecosystem": ecosystem,
                    },
                    "versions": versions or [],
                    "ranges": ranges or [],
                }
            ],
        }
    )


def semver_range(*events: dict[str, str]) -> list[dict[str, object]]:
    return [{"type": "SEMVER", "events": list(events)}]


def test_fixed_boundary_is_exclusive() -> None:
    advisory = make_advisory(ranges=semver_range({"introduced": "0"}, {"fixed": "4.17.21"}))

    assert match_affected_version(advisory, "lodash", "4.17.20") is VersionMatchStatus.AFFECTED
    assert match_affected_version(advisory, "lodash", "4.17.21") is VersionMatchStatus.NOT_AFFECTED
    assert match_affected_version(advisory, "lodash", "4.17.22") is VersionMatchStatus.NOT_AFFECTED


def test_last_affected_boundary_is_inclusive() -> None:
    advisory = make_advisory(ranges=semver_range({"introduced": "0"}, {"last_affected": "4.5.0"}))

    assert match_affected_version(advisory, "lodash", "4.5.0") is VersionMatchStatus.AFFECTED
    assert match_affected_version(advisory, "lodash", "4.5.1") is VersionMatchStatus.NOT_AFFECTED


def test_introduced_boundary_is_inclusive() -> None:
    advisory = make_advisory(
        ranges=semver_range(
            {"introduced": "2.0.0"},
            {"fixed": "3.0.0"},
        )
    )

    assert match_affected_version(advisory, "lodash", "1.9.9") is VersionMatchStatus.NOT_AFFECTED
    assert match_affected_version(advisory, "lodash", "2.0.0") is VersionMatchStatus.AFFECTED


def test_exact_affected_version_matches() -> None:
    advisory = make_advisory(versions=["1.0.0", "2.0.0"])

    assert match_affected_version(advisory, "lodash", "2.0.0") is VersionMatchStatus.AFFECTED
    assert match_affected_version(advisory, "lodash", "3.0.0") is VersionMatchStatus.UNKNOWN


def test_package_name_and_ecosystem_must_match() -> None:
    advisory = make_advisory(
        package_name="lodash",
        ecosystem="npm",
        ranges=semver_range({"introduced": "0"}, {"fixed": "4.17.21"}),
    )

    assert (
        match_affected_version(advisory, "lodash-es", "4.17.20") is VersionMatchStatus.NOT_AFFECTED
    )
    assert (
        match_affected_version(advisory, "lodash", "4.17.20", "RubyGems")
        is VersionMatchStatus.NOT_AFFECTED
    )


def test_unsupported_range_returns_unknown() -> None:
    advisory = make_advisory(
        ranges=[{"type": "GIT", "repo": "https://example.com/repo", "events": []}]
    )

    assert match_affected_version(advisory, "lodash", "1.0.0") is VersionMatchStatus.UNKNOWN


def test_limit_event_returns_unknown() -> None:
    advisory = make_advisory(
        ranges=semver_range(
            {"introduced": "1.0.0"},
            {"limit": "2.0.0"},
        )
    )

    assert match_affected_version(advisory, "lodash", "1.5.0") is VersionMatchStatus.UNKNOWN


def test_malformed_installed_version_returns_unknown() -> None:
    advisory = make_advisory(ranges=semver_range({"introduced": "0"}, {"fixed": "4.17.21"}))

    assert match_affected_version(advisory, "lodash", "not-a-version") is VersionMatchStatus.UNKNOWN


def test_prerelease_is_compared_using_semver() -> None:
    advisory = make_advisory(ranges=semver_range({"introduced": "1.0.0"}, {"fixed": "2.0.0"}))

    assert match_affected_version(advisory, "lodash", "2.0.0-rc.1") is VersionMatchStatus.AFFECTED
    assert match_affected_version(advisory, "lodash", "2.0.0") is VersionMatchStatus.NOT_AFFECTED


def test_real_captured_lodash_advisory() -> None:
    fixture = (
        Path(__file__).resolve().parents[3]
        / "eval"
        / "spikes"
        / "e1"
        / "osv_vulnerability_detail.json"
    )
    capture = json.loads(fixture.read_text(encoding="utf-8"))
    advisory = OSVAdvisory.model_validate(capture["response"])

    assert match_affected_version(advisory, "lodash", "4.17.20") is VersionMatchStatus.AFFECTED
    assert match_affected_version(advisory, "lodash", "4.17.21") is VersionMatchStatus.NOT_AFFECTED
    assert match_affected_version(advisory, "lodash-es", "4.17.20") is VersionMatchStatus.AFFECTED
    assert (
        match_affected_version(advisory, "lodash-rails", "4.17.20")
        is VersionMatchStatus.NOT_AFFECTED
    )


def test_multiple_disjoint_ranges_are_matched_correctly() -> None:
    advisory = make_advisory(
        ranges=semver_range(
            {"introduced": "1.0.0"},
            {"fixed": "2.0.0"},
            {"introduced": "3.0.0"},
            {"fixed": "4.0.0"},
        )
    )

    assert match_affected_version(advisory, "lodash", "0.9.0") is VersionMatchStatus.NOT_AFFECTED
    assert match_affected_version(advisory, "lodash", "1.5.0") is VersionMatchStatus.AFFECTED
    assert match_affected_version(advisory, "lodash", "2.5.0") is VersionMatchStatus.NOT_AFFECTED
    assert match_affected_version(advisory, "lodash", "3.5.0") is VersionMatchStatus.AFFECTED
    assert match_affected_version(advisory, "lodash", "4.0.0") is VersionMatchStatus.NOT_AFFECTED


def test_malformed_event_order_returns_unknown() -> None:
    advisory = make_advisory(
        ranges=semver_range(
            {"fixed": "2.0.0"},
            {"introduced": "1.0.0"},
        )
    )

    assert match_affected_version(advisory, "lodash", "1.5.0") is VersionMatchStatus.UNKNOWN


def test_overlapping_introduced_events_return_unknown() -> None:
    advisory = make_advisory(
        ranges=semver_range(
            {"introduced": "1.0.0"},
            {"introduced": "2.0.0"},
            {"fixed": "3.0.0"},
        )
    )

    assert match_affected_version(advisory, "lodash", "2.5.0") is VersionMatchStatus.UNKNOWN


def test_open_ended_affected_range() -> None:
    advisory = make_advisory(ranges=semver_range({"introduced": "2.0.0"}))

    assert match_affected_version(advisory, "lodash", "1.9.9") is VersionMatchStatus.NOT_AFFECTED
    assert match_affected_version(advisory, "lodash", "2.0.0") is VersionMatchStatus.AFFECTED
    assert match_affected_version(advisory, "lodash", "5.0.0") is VersionMatchStatus.AFFECTED
