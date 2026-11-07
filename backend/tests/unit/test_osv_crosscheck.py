"""Tests for OSV batch and hydrated-advisory cross-checking."""

import pytest

from deprisk.vulnerability.osv_crosscheck import (
    OSVCrossCheckStatus,
    cross_check_osv_result,
)
from deprisk.vulnerability.osv_version_matcher import VersionMatchStatus
from deprisk.vulnerability.registry_candidates import RegistryQueryCandidate


@pytest.fixture
def package_candidate() -> RegistryQueryCandidate:
    return RegistryQueryCandidate(
        package_name="lodash",
        package_version="4.17.20",
        install_paths=("node_modules/lodash",),
    )


def test_affected_result_is_agreement(
    package_candidate: RegistryQueryCandidate,
) -> None:
    decision = cross_check_osv_result(
        package_candidate,
        "GHSA-example",
        VersionMatchStatus.AFFECTED,
    )

    assert decision.status is OSVCrossCheckStatus.AGREEMENT
    assert decision.local_status is VersionMatchStatus.AFFECTED
    assert decision.candidate == package_candidate
    assert decision.advisory_id == "GHSA-example"
    assert "confirms" in decision.explanation


def test_not_affected_result_is_disagreement(
    package_candidate: RegistryQueryCandidate,
) -> None:
    decision = cross_check_osv_result(
        package_candidate,
        "GHSA-example",
        VersionMatchStatus.NOT_AFFECTED,
    )

    assert decision.status is OSVCrossCheckStatus.DISAGREEMENT
    assert decision.local_status is VersionMatchStatus.NOT_AFFECTED
    assert "does not include the installed version" in decision.explanation
    assert "does not prove a false positive" in decision.explanation


def test_unknown_result_is_inconclusive(
    package_candidate: RegistryQueryCandidate,
) -> None:
    decision = cross_check_osv_result(
        package_candidate,
        "GHSA-example",
        VersionMatchStatus.UNKNOWN,
    )

    assert decision.status is OSVCrossCheckStatus.INCONCLUSIVE
    assert decision.local_status is VersionMatchStatus.UNKNOWN
    assert "insufficient or unsupported" in decision.explanation


def test_cross_check_preserves_multiple_install_paths() -> None:
    candidate = RegistryQueryCandidate(
        package_name="lodash",
        package_version="4.17.20",
        install_paths=(
            "node_modules/lodash",
            "node_modules/app/node_modules/lodash",
        ),
    )

    decision = cross_check_osv_result(
        candidate,
        "GHSA-example",
        VersionMatchStatus.AFFECTED,
    )

    assert decision.candidate.install_paths == candidate.install_paths


def test_cross_check_decision_is_immutable(
    package_candidate: RegistryQueryCandidate,
) -> None:
    decision = cross_check_osv_result(
        package_candidate,
        "GHSA-example",
        VersionMatchStatus.AFFECTED,
    )

    with pytest.raises(ValueError):
        decision.status = OSVCrossCheckStatus.DISAGREEMENT  # type: ignore[misc]
