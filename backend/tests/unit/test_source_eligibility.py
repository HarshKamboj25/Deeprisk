import pytest

from deprisk.core.models import DependencyNode, PackageSourceType
from deprisk.vulnerability.source_eligibility import (
    SourceEligibilityStatus,
    assess_source_eligibility,
)


def make_node(
    source_type: PackageSourceType,
    resolved: str | None = None,
) -> DependencyNode:
    if resolved is None:
        resolved = {
            PackageSourceType.REGISTRY: ("https://registry.npmjs.org/example/-/example-1.2.3.tgz"),
            PackageSourceType.GIT: "git+https://github.com/example/example.git",
            PackageSourceType.FILE: "file:../example",
            PackageSourceType.URL: "https://packages.example.com/example.tgz",
            PackageSourceType.UNKNOWN: None,
        }[source_type]

    return DependencyNode(
        install_path="node_modules/example",
        name="example",
        version="1.2.3",
        source_type=source_type,
        resolved=resolved,
    )


def test_registry_package_is_eligible():
    decision = assess_source_eligibility(make_node(PackageSourceType.REGISTRY))

    assert decision.status == SourceEligibilityStatus.ELIGIBLE
    assert decision.source_type is PackageSourceType.REGISTRY


@pytest.mark.parametrize(
    "source_type",
    [
        PackageSourceType.GIT,
        PackageSourceType.FILE,
        PackageSourceType.URL,
    ],
)
def test_non_registry_sources_are_ineligible(source_type):
    decision = assess_source_eligibility(make_node(source_type))

    assert decision.status == SourceEligibilityStatus.INELIGIBLE
    assert source_type.value in decision.reason


def test_unknown_source_is_not_eligible():
    decision = assess_source_eligibility(make_node(PackageSourceType.UNKNOWN))

    assert decision.status == SourceEligibilityStatus.UNKNOWN


def test_missing_resolved_url_is_unknown():
    node = DependencyNode(
        install_path="node_modules/example",
        name="example",
        version="1.2.3",
        source_type=PackageSourceType.REGISTRY,
        resolved=None,
    )
    decision = assess_source_eligibility(node)

    assert decision.status == SourceEligibilityStatus.UNKNOWN


def test_registry_type_with_attacker_url_is_unknown():
    decision = assess_source_eligibility(
        make_node(
            PackageSourceType.REGISTRY,
            "https://attacker.example/package.tgz",
        )
    )

    assert decision.status == SourceEligibilityStatus.UNKNOWN


def test_registry_url_with_unknown_source_type_is_unknown():
    decision = assess_source_eligibility(
        make_node(
            PackageSourceType.UNKNOWN,
            "https://registry.npmjs.org/example/-/example-1.2.3.tgz",
        )
    )

    assert decision.status == SourceEligibilityStatus.UNKNOWN


def test_registry_type_with_malformed_url_is_unknown():
    decision = assess_source_eligibility(make_node(PackageSourceType.REGISTRY, "https://[invalid"))

    assert decision.status == SourceEligibilityStatus.UNKNOWN


def test_wrong_source_type_with_registry_url_is_unknown():
    decision = assess_source_eligibility(
        make_node(
            PackageSourceType.URL,
            "https://registry.npmjs.org/example/-/example-1.2.3.tgz",
        )
    )

    assert decision.status == SourceEligibilityStatus.UNKNOWN


def test_decision_preserves_package_identity():
    decision = assess_source_eligibility(make_node(PackageSourceType.REGISTRY))

    assert decision.install_path == "node_modules/example"
    assert decision.package_name == "example"
    assert decision.package_version == "1.2.3"


def test_decision_is_immutable():
    decision = assess_source_eligibility(make_node(PackageSourceType.REGISTRY))

    with pytest.raises((ValueError, TypeError)):
        decision.status = SourceEligibilityStatus.INELIGIBLE
