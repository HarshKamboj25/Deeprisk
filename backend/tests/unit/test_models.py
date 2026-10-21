import pytest
from pydantic import ValidationError

from deprisk.core.models import (
    ROOT_INSTALL_PATH,
    AdvisoryReference,
    DependencyEdge,
    DependencyNode,
    DependencyScope,
    Ecosystem,
    EdgeResolution,
    FindingEvidence,
    RiskAssessment,
    VulnerabilityFinding,
)


def test_dependency_node_preserves_install_path() -> None:
    node = DependencyNode(
        install_path="node_modules/example",
        name="example",
        version="1.2.3",
    )

    assert node.install_path == "node_modules/example"
    assert node.ecosystem == Ecosystem.NPM


def test_same_package_version_can_have_distinct_install_paths() -> None:
    first = DependencyNode(
        install_path="node_modules/example",
        name="example",
        version="1.2.3",
    )
    second = DependencyNode(
        install_path="node_modules/other/node_modules/example",
        name="example",
        version="1.2.3",
    )

    assert first.name == second.name
    assert first.version == second.version
    assert first.install_path != second.install_path


def test_risk_score_must_be_between_zero_and_one_hundred() -> None:
    with pytest.raises(ValidationError):
        RiskAssessment(score=101)


def test_finding_keeps_explainability_evidence() -> None:
    evidence = FindingEvidence(
        kind="kev",
        description="Advisory appears in the KEV catalogue.",
        source="CISA",
    )
    finding = VulnerabilityFinding(
        package_name="example",
        package_version="1.2.3",
        advisory=AdvisoryReference(advisory_id="OSV-TEST-1"),
        affected_install_paths=("node_modules/example",),
        risk=RiskAssessment(score=80, evidence=(evidence,)),
    )

    assert finding.risk is not None
    assert finding.risk.evidence[0].kind == "kev"


# --- DependencyEdge -------------------------------------------------------


def test_root_install_path_is_empty_string() -> None:
    assert ROOT_INSTALL_PATH == ""


def test_edge_resolution_values_are_stable() -> None:
    assert {member.value for member in EdgeResolution} == {
        "resolved",
        "missing_optional",
        "missing",
    }


def test_root_edge_is_allowed_and_defaults_to_resolved() -> None:
    edge = DependencyEdge(
        parent_path=ROOT_INSTALL_PATH,
        child_path="node_modules/example",
        dependency_name="example",
        requested_range="^1.0.0",
        scope=DependencyScope.PRODUCTION,
    )

    assert edge.parent_path == ""
    assert edge.child_path == "node_modules/example"
    assert edge.dependency_name == "example"
    assert edge.resolution is EdgeResolution.RESOLVED


def test_nested_resolved_edge_keeps_both_install_paths() -> None:
    edge = DependencyEdge(
        parent_path="node_modules/a",
        child_path="node_modules/a/node_modules/b",
        dependency_name="b",
        requested_range="^1.0.0",
    )

    assert edge.parent_path == "node_modules/a"
    assert edge.child_path == "node_modules/a/node_modules/b"
    assert edge.scope is DependencyScope.UNKNOWN


def test_scoped_dependency_name_is_preserved() -> None:
    edge = DependencyEdge(
        parent_path="",
        child_path="node_modules/@demo/scoped",
        dependency_name="@demo/scoped",
    )

    assert edge.dependency_name == "@demo/scoped"


def test_resolved_edge_requires_child_path() -> None:
    with pytest.raises(ValidationError, match="child_path is required"):
        DependencyEdge(parent_path="", dependency_name="example")


def test_missing_optional_edge_has_no_child_path() -> None:
    edge = DependencyEdge(
        parent_path="node_modules/a",
        dependency_name="fsevents",
        requested_range="^2.0.0",
        scope=DependencyScope.OPTIONAL,
        is_optional=True,
        resolution=EdgeResolution.MISSING_OPTIONAL,
    )

    assert edge.child_path is None
    assert edge.resolution is EdgeResolution.MISSING_OPTIONAL
    assert edge.is_optional is True


def test_missing_edge_has_no_child_path() -> None:
    edge = DependencyEdge(
        parent_path="",
        dependency_name="ghost",
        requested_range="^1.0.0",
        resolution=EdgeResolution.MISSING,
    )

    assert edge.child_path is None
    assert edge.resolution is EdgeResolution.MISSING


@pytest.mark.parametrize(
    ("resolution", "is_optional"),
    [
        (EdgeResolution.MISSING, False),
        (EdgeResolution.MISSING_OPTIONAL, True),
    ],
)
def test_unresolved_edge_must_not_have_child_path(
    resolution: EdgeResolution, is_optional: bool
) -> None:
    with pytest.raises(ValidationError, match="child_path must be None"):
        DependencyEdge(
            parent_path="",
            child_path="node_modules/example",
            dependency_name="example",
            is_optional=is_optional,
            resolution=resolution,
        )


def test_missing_optional_requires_optional_flag() -> None:
    with pytest.raises(ValidationError, match="requires is_optional=True"):
        DependencyEdge(
            parent_path="",
            dependency_name="example",
            resolution=EdgeResolution.MISSING_OPTIONAL,
        )


def test_optional_dependency_cannot_be_plain_missing() -> None:
    with pytest.raises(ValidationError, match="must use 'missing_optional'"):
        DependencyEdge(
            parent_path="",
            dependency_name="example",
            is_optional=True,
            resolution=EdgeResolution.MISSING,
        )


def test_empty_child_path_is_rejected_even_when_resolved() -> None:
    with pytest.raises(ValidationError):
        DependencyEdge(parent_path="", child_path="", dependency_name="example")


def test_empty_child_path_is_rejected_for_unresolved_edge() -> None:
    with pytest.raises(ValidationError):
        DependencyEdge(
            parent_path="",
            child_path="",
            dependency_name="example",
            resolution=EdgeResolution.MISSING,
        )


def test_empty_dependency_name_is_rejected() -> None:
    with pytest.raises(ValidationError):
        DependencyEdge(parent_path="", child_path="node_modules/example", dependency_name="")


def test_relaxed_parent_path_does_not_relax_node_install_path() -> None:
    with pytest.raises(ValidationError):
        DependencyNode(install_path="", name="example", version="1.0.0")


def test_edge_is_immutable() -> None:
    edge = DependencyEdge(
        parent_path="",
        child_path="node_modules/example",
        dependency_name="example",
    )

    with pytest.raises(ValidationError):
        edge.child_path = "node_modules/other"


def test_unresolved_edge_serializes_resolution_and_null_child() -> None:
    edge = DependencyEdge(
        parent_path="",
        dependency_name="ghost",
        resolution=EdgeResolution.MISSING,
    )

    dumped = edge.model_dump(mode="json")

    assert dumped["resolution"] == "missing"
    assert dumped["child_path"] is None
    assert dumped["parent_path"] == ""
