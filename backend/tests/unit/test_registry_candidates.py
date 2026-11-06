import pytest

from deprisk.core.models import DependencyNode, PackageSourceType
from deprisk.vulnerability.registry_candidates import select_registry_candidates
from deprisk.vulnerability.source_eligibility import SourceEligibilityStatus

REGISTRY_URL = "https://registry.npmjs.org/example/-/example-1.2.3.tgz"


def make_node(
    install_path: str,
    name: str = "example",
    version: str = "1.2.3",
    source_type: PackageSourceType = PackageSourceType.REGISTRY,
    resolved: str | None = REGISTRY_URL,
) -> DependencyNode:
    return DependencyNode(
        install_path=install_path,
        name=name,
        version=version,
        source_type=source_type,
        resolved=resolved,
    )


def test_selects_registry_package() -> None:
    result = select_registry_candidates([make_node("node_modules/example")])

    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate.package_name == "example"
    assert candidate.package_version == "1.2.3"
    assert candidate.install_paths == ("node_modules/example",)
    assert result.decisions[0].status is SourceEligibilityStatus.ELIGIBLE


@pytest.mark.parametrize(
    ("source_type", "resolved", "expected_status"),
    [
        (
            PackageSourceType.GIT,
            "git+https://github.com/acme/example.git",
            SourceEligibilityStatus.INELIGIBLE,
        ),
        (
            PackageSourceType.FILE,
            "file:../example",
            SourceEligibilityStatus.INELIGIBLE,
        ),
        (
            PackageSourceType.URL,
            "https://example.com/example.tgz",
            SourceEligibilityStatus.INELIGIBLE,
        ),
        (
            PackageSourceType.UNKNOWN,
            None,
            SourceEligibilityStatus.UNKNOWN,
        ),
    ],
)
def test_excludes_non_registry_and_unknown_sources(
    source_type: PackageSourceType,
    resolved: str | None,
    expected_status: SourceEligibilityStatus,
) -> None:
    result = select_registry_candidates(
        [make_node("node_modules/example", source_type=source_type, resolved=resolved)]
    )

    assert result.candidates == ()
    assert result.decisions[0].status is expected_status


def test_groups_same_package_and_version_across_install_paths() -> None:
    result = select_registry_candidates(
        [
            make_node("node_modules/a/node_modules/example"),
            make_node("node_modules/example"),
        ]
    )

    assert len(result.candidates) == 1
    assert result.candidates[0].install_paths == (
        "node_modules/a/node_modules/example",
        "node_modules/example",
    )


def test_keeps_different_versions_as_separate_candidates() -> None:
    result = select_registry_candidates(
        [
            make_node("node_modules/example", version="1.2.3"),
            make_node("node_modules/other/node_modules/example", version="2.0.0"),
        ]
    )

    assert [(item.package_name, item.package_version) for item in result.candidates] == [
        ("example", "1.2.3"),
        ("example", "2.0.0"),
    ]


def test_ineligible_installation_is_not_added_to_registry_candidate() -> None:
    result = select_registry_candidates(
        [
            make_node("node_modules/example"),
            make_node(
                "node_modules/custom-example",
                source_type=PackageSourceType.GIT,
                resolved="git+https://github.com/acme/example.git",
            ),
        ]
    )

    assert len(result.candidates) == 1
    assert result.candidates[0].install_paths == ("node_modules/example",)
    assert len(result.decisions) == 2
    assert {item.status for item in result.decisions} == {
        SourceEligibilityStatus.ELIGIBLE,
        SourceEligibilityStatus.INELIGIBLE,
    }


def test_selection_is_deterministic_for_different_input_orders() -> None:
    nodes = [
        make_node("node_modules/z-example", name="z-example"),
        make_node("node_modules/a-example", name="a-example"),
        make_node("node_modules/example"),
    ]

    forward = select_registry_candidates(nodes)
    reverse = select_registry_candidates(list(reversed(nodes)))

    assert forward == reverse


def test_empty_input_returns_empty_selection() -> None:
    result = select_registry_candidates([])

    assert result.candidates == ()
    assert result.decisions == ()


def test_duplicate_install_paths_are_rejected() -> None:
    with pytest.raises(ValueError, match="Duplicate install path"):
        select_registry_candidates(
            [
                make_node("node_modules/example"),
                make_node("node_modules/example"),
            ]
        )
