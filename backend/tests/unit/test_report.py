import json
from dataclasses import replace
from pathlib import Path

from deprisk.core.models import (
    AdvisoryReference,
    DependencyEdge,
    DependencyNode,
    DependencyScope,
    Ecosystem,
    EdgeResolution,
    PackageSourceType,
    ParsedLockfile,
    RemediationReference,
    RemediationStatus,
    VulnerabilityFinding,
)
from deprisk.core.scope import (
    EffectiveScope,
    NodeReachability,
    ScopePropagationResult,
)
from deprisk.report import build_repository_report, render_json_report
from deprisk.repository import RepositoryLockfile
from deprisk.scan import RepositoryAnalysis, RepositoryScanResult
from deprisk.vulnerability.finding_aggregator import aggregate_findings
from deprisk.vulnerability.osv_aliases import OSVAliasGroup
from deprisk.vulnerability.osv_crosscheck import (
    OSVCrossCheckDecision,
    OSVCrossCheckStatus,
)
from deprisk.vulnerability.osv_service import (
    OSVLookupResult,
    OSVMatchDecision,
    OSVPackageResult,
)
from deprisk.vulnerability.osv_version_matcher import VersionMatchStatus
from deprisk.vulnerability.registry_candidates import (
    RegistryCandidateSelection,
    RegistryQueryCandidate,
)
from deprisk.vulnerability.source_eligibility import (
    SourceEligibilityDecision,
    SourceEligibilityStatus,
)


def make_reachability(path: str) -> NodeReachability:
    return NodeReachability(
        install_path=path,
        effective_scope=EffectiveScope.PRODUCTION,
        is_production=True,
        is_dev=False,
        is_optional=False,
        is_dev_optional=False,
        is_peer=False,
        is_unreachable=False,
        reached_states=frozenset({"(PROD, REQ)"}),
        has_production_path=True,
        has_development_path=False,
        has_optional_path=False,
        has_required_path=True,
    )


def make_scan_result(tmp_path: Path) -> RepositoryScanResult:
    repository_path = tmp_path / "sample-project"
    repository_path.mkdir()
    lockfile_path = repository_path / "package-lock.json"
    lockfile_path.write_text("{}", encoding="utf-8")

    lodash = DependencyNode(
        install_path="node_modules/lodash",
        name="lodash",
        version="4.17.20",
        ecosystem=Ecosystem.NPM,
        scopes=frozenset({DependencyScope.PRODUCTION}),
        is_direct=True,
        source_type=PackageSourceType.REGISTRY,
        resolved="https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
    )

    git_package = DependencyNode(
        install_path="node_modules/custom-package",
        name="custom-package",
        version="1.0.0",
        source_type=PackageSourceType.GIT,
        resolved="git+https://github.com/example/custom-package.git",
    )

    candidate = RegistryQueryCandidate(
        package_name="lodash",
        package_version="4.17.20",
        install_paths=("node_modules/lodash",),
    )

    advisory = AdvisoryReference(
        advisory_id="GHSA-one",
        aliases=("CVE-2026-1234",),
        summary="Test vulnerability",
        remediations=(
            RemediationReference(
                package_name="lodash",
                ecosystem="npm",
                fixed_versions=("4.17.21",),
                status=RemediationStatus.AVAILABLE,
            ),
            RemediationReference(
                package_name="custom-package",
                ecosystem="npm",
                fixed_versions=(),
                status=RemediationStatus.UNKNOWN,
            ),
        ),
    )

    finding = VulnerabilityFinding(
        package_name="lodash",
        package_version="4.17.20",
        advisory=advisory,
        affected_install_paths=("node_modules/lodash",),
    )

    alias_group = OSVAliasGroup(
        canonical_id="GHSA-one",
        advisory_ids=("GHSA-one",),
        aliases=("CVE-2026-1234",),
    )

    source_decisions = (
        SourceEligibilityDecision(
            install_path="node_modules/lodash",
            package_name="lodash",
            package_version="4.17.20",
            source_type=PackageSourceType.REGISTRY,
            status=SourceEligibilityStatus.ELIGIBLE,
            reason="Trusted npm registry source.",
        ),
        SourceEligibilityDecision(
            install_path="node_modules/custom-package",
            package_name="custom-package",
            package_version="1.0.0",
            source_type=PackageSourceType.GIT,
            status=SourceEligibilityStatus.INELIGIBLE,
            reason="Git package is not eligible for registry matching.",
        ),
    )

    analysis = RepositoryAnalysis(
        repository=RepositoryLockfile(
            repository_path=repository_path,
            lockfile_path=lockfile_path,
            content="{}",
        ),
        parsed_lockfile=ParsedLockfile(nodes=(lodash, git_package)),
        edges=(),
        scope_result=ScopePropagationResult(
            nodes={
                "node_modules/lodash": make_reachability("node_modules/lodash"),
                "node_modules/custom-package": make_reachability("node_modules/custom-package"),
            },
        ),
        candidate_selection=RegistryCandidateSelection(
            candidates=(candidate,),
            decisions=source_decisions,
        ),
    )

    osv_result = OSVLookupResult(
        package_results=(
            OSVPackageResult(
                candidate=candidate,
                advisory_ids=("GHSA-one",),
            ),
        ),
        normalized_advisories=(advisory,),
        alias_groups=(alias_group,),
        match_decisions=(
            OSVMatchDecision(
                candidate=candidate,
                advisory_id="GHSA-one",
                status=VersionMatchStatus.AFFECTED,
            ),
        ),
        cross_check_decisions=(
            OSVCrossCheckDecision(
                candidate=candidate,
                advisory_id="GHSA-one",
                local_status=VersionMatchStatus.AFFECTED,
                status=OSVCrossCheckStatus.AGREEMENT,
                explanation="OSV batch and hydrated evidence agree.",
            ),
        ),
        findings=(finding,),
    )

    aggregated = aggregate_findings(
        osv_result.findings,
        osv_result.alias_groups,
    )

    return RepositoryScanResult(
        analysis=analysis,
        osv_result=osv_result,
        aggregated_findings=aggregated,
    )


def test_report_contains_repository_and_dependency_evidence(
    tmp_path: Path,
) -> None:
    report = build_repository_report(make_scan_result(tmp_path))

    assert report.repository_name == "sample-project"
    assert report.lockfile_path == "package-lock.json"
    assert report.summary.total_dependencies == 2
    assert report.summary.registry_candidates == 1
    assert report.summary.eligible_sources == 1
    assert report.summary.ineligible_sources == 1

    lodash = next(item for item in report.dependencies if item.name == "lodash")
    assert lodash.reachability.effective_scope is EffectiveScope.PRODUCTION
    assert lodash.source_eligibility.status is SourceEligibilityStatus.ELIGIBLE

    git_package = next(item for item in report.dependencies if item.name == "custom-package")
    assert git_package.source_eligibility.status is SourceEligibilityStatus.INELIGIBLE


def test_report_preserves_confirmed_finding_and_install_paths(
    tmp_path: Path,
) -> None:
    report = build_repository_report(make_scan_result(tmp_path))

    assert report.summary.confirmed_findings == 1
    assert len(report.findings) == 1

    finding = report.findings[0]
    assert finding.package.name == "lodash"
    assert finding.advisory_ids == ("GHSA-one",)
    assert finding.affected_install_paths == ("node_modules/lodash",)


def test_json_report_is_valid_and_deterministic(
    tmp_path: Path,
) -> None:
    result = make_scan_result(tmp_path)

    first_report = render_json_report(build_repository_report(result))
    second_report = render_json_report(build_repository_report(result))

    assert first_report == second_report

    parsed = json.loads(first_report)

    assert parsed["schema_version"] == "1.1"
    assert parsed["repository_name"] == "sample-project"
    assert parsed["summary"]["confirmed_findings"] == 1
    assert parsed["findings"][0]["package"]["name"] == "lodash"

    normalized_remediations = parsed["normalized_advisories"][0]["remediations"]

    lodash_fix = next(item for item in normalized_remediations if item["package_name"] == "lodash")
    unknown_fix = next(
        item for item in normalized_remediations if item["package_name"] == "custom-package"
    )

    assert lodash_fix["fixed_versions"] == ["4.17.21"]
    assert lodash_fix["status"] == "available"

    assert unknown_fix["fixed_versions"] == []
    assert unknown_fix["status"] == "unknown"

    finding_remediations = parsed["findings"][0]["advisories"][0]["remediations"]
    assert finding_remediations == normalized_remediations


def test_unknown_match_is_not_reported_as_confirmed(
    tmp_path: Path,
) -> None:
    result = make_scan_result(tmp_path)

    unknown_decision = OSVMatchDecision(
        candidate=result.analysis.candidate_selection.candidates[0],
        advisory_id="GHSA-unknown",
        status=VersionMatchStatus.UNKNOWN,
    )

    inconclusive_check = OSVCrossCheckDecision(
        candidate=unknown_decision.candidate,
        advisory_id="GHSA-unknown",
        local_status=VersionMatchStatus.UNKNOWN,
        status=OSVCrossCheckStatus.INCONCLUSIVE,
        explanation="Insufficient version evidence.",
    )

    result = RepositoryScanResult(
        analysis=result.analysis,
        osv_result=OSVLookupResult(
            match_decisions=(unknown_decision,),
            cross_check_decisions=(inconclusive_check,),
        ),
        aggregated_findings=(),
    )

    report = build_repository_report(result)

    assert report.summary.confirmed_findings == 0
    assert report.summary.unknown_version_matches == 1
    assert report.summary.cross_check_inconclusive == 1
    assert report.findings == ()


def test_report_contains_cross_check_explanation(
    tmp_path: Path,
) -> None:
    report = build_repository_report(make_scan_result(tmp_path))

    assert len(report.cross_check_decisions) == 1
    assert report.cross_check_decisions[0].status is OSVCrossCheckStatus.AGREEMENT
    assert "agree" in report.cross_check_decisions[0].explanation.lower()


def test_json_report_preserves_unresolved_dependency_edges(
    tmp_path: Path,
) -> None:
    result = make_scan_result(tmp_path)

    edges = (
        DependencyEdge(
            parent_path="",
            child_path=None,
            dependency_name="missing-required",
            scope=DependencyScope.PRODUCTION,
            resolution=EdgeResolution.MISSING,
        ),
        DependencyEdge(
            parent_path="",
            child_path=None,
            dependency_name="missing-optional",
            scope=DependencyScope.OPTIONAL,
            is_optional=True,
            resolution=EdgeResolution.MISSING_OPTIONAL,
        ),
    )
    analysis = replace(result.analysis, edges=edges)
    result = replace(result, analysis=analysis)

    parsed = json.loads(render_json_report(build_repository_report(result)))

    assert parsed["summary"]["total_edges"] == 2

    edges_by_name = {edge["dependency_name"]: edge for edge in parsed["edges"]}

    assert edges_by_name["missing-required"]["child_path"] is None
    assert edges_by_name["missing-required"]["resolution"] == "missing"
    assert edges_by_name["missing-optional"]["child_path"] is None
    assert edges_by_name["missing-optional"]["resolution"] == "missing_optional"
    assert edges_by_name["missing-optional"]["is_optional"] is True


def test_json_report_never_classifies_unreachable_dependency_as_safe(
    tmp_path: Path,
) -> None:
    result = make_scan_result(tmp_path)

    unreachable = NodeReachability(
        install_path="node_modules/custom-package",
        effective_scope=EffectiveScope.UNREACHABLE,
        is_production=False,
        is_dev=False,
        is_optional=False,
        is_dev_optional=False,
        is_peer=False,
        is_unreachable=True,
        reached_states=frozenset(),
        has_production_path=False,
        has_development_path=False,
        has_optional_path=False,
        has_required_path=False,
    )

    scope_result = result.analysis.scope_result.model_copy(
        update={
            "nodes": {
                "node_modules/lodash": result.analysis.scope_result.nodes["node_modules/lodash"],
                "node_modules/custom-package": unreachable,
            },
            "unreachable_paths": ("node_modules/custom-package",),
        }
    )
    analysis = replace(result.analysis, scope_result=scope_result)
    result = replace(result, analysis=analysis)

    parsed = json.loads(render_json_report(build_repository_report(result)))

    dependency = next(
        item
        for item in parsed["dependencies"]
        if item["install_path"] == "node_modules/custom-package"
    )

    assert dependency["reachability"]["effective_scope"] == "unreachable"
    assert dependency["reachability"]["is_unreachable"] is True
    assert dependency["reachability"]["reached_states"] == []
    assert parsed["unreachable_paths"] == ["node_modules/custom-package"]
    assert parsed["summary"]["unreachable_dependencies"] == 1
    assert "safe" not in dependency["reachability"]


def test_github_report_uses_canonical_repository_identity(
    tmp_path: Path,
) -> None:
    result = make_scan_result(tmp_path)
    temporary_path = result.analysis.repository.repository_path

    github_repository = replace(
        result.analysis.repository,
        repository_name="deprisk",
        repository_url="https://github.com/example/deprisk",
    )
    analysis = replace(result.analysis, repository=github_repository)
    result = replace(result, analysis=analysis)

    report = build_repository_report(result)

    assert report.repository_name == "deprisk"
    assert report.repository_path == "https://github.com/example/deprisk"
    assert report.lockfile_path == "package-lock.json"
    assert str(temporary_path) not in report.repository_path


def test_local_report_preserves_filesystem_repository_identity(
    tmp_path: Path,
) -> None:
    result = make_scan_result(tmp_path)

    report = build_repository_report(result)

    assert report.repository_name == "sample-project"
    assert report.repository_path == str(result.analysis.repository.repository_path)
    assert report.lockfile_path == "package-lock.json"
