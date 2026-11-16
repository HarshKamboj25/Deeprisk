"""Deterministic, explainable JSON reports for repository vulnerability scans."""

import json

from pydantic import BaseModel, ConfigDict

from deprisk.core.models import (
    AdvisoryReference,
    DependencyEdge,
    DependencyNode,
    DependencyScope,
    Ecosystem,
    PackageSourceType,
)
from deprisk.core.scope import EffectiveScope, NodeReachability
from deprisk.scan import RepositoryScanResult
from deprisk.vulnerability.enrichment_models import EnrichmentResult
from deprisk.vulnerability.finding_aggregator import AggregatedFinding
from deprisk.vulnerability.osv_crosscheck import (
    OSVCrossCheckDecision,
    OSVCrossCheckStatus,
)
from deprisk.vulnerability.osv_service import (
    OSVMatchDecision,
    OSVPackageResult,
)
from deprisk.vulnerability.osv_version_matcher import VersionMatchStatus
from deprisk.vulnerability.source_eligibility import (
    SourceEligibilityDecision,
    SourceEligibilityStatus,
)


class ReachabilityReport(BaseModel):
    """Deterministic graph reachability evidence for one installation."""

    model_config = ConfigDict(frozen=True)

    effective_scope: EffectiveScope
    is_production: bool
    is_dev: bool
    is_optional: bool
    is_dev_optional: bool
    is_peer: bool
    is_unreachable: bool
    reached_states: tuple[str, ...]
    has_production_path: bool
    has_development_path: bool
    has_optional_path: bool
    has_required_path: bool


class DependencyReportEntry(BaseModel):
    """Report representation of one physical package installation."""

    model_config = ConfigDict(frozen=True)

    install_path: str
    name: str
    version: str
    ecosystem: Ecosystem
    scopes: tuple[DependencyScope, ...]
    is_direct: bool
    source_type: PackageSourceType
    resolved: str | None
    has_install_script: bool
    reachability: ReachabilityReport
    source_eligibility: SourceEligibilityDecision


class RepositoryReportSummary(BaseModel):
    """Aggregate counts for a repository vulnerability scan."""

    model_config = ConfigDict(frozen=True)

    total_dependencies: int
    total_edges: int
    registry_candidates: int
    eligible_sources: int
    ineligible_sources: int
    unknown_sources: int
    confirmed_findings: int
    unknown_version_matches: int
    not_affected_matches: int
    cross_check_disagreements: int
    cross_check_inconclusive: int
    unreachable_dependencies: int
    scope_parser_disagreements: int


class RepositoryReport(BaseModel):
    """Complete machine-readable repository security report."""

    model_config = ConfigDict(frozen=True)

    schema_version: str = "1.1"
    repository_name: str
    repository_path: str
    lockfile_path: str
    summary: RepositoryReportSummary
    dependencies: tuple[DependencyReportEntry, ...]
    edges: tuple[DependencyEdge, ...]
    source_eligibility_decisions: tuple[SourceEligibilityDecision, ...]
    osv_package_results: tuple[OSVPackageResult, ...]
    normalized_advisories: tuple[AdvisoryReference, ...]
    findings: tuple[AggregatedFinding, ...]
    enrichment: EnrichmentResult = EnrichmentResult()
    match_decisions: tuple[OSVMatchDecision, ...]
    cross_check_decisions: tuple[OSVCrossCheckDecision, ...]
    unreachable_paths: tuple[str, ...]
    scope_disagreements_with_parser: tuple[str, ...]


def _reachability_report(
    reachability: NodeReachability,
) -> ReachabilityReport:
    """Convert graph reachability into deterministic report data."""

    return ReachabilityReport(
        effective_scope=reachability.effective_scope,
        is_production=reachability.is_production,
        is_dev=reachability.is_dev,
        is_optional=reachability.is_optional,
        is_dev_optional=reachability.is_dev_optional,
        is_peer=reachability.is_peer,
        is_unreachable=reachability.is_unreachable,
        reached_states=tuple(sorted(reachability.reached_states)),
        has_production_path=reachability.has_production_path,
        has_development_path=reachability.has_development_path,
        has_optional_path=reachability.has_optional_path,
        has_required_path=reachability.has_required_path,
    )


def _dependency_entry(
    node: DependencyNode,
    reachability: NodeReachability,
    eligibility: SourceEligibilityDecision,
) -> DependencyReportEntry:
    """Build one dependency report entry."""

    return DependencyReportEntry(
        install_path=node.install_path,
        name=node.name,
        version=node.version,
        ecosystem=node.ecosystem,
        scopes=tuple(sorted(node.scopes, key=lambda scope: scope.value)),
        is_direct=node.is_direct,
        source_type=node.source_type,
        resolved=node.resolved,
        has_install_script=node.has_install_script,
        reachability=_reachability_report(reachability),
        source_eligibility=eligibility,
    )


def build_repository_report(
    result: RepositoryScanResult,
) -> RepositoryReport:
    """Build an explainable report without changing scan evidence."""

    analysis = result.analysis
    nodes = analysis.parsed_lockfile.nodes

    eligibility_by_path = {
        decision.install_path: decision for decision in analysis.candidate_selection.decisions
    }

    dependencies: list[DependencyReportEntry] = []

    for node in sorted(nodes, key=lambda item: item.install_path):
        reachability = analysis.scope_result.nodes.get(node.install_path)
        eligibility = eligibility_by_path.get(node.install_path)

        if reachability is None:
            raise ValueError(f"Missing scope result for installation: {node.install_path}")

        if eligibility is None:
            raise ValueError(
                f"Missing source eligibility decision for installation: {node.install_path}"
            )

        dependencies.append(_dependency_entry(node, reachability, eligibility))

    source_decisions = tuple(
        sorted(
            analysis.candidate_selection.decisions,
            key=lambda decision: decision.install_path,
        )
    )

    match_decisions = tuple(
        sorted(
            result.osv_result.match_decisions,
            key=lambda decision: (
                decision.candidate.package_name,
                decision.candidate.package_version,
                decision.advisory_id,
            ),
        )
    )

    cross_checks = tuple(
        sorted(
            result.osv_result.cross_check_decisions,
            key=lambda decision: (
                decision.candidate.package_name,
                decision.candidate.package_version,
                decision.advisory_id,
            ),
        )
    )

    edges = tuple(
        sorted(
            analysis.edges,
            key=lambda edge: (
                edge.parent_path,
                edge.dependency_name,
                edge.child_path or "",
                edge.resolution.value,
            ),
        )
    )

    summary = RepositoryReportSummary(
        total_dependencies=len(nodes),
        total_edges=len(edges),
        registry_candidates=len(analysis.candidate_selection.candidates),
        eligible_sources=sum(
            decision.status is SourceEligibilityStatus.ELIGIBLE for decision in source_decisions
        ),
        ineligible_sources=sum(
            decision.status is SourceEligibilityStatus.INELIGIBLE for decision in source_decisions
        ),
        unknown_sources=sum(
            decision.status is SourceEligibilityStatus.UNKNOWN for decision in source_decisions
        ),
        confirmed_findings=len(result.aggregated_findings),
        unknown_version_matches=sum(
            decision.status is VersionMatchStatus.UNKNOWN for decision in match_decisions
        ),
        not_affected_matches=sum(
            decision.status is VersionMatchStatus.NOT_AFFECTED for decision in match_decisions
        ),
        cross_check_disagreements=sum(
            decision.status is OSVCrossCheckStatus.DISAGREEMENT for decision in cross_checks
        ),
        cross_check_inconclusive=sum(
            decision.status is OSVCrossCheckStatus.INCONCLUSIVE for decision in cross_checks
        ),
        unreachable_dependencies=len(analysis.scope_result.unreachable_paths),
        scope_parser_disagreements=len(analysis.scope_result.disagreements_with_parser),
    )

    repository_name = (
        analysis.repository.repository_name or analysis.repository.repository_path.name
    )
    repository_path = analysis.repository.repository_url or str(analysis.repository.repository_path)

    return RepositoryReport(
        repository_name=repository_name,
        repository_path=repository_path,
        lockfile_path="package-lock.json",
        summary=summary,
        dependencies=tuple(dependencies),
        edges=edges,
        source_eligibility_decisions=source_decisions,
        osv_package_results=result.osv_result.package_results,
        normalized_advisories=result.osv_result.normalized_advisories,
        findings=result.aggregated_findings,
        enrichment=result.enrichment_result,
        match_decisions=match_decisions,
        cross_check_decisions=cross_checks,
        unreachable_paths=analysis.scope_result.unreachable_paths,
        scope_disagreements_with_parser=(analysis.scope_result.disagreements_with_parser),
    )


def render_json_report(report: RepositoryReport) -> str:
    """Serialize a repository report into deterministic, readable JSON."""

    return json.dumps(
        report.model_dump(mode="json"),
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    )
