"""Local repository analysis and vulnerability scanning pipeline."""

from dataclasses import dataclass, field, replace
from pathlib import Path

from deprisk.core.graph import build_graph_edges
from deprisk.core.lockfile import parse_lockfile
from deprisk.core.models import DependencyEdge, ParsedLockfile
from deprisk.core.scope import ScopePropagationResult, propagate_scopes
from deprisk.github_repository import (
    download_github_repository_tarball,
    extract_github_repository_tarball,
    parse_github_repository_url,
)
from deprisk.repository import RepositoryLockfile, load_repository_lockfile
from deprisk.vulnerability.enrichment_models import EnrichmentResult
from deprisk.vulnerability.enrichment_service import VulnerabilityEnrichmentService
from deprisk.vulnerability.finding_aggregator import (
    AggregatedFinding,
    aggregate_findings,
)
from deprisk.vulnerability.osv_service import (
    OSVLookupResult,
    OSVVulnerabilityService,
)
from deprisk.vulnerability.registry_candidates import (
    RegistryCandidateSelection,
    select_registry_candidates,
)


@dataclass(frozen=True, slots=True)
class RepositoryAnalysis:
    """Explainable intermediate results from local repository analysis."""

    repository: RepositoryLockfile
    parsed_lockfile: ParsedLockfile
    edges: tuple[DependencyEdge, ...]
    scope_result: ScopePropagationResult
    candidate_selection: RegistryCandidateSelection


@dataclass(frozen=True, slots=True)
class RepositoryScanResult:
    """Complete local repository vulnerability scan output."""

    analysis: RepositoryAnalysis
    osv_result: OSVLookupResult
    aggregated_findings: tuple[AggregatedFinding, ...]
    enrichment_result: EnrichmentResult = field(default_factory=EnrichmentResult)


def analyze_local_repository(repository_path: str | Path) -> RepositoryAnalysis:
    """Parse a local npm repository and analyze its dependency graph."""

    repository = load_repository_lockfile(repository_path)
    parsed = parse_lockfile(repository.content, manifest_content=repository.manifest_content)
    edges = tuple(build_graph_edges(parsed))
    scope_result = propagate_scopes(parsed.nodes, edges)
    candidate_selection = select_registry_candidates(parsed.nodes)

    return RepositoryAnalysis(
        repository=repository,
        parsed_lockfile=parsed,
        edges=edges,
        scope_result=scope_result,
        candidate_selection=candidate_selection,
    )


async def scan_local_repository(
    repository_path: str | Path,
    osv_service: OSVVulnerabilityService,
    enrichment_service: VulnerabilityEnrichmentService | None = None,
) -> RepositoryScanResult:
    """Run the complete local repository vulnerability scanning pipeline."""

    analysis = analyze_local_repository(repository_path)

    osv_result = await osv_service.lookup(analysis.candidate_selection.candidates)

    aggregated_findings = aggregate_findings(
        findings=osv_result.findings,
        alias_groups=osv_result.alias_groups,
        ecosystem="npm",
    )

    enrichment_result = (
        await enrichment_service.enrich(aggregated_findings)
        if enrichment_service is not None
        else EnrichmentResult()
    )

    return RepositoryScanResult(
        analysis=analysis,
        osv_result=osv_result,
        aggregated_findings=aggregated_findings,
        enrichment_result=enrichment_result,
    )


async def scan_github_repository(
    repository_url: str,
    osv_service: OSVVulnerabilityService,
    enrichment_service: VulnerabilityEnrichmentService | None = None,
) -> RepositoryScanResult:
    """Safely download and scan a GitHub repository."""

    repository = parse_github_repository_url(repository_url)
    archive = await download_github_repository_tarball(repository.canonical_url)

    with extract_github_repository_tarball(archive) as repository_path:
        result = await scan_local_repository(
            repository_path,
            osv_service,
            enrichment_service,
        )

        repository_lockfile = replace(
            result.analysis.repository,
            repository_name=repository.repository,
            repository_url=repository.canonical_url,
        )
        analysis = replace(
            result.analysis,
            repository=repository_lockfile,
        )

        return replace(result, analysis=analysis)
