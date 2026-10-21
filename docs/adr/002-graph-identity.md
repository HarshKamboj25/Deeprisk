# ADR-002: Graph node identity and install paths

Status: accepted

## Context
The same package name and version may occur at multiple installation paths.
Merging those locations can lose dependency relationships.

## Decision
1. InstallNode is a physical installation location.
   Identity: (scan_id, install_path). The root project path is "".
2. PackageVersion is a grouping key:
   (ecosystem, name, version). It is used for advisory matching and finding deduplication,
   never as the graph node identity.
3. Edge connects a parent InstallNode to a child InstallNode.
   It stores dependency name, requested range, edge type, and resolution.
4. Resolve dependencies using Node module-resolution semantics.
5. Preserve unresolved dependencies with a reason rather than silently dropping them.
6. A finding links to all affected installation instances.
7. Calculate dependency paths and production scope per installation instance.

## Required tests
- The same b@1.0.0 at two paths creates two InstallNodes.
- Those instances retain their distinct parent relationships.
- They can share one PackageVersion and one grouped finding.
- An unresolved optional dependency is retained with a missing_optional reason.

## Unverified
- Exact workspace and link:true behavior in real lockfiles.
- Exact dev, optional, peer, and devOptional flags.
- Whether sampled lockfiles auto-install peer dependencies.