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

## Amendment (Checkpoints A to D)

Status of the decisions above, as implemented and verified:
- Points 1-5 and 7 hold as written. The edge carries: parent_path, child_path (None when
  unresolved), dependency_name, requested_range, scope, is_optional and resolution
  (resolved, missing_optional, missing). The "edge type" in point 3 is carried by scope.
- Required tests: the two-instances and distinct-parents tests exist (test_graph.py,
  test_lockfile_graph_integration.py, test_real_lockfiles.py), and so does the
  missing_optional test. The "share one PackageVersion and one grouped finding" test does
  not exist yet, because findings and the PackageVersion grouping key are not implemented.
- Point 6 (findings link to all affected instances) is not implemented yet. It is tracked
  as part of E5 in docs/tracker.md.
- The three unverified items are now observed in the committed real fixtures: workspaces
  produce `link` entries and member paths outside node_modules (the parser rejects these on
  purpose); dev, optional, devOptional and peer flags appear; a peer dependency is installed
  and flagged peer when nothing else requires it.
- Further decisions and the open items are in ADR-003.
