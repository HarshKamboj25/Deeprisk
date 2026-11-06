# DepRisk tracker

Status values: Not started | In progress | Implemented | Verified
Only Verified counts as done. Verified means the tests pass on the developer's machine.

Last updated after E2 registry candidate selection; commit 70361a4.
Schedule: four-week maximum. The project start date is UNRESOLVED: no verified date is
available, so elapsed and remaining time are not tracked here. Record the date when it is
known.
Item IDs in this file (E1 and later) supersede the informal checkpoint labels used earlier in
the project planning.

## Summary
- 376 tests pass and 4 are skipped; the full suite collects 380 tests. L1 fixture cross-checks cover four committed npm lockfiles.
- Implemented and verified: lockfile parser (v2 and v3), dependency graph with install-path
  identity, parser hardening, real npm lockfile fixtures, and graph-derived scope propagation (L1).
- Source-aware eligibility and deterministic registry candidate selection are implemented and tested; OSV API integration and advisory matching remain pending.
- Not started: external vulnerability intelligence (OSV, EPSS, KEV, NVD), scoring,
  reachability, remediation, repository ingestion, API, database, frontend, evaluation.
- The core milestone (local repository -> parser -> graph -> OSV matching -> explainable
  report) is NOT complete.

## Completed
| ID | Deliverable | Status | Commit | Evidence |
|---|---|---|---|---|
| D1-1 | Prerequisites installed and checked | Verified | - | See Environment |
| D1-2 | Scaffold, tooling, check script | Verified | - | scripts\check.ps1 passes |
| D1-3 | Domain models | Verified | - | tests/unit/test_models.py |
| A | Edge model: EdgeResolution, root edges | Verified | 6108ba4 | test_models.py |
| B | Graph resolution fix, unresolved edges, edge ordering | Verified | ac777db | test_graph.py (19) |
| C | Parser-to-graph interface, per-install directness and scope | Verified | 0478f13 | test_parsed_lockfile.py (18), test_lockfile_graph_integration.py (11) |
| D-1 | Real npm lockfile fixtures with provenance and SHA-256 sums | Verified | 2560cd5 | 12 files, 0 hash mismatches |
| D-2 | Parser hardening, ParseLimits, derived is_dev, GraphBuildError | Verified | d75f91e | hardening (66), limits (27), is_dev (26), real lockfiles (56) |
| D-3 | ADR-003, ADR-002 amendment, this tracker | In progress | - | Pending review |

## Audit findings (graph and parser audit)
| ID | Finding | Status |
|---|---|---|
| C1 | Edge model rejected the root path | Fixed in A |
| C2, C3 | Scoped root dependencies dropped; root bound to the wrong install | Fixed in B |
| C4 | Direct and scope decided by name instead of install path | Fixed in C |
| G1, G2 | No nested edges; parser and graph not connected | Fixed in C |
| G3, G4 | Unresolved edges dropped; required ADR-002 tests missing | Fixed in A, B and C (see ADR-002 amendment for what remains) |
| R1, R2, R5, R6, R8 | Path and name validation, duplicate keys, missing root, limits, graph error type | Fixed in D (L5: defaults unvalidated at scale) |
| R3 | Alias installs not marked direct | Fixed in C; confirmed on real fixtures |
| R7 | Edge order depended on input order; edges with an identical (parent, name, scope) but different attributes keep the last one | Order pinned by tests in B. The last-wins case remains, but the parser cannot produce it. |
| G6 | is_dev inconsistent with scopes; transitive scope missing | is_dev fixed in D. Scope propagation verified (F1). |
| G5 | Parser-side package source identity and source-aware eligibility safeguard | Parser, eligibility guard, and registry candidate selection implemented and tested; OSV query integration remains pending under E2 |
| R4 | Workspaces and link entries rejected | OPEN by decision (L3) |
| - | Hand-written fixture in recorded/ | OPEN (L9) |
| - | Python dependencies unpinned | OPEN (L10) |

## Remaining work
| ID | Deliverable | Depends on | Acceptance criteria | Status |
|---|---|---|---|---|
| E1 | API verification spike: OSV, EPSS, KEV, NVD | - | Real timestamped responses inspected; findings documented; full checks pass | Verified |
| E2 | Package source identity modeling and source-aware OSV matching | C | Non-registry versions are never matched as registry versions | In progress: shared classifier, eligibility guard, and deterministic registry candidate selection implemented and tested (commit 70361a4); OSV integration pending |
| E3 | OSV client: batch query, hydrate, cache, normalize, alias grouping | E1 | Gold cases pass; failures and rate limits handled | Not started |
| E4 | Local affected-range matcher with OSV cross-check | E3 | Disagreements with OSV are logged and explained | Not started |
| E5 | Core vertical slice: CLI local repository -> parser -> graph -> OSV matching -> explainable report | E2-E4 | Tested on at least 3 real repositories; findings group by (PackageVersion, alias group) and link to every affected install (ADR-002 point 6) | Not started |
| F1 | Transitive production-scope propagation | C | Scope derived from the graph; cross-checked against npm flags on all four committed fixtures; disagreements reported; must pass before F3 | Verified |
| F2 | EPSS, KEV and NVD enrichment with snapshots | E1 | Missing data never treated as zero risk | Not started |
| F3 | Scoring v1 (versioned hypothesis, score interval) | F1, F2 | Sensitivity analysis documented; weights not presented as validated | Not started |
| G1 | Reachability tiers 0 and 1; Tier 2 only after the parser spike and tests pass | E5 | Evidence recorded; no-path-found never reported as safe | Not started |
| G2 | Remediation recommendations | E5 | Fixed versions from advisory data; unknown fix stated | Not started |
| H1 | Safe repository ingestion (GitHub tarball, SSRF, safe extraction) | - | Security tests pass | Not started |
| H2 | Workspaces and link support (separate checkpoint) | C | Policy chosen from fixture evidence; workspace-v3 handled or rejected by design | Not started |
| H3 | Tests for the three parser "must be an object" branches | - | Root document, packages, and package entry each raise LockfileParseError | Verified |
| H4 | Validate ParseLimits defaults against larger real lockfiles | - | Measured sizes and times recorded; defaults kept or changed with evidence | Verified |
| H5 | Housekeeping: pin Python dependencies; relabel or remove the hand-written fixture | - | Locked versions; no misleading fixture | Not started |
| H6 | Bound the two unbounded error messages (dependency name in the string-range error, lockfileVersion value) with the quoting helper | - | Both messages stay short for 100,000-character input; tests added | Not started |
| I | Persistence, API, dashboard, evaluation report, final documentation | - | As in the Phase 1 plan | Not started |

## Outstanding requirements (binding)
- Transitive production-scope propagation (F1) is implemented and verified against all four committed fixtures. It remains a prerequisite for vulnerability scoring.
- OSV vulnerability matching (E3-E5) is the next major milestone.
- npm workspaces and `link` entries remain unsupported and need a separate checkpoint (H2).
- The parser's three "must be an object" branches still need tests (H3).
- Parse-limit defaults need validation against larger real lockfiles (H4).
- Parser-side package source identity, eligibility guard, and registry candidate selection are implemented and tested. Integration with OSV advisory queries remains pending under E2.
- E1 real API responses have been captured and inspected. Pagination, rate limits, error schemas, and production reliability remain unverified; see eval/spikes/e1/verification-report.md.

## Test inventory (380 collected: 376 passed, 4 skipped)
| File | Tests |
|---|---|
| test_smoke.py | 1 |
| test_lockfile.py | 8 |
| test_models.py | 22 |
| test_graph.py | 19 |
| test_parsed_lockfile.py | 18 |
| test_lockfile_graph_integration.py | 11 |
| test_lockfile_hardening.py | 69 |
| test_parse_limits.py | 27 |
| test_is_dev.py | 26 |
| test_real_lockfiles.py | 90 passed, 4 skipped |
| test_scope_propagation.py | 40 |
| test_package_sources.py | 22 |
| test_source_eligibility.py | 12 |
| test_registry_candidates.py | 11 |

## Environment
- Python 3.12.10
- Node.js v24.19.0
- npm 12.0.2 (registry https://registry.npmjs.org/)
- Git 2.55.0
- Docker: not installed or not on PATH (needed for PostgreSQL later)

## Verified facts
Observed in the five committed npm-generated fixtures (npm 12.0.2; counts also matched an
independent run with npm 10.9.7):
- npm writes lockfileVersion 3 by default and version 2 when asked.
- Every non-workspace lockfile has a root entry, canonical install paths and no duplicate keys.
- An alias install sits at node_modules/<alias> and its entry name is the real package.
- The dev, optional, devOptional and peer flags appear: dev on 228 entries and optional on 1
  entry in each general lockfile; optional on 11, devOptional on 4 and peer on 1 in flags-v3.
  A peer dependency that nothing else requires is installed and flagged peer.
- peerDependenciesMeta is present: 8 entries in each general lockfile and 1 in peer-v3.
- The workspace project has 2 `link` entries and 3 install paths outside node_modules, which
  the parser rejects.
- The same package version appears at several install paths, with distinct parents.

## Parse-limit measurements (H4)

Defaults retained: 50,000,000 characters, 100,000 installed packages,
32 path segments, and 1,024 characters per install path.

Committed fixture measurements:
- flags-v3: 9,113 bytes, 20 packages, median 0.53 ms.
- general-v2: 289,282 bytes, 342 packages, median 12.87 ms.
- general-v3: 163,444 bytes, 342 packages, median 12.03 ms.
- peer-v3: 109,516 bytes, 218 packages, median 6.78 ms.
- workspace-v3: rejected as expected because linked package entries are unsupported.

Generated npm lockfile:
- 372,033 bytes, 748 packages, longest path 76 characters, 7 path segments.
- Three runs: 41.02 ms, 43.82 ms, 43.63 ms; median 43.63 ms.

Five local real-project lockfiles also passed:
- Introduction to Express.js: 78,713 characters, 181 packages.
- secure-connect-platform: 73,141 characters, 174 packages.
- Request & Response Handling: 72,619 characters, 166 packages.
- MVC Art: 72,613 characters, 166 packages.
- Controllers & Business Logic: 72,603 characters, 166 packages.

The observed measurements are below the configured defaults. Defaults are retained.
These measurements do not constitute stress testing at the configured maximum
character or package limits.

## Unverified
- OSV response structure for npm, EPSS fields, KEV feed schema, NVD metrics and response shape.
  Some were described in Phase 1 from documentation and search results, not real responses.
- The shape of peerDependenciesMeta values on npm 12.0.2: the field is present in the
  committed lockfiles but its contents were not printed. The {optional: true} shape was seen
  on npm 10.9.7.
- Lockfile shapes for git, file and bundled dependencies, and from other npm versions.
- Lockfiles at monorepo scale, and whether the parse limits suit them.
- Real output containing dev+optional or dev+peer flags together.

## Decisions
- ADR-001: Phase 1 decisions and safeguards
- ADR-002: Graph node identity and install paths (amended)
- ADR-003: Parser hardening, scope semantics and graph decoupling

