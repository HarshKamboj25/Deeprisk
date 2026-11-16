# DepRisk tracker

Status values: Not started | In progress | Implemented | Verified
Only Verified counts as done. Verified means the tests pass on the developer's machine.

Last updated after persistence, asynchronous API integration, worker recovery and full backend verification.
Schedule: four-week maximum. The project start date is UNRESOLVED: no verified date is
available, so elapsed and remaining time are not tracked here. Record the date when it is
known.
Item IDs in this file (E1 and later) supersede the informal checkpoint labels used earlier in
the project planning.

## Summary
- Latest full backend suite: 849 passed, 6 skipped, 0 failed (2026-11-10).
- Implemented and verified: lockfile parser (v2 and v3), dependency graph, parser hardening, real npm lockfile fixtures, graph-derived scope propagation, OSV matching, enrichment, scoring, reachability, and remediation.
- E2-E5, F1-F3, G1, G2, H1, H2, H5 and H6 are implemented and verified. Persistence and asynchronous API implementation are also regression-tested.
- Remaining work: React dashboard, dependency graph visualization, evaluation report, final documentation and product-level validation.
- The core local repository -> parser -> graph -> OSV matching -> explainable report milestone remains Verified.
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
| G5 | Parser-side package source identity and source-aware eligibility safeguard | Verified: parser identity, eligibility guard, deterministic candidate selection, and end-to-end OSV boundary integration |
| R4 | Workspaces and link entries rejected | Resolved by H2: explicit unsupported policy, deterministic rejection and regression coverage |
| - | Hand-written fixture in recorded/ | Resolved in H5: unused misleading fixture removed; genuine recorded fixtures retained |
| - | Python dependencies unpinned | Resolved in H5: exact-version requirements lock created and validated |

## Remaining work
| ID | Deliverable | Depends on | Acceptance criteria | Status |
|---|---|---|---|---|
| E1 | API verification spike: OSV, EPSS, KEV, NVD | - | Real timestamped responses inspected; findings documented; full checks pass | Verified |
| E2 | Package source identity modeling and source-aware OSV matching | C | Non-registry versions are never matched as registry versions | Verified: source eligibility and end-to-end OSV integration test pass |
| E3 | OSV client: batch query, hydrate, cache, normalize, alias grouping, and npm version verification | E1 | Gold cases pass; bounded transient-error and rate-limit retries; affected findings verified | Verified |
| E4 | Local affected-range matcher with OSV cross-check | E3 | Disagreements with OSV are logged and explained | Verified |
| E5 | Core vertical slice: CLI local repository -> parser -> graph -> OSV matching -> explainable report | E2-E4 | Tested on at least 3 real repositories; findings group by (PackageVersion, alias group) and link to every affected install (ADR-002 point 6) | Verified | Three live repositories: 84/0, 174/12, 68/3 dependencies/findings; aggregation and install-path unit tests pass; full suite: 590 passed, 5 skipped |
| F1 | Transitive production-scope propagation | C | Scope derived from the graph; cross-checked against npm flags on all four committed fixtures; disagreements reported; must pass before F3 | Verified |
| F2 | EPSS, KEV and NVD enrichment with snapshots | E1 | Missing data never treated as zero risk | Verified | Snapshot tests, full suite (590 passed, 5 skipped), live scan: EPSS 16 available/1 not found; KEV 17 not found; NVD 16 available/1 not found; 0 unavailable |
| F3 | Scoring v1 (versioned hypothesis, score interval) | F1, F2 | Sensitivity analysis documented; weights not presented as validated | Verified | 22 scoring-service tests passed; sensitivity analysis: docs/scoring-v1-sensitivity-analysis.md; full unit suite: 705 passed, 5 skipped |
| G1 | Reachability tiers 0 and 1; Tier 2 only after the parser spike and tests pass | E5 | Evidence recorded; no-path-found never reported as safe | Verified | Tier 0/1 propagation; direct-versus-nested installation tests; unresolved edges preserved; unreachable safety boundary and scoring limitation documented; focused regression suite: 189 passed, 0 failed |
| G2 | Remediation recommendations | E5 | Fixed versions from advisory data; unknown fix stated | Verified |
| H1 | Safe repository ingestion (GitHub tarball, SSRF, safe extraction) | - | Security tests pass; full backend suite: 798 passed, 5 skipped, 0 failed | Verified |
| H2 | Workspaces and link support (separate checkpoint) | C | Fixture-backed explicit rejection; link-first detection is order-independent; focused and full backend tests pass | Verified |
| H3 | Tests for the three parser "must be an object" branches | - | Root document, packages, and package entry each raise LockfileParseError | Verified |
| H4 | Validate ParseLimits defaults against larger real lockfiles | - | Measured sizes and times recorded; defaults kept or changed with evidence | Verified |
| H5 | Housekeeping: pin Python dependencies; relabel or remove the hand-written fixture | - | Exact-version dependency lock validated; misleading fixture removed; full backend suite: 799 passed, 5 skipped, 0 failed | Verified |
| H6 | Bound the two unbounded error messages (dependency name in the string-range error, lockfileVersion value) with the quoting helper | - | Both messages bounded for 100,000-character input; 29 focused tests passed; Ruff clean; full backend suite: 801 passed, 5 skipped, 0 failed | Verified |
| I | Persistence, API, dashboard, evaluation report, final documentation | - | Persistence and migrations; asynchronous API; bounded worker pool; startup recovery; dashboard; evaluation; final documentation and validation | In progress | Persistence and API implemented; SQLite migrations and migration cycle verified; PostgreSQL migration SQL inspected offline (no live server). Full backend: 849 passed, 6 skipped, 0 failed; Ruff clean; 95 files formatted. Dashboard, evaluation and final documentation remain outstanding |

## Outstanding requirements (binding)
- Transitive production-scope propagation (F1) is implemented and verified against all four committed fixtures. It remains a prerequisite for vulnerability scoring.
- OSV lookup and version verification (E3), plus explainable OSV consistency cross-checking and disagreement warning logs (E4), are verified. E5, the complete repository-to-report vertical slice, is verified.
- npm workspaces and `link` entries are explicitly unsupported by design (H2); linked entries are rejected before installation-path parsing, independent of JSON entry order.
- Parser-side package source identity, eligibility guard, deterministic registry candidate selection, and source-to-OSV integration are implemented and verified under E2.
- E1 real API responses have been captured and inspected. Client retries for selected transient failures and HTTP 429 are implemented under E3; pagination, production rate-limit behavior, broader error schemas, and production reliability remain unverified; see eval/spikes/e1/verification-report.md.

## Historical test inventory (E4-era snapshot: 466 collected, 462 passed, 4 skipped)
| File | Tests |
|---|---:|
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
| test_osv_aliases.py | 7 |
| test_osv_client.py | 25 |
| test_osv_models.py | 6 |
| test_osv_normalizer.py | 11 |
| test_osv_pipeline_integration.py | 1 |
| test_osv_service.py | 8 |
| test_osv_crosscheck.py | 5 |
| test_osv_version_matcher.py | 14 |
| test_ttl_cache.py | 9 |

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
- The workspace project has 2 `link` entries and 3 install paths outside node_modules. H2 verifies deterministic rejection before unsupported workspace paths are parsed.
- The same package version appears at several install paths, with distinct parents.

## Parse-limit measurements (H4)

Defaults retained: 50,000,000 characters, 100,000 installed packages,
32 path segments, and 1,024 characters per install path.

Committed fixture measurements:
- flags-v3: 9,113 bytes, 20 packages, median 0.53 ms.
- general-v2: 289,282 bytes, 342 packages, median 12.87 ms.
- general-v3: 163,444 bytes, 342 packages, median 12.03 ms.
- peer-v3: 109,516 bytes, 218 packages, median 6.78 ms.
- workspace-v3: rejected by the explicit link-first policy; regression test confirms rejection is independent of JSON entry order.

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
- Production API behavior remains partly unverified: pagination, production rate-limit behavior, broader error schemas and production reliability. Real OSV, EPSS, KEV and NVD responses were captured and inspected; see eval/spikes/e1/verification-report.md.
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
- ADR-004: Source-aware vulnerability matching
- ADR-005: OSV advisory lookup and version verification
- ADR-006: OSV batch-to-advisory consistency cross-check
