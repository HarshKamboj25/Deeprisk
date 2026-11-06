# ADR-003: Parser hardening, scope semantics and graph decoupling

Status: accepted
Checkpoints: C (0478f13) and D (2560cd5 fixtures, d75f91e hardening)

## Context
ADR-002 fixed how the graph identifies installations. Checkpoints A and B made the edge model
follow it. Checkpoints C and D connected the parser to the graph and hardened the parser,
because a lockfile is untrusted input. The decisions below were made test-first and checked
against real npm lockfiles.

## Decisions

### Parser output and graph input (Checkpoint C)
1. `parse_lockfile` returns a `ParsedLockfile` (nodes plus the root's declared dependencies).
   `parse_lockfile_text` is a thin wrapper that returns the node list, so existing callers
   did not change.
2. Each package's declared dependencies are stored on its node
   (`DependencyNode.declared_dependencies`), not in a separate map, so the graph builder needs
   no extra input.
3. Declared dependencies map to scopes: dependencies -> production; root devDependencies ->
   development; optionalDependencies -> optional (is_optional=True); peerDependencies -> peer
   (optional when peerDependenciesMeta marks the peer optional).
4. A node is direct only when it is installed at node_modules/<root dependency key>. A nested
   copy that shares a name with a root dependency is never direct. An alias install is matched
   by its directory key; the real package name comes from the entry's name field.
5. Declared dependency maps are validated strictly: an object, non-empty names, string ranges.

### Edge construction (Checkpoints A and B; recorded because ADR-002 left the details open)
6. Edge resolution is `resolved`, `missing_optional` or `missing`. An unresolved dependency is
   kept as an edge with child_path None. The root's path is "".
7. Root dependencies are resolved by the same Node-style lookup as any other dependency,
   starting at the root.
8. An edge is identified by (parent path, dependency name, scope). Edges are sorted by parent
   path, dependency name, scope and child path (None sorts as empty), so order never depends on
   input order.

### Parser hardening (Checkpoint D)
9. Every malformed input raises `LockfileParseError`. Text taken from the file before it is
   validated (duplicate keys, install paths) is quoted through a helper that escapes it and
   cuts it at about 80 characters. Messages that name an install path after validation print
   it as is (validated, within max_path_length). Two messages still echo untruncated file
   text: the dependency name in the string-range error and the lockfileVersion value. They
   are escaped, so they cannot inject lines into a log, but their length is unbounded (L11).
10. Duplicate JSON keys are rejected. None of the real lockfiles examined contains one, and
    silently keeping the last value would let a file hide a value from the scanner.
11. A lockfile with no root entry ("") is rejected.
12. Deeply nested JSON raises `LockfileParseError` ("nested too deeply") instead of a raw
    RecursionError. The depth at which Python's json module gives up varies by build (CPython
    3.12.3 parsed 5,000 levels and failed at 10,000), so the code catches RecursionError and the
    tests use 200,000 levels.
13. An install path must be `node_modules/<name>` repeated, where <name> is `pkg` or
    `@scope/pkg`. Rejected: any other segment (including workspace paths such as
    packages/app), empty, "." and ".." names, backslashes, whitespace and control characters,
    and half-formed scopes. Uppercase is allowed (legacy package names).
14. The entry `name` field, when present, must be a valid package name. A present non-string
    value (null, 0, false, [], {}) is rejected. When absent, the name comes from the path.
    Root dependency keys are deliberately not validated: they are never used as paths, and an
    unmatched key just produces a missing edge.
15. `ParseLimits` (immutable, every value at least 1):

    | Field | Default | Meaning |
    |---|---|---|
    | max_characters | 50,000,000 | Checked before parsing |
    | max_packages | 100,000 | Installed packages; the root entry is excluded |
    | max_path_segments | 32 | node_modules levels; a scoped name counts once |
    | max_path_length | 1,024 | Characters in one install path |

    Limits are inclusive. The defaults are hypotheses, set far above anything observed.

### Scope semantics
16. Scopes are recorded per install instance, from root declarations (direct instances only)
    and npm's dev, optional, devOptional and peer flags.
17. `is_dev` is derived from scopes: true when development is present and neither production
    nor optional is. Peer is ignored. Conflicting evidence never produces dev-only, so risk is
    not understated. `is_dev == False` does not mean production: a package with no recorded
    scope is unclassified. The meaning is in the model's field description. The model enforces
    nothing; the parser derives the value and a test checks it for all 256 flag and
    declaration combinations.

### Graph and parser decoupling
18. `graph.py` raises `GraphBuildError` (a ValueError) for duplicate install paths and no
    longer imports the parser module.

## Alternatives considered
- Declared dependencies in a separate per-path map: rejected, it would have forced a signature
  change and rewrites of existing graph tests.
- Warning on duplicate keys or a missing root instead of rejecting: rejected, silent
  acceptance is the risk, and none of the real lockfiles examined has either.
- Taking production scope straight from npm's flags: deferred (see L1). The flags are claims
  inside an untrusted file, so a graph-derived value cross-checked against them is preferred.

## Evidence
- 257 tests pass on the developer's machine: 79 existing before Checkpoint D plus 178 new, including the three H3 object-validation tests.
- Five real npm-generated projects are committed under tests/fixtures/recorded/npm-lockfiles/
  with PROVENANCE.md and SHA256SUMS.txt (npm 12.0.2, the only npm version committed). Git is
  told not to alter their bytes. Node and edge counts matched an independent run with npm
  10.9.7 (outside the repository) for every project reported.
- Parse cost: path validation added roughly 23% to parse time on a synthetic 100,000-package
  file in a noisy environment; real lockfiles parse in milliseconds. Not measured on the
  developer's machine.

### Graph-derived deployment scope (L1)

19. Transitive deployment scope is derived from the dependency graph using `propagate_scopes(nodes, edges)`. Parser-level evidence remains unchanged: `DependencyNode.is_dev`, `DependencyNode.scopes`, and raw edge scopes are not mutated.

20. Scope propagation uses physical `install_path` as node identity. Each node preserves every distinct reachable path state. The state space consists of eight combinations:

    | Environment | Required | Optional |
    |---|---|---|
    | Production | (PROD, REQ) | (PROD, OPT) |
    | Development | (DEV, REQ) | (DEV, OPT) |
    | Peer | (PEER, REQ) | (PEER, OPT) |
    | Unknown | (UNKNOWN, REQ) | (UNKNOWN, OPT) |

21. Optionality propagates through descendants. Development optional paths remain distinct from production optional paths. Optional peer dependencies preserve their optional state. Peer edges inherit the deployment context of their parent; a standalone root peer dependency starts in the PEER context.

22. UNKNOWN is conservative evidence. An UNKNOWN parent remains UNKNOWN across outgoing edges, including development edges. UNKNOWN evidence cannot be classified as development-only or dev-optional unless an unconditional production path independently establishes production precedence. An unconditional production path (PROD, REQ) takes precedence over other reached states.

23. Effective classifications are represented by `EffectiveScope`: PRODUCTION, DEVELOPMENT, OPTIONAL, DEV_OPTIONAL, PEER, UNKNOWN, and UNREACHABLE. The result preserves all reached states and separate path-evidence flags. Missing edges with `child_path=None` terminate propagation.

24. Parser disagreements are reported only for explicit contradictory evidence:
    - A parser dev-only claim contradicted by graph-derived unconditional PRODUCTION.
    - An explicitly recorded production scope contradicted by graph-derived DEVELOPMENT-only classification.

    Unclassified parser evidence is not treated as a disagreement merely because graph propagation resolves it. OPTIONAL, DEV_OPTIONAL, PEER, UNKNOWN, and UNREACHABLE classifications do not independently imply a production/development contradiction.

25. Propagation uses a finite-state worklist algorithm. The result and nested collections are immutable. Parser models and existing parser behavior remain unchanged.

### L1 fixture validation evidence

26. Scope propagation was cross-checked against all four committed real npm lockfile fixtures: general-v3, general-v2, peer-v3, and flags-v3.

27. The fixture integration tests verify:
    - Every parsed physical node is represented in the propagation result.
    - No node is unreachable in the four tested fixtures.
    - No evidence-based parser/graph contradictions are reported.
    - npm dev, optional, devOptional, and peer flags are compared using the documented scope semantics.
    - The peer-flagged `react` node in flags-v3 is classified as PRODUCTION because its peer edge originates from a production parent.
    - Repeated propagation produces deterministic results.

28. Observed graph-derived scope distributions:

    | Fixture | Production | Development | DEV_OPTIONAL | Optional |
    |---|---:|---:|---:|---:|
    | general-v3 | 113 | 174 | 54 | 1 |
    | general-v2 | 113 | 174 | 54 | 1 |
    | peer-v3 | 218 | 0 | 0 | 0 |
    | flags-v3 | 5 | 0 | 4 | 11 |

29. The four fixture tests skipped are limited to flag-specific cases where the corresponding fixture contains no packages with the requested flag. The full test suite collected 357 tests: 353 passed and 4 skipped.

30. L1 is verified on the four committed fixtures. This does not establish compatibility with every npm version, workspace/link entry, or unobserved flag combination.

31. L6 parser-side source identity is implemented. `PackageSourceType` distinguishes registry, git, file, URL, and unknown sources. The parser preserves `resolved`, `integrity`, and `hasInstallScript`. Twenty-two focused source tests pass; the full suite collects 357 tests, with 353 passed and 4 skipped. Source-aware OSV matching remains pending under E2. Link/workspace entries remain unsupported under L3.

## Known limitations and outstanding requirements

| # | Item | Why it matters | Where it lands |
|---|---|---|---|
| L1 | Transitive production scope propagation | Verified. Graph-derived scope is implemented and cross-checked against all four committed npm fixtures. See decisions 19–30 and L1 fixture validation evidence. | Completed in L1; required before scoring work. |
| L2 | OSV matching is not started. The core milestone (local repository -> parser -> graph -> OSV matching -> explainable report) is incomplete. | Binding safeguard S4. | Next major milestone. |
| L3 | npm workspaces and `link` entries are rejected on purpose. | A standard workspace project cannot be scanned (fixture workspace-v3). | Separate checkpoint, policy chosen from the fixture evidence. |
| L4 | The three required-object validation branches now have tests for the root document, `packages`, and package entry. | Validation coverage added. | Completed in H3; three tests pass in test_lockfile_hardening.py. |
| L5 | Parse-limit defaults have been measured against committed fixtures, a generated 748-package lockfile, and local real-project lockfiles; the configured maximum limits have not been stress-tested. | Measurements support retaining the current defaults, but do not prove behavior at the configured maxima. | H4 measurements recorded in docs/tracker.md; retain defaults and revisit with larger-scale evidence. |
| L6 | Parser-side package source identity is modeled for registry, git, file, URL, and unknown sources; `resolved`, `integrity`, and `hasInstallScript` are preserved. npm link/workspace entries remain unsupported under L3. | OSV matching must use this identity so Git, file, URL, and unknown sources are not treated as registry versions. | Parser implementation verified; matcher safeguard remains pending in E2. |
| L7 | External API behavior is unverified (OSV, EPSS, KEV, NVD). | Phase 1 notes marked some facts verified from documentation and search results. Under safeguard S6 they stay unverified until real responses are inspected. | The API verification spike, before OSV implementation. |
| L8 | Fixture coverage is thin: one project per shape, one npm version committed (12.0.2; counts were cross-checked against npm 10.9.7 outside the repository). `dev`+`peer` and `dev`+`optional` flag combinations were never seen in real output, and treating peer as orthogonal is an assumption. | Real files may differ. | Add fixtures as new shapes appear. |
| L9 | The hand-written `recorded/package-lock-v3-minimal.json` is referenced by no test and sits in a folder that implies real recorded data. | Misleading provenance. | Relabel or remove. |
| L10 | Python dependencies have lower bounds only and no lock. | Reproducibility and supply-chain hygiene of the tool itself. | Pin before release. |
| L11 | Two error messages echo untruncated file text: the dependency name in the string-range error and the lockfileVersion value (100,000 characters measured). They are escaped, so no log injection, but their length is unbounded. | Safe logging. | Small code fix: bound both with the quoting helper, plus tests (tracker H6). |
