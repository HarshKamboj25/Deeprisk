# ADR-005: OSV advisory lookup and version verification

Status: accepted

## Context

DepRisk needs external vulnerability intelligence to identify advisories
for installed npm packages and determine whether the installed versions
are affected.

The E1 API verification spike captured and inspected real OSV responses.
The implementation must preserve package-to-advisory associations,
avoid treating every returned advisory as a confirmed vulnerability,
and handle unsupported or ambiguous version evidence conservatively.

Source eligibility is defined separately in ADR-004.

## Decision

1. Use the OSV v1 API as the initial vulnerability intelligence source
   for npm packages.

2. Query eligible registry candidates through the OSV batch endpoint.
   Each query contains the npm ecosystem, package name, and installed
   package version.

3. Hydrate advisory identifiers returned by batch queries using the
   OSV advisory detail endpoint.

4. Use bounded in-memory TTL caches for batch results and advisory
   details. Cache capacity and lifetime are configurable.

5. Retry transient network failures, timeouts, HTTP 429, and selected
   server errors with bounded retry attempts and backoff. Respect
   numeric Retry-After values when supplied.

6. Validate advisory identifiers before constructing detail request
   URLs. Reject empty or unsafe identifiers.

7. Normalize OSV advisory details into DepRisk advisory references.
   Preserve aliases and severity information where available.
   Do not invent a numeric CVSS score when the source does not provide
   one in a supported form.

8. Group advisories connected through shared aliases into deterministic
   alias groups. Alias relationships are transitive.

9. Match installed npm versions against matching OSV affected-package
   entries using semantic-version comparison.

10. Supported SEMVER event boundaries:
    - introduced: inclusive lower boundary
    - fixed: exclusive upper boundary
    - last_affected: inclusive upper boundary
    - an unclosed introduced range: open-ended

11. Exact affected-version entries are checked in addition to range
    evidence. Exact version matching currently uses the supplied
    version string.

12. Unsupported range types, limit events, malformed event sequences,
    and ambiguous evidence produce UNKNOWN rather than a confirmed
    affected result.

13. Preserve a match decision for each package-advisory pair.
    Create a VulnerabilityFinding only when the version matcher returns
    AFFECTED. UNKNOWN and NOT_AFFECTED decisions do not create findings.

14. Preserve package identity and affected install paths when creating
    findings. Shared advisory details may be hydrated once while
    retaining separate package associations.

15. Source eligibility remains an upstream requirement. The caller
    must pass candidates produced by select_registry_candidates().
    OSVVulnerabilityService accepts RegistryQueryCandidate objects
    and does not independently reclassify DependencyNode sources.

## Verification

- OSV response models are validated using captured E1 fixtures.
- OSV client tests cover batch queries, advisory hydration, caching,
  retries, and advisory identifier validation.
- Normalization and alias grouping have dedicated unit tests.
- Version matching tests cover boundaries, disjoint ranges,
  open-ended ranges, malformed events, unsupported evidence,
  prereleases, and a captured lodash advisory.
- Service tests cover shared advisory hydration, multiple advisories,
  alias grouping, affected findings, NOT_AFFECTED results, UNKNOWN
  results, and empty input.
- An end-to-end integration test verifies source eligibility through
  registry candidate selection and OSV lookup. Non-registry and unknown
  sources are excluded from the OSV batch request.
- Latest full check: 454 passed, 4 skipped, 458 collected.
- Ruff lint, Ruff formatting, and strict mypy passed.

## Limitations

- The initial implementation supports npm package queries only.
- OSV limit event semantics are not implemented; such evidence returns
  UNKNOWN.
- Unsupported range types are not interpreted.
- Exact affected-version entries currently use string equality.
- Cache storage is in-memory and is not shared across processes.
- API pagination, production rate limits, long-term availability, and
  broader failure behavior remain unverified beyond the implemented
  retry and error handling.
- EPSS, CISA KEV, and NVD enrichment are separate future work.
- OSV disagreement logging and cross-check behavior remain separate
  from this implementation and must be addressed under E4.
- The complete local repository-to-report vertical slice remains
  future work under E5.
