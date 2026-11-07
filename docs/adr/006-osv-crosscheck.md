# ADR-006: OSV batch-to-advisory consistency cross-check

Status: accepted

## Context

E3 implements local npm version applicability matching against hydrated OSV
advisory details. E4 requires explainable cross-check decisions and logging
when OSV batch results disagree with local affected-range evaluation.

## Decision

1. Compare each advisory returned by an OSV batch query with the local
   applicability decision computed from its hydrated advisory details.
2. Record one immutable OSVCrossCheckDecision per returned package-advisory
   pair, preserving package identity, installed version, install paths,
   advisory ID, local status, cross-check status, and explanation.
3. Classify outcomes as:
   - AGREEMENT: the batch query returned the advisory and the local matcher
     classified the installed version as AFFECTED.
   - DISAGREEMENT: the batch query returned the advisory but the local
     matcher classified the installed version as NOT_AFFECTED.
   - INCONCLUSIVE: the batch query returned the advisory but the local
     matcher classified the installed version as UNKNOWN.
4. Emit a WARNING log for each disagreement containing the package name,
   version, advisory ID, install paths, and explanation.
5. Return all cross-check decisions in OSVLookupResult.
6. Preserve the existing finding policy: only AFFECTED local decisions
   produce VulnerabilityFinding objects.

## Interpretation and limitations

This is a consistency check between two stages of the same OSV API
workflow, not independent confirmation by another vulnerability
intelligence source.

An OSV batch result containing an advisory ID does not itself establish
that the hydrated advisory's supported ranges include the installed
version. A disagreement signals an inconsistency requiring investigation,
not proof of a false positive.

UNKNOWN remains inconclusive and must not be treated as safe.
Advisories absent from batch results are not independently checked.
Warning logs are emitted through Python logging; durable log retention
depends on the application's logging configuration.

## Verification

- Five cross-check unit tests cover agreement, disagreement,
  inconclusive evidence, install-path preservation, and immutability.
- Three service integration tests cover all three outcomes.
- The disagreement integration test verifies WARNING output and its
  package, version, advisory, install-path, and explanation fields.
- Full project check: 466 collected, 462 passed, 4 skipped.
- Ruff lint, Ruff format, and strict mypy passed.

## Follow-up

E5 will expose the cross-check decisions through the local
repository-to-report vertical slice.
