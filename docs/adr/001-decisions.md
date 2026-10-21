# ADR-001: Phase 1 decisions and implementation safeguards

Status: accepted

## Architecture decisions
- Single-user local product; API binds to 127.0.0.1 by default.
- Inputs: public GitHub URL with optional ref and local path.
- API local-path access must be restricted to an allowlisted root.
- Support package-lock.json v2/v3 only in the MVP.
- OSV is the primary advisory source; NVD is supplementary.
- EPSS and KEV enrichment is keyed by CVE.
- GitHub repositories are fetched via safe tarball extraction.
- Never install or execute scanned repository code.
- Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2, and Alembic.
- The analysis core must not import web-framework or database code.
- Use an in-process worker pool with persisted job state.
- Use networkx for dependency graphs; no Neo4j.
- Frontend: React, Vite, JavaScript, React Router, CSS Modules, Cytoscape.js.
- Risk scoring v1 is a versioned hypothesis, not a scientifically validated formula.
- Keep scan-specific evidence snapshots for reproducibility.

## Binding safeguards
- Preserve each dependency installation path in the graph.
- Implement Tier 0 and Tier 1 reachability first.
- Add Tier 2 only after the parser spike, core pipeline, and tests pass.
- Evaluate scoring sensitivity; do not present proposed weights as validated.
- First complete: local repository -> lockfile parser -> dependency graph -> OSV matching -> explainable report.
- Cut stretch features before security, correctness tests, or honest evaluation.
- Mark external API behavior verified only after inspecting real responses.
- Build incrementally and test every milestone.