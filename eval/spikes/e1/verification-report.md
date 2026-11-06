# E1: External Vulnerability API Verification Report

Capture date: 2026-11-06

## Captured API responses

| API | HTTP | Observation |
|---|---:|---|
| OSV single query | 200 | lodash returned 4 vulnerabilities |
| OSV batch query | 200 | Two results: 4 and 1 vulnerabilities |
| OSV vulnerability detail | 200 | Five affected package entries |
| FIRST EPSS | 200 | Score and percentile returned as strings |
| CISA KEV | 200 | 1,768 records; catalog count matched |
| NVD | 200 | CVE nested under vulnerabilities[].cve |

## Verified observations

- OSV uses vulns for single queries and results for batch queries.
- OSV affected entries contain package identity and structured version ranges.
- Observed range events include introduced, fixed, and last_affected.
- OSV severity can contain a CVSS vector string.
- EPSS provides cve, epss, percentile, and date.
- KEV CWE data was absent in 175 of 1,768 records.
- KEV ransomware values included Known and Unknown.
- NVD returned CVSS v3.1, CVSS v2, and SSVC metric families in the sample.
- All six captured requests returned HTTP 200.

## Implementation implications

- Match all OSV affected package entries.
- Handle range events explicitly.
- Parse EPSS decimal strings and preserve score dates.
- Treat missing CWE and other optional metadata defensively.
- Preserve NVD metric source and type; define deterministic CVSS selection.
- Use the dedicated KEV catalog for KEV membership.

## Unverified

- Pagination under load and actual page-token handling.
- Rate limits and retry behavior.
- Invalid-request and service-error response schemas.
- EPSS historical and bulk-query behavior.
- CISA feed outage and schema-change behavior.
- NVD multi-page and API-key behavior.
- Production-scale latency and reliability.

## Official documentation

- https://google.github.io/osv.dev/api/
- https://www.first.org/epss/api
- https://github.com/cisagov/kev-data/blob/develop/known_exploited_vulnerabilities_schema.json
- https://nvd.nist.gov/developers/vulnerabilities

Raw timestamped captures are stored beside this report. Reproduce with: python eval/spikes/e1/capture_api_samples.py

No production API client or scoring implementation was added in E1.
