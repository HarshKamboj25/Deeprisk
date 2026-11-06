from datetime import datetime, timezone
from pathlib import Path
import json

import httpx

OUT = Path("eval/spikes/e1")
OUT.mkdir(parents=True, exist_ok=True)

TIMEOUT = 30.0
HEADERS = {"User-Agent": "DepRisk-E1-API-Verification/1.0"}

requests_to_run = [
    (
        "osv_query_lodash",
        "POST",
        "https://api.osv.dev/v1/query",
        {
            "package": {"name": "lodash", "ecosystem": "npm"},
            "version": "4.17.20",
        },
    ),
    (
        "osv_querybatch_npm",
        "POST",
        "https://api.osv.dev/v1/querybatch",
        {
            "queries": [
                {
                    "package": {"name": "lodash", "ecosystem": "npm"},
                    "version": "4.17.20",
                },
                {
                    "package": {"name": "minimist", "ecosystem": "npm"},
                    "version": "1.2.5",
                },
            ]
        },
    ),
    (
        "osv_vulnerability_detail",
        "GET",
        "https://api.osv.dev/v1/vulns/GHSA-35jh-r3h4-6jhm",
        None,
    ),
    (
        "epss_log4shell",
        "GET",
        "https://api.first.org/data/v1/epss?cve=CVE-2021-44228",
        None,
    ),
    (
        "cisa_kev_catalog",
        "GET",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        None,
    ),
    (
        "nvd_log4shell",
        "GET",
        "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228",
        None,
    ),
]

manifest = []

with httpx.Client(
    timeout=TIMEOUT,
    headers=HEADERS,
    follow_redirects=True,
) as client:
    for name, method, url, payload in requests_to_run:
        captured_at = datetime.now(timezone.utc).isoformat()

        try:
            if method == "POST":
                response = client.post(url, json=payload)
            else:
                response = client.get(url)

            try:
                body = response.json()
            except ValueError:
                body = {"raw_text": response.text[:20000]}

            record = {
                "name": name,
                "captured_at_utc": captured_at,
                "method": method,
                "url": url,
                "request_body": payload,
                "http_status": response.status_code,
                "response_headers": {
                    key: value
                    for key, value in response.headers.items()
                    if key.lower() in {
                        "content-type",
                        "date",
                        "retry-after",
                        "x-ratelimit-limit",
                        "x-ratelimit-remaining",
                        "x-ratelimit-reset",
                        "last-modified",
                        "etag",
                    }
                },
                "response": body,
            }

            filename = OUT / f"{name}.json"
            filename.write_text(
                json.dumps(record, indent=2),
                encoding="utf-8",
            )

            manifest.append({
                "name": name,
                "status": response.status_code,
                "file": str(filename),
            })

            print(f"{name}: HTTP {response.status_code} -> {filename}")

        except httpx.HTTPError as exc:
            manifest.append({
                "name": name,
                "error": str(exc),
            })
            print(f"{name}: REQUEST ERROR -> {exc}")

(OUT / "manifest.json").write_text(
    json.dumps({
        "run_at_utc": datetime.now(timezone.utc).isoformat(),
        "results": manifest,
    }, indent=2),
    encoding="utf-8",
)

print("\nCapture complete.")
