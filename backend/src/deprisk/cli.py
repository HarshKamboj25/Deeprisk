"""Command-line interface for DepRisk."""

import argparse
import asyncio
import sys
from collections.abc import Sequence
from pathlib import Path

import httpx

from deprisk.report import build_repository_report, render_json_report
from deprisk.repository import RepositoryScanError
from deprisk.scan import scan_github_repository, scan_local_repository
from deprisk.scanner_services import build_scanner_services


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="deprisk",
        description="Explainable software supply-chain vulnerability scanner.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a local or GitHub npm repository.",
    )

    scan_parser.add_argument(
        "repository",
        type=str,
        help="Local repository path or GitHub repository URL.",
    )

    scan_parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("deprisk-report.json"),
        help="JSON report output path.",
    )

    return parser


async def _run_scan(repository: Path) -> str:
    async with httpx.AsyncClient() as client:
        services = build_scanner_services(client)

        result = await scan_local_repository(
            repository,
            services.osv_service,
            services.enrichment_service,
        )

    report = build_repository_report(result)
    return render_json_report(report)


async def _run_github_scan(repository_url: str) -> str:
    async with httpx.AsyncClient() as client:
        services = build_scanner_services(client)

        result = await scan_github_repository(
            repository_url,
            services.osv_service,
            services.enrichment_service,
        )

    report = build_repository_report(result)
    return render_json_report(report)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        try:
            is_url = "://" in args.repository

            if is_url:
                report_json = asyncio.run(_run_github_scan(args.repository))
                repository_label = args.repository
            else:
                repository = Path(args.repository)
                report_json = asyncio.run(_run_scan(repository))
                repository_label = str(repository.resolve())

            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(report_json + "\n", encoding="utf-8")

            print(f"Scan completed: {repository_label}")
            print(f"Report saved: {args.output.resolve()}")

            return 0

        except (RepositoryScanError, OSError, ValueError, httpx.HTTPError) as exc:
            print(f"DepRisk scan failed: {exc}", file=sys.stderr)
            return 1

    return 2
