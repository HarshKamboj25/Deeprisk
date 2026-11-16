"""Tests for shared scanner service construction."""

import httpx

from deprisk.scanner_services import (
    ScannerServices,
    build_scanner_services,
)
from deprisk.vulnerability.enrichment_service import (
    VulnerabilityEnrichmentService,
)
from deprisk.vulnerability.osv_service import OSVVulnerabilityService


def test_build_scanner_services_returns_expected_services() -> None:
    client = httpx.AsyncClient()

    try:
        services = build_scanner_services(client)

        assert isinstance(services, ScannerServices)
        assert isinstance(services.osv_service, OSVVulnerabilityService)
        assert isinstance(
            services.enrichment_service,
            VulnerabilityEnrichmentService,
        )
    finally:
        import asyncio

        asyncio.run(client.aclose())
