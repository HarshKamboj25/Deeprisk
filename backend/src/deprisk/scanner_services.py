"""Shared vulnerability scanner service construction."""

import os
from dataclasses import dataclass

import httpx

from deprisk.vulnerability.enrichment_service import (
    VulnerabilityEnrichmentService,
)
from deprisk.vulnerability.epss_client import EPSSClient
from deprisk.vulnerability.kev_client import KEVClient
from deprisk.vulnerability.nvd_client import NVDClient
from deprisk.vulnerability.osv_client import OSVClient
from deprisk.vulnerability.osv_service import OSVVulnerabilityService


@dataclass(frozen=True, slots=True)
class ScannerServices:
    """Vulnerability services used by the scanning pipeline."""

    osv_service: OSVVulnerabilityService
    enrichment_service: VulnerabilityEnrichmentService


def build_scanner_services(client: httpx.AsyncClient) -> ScannerServices:
    """Build scanner services using a caller-managed HTTP client."""

    osv_client = OSVClient(client=client)
    epss_client = EPSSClient(client=client)
    kev_client = KEVClient(client=client)
    nvd_client = NVDClient(
        client=client,
        api_key=os.getenv("NVD_API_KEY"),
    )

    return ScannerServices(
        osv_service=OSVVulnerabilityService(osv_client),
        enrichment_service=VulnerabilityEnrichmentService(
            epss_client=epss_client,
            kev_client=kev_client,
            nvd_client=nvd_client,
        ),
    )
