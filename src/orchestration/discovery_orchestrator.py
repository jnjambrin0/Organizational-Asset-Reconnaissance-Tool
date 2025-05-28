"""Orchestrates the discovery process using various modules."""

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Set, Callable, Dict, Any

from src.core.models import ReconnaissanceResult
from src.config.settings import get_settings
from src.utils.rate_limiter import get_rate_limiter

# Import discovery modules directly
from src.discovery import asn_discovery, ip_discovery, domain_discovery

# Import enhanced cloud detection
from src.discovery.enhanced_cloud_detection import detect_enhanced_cloud_services

from src.utils.logging_config import create_progress_logger, get_logger

logger = get_logger(__name__)

# Adjust max_workers based on typical usage and API limits
DEFAULT_MAX_WORKERS = 10


# --- Phase 1: Domain Discovery ---
def run_phase1_domains(
    target_organization: Optional[str],
    base_domains: Optional[Set[str]],
    result: ReconnaissanceResult,
    max_workers: int = DEFAULT_MAX_WORKERS,
    progress_callback: Optional[Callable[[float, str], None]] = None,
    status_callback: Optional[Callable[[str, str], None]] = None,
):
    """
    Phase 1: Domain Discovery - Find domains and subdomains related to the target organization

    Args:
        target_organization: Name of the target organization
        base_domains: Set of known domains to start with
        result: ReconnaissanceResult object to populate
        max_workers: Maximum number of concurrent workers
        progress_callback: Optional callback for progress updates
        status_callback: Optional callback for status updates
    """
    logger.info(
        f"🌍 Phase 1: Discovering Domains & Subdomains for {target_organization}"
    )

    # Create a progress logger for terminal
    progress = create_progress_logger(
        "domain_discovery", total=100, prefix="Domain Discovery"
    )
    progress.update(0, "Starting domain discovery...")

    if status_callback:
        status_callback("🔍", f"Searching for domains related to {target_organization}")

    try:
        # Pass callbacks to domain_discovery for more granular progress updates
        domain_discovery.find_domains(
            target_organization,
            base_domains,
            result,
            max_workers,
            progress_callback=lambda p, msg: (
                progress.update(p, msg),  # Update terminal progress
                (
                    progress_callback(p, msg) if progress_callback else None
                ),  # Update UI progress
            ),
        )

        progress.update(100, "Domain discovery completed")
        if status_callback:
            status_callback(
                "✅",
                f"Domain discovery complete - Found {len(result.domains)} domains and {len(result.get_all_subdomains())} subdomains",
            )

        logger.info(
            f"✅ Phase 1 completed: Found {len(result.domains)} domains and {len(result.get_all_subdomains())} subdomains"
        )
    except Exception as e:
        logger.exception(f"❌ Error during Phase 1 (Domain Discovery): {e}")
        result.add_warning(f"Phase 1 Error: {e}")
        if status_callback:
            status_callback("❌", f"Domain discovery error: {e}")


# --- Phase 2: ASN Discovery ---
def run_phase2_asns(
    target_organization: Optional[str],
    base_domains: Optional[Set[str]],  # May still be useful for BGP queries
    result: ReconnaissanceResult,
    max_workers: int = DEFAULT_MAX_WORKERS,
    progress_callback: Optional[Callable[[float, str], None]] = None,
    status_callback: Optional[Callable[[str, str], None]] = None,
):
    """
    Phase 2: ASN Discovery - Find autonomous systems related to the target organization

    Args:
        target_organization: Name of the target organization
        base_domains: Set of known domains (may be used for ASN lookup)
        result: ReconnaissanceResult object to populate
        max_workers: Maximum number of concurrent workers
        progress_callback: Optional callback for progress updates
        status_callback: Optional callback for status updates
    """
    logger.info(f"🌐 Phase 2: Discovering ASNs for {target_organization}")

    # Create a progress logger for terminal
    progress = create_progress_logger(
        "asn_discovery", total=100, prefix="ASN Discovery"
    )
    progress.update(0, "Starting ASN discovery...")

    if status_callback:
        status_callback("🔍", f"Searching for ASNs related to {target_organization}")

    try:
        # asn_discovery modifies the result object directly
        asn_discovery.find_asns_for_organization(
            target_organization,
            base_domains,
            result,
            max_workers,
            progress_callback=lambda p, msg: (
                progress.update(p, msg),  # Update terminal progress
                (
                    progress_callback(p, msg) if progress_callback else None
                ),  # Update UI progress
            ),
        )

        progress.update(100, "ASN discovery completed")
        if status_callback:
            status_callback(
                "✅", f"ASN discovery complete - Found {len(result.asns)} ASNs"
            )

        logger.info(f"✅ Phase 2 completed: Found {len(result.asns)} ASNs")
    except Exception as e:
        logger.exception(f"❌ Error during Phase 2 (ASN Discovery): {e}")
        result.add_warning(f"Phase 2 Error: {e}")
        if status_callback:
            status_callback("❌", f"ASN discovery error: {e}")


# --- Phase 3: IP Range Discovery ---
def run_phase3_ip_ranges(
    result: ReconnaissanceResult,
    max_workers: int = DEFAULT_MAX_WORKERS,
    progress_callback: Optional[Callable[[float, str], None]] = None,
    status_callback: Optional[Callable[[str, str], None]] = None,
):
    """
    Phase 3: IP Range Discovery - Find IP ranges for identified ASNs

    Args:
        result: ReconnaissanceResult object containing ASNs and to populate with IP ranges
        max_workers: Maximum number of concurrent workers
        progress_callback: Optional callback for progress updates
        status_callback: Optional callback for status updates
    """
    logger.info(f"💻 Phase 3: Discovering IP Ranges for {len(result.asns)} ASNs")

    # Create a progress logger for terminal
    progress = create_progress_logger(
        "ip_discovery", total=100, prefix="IP Range Discovery"
    )
    progress.update(0, "Starting IP range discovery...")

    if not result.asns:
        logger.warning("⚠️ Phase 3 - Skipping IP Range discovery as no ASNs were found")
        progress.update(100, "Skipped (no ASNs found)")
        if status_callback:
            status_callback("⚠️", "Skipping IP Range discovery (no ASNs found)")
        return

    if status_callback:
        status_callback("🔍", f"Mapping IP ranges for {len(result.asns)} ASNs")

    try:
        # ip_discovery modifies the result object directly
        ip_discovery.find_ip_ranges_for_asns(
            result.asns,
            result,
            max_workers,
            progress_callback=lambda p, msg: (
                progress.update(p, msg),  # Update terminal progress
                (
                    progress_callback(p, msg) if progress_callback else None
                ),  # Update UI progress
            ),
        )

        progress.update(100, "IP range discovery completed")
        if status_callback:
            status_callback(
                "✅",
                f"IP range discovery complete - Found {len(result.ip_ranges)} IP ranges",
            )

        logger.info(f"✅ Phase 3 completed: Found {len(result.ip_ranges)} IP ranges")
    except Exception as e:
        logger.exception(f"❌ Error during Phase 3 (IP Range Discovery): {e}")
        result.add_warning(f"Phase 3 Error: {e}")
        if status_callback:
            status_callback("❌", f"IP range discovery error: {e}")


# --- Phase 4: Enhanced Cloud Detection ---
def run_phase4_cloud(
    result: ReconnaissanceResult,
    max_workers: int = DEFAULT_MAX_WORKERS,
    progress_callback: Optional[Callable[[float, str], None]] = None,
    status_callback: Optional[Callable[[str, str], None]] = None,
):
    """
    Phase 4: Enhanced Cloud Detection - Identify cloud services used by the target

    Args:
        result: ReconnaissanceResult object containing domains/IPs and to populate with cloud services
        max_workers: Maximum number of concurrent workers
        progress_callback: Optional callback for progress updates
        status_callback: Optional callback for status updates
    """
    logger.info(f"☁️ Phase 4: Enhanced Cloud Service Detection")

    # Create a progress logger for terminal
    progress = create_progress_logger(
        "enhanced_cloud_detection", total=100, prefix="Enhanced Cloud Detection"
    )
    progress.update(0, "Starting enhanced cloud service detection...")

    if status_callback:
        status_callback("🔍", "Analyzing resources for cloud service usage")

    total_assets = len(result.ip_ranges) + len(result.domains)
    if total_assets == 0:
        logger.warning(
            "⚠️ Phase 4 - Skipping Cloud detection as no domains or IP ranges were found"
        )
        progress.update(100, "Skipped (no resources to check)")
        if status_callback:
            status_callback("⚠️", "Skipping Cloud detection (no resources to check)")
        return

    try:
        # Use enhanced cloud detection with rate limiting and comprehensive provider coverage
        detect_enhanced_cloud_services(
            result,
            progress_callback=lambda p, msg: (
                progress.update(p, msg),  # Update terminal progress
                (
                    progress_callback(p, msg) if progress_callback else None
                ),  # Update UI progress
            ),
            status_callback=status_callback,
        )

        progress.update(100, "Enhanced cloud service detection completed")
        if status_callback:
            status_callback(
                "✅",
                f"Enhanced cloud detection complete - Found {len(result.cloud_services)} cloud services",
            )

        logger.info(
            f"✅ Phase 4 completed: Found {len(result.cloud_services)} cloud services"
        )
    except Exception as e:
        logger.exception(f"❌ Error during Phase 4 (Enhanced Cloud Detection): {e}")
        result.add_warning(f"Phase 4 Error: {e}")
        if status_callback:
            status_callback("❌", f"Enhanced cloud detection error: {e}")


# --- Main Orchestration Function ---
def run_discovery(
    target_organization: str,
    base_domains: Optional[Set[str]] = None,
    include_subdomain_discovery: bool = True,
    max_workers: int = DEFAULT_MAX_WORKERS,
    progress_callback: Optional[Callable[[float, str], None]] = None,
    status_callback: Optional[Callable[[str, str], None]] = None,
) -> ReconnaissanceResult:
    """
    Runs the full discovery process with detailed logging and progress reporting.
    Now uses enhanced cloud detection for better provider coverage and reliability.

    Args:
        target_organization: Name of the target organization
        base_domains: Set of known domains to start with
        include_subdomain_discovery: Whether to discover subdomains
        max_workers: Maximum number of concurrent workers
        progress_callback: Optional callback for progress updates
        status_callback: Optional callback for status updates

    Returns:
        ReconnaissanceResult object containing all discovered assets
    """
    start_time = time.time()
    result = ReconnaissanceResult(target_organization=target_organization)
    logger.info(f"🚀 Starting reconnaissance for: {target_organization}")

    # Phase 1: Domain Discovery
    phase_start = time.time()
    run_phase1_domains(
        target_organization,
        base_domains,
        result,
        max_workers,
        progress_callback=lambda p, msg: (
            progress_callback(p / 4, msg) if progress_callback else None
        ),
        status_callback=status_callback,
    )
    logger.debug(f"Phase 1 completed in {time.time() - phase_start:.2f}s")

    # Phase 2: ASN Discovery
    phase_start = time.time()
    run_phase2_asns(
        target_organization,
        base_domains,
        result,
        max_workers,
        progress_callback=lambda p, msg: (
            progress_callback(25 + (p / 4), msg) if progress_callback else None
        ),
        status_callback=status_callback,
    )
    logger.debug(f"Phase 2 completed in {time.time() - phase_start:.2f}s")

    # Phase 3: IP Range Discovery
    phase_start = time.time()
    run_phase3_ip_ranges(
        result,
        max_workers,
        progress_callback=lambda p, msg: (
            progress_callback(50 + (p / 4), msg) if progress_callback else None
        ),
        status_callback=status_callback,
    )
    logger.debug(f"Phase 3 completed in {time.time() - phase_start:.2f}s")

    # Phase 4: Enhanced Cloud Detection
    phase_start = time.time()
    run_phase4_cloud(
        result,
        max_workers,
        progress_callback=lambda p, msg: (
            progress_callback(75 + (p / 4), msg) if progress_callback else None
        ),
        status_callback=status_callback,
    )
    logger.debug(f"Phase 4 completed in {time.time() - phase_start:.2f}s")

    # --- Finalization ---
    end_time = time.time()
    duration = end_time - start_time
    logger.info(
        f"✨ Reconnaissance completed for {target_organization} in {duration:.2f} seconds"
    )
    logger.info(
        f"📊 Summary: Found {len(result.asns)} ASNs, {len(result.ip_ranges)} IP Ranges, "
        + f"{len(result.domains)} Domains, {len(result.get_all_subdomains())} Subdomains, "
        + f"{len(result.cloud_services)} Cloud Services"
    )

    # Update final UI progress if callback exists (now safe, in main thread)
    if progress_callback:
        progress_callback(
            100.0, f"Finished ({len(result.cloud_services)} cloud services found)"
        )

    if result.warnings:
        logger.warning(f"⚠️ Scan completed with {len(result.warnings)} warnings")

    return result


# Example Usage (for testing individual phases or full run):
if __name__ == "__main__":
    import sys

    sys.path.insert(0, sys.path[0] + "/../..")
    from src.utils.logging_config import setup_logging

    setup_logging(level=logging.INFO, use_enhanced_formatter=True, color_enabled=True)

    # target = "Google LLC"
    # domains = {"google.com"}
    target = "Cloudflare, Inc."
    domains = {"cloudflare.com"}

    final_result = run_discovery(target, domains)

    print("\n--- Final Discovery Results ---")
    print(f"Target: {final_result.target_organization}")
    print(f"ASNs ({len(final_result.asns)}):")
    # for asn in sorted(list(final_result.asns), key=lambda x: x.number):
    #     print(f"  - {asn}")
    print(f"IP Ranges ({len(final_result.ip_ranges)}):")
    # for ipr in sorted(list(final_result.ip_ranges), key=lambda x: ipaddress.ip_network(x.cidr)):
    #     print(f"  - {ipr}")
    print(f"Domains ({len(final_result.domains)}):")
    # for dom in sorted(list(final_result.domains), key=lambda x: x.name):
    #     print(f"  - {dom.name} (Subdomains: {len(dom.subdomains)})")
    print(f"Cloud Services ({len(final_result.cloud_services)}):")
    # for svc in sorted(list(final_result.cloud_services), key=lambda x: (x.provider, x.identifier)):
    #      print(f"  - {svc}")

    if final_result.warnings:
        print("\n--- Warnings --- ")
        for warn in final_result.warnings:
            print(f"- {warn}")
