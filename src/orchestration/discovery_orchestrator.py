"""Orchestrates the discovery process using various modules."""

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Set

from src.core.models import ReconnaissanceResult
# Import discovery modules directly
from src.discovery import asn_discovery, ip_discovery, domain_discovery, cloud_detection

logger = logging.getLogger(__name__)

# Adjust max_workers based on typical usage and API limits
DEFAULT_MAX_WORKERS = 10

# --- Phase 1: Domain Discovery ---
def run_phase1_domains(
    target_organization: Optional[str], 
    base_domains: Optional[Set[str]], 
    result: ReconnaissanceResult, 
    max_workers: int = DEFAULT_MAX_WORKERS
):
    logger.info("Phase 1: Discovering Domains & Subdomains...")
    try:
        # domain_discovery.find_domains modifies the result object directly
        domain_discovery.find_domains(target_organization, base_domains, result, max_workers)
        logger.info(f"Phase 1 - Domain discovery completed. Result: {len(result.domains)} Domains, {len(result.get_all_subdomains())} Subdomains")
    except Exception as e:
        logger.exception("Error during Phase 1 (Domain Discovery)")
        result.add_warning(f"Phase 1 Error: {e}")
        # Optionally re-raise or handle differently

# --- Phase 2: ASN Discovery ---
def run_phase2_asns(
    target_organization: Optional[str], 
    base_domains: Optional[Set[str]], # May still be useful for BGP queries
    result: ReconnaissanceResult, 
    max_workers: int = DEFAULT_MAX_WORKERS
):
    logger.info("Phase 2: Discovering ASNs...")
    try:
        # asn_discovery modifies the result object directly
        asn_discovery.find_asns_for_organization(target_organization, base_domains, result, max_workers)
        logger.info(f"Phase 2 - ASN discovery completed. Result: {len(result.asns)} ASNs")
    except Exception as e:
        logger.exception("Error during Phase 2 (ASN Discovery)")
        result.add_warning(f"Phase 2 Error: {e}")

# --- Phase 3: IP Range Discovery ---
def run_phase3_ip_ranges(
    result: ReconnaissanceResult, 
    max_workers: int = DEFAULT_MAX_WORKERS
):
    logger.info(f"Phase 3: Discovering IP Ranges for {len(result.asns)} ASNs...")
    if not result.asns:
        logger.warning("Phase 3 - Skipping IP Range discovery as no ASNs were found.")
        return
    try:
        # ip_discovery modifies the result object directly
        ip_discovery.find_ip_ranges_for_asns(result.asns, result, max_workers)
        logger.info(f"Phase 3 - IP Range discovery completed. Result: {len(result.ip_ranges)} IP Ranges")
    except Exception as e:
        logger.exception("Error during Phase 3 (IP Range Discovery)")
        result.add_warning(f"Phase 3 Error: {e}")

# --- Phase 4: Cloud Detection ---
def run_phase4_cloud(
    result: ReconnaissanceResult, 
    max_workers: int = DEFAULT_MAX_WORKERS
):
    logger.info("Phase 4: Detecting Cloud Services...")
    futures_cloud = []
    try:
        with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="DiscoveryPhase4_Cloud") as executor:
            if result.ip_ranges:
                 # Pass result object to be modified
                 futures_cloud.append(executor.submit(cloud_detection.detect_cloud_from_ips, result.ip_ranges, result))
            else:
                 logger.debug("Phase 4 - Skipping Cloud IP detection (no IP ranges found).")
                 
            if result.domains:
                 # Pass result object to be modified
                 futures_cloud.append(executor.submit(cloud_detection.detect_cloud_from_domains, result.domains, result))
            else:
                 logger.debug("Phase 4 - Skipping Cloud Domain detection (no domains found).")
            
            # Wait for all submitted cloud tasks to complete
            for future in as_completed(futures_cloud):
                try:
                    future.result() # Wait for completion and raise exceptions if any occurred within the task
                except Exception as e:
                     logger.error(f"Error occurred within a cloud detection task: {e}")
                     result.add_warning(f"Cloud detection sub-task failed: {e}")
                     # Continue processing other futures
                     
        logger.info(f"Phase 4 - Cloud detection completed. Result: {len(result.cloud_services)} Cloud Services")
    except Exception as e:
         logger.exception("Error during Phase 4 (Cloud Detection orchestration)")
         result.add_warning(f"Phase 4 Error: {e}")


# --- Main Orchestration Function (Optional - Can be done directly in app.py now) ---
# Kept for potential direct use or testing, but app.py will call phases individually.
def run_full_discovery(
    target_organization: str,
    base_domains: Optional[Set[str]] = None,
    max_workers: int = DEFAULT_MAX_WORKERS
) -> ReconnaissanceResult:
    """Runs the full discovery process sequentially by phase."""
    start_time = time.time()
    result = ReconnaissanceResult(target_organization=target_organization)
    logger.info(f"Starting full discovery orchestration for: {target_organization}")

    run_phase1_domains(target_organization, base_domains, result, max_workers)
    run_phase2_asns(target_organization, base_domains, result, max_workers)
    run_phase3_ip_ranges(result, max_workers)
    run_phase4_cloud(result, max_workers)

    # --- Finalization ---
    end_time = time.time()
    duration = end_time - start_time
    logger.info(f"Discovery orchestration completed for {target_organization} in {duration:.2f} seconds.")
    logger.info(f"Summary: Found {len(result.asns)} ASNs, {len(result.ip_ranges)} IP Ranges, {len(result.domains)} Domains, {len(result.get_all_subdomains())} Subdomains, {len(result.cloud_services)} Cloud Services.")
    if result.warnings:
        logger.warning(f"Scan completed with {len(result.warnings)} warnings.")
    
    return result

# Example Usage (for testing individual phases or full run):
if __name__ == '__main__':
    import sys
    sys.path.insert(0, sys.path[0] + '/../..') 
    from src.utils.logging_config import setup_logging
    setup_logging(logging.INFO) # Use INFO level for orchestration summary

    # target = "Google LLC"
    # domains = {"google.com"}
    target = "Cloudflare, Inc."
    domains = {"cloudflare.com"}
    
    final_result = run_full_discovery(target, domains)
    
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