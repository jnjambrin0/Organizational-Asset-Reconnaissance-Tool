"""Orchestrates the discovery process using various modules."""

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Set

from src.core.models import ReconnaissanceResult
from src.discovery import asn_discovery, ip_discovery, domain_discovery, cloud_detection

logger = logging.getLogger(__name__)

# Adjust max_workers based on typical usage and API limits
DEFAULT_MAX_WORKERS = 10

def run_discovery(
    target_organization: str,
    base_domains: Optional[Set[str]] = None,
    max_workers: int = DEFAULT_MAX_WORKERS
) -> ReconnaissanceResult:
    """Runs the full discovery process for a target organization.

    Args:
        target_organization: The name of the target organization.
        base_domains: Optional set of known base domains.
        max_workers: Max number of concurrent threads for discovery tasks.

    Returns:
        A ReconnaissanceResult object containing all discovered assets and warnings.
    """
    start_time = time.time()
    result = ReconnaissanceResult(target_organization=target_organization)
    logger.info(f"Starting discovery orchestration for: {target_organization}")

    # --- Phase 1: Domain Discovery (Gets domains and resolved IPs) ---
    logger.info("Phase 1: Discovering Domains & Subdomains...")
    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="DiscoveryPhase1_Domain") as executor:
        future_domain = executor.submit(domain_discovery.find_domains, target_organization, base_domains, result)
        # Wait for domain discovery to complete before proceeding
        future_domain.result() # Explicitly wait for the future to complete
        
    logger.info("Phase 1 - Domain discovery task completed.") # Updated log
    logger.info(f"Result after Phase 1: {len(result.domains)} Domains, {len(result.get_all_subdomains())} Subdomains")

    # --- Phase 2: ASN Discovery (Uses org name, domains, and resolved IPs) ---
    logger.info("Phase 2: Discovering ASNs...")
    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="DiscoveryPhase2_ASN") as executor:
        # Pass the result object which now contains resolved IPs from Phase 1
        future_asn = executor.submit(asn_discovery.find_asns_for_organization, target_organization, base_domains, result)
        # Wait for ASN discovery (including internal IP->ASN lookups) to complete
        future_asn.result() # Explicitly wait for the future to complete

    logger.info("Phase 2 - ASN discovery task completed.") # Updated log
    logger.info(f"Result after Phase 2: {len(result.asns)} ASNs")

    # --- Phase 3: IP Range Discovery (Requires discovered ASNs) ---
    logger.info(f"Phase 3: Discovering IP Ranges for {len(result.asns)} ASNs...")
    if result.asns:
        with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="DiscoveryPhase3_IP") as executor:
            # Pass max_workers to the ip_discovery function
            future_ip = executor.submit(ip_discovery.find_ip_ranges_for_asns, result.asns, result, max_workers=max_workers)
            # Wait for IP range discovery to complete
            future_ip.result() # Explicitly wait for the future to complete
    else:
        logger.warning("Phase 3 - Skipping IP Range discovery as no ASNs were found in Phase 2.")
        
    logger.info("Phase 3 - IP Range discovery task completed.") # Updated log
    logger.info(f"Result after Phase 3: {len(result.ip_ranges)} IP Ranges")

    # --- Phase 4: Cloud Detection (Requires IPs and Domains) ---
    logger.info("Phase 4: Detecting Cloud Services...")
    futures_cloud = []
    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="DiscoveryPhase4_Cloud") as executor:
        if result.ip_ranges:
             futures_cloud.append(executor.submit(cloud_detection.detect_cloud_from_ips, result.ip_ranges, result))
        else:
             logger.debug("Phase 4 - Skipping Cloud IP detection (no IP ranges found in Phase 3).")
             
        if result.domains:
            futures_cloud.append(executor.submit(cloud_detection.detect_cloud_from_domains, result.domains, result))
        else:
             logger.debug("Phase 4 - Skipping Cloud Domain detection (no domains found in Phase 1).")
        
        # Wait for all submitted cloud tasks to complete
        for future in as_completed(futures_cloud):
            try:
                future.result() # Wait for completion, handle potential exceptions if needed
            except Exception as e:
                 logger.error(f"Error in cloud detection task: {e}")
                 result.add_warning(f"Cloud detection task failed: {e}")

    logger.info("Phase 4 - Cloud detection tasks completed.") # Updated log
    logger.info(f"Result after Phase 4: {len(result.cloud_services)} Cloud Services")

    # --- Finalization ---
    end_time = time.time()
    duration = end_time - start_time
    logger.info(f"Discovery orchestration completed for {target_organization} in {duration:.2f} seconds.")
    logger.info(f"Summary: Found {len(result.asns)} ASNs, {len(result.ip_ranges)} IP Ranges, {len(result.domains)} Domains, {len(result.get_all_subdomains())} Subdomains, {len(result.cloud_services)} Cloud Services.")
    if result.warnings:
        logger.warning(f"Scan completed with {len(result.warnings)} warnings.")
    
    return result

# Example Usage:
if __name__ == '__main__':
    import sys
    sys.path.insert(0, sys.path[0] + '/../..') 
    from src.utils.logging_config import setup_logging
    setup_logging(logging.INFO) # Use INFO level for orchestration summary

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