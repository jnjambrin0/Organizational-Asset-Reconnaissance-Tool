"""Module for discovering IP ranges associated with ASNs or domains."""

import logging
import re
from typing import Set, Optional
import subprocess # Add subprocess import

from bs4 import BeautifulSoup
import ipaddress # For validating CIDR
from concurrent.futures import ThreadPoolExecutor, as_completed # Add imports

# Import netaddr for summarization
from netaddr import IPSet, cidr_merge 

from src.core.models import ASN, IPRange, Domain, ReconnaissanceResult
from src.utils.network import make_request
from src.core.exceptions import DataSourceError

logger = logging.getLogger(__name__)

BGP_HE_NET_URL = "https://bgp.he.net"
# Define IRR default server (can be overridden)
DEFAULT_IRR_SERVER = "whois.radb.net"

def _is_valid_cidr(cidr_str: str) -> bool:
    """Check if a string is a valid IPv4 or IPv6 CIDR."""
    try:
        ipaddress.ip_network(cidr_str, strict=False)
        return True
    except ValueError:
        return False

def _parse_bgp_he_net_asn_page(html_content: str, asn: ASN, result: ReconnaissanceResult) -> Set[IPRange]:
    """Parses the BGP.HE.NET ASN page for announced prefixes."""
    ips: Set[IPRange] = set()
    try:
        soup = BeautifulSoup(html_content, 'lxml')
    except Exception as e:
        logger.error(f"Failed to initialize BeautifulSoup parser for ASN {asn.number}: {e}")
        return ips

    # Find tables containing prefixes - selectors might need adjustment
    for version_tag, version_num in [('prefixes4', 4), ('prefixes6', 6)]:
        table_id = f'table_{version_tag}'
        try:
            prefix_table = soup.find('table', {'id': table_id})
            if not prefix_table:
                logger.debug(f"No table with id '{table_id}' found for AS{asn.number}")
                continue

            rows = prefix_table.find_all('tr')
            if not rows or len(rows) <= 1: # Check if table has content rows
                 logger.debug(f"Prefix table '{table_id}' for AS{asn.number} appears empty.")
                 continue

            logger.debug(f"Parsing table '{table_id}' for AS{asn.number}...")
            for row in rows[1:]: # Skip header row
                cells = row.find_all('td')
                if len(cells) > 0:
                    prefix_link = cells[0].find('a')
                    if prefix_link:
                        cidr = prefix_link.get_text(strip=True)
                        if _is_valid_cidr(cidr):
                            # Try to get country from description if available (might be in another cell)
                            country = None # Placeholder - parsing country needs specific logic
                            # Maybe parse description from sibling cell? Example:
                            # description_cell = cells[1].get_text(strip=True) if len(cells) > 1 else None
                            logger.debug(f"Found IPv{version_num} prefix for AS{asn.number}: {cidr}")
                            ips.add(IPRange(cidr=cidr, version=version_num, asn=asn, country=country, data_source="BGP.HE.NET"))
                        else:
                            logger.warning(f"Invalid CIDR '{cidr}' found in table '{table_id}' for AS{asn.number} in row: {row}")
                    else:
                         logger.warning(f"No link found in first cell of row in table '{table_id}' for AS{asn.number}: {row}")
                else:
                    logger.warning(f"Row with no cells found in table '{table_id}' for AS{asn.number}: {row}")

        except Exception as e:
            # Log exceptions during the processing of a specific table (IPv4 or IPv6)
            warning_msg = f"Error parsing table '{table_id}' for AS{asn.number}: {e}"
            logger.exception(warning_msg)
            result.add_warning(f"BGP.HE.NET Parser: {warning_msg}")

    return ips

def _fetch_and_parse_asn_page(asn: ASN, result: ReconnaissanceResult) -> Set[IPRange]:
    """Fetches and parses the BGP.HE.NET page for a single ASN."""
    logger.debug(f"Querying IP ranges for ASN: {asn.number}")
    url = f"{BGP_HE_NET_URL}/AS{asn.number}"
    try:
        response = make_request(url, source_name=f"BGP.HE.NET-AS{asn.number}")
        response.raise_for_status()
        ips_from_asn = _parse_bgp_he_net_asn_page(response.text, asn, result)
        logger.debug(f"Found {len(ips_from_asn)} IP ranges for AS{asn.number} via BGP.HE.NET")
        return ips_from_asn
    except DataSourceError as e:
        warning_msg = f"Failed to query or parse BGP.HE.NET for AS{asn.number}: {e}"
        logger.error(warning_msg)
        result.add_warning(warning_msg)
    except Exception as e:
        warning_msg = f"Unexpected error processing BGP.HE.NET for AS{asn.number}: {e}"
        logger.exception(warning_msg)
        result.add_warning(warning_msg)
    return set() # Return empty set on error

# --- Add IRR Query Function --- 
def _parse_irr_output(output: str, asn: ASN, result: ReconnaissanceResult) -> Set[IPRange]:
    """Parses the text output from an IRR whois query for route/route6 objects."""
    discovered_ips: Set[IPRange] = set()
    # Regex to find route or route6 lines (adjust as needed for different IRR formats)
    route_regex = re.compile(r"^(route|route6):\s*([0-9a-fA-F:./]+)") 
    
    current_country = None # Placeholder, IRR output format varies wildly
    
    lines = output.splitlines()
    for line in lines:
        match = route_regex.match(line)
        if match:
            cidr = match.group(2).strip()
            if _is_valid_cidr(cidr):
                try:
                    network = ipaddress.ip_network(cidr, strict=False)
                    version = network.version
                    # Create IPRange object - Country parsing is complex and omitted here
                    ipr = IPRange(
                        cidr=cidr,
                        version=version,
                        asn=asn,
                        country=None, # Country info often not reliable/present in route objects
                        data_source=f"IRR({asn.number})"
                    )
                    discovered_ips.add(ipr)
                except ValueError: # Should be caught by _is_valid_cidr, but for safety
                    logger.warning(f"IRR Parser: Skipping invalid CIDR '{cidr}' found for AS{asn.number}")
            else:
                 logger.warning(f"IRR Parser: Regex matched invalid CIDR '{cidr}' for AS{asn.number}")
                 
    return discovered_ips

def _query_irr_for_asn(asn: ASN, result: ReconnaissanceResult, irr_server: str = DEFAULT_IRR_SERVER) -> Set[IPRange]:
    """Queries an IRR server for routes originated by a specific ASN."""
    logger.debug(f"Querying IRR ({irr_server}) for routes originated by AS{asn.number}")
    # Command to query routes for the ASN
    # The exact flags might vary slightly depending on the whois client and server
    command = ["whois", "-h", irr_server, "--", f"-i origin AS{asn.number}"] 
    # Alternative flags sometimes needed: !gAS{asn.number} or -T route,route6
    
    try:
        # Execute the whois command
        process = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False) # Added timeout, check=False
        
        if process.returncode != 0:
             # Handle errors like command not found or server connection issues
             stderr_output = process.stderr.strip()
             warning_msg = f"IRR query command '{' '.join(command)}' failed (code {process.returncode}). Stderr: {stderr_output if stderr_output else 'None'}"
             logger.error(warning_msg)
             result.add_warning(f"IRR Query: {warning_msg}")
             return set()

        # Check for common error messages in stdout as well
        stdout_lower = process.stdout.lower()
        if "error" in stdout_lower or "query refused" in stdout_lower or "no entries found" in stdout_lower:
             logger.debug(f"IRR query for AS{asn.number} returned no routes or an error message.")
             return set()
             
        # Parse the successful output
        return _parse_irr_output(process.stdout, asn, result)

    except FileNotFoundError:
        warning_msg = "'whois' command not found. Cannot query IRR. Please install it."
        logger.error(warning_msg)
        result.add_warning(f"IRR Query: {warning_msg}")
        # Potentially disable future IRR queries if command not found?
        return set()
    except subprocess.TimeoutExpired:
        warning_msg = f"IRR query command '{' '.join(command)}' timed out."
        logger.warning(warning_msg)
        result.add_warning(f"IRR Query: {warning_msg}")
        return set()
    except Exception as e:
        warning_msg = f"Unexpected error running IRR query command '{' '.join(command)}': {e}"
        logger.exception(warning_msg)
        result.add_warning(f"IRR Query: {warning_msg}")
        return set()

def find_ip_ranges_for_asns(asns: Set[ASN], result: ReconnaissanceResult, max_workers: Optional[int] = None):
    """Find IP ranges announced by a set of ASNs using BGP.HE.NET and IRR in parallel, 
       summarize them, and add to result."""
    # Keep track of raw CIDRs found from all sources
    raw_cidrs_found: Set[str] = set()
    
    if not asns:
        logger.info("No ASNs provided, skipping IP range discovery.")
        return # No ASNs to process
    
    num_workers = max_workers if max_workers is not None else 10 
    logger.info(f"Starting parallel IP range discovery for {len(asns)} ASNs using up to {num_workers} workers.")

    # --- Parallel execution to fetch raw CIDRs --- 
    with ThreadPoolExecutor(max_workers=num_workers, thread_name_prefix="ASN_IPRange") as executor:
        future_to_asn_bgp = {executor.submit(_fetch_and_parse_asn_page, asn, result): asn for asn in asns}
        future_to_asn_irr = {executor.submit(_query_irr_for_asn, asn, result): asn for asn in asns}

        # Process BGP.HE.NET results - Collect CIDRs directly
        for future in as_completed(future_to_asn_bgp):
            asn = future_to_asn_bgp[future]
            try:
                ips_from_asn_bgp = future.result() # This returns Set[IPRange]
                # Extract CIDRs from the returned IPRange objects
                raw_cidrs_found.update(ipr.cidr for ipr in ips_from_asn_bgp)
            except Exception as exc:
                logger.error(f"ASN IP range fetch future (BGP) for AS{asn.number} generated an exception: {exc}")
                
        # Process IRR results - Collect CIDRs directly
        for future in as_completed(future_to_asn_irr):
            asn = future_to_asn_irr[future]
            try:
                ips_from_asn_irr = future.result() # This returns Set[IPRange]
                # Extract CIDRs from the returned IPRange objects
                raw_cidrs_found.update(ipr.cidr for ipr in ips_from_asn_irr)
            except Exception as exc:
                logger.error(f"ASN IP range fetch future (IRR) for AS{asn.number} generated an exception: {exc}")

    logger.info(f"Found {len(raw_cidrs_found)} raw IP ranges from BGP and IRR.")

    # --- Summarize discovered CIDRs --- 
    summarized_ranges: Set[IPRange] = set()
    if raw_cidrs_found:
        try:
            # Use netaddr.cidr_merge for efficient summarization
            merged_cidrs = cidr_merge(list(raw_cidrs_found))
            logger.info(f"Summarized {len(raw_cidrs_found)} raw ranges into {len(merged_cidrs)} CIDRs.")
            
            # Create IPRange objects for the summarized CIDRs
            for merged_cidr in merged_cidrs:
                try:
                    network = ipaddress.ip_network(str(merged_cidr)) # Convert netaddr CIDR back to string/ipaddress obj
                    summarized_ranges.add(IPRange(
                        cidr=str(merged_cidr),
                        version=network.version,
                        asn=None, # ASN info is lost during merge
                        country=None, # Country info lost
                        data_source="Summarized (BGP/IRR)"
                    ))
                except ValueError as e:
                     logger.warning(f"Could not create IPRange for merged CIDR '{merged_cidr}': {e}")
                     
        except Exception as e:
             warning_msg = f"Error during IP range summarization: {e}"
             logger.exception(warning_msg)
             result.add_warning(f"IP Discovery: {warning_msg}")
             # Fallback? Or just proceed with empty set?

    # --- Add summarized IPs to main result --- 
    added_count = 0
    for ipr in summarized_ranges:
        result.add_ip_range(ipr)
        added_count += 1

    logger.info(f"Finished IP range discovery. Added {added_count} summarized ranges to result.")

def find_ip_ranges_for_domains(domains: Set[Domain], result: ReconnaissanceResult):
    """Find IP ranges associated with domains (placeholder)."""
    # ... (Existing logic is placeholder) ...
    warning_msg = "Direct Domain -> IP Range discovery is complex and not fully implemented."
    logger.warning(warning_msg)
    # result.add_warning(warning_msg)
    # No ranges added in placeholder implementation

# Example usage (for testing):
if __name__ == '__main__':
    import sys
    sys.path.insert(0, sys.path[0] + '/../..') 
    from src.utils.logging_config import setup_logging
    setup_logging(logging.DEBUG)
    
    # test_asns = {ASN(number=15169, name="Google LLC"), ASN(number=8075, name="Microsoft Corporation")}
    test_asns = {ASN(number=13335, name="Cloudflare, Inc.")}
    ip_ranges = find_ip_ranges_for_asns(test_asns)
    print(f"\n--- Found IP Ranges ({len(ip_ranges)}) ---")
    # Sort for consistent output
    sorted_ips = sorted(list(ip_ranges), key=lambda x: (x.version, ipaddress.ip_network(x.cidr)))
    for ipr in sorted_ips:
        print(ipr) 