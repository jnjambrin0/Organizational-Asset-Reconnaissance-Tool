"""Module for discovering IP ranges associated with ASNs or domains."""

import logging
import re
from typing import Set, Optional, Callable, List
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

def find_ip_ranges_for_asns(
    asns: Set[ASN], 
    result: ReconnaissanceResult, 
    max_workers: Optional[int] = None,
    progress_callback: Optional[Callable[[float, str], None]] = None # Added callback
    ):
    """Find IP ranges announced by a set of ASNs using BGP.HE.NET and IRR in parallel, 
       summarize them, and add to result.
    
    Args:
        asns: Set of ASN objects to query.
        result: ReconnaissanceResult object to populate.
        max_workers: Maximum concurrent workers.
        progress_callback: Optional callback for progress updates.
    """
    # Keep track of raw CIDRs found from all sources
    raw_cidrs_found: Set[str] = set()
    
    if not asns:
        logger.info("No ASNs provided, skipping IP range discovery.")
        if progress_callback: progress_callback(100.0, "Skipped (no ASNs)")
        return # No ASNs to process
    
    num_workers = max_workers if max_workers is not None else 10 
    logger.info(f"Starting parallel IP range discovery for {len(asns)} ASNs using up to {num_workers} workers.")

    # --- Report Initial Progress --- 
    if progress_callback:
        progress_callback(0.0, "Starting IP range discovery...")

    # --- Parallel execution to fetch raw CIDRs --- 
    # Total tasks = number of ASNs (for BGP.HE) + number of ASNs (for IRR)
    total_tasks = len(asns) * 2
    completed_tasks = 0
    
    with ThreadPoolExecutor(max_workers=num_workers, thread_name_prefix="ASN_IPRange") as executor:
        # Submit BGP.HE.NET tasks
        future_to_asn_bgp = {executor.submit(_fetch_and_parse_asn_page, asn, result): asn for asn in asns}
        # Submit IRR tasks
        future_to_asn_irr = {executor.submit(_query_irr_for_asn, asn, result): asn for asn in asns}
        
        # Combine futures for processing completion
        all_futures = list(future_to_asn_bgp.keys()) + list(future_to_asn_irr.keys())
        
        for future in as_completed(all_futures):
            completed_tasks += 1
            asn = None
            source = "Unknown"
            if future in future_to_asn_bgp:
                 asn = future_to_asn_bgp[future]
                 source = "BGP.HE.NET"
            elif future in future_to_asn_irr:
                 asn = future_to_asn_irr[future]
                 source = "IRR"
                 
            try:
                ips_from_source = future.result()
                if ips_from_source:
                    logger.debug(f"Got {len(ips_from_source)} raw IP ranges for AS{asn.number if asn else 'N/A'} from {source}")
                    # Add CIDRs to the raw set
                    raw_cidrs_found.update(ipr.cidr for ipr in ips_from_source)
                # else: logger.debug(f"No IP ranges found for AS{asn.number if asn else 'N/A'} from {source}")
            except Exception as exc:
                 logger.error(f"Error fetching IP ranges for AS{asn.number if asn else 'N/A'} from {source}: {exc}")
                 result.add_warning(f"IP Range Discovery: Error getting data for AS{asn.number if asn else 'N/A'} from {source} - {exc}")
                 
            # Update progress after each task completion
            if progress_callback:
                 # Scale progress from 0% to 80% during data fetching
                 progress = (completed_tasks / total_tasks) * 80 if total_tasks > 0 else 80
                 progress_callback(progress, f"Fetched data source {completed_tasks}/{total_tasks}")

    # --- Summarization ---
    if not raw_cidrs_found:
        logger.warning("No raw CIDRs were found from any source. Cannot summarize.")
        if progress_callback: progress_callback(100.0, "Finished (no CIDRs found)")
        return

    logger.info(f"Found {len(raw_cidrs_found)} raw CIDRs. Summarizing...")
    if progress_callback: progress_callback(85.0, "Summarizing found IP ranges...")

    summarized_cidrs_result: List[ipaddress._BaseNetwork] = [] # Store final combined results here
    chunk_size = 10000  # Process in chunks of 10k
    raw_cidr_list = list(raw_cidrs_found) # Convert set to list for slicing

    try:
        # Convert raw strings to ip_network objects and separate by version
        ipv4_objects: List[ipaddress.IPv4Network] = []
        ipv6_objects: List[ipaddress.IPv6Network] = []
        conversion_errors = 0
        for cidr_str in raw_cidr_list:
            try:
                # Use strict=False to handle potential network/broadcast addresses if needed
                network = ipaddress.ip_network(cidr_str, strict=False)
                if network.version == 4:
                    # Ensure correct type hint if needed later, though list handles it
                    ipv4_objects.append(network)
                elif network.version == 6:
                    ipv6_objects.append(network)
            except ValueError:
                logger.warning(f"Summarization: Skipping invalid CIDR format '{cidr_str}' during conversion.")
                conversion_errors += 1

        total_converted = len(ipv4_objects) + len(ipv6_objects)
        logger.info(f"Successfully converted {total_converted} strings ({len(ipv4_objects)} IPv4, {len(ipv6_objects)} IPv6). Skipped {conversion_errors} invalid strings.")

        # Check if we actually have objects to process
        if not ipv4_objects and not ipv6_objects:
            logger.warning("Summarization: No valid network objects to process after conversion.")
            if progress_callback: progress_callback(100.0, "Finished (no valid CIDRs)")
            return

        # --- Helper function to collapse addresses with chunking ---
        def collapse_list_with_chunking(network_list: List[ipaddress._BaseNetwork], version: int) -> List[ipaddress._BaseNetwork]:
            """Collapses a list of networks (all same version) using chunking."""
            collapsed_results: List[ipaddress._BaseNetwork] = []
            if not network_list:
                return collapsed_results

            # Use the already defined chunk_size
            if len(network_list) <= chunk_size:
                logger.info(f"Collapsing {len(network_list)} IPv{version} network objects directly...")
                try:
                    collapsed_results = list(ipaddress.collapse_addresses(network_list))
                    logger.info(f"Summarized {len(network_list)} IPv{version} networks into {len(collapsed_results)} optimized ranges using ipaddress.")
                except Exception as e:
                     logger.error(f"Error collapsing IPv{version} networks directly: {e}")
                     result.add_warning(f"IP Range Summarization (ipaddress): Error collapsing IPv{version} list directly - {e}")
            else:
                logger.info(f"Processing {len(network_list)} IPv{version} network objects in chunks of {chunk_size} using ipaddress...")
                merged_chunks_results = []
                num_chunks = (len(network_list) + chunk_size - 1) // chunk_size

                for i in range(num_chunks):
                    start_index = i * chunk_size
                    end_index = min(start_index + chunk_size, len(network_list)) # Ensure end_index is not out of bounds
                    chunk = network_list[start_index:end_index]

                    if not chunk: # Skip empty chunks if any edge case creates one
                        continue

                    logger.debug(f"Collapsing IPv{version} chunk {i+1}/{num_chunks} (size {len(chunk)})...")
                    try:
                        # Ensure collapse_addresses is called on a non-empty list
                        if chunk:
                             collapsed_chunk_result = list(ipaddress.collapse_addresses(chunk))
                             merged_chunks_results.extend(collapsed_chunk_result)
                             logger.debug(f"IPv{version} chunk {i+1} collapsed into {len(collapsed_chunk_result)} ranges.")
                    except Exception as chunk_exc:
                        # Log the specific chunk that failed if possible, or just the error
                        logger.error(f"Error collapsing IPv{version} CIDR chunk {i+1} with ipaddress: {chunk_exc}")
                        result.add_warning(f"IP Range Summarization (ipaddress): Error processing IPv{version} chunk {i+1} - {chunk_exc}")
                        # Consider if we should continue with other chunks or stop

                    # Update progress within chunking (rough estimate, split between v4/v6)
                    if progress_callback:
                         # Calculate overall progress based on combined list size and chunk progress
                         total_objects = len(ipv4_objects) + len(ipv6_objects)
                         # Track overall items processed so far
                         processed_count = 0
                         if version == 4:
                             processed_count = start_index + len(chunk)
                         elif version == 6:
                             # Add all v4 count + current progress in v6
                             processed_count = len(ipv4_objects) + start_index + len(chunk)

                         # Scale progress from 85% to 95% based on overall items processed
                         progress = 85 + (processed_count / total_objects * 10) if total_objects > 0 else 95
                         progress = min(progress, 95.0) # Cap at 95% before final step

                         progress_callback(progress, f"Summarizing IPv{version} chunk {i+1}/{num_chunks}")


                # Final collapse of the already collapsed chunks for this version
                logger.info(f"Performing final collapse on {len(merged_chunks_results)} partially summarized IPv{version} CIDRs using ipaddress...")
                if merged_chunks_results:
                    try:
                        # Ensure final collapse list isn't empty
                        if merged_chunks_results:
                            collapsed_results = list(ipaddress.collapse_addresses(merged_chunks_results))
                            logger.info(f"Final collapse complete for IPv{version}. Summarized into {len(collapsed_results)} ranges.")
                        else:
                             logger.info(f"No results after merging IPv{version} chunks, skipping final collapse.")
                             collapsed_results = []
                    except Exception as e:
                         logger.error(f"Error during final collapse for IPv{version}: {e}")
                         result.add_warning(f"IP Range Summarization (ipaddress): Error during final IPv{version} collapse - {e}")
                         collapsed_results = [] # Set empty on error
                else:
                    logger.warning(f"No IPv{version} CIDRs left after processing chunks (possibly due to errors).")
                    collapsed_results = [] # Ensure empty list

            return collapsed_results

        # --- Collapse IPv4 and IPv6 separately ---
        # Use the helper function for both
        summarized_ipv4 = collapse_list_with_chunking(ipv4_objects, 4)
        summarized_ipv6 = collapse_list_with_chunking(ipv6_objects, 6)

        # Combine the results
        summarized_cidrs_result = summarized_ipv4 + summarized_ipv6
        total_summarized = len(summarized_cidrs_result)

        logger.info(f"Total summarization complete. Optimized into {total_summarized} ranges ({len(summarized_ipv4)} IPv4, {len(summarized_ipv6)} IPv6).")
        # Progress reaches 95% after collapsing both lists
        if progress_callback: progress_callback(95.0, f"Summarized into {total_summarized} ranges")

        # --- Create IPRange objects for summarized results ---
        final_ip_ranges: Set[IPRange] = set()
        # Use the combined summarized_cidrs_result list
        creation_count = 0
        total_to_create = len(summarized_cidrs_result)
        for cidr_obj in summarized_cidrs_result:
            cidr_str = str(cidr_obj)
            # Find the original ASN - this is tricky after merging.
            # Simplification: Assign ASN if ONLY one ASN was involved, otherwise leave None.
            # More complex logic could try to find the 'best fit' ASN but is prone to errors.
            origin_asn = None
            # Retrieve the set of ASNs being processed in this phase
            # Assuming 'asns' is available in this scope from the outer function
            # (Need to confirm this context or pass 'asns' if necessary)
            # We need access to the 'asns' set that was passed to the main find_ip_ranges_for_asns function
            # Let's check if it's available implicitly or needs to be passed down
            # It IS available in the scope of find_ip_ranges_for_asns where this code resides.
            if len(asns) == 1:
                 origin_asn = next(iter(asns)) # Get the single ASN

            final_ip_ranges.add(IPRange(
                 cidr=cidr_str,
                 version=cidr_obj.version,
                 asn=origin_asn, # Simplified ASN assignment - often None after merge
                 country=None, # Country info lost during merge
                 data_source="Summarized (BGP.HE/IRR/ipaddress)" # Updated source
            ))
            creation_count += 1
            # Update progress during final object creation (95% to 100%)
            if progress_callback:
                progress = 95 + (creation_count / total_to_create * 5) if total_to_create > 0 else 100
                progress_callback(min(progress, 100.0), f"Creating final range objects {creation_count}/{total_to_create}")


        # Add the summarized ranges to the result
        result.ip_ranges.update(final_ip_ranges)
        logger.info(f"Added {len(final_ip_ranges)} summarized IP ranges to the result.")
        # Final progress update should be handled by the orchestrator, but ensure 100% here too
        if progress_callback: progress_callback(100.0, f"Finished IP Range Discovery ({len(final_ip_ranges)} ranges)")

    except Exception as e:
         # Catch any unexpected errors during the whole summarization process
         logger.exception(f"Error during IP range summarization phase: {e}")
         result.add_warning(f"IP Range Summarization Error: {e}")
         if progress_callback: progress_callback(100.0, "Error during summarization")

# --- IP Range Discovery from Domains (Placeholder/Not Used in Main Orchestration) ---
# This might be useful if ASNs are unknown but domains are known

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