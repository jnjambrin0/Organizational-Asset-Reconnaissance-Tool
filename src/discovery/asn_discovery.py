"""Module for discovering Autonomous System Numbers (ASNs)."""

import logging
import re
from typing import Set, Optional
from urllib.parse import quote_plus
import ipaddress

from bs4 import BeautifulSoup
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError, ASNRegistryError
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.core.models import ASN, ReconnaissanceResult
from src.utils.network import make_request
from src.core.exceptions import DataSourceError

logger = logging.getLogger(__name__)

BGP_HE_NET_URL = "https://bgp.he.net"

DEFAULT_MAX_WHOIS_WORKERS = 10

def _parse_bgp_he_net_search(html_content: str, result: ReconnaissanceResult) -> Set[ASN]:
    """Parses the BGP.HE.NET search results page for ASNs."""
    asns: Set[ASN] = set()
    try:
        soup = BeautifulSoup(html_content, 'lxml')
    except Exception as e:
        logger.error(f"Failed to initialize BeautifulSoup parser: {e}")
        return asns # Cannot parse if soup fails

    # Find the table containing search results - this selector might need adjustment
    try:
        results_table = soup.find('table', {'id': 'search'})
        if not results_table:
             # Check for direct ASN result page
            asn_div = soup.find('div', {'id': 'asn'})
            if asn_div:
                asn_text = asn_div.find('h1').get_text(strip=True) if asn_div.find('h1') else ""
                asn_match = re.match(r"AS(\d+)", asn_text)
                if asn_match:
                    asn_number = int(asn_match.group(1))
                    # Extract description - this is highly dependent on page structure
                    description = "Description parsing needed" # Placeholder
                    logger.debug(f"Found direct ASN: {asn_number}")
                    asns.add(ASN(number=asn_number, description=description, data_source="BGP.HE.NET"))
                else:
                    logger.warning("Could not parse ASN from direct page title.")
            else:
                # Only log warning if neither search table nor direct ASN info found
                 warning_msg = "Could not find search results table or direct ASN info on BGP.HE.NET page."
                 logger.warning(warning_msg)
                 result.add_warning(f"BGP.HE.NET Parser: {warning_msg}")
            return asns

        rows = results_table.find_all('tr')
        for row in rows[1:]: # Skip header row
            cells = row.find_all('td')
            if len(cells) > 0:
                first_cell_link = cells[0].find('a')
                if first_cell_link and first_cell_link.get('href', '').startswith('/ASN/'):
                    try:
                        asn_text = first_cell_link.get_text(strip=True)
                        asn_match = re.match(r"AS(\d+)", asn_text)
                        if asn_match:
                            asn_number = int(asn_match.group(1))
                            # Try to get description from the next cell if available
                            description = cells[1].get_text(strip=True) if len(cells) > 1 else None
                            logger.debug(f"Found ASN: {asn_number}, Description: {description}")
                            asns.add(ASN(number=asn_number, name=description, description=description, data_source="BGP.HE.NET"))
                    except (ValueError, IndexError, AttributeError, TypeError) as e:
                        warning_msg = f"Could not parse ASN row: {row}. Error: {e}"
                        logger.warning(warning_msg)
                        result.add_warning(f"BGP.HE.NET Parser: {warning_msg}")
    except Exception as e:
        warning_msg = f"Unexpected error during BGP.HE.NET HTML parsing: {e}"
        logger.exception(warning_msg)
        result.add_warning(f"BGP.HE.NET Parser: {warning_msg}")

    return asns

def _query_bgp_he_net(query: str, result: ReconnaissanceResult) -> Set[ASN]:
    """Queries BGP.HE.NET search and parses the results."""
    search_url = f"{BGP_HE_NET_URL}/search?search%5Bsearch%5D={quote_plus(query)}&commit=Search"
    logger.info(f"Querying BGP.HE.NET for: {query}")
    try:
        response = make_request(search_url, source_name="BGP.HE.NET")
        response.raise_for_status() # Ensure we check status codes
        return _parse_bgp_he_net_search(response.text, result)
    except DataSourceError as e:
        warning_msg = f"Failed to query or parse BGP.HE.NET for \"{query}\": {e}"
        logger.error(warning_msg)
        result.add_warning(warning_msg)
    except Exception as e:
        warning_msg = f"Unexpected error during BGP.HE.NET processing for \"{query}\": {e}"
        logger.exception(warning_msg)
        result.add_warning(warning_msg)
    return set()

def find_asns_for_organization(
    org_name: str, 
    base_domains: Optional[Set[str]], 
    result: ReconnaissanceResult,
    max_workers: int = DEFAULT_MAX_WHOIS_WORKERS
):
    """Find ASNs associated with an organization or its domains and add them to the result object.

    Uses BGP.HE.NET and IP->ASN lookup via RDAP/WHOIS.

    Args:
        org_name: The name of the target organization.
        base_domains: Optional set of known base domains for the organization.
        result: The ReconnaissanceResult object to add findings and warnings to.
        max_workers: Maximum number of workers for concurrent IPWhois lookups.
    """
    discovered_asns: Set[ASN] = set()
    logger.info(f"Starting ASN discovery for organization: {org_name}")

    # --- Query BGP.HE.NET by Org Name --- 
    bgp_queries = set()
    if org_name:
        bgp_queries.add(org_name)
        # Removed direct call: asns_from_org = _query_bgp_he_net(org_name, result)
        # discovered_asns.update(asns_from_org)
        # logger.info(f"Found {len(asns_from_org)} ASNs for org name '{org_name}' via BGP.HE.NET")

    # --- Query BGP.HE.NET by Domain Name --- 
    if base_domains:
         logger.info(f"Adding base domains to BGP.HE.NET queries: {base_domains}")
         bgp_queries.update(base_domains)
         # Removed loop and direct calls:
         # for domain in base_domains:
         #     asns_from_domain = _query_bgp_he_net(domain, result)
         #     discovered_asns.update(asns_from_domain)
         #     logger.info(f"Found {len(asns_from_domain)} ASNs for domain '{domain}' via BGP.HE.NET")

    # --- Execute BGP.HE.NET Queries in Parallel --- 
    if bgp_queries:
         logger.info(f"Querying BGP.HE.NET in parallel for: {bgp_queries}")
         with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="BGPQuery") as executor:
             future_to_query = {executor.submit(_query_bgp_he_net, query, result): query for query in bgp_queries}
             
             for future in as_completed(future_to_query):
                 query = future_to_query[future]
                 try:
                     asns_from_query = future.result()
                     if asns_from_query:
                         discovered_asns.update(asns_from_query)
                         logger.info(f"Found {len(asns_from_query)} ASNs for query '{query}' via BGP.HE.NET")
                     else:
                         logger.debug(f"No ASNs found for query '{query}' via BGP.HE.NET")
                 except Exception as exc:
                     warning_msg = f"BGP.HE.NET query '{query}' generated an exception: {exc}"
                     logger.error(warning_msg)
                     result.add_warning(f"BGP.HE.NET: {warning_msg}")
    else:
         logger.info("No queries for BGP.HE.NET (no org name or base domains provided).")

    # --- IP Address -> ASN Lookup (using resolved IPs from Domain Discovery) ---
    logger.info("Attempting IP -> ASN lookup for resolved domain/subdomain IPs...")
    all_ips_to_check = set()
    if result.domains:
         logger.info("Collecting IPs from discovered domains and subdomains for ASN lookup...")
         for domain in result.domains:
              # Iterate through subdomains to get IPs
              for subdomain in domain.subdomains:
                  if subdomain.resolved_ips:
                       all_ips_to_check.update(subdomain.resolved_ips)
    
    if not all_ips_to_check:
         logger.warning("No resolved IPs found from domains/subdomains to perform ASN lookup.")
    else:
        logger.info(f"Found {len(all_ips_to_check)} unique public IPs to check for ASN origin using up to {max_workers} workers.")
        found_asns_from_ips = set() # Collect ASN objects found from IPs

        with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="IPWhoisLookup") as executor:
            # Map future to the IP address it's processing
            future_to_ip = {executor.submit(_lookup_asn_for_ip, ip): ip for ip in all_ips_to_check}
            
            processed_count = 0
            total_count = len(future_to_ip)
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                processed_count += 1
                try:
                    asn_info = future.result() # _lookup_asn_for_ip returns ASN object or None
                    if asn_info:
                         # Check if already found via BGP or another IP before adding
                         if asn_info not in discovered_asns and asn_info not in found_asns_from_ips:
                              logger.info(f"({processed_count}/{total_count}) Found ASN {asn_info.number} ({asn_info.description or 'No description'}) for IP {ip}")
                              found_asns_from_ips.add(asn_info)
                         else:
                             logger.debug(f"({processed_count}/{total_count}) ASN {asn_info.number} (from IP {ip}) already discovered.")
                    # else: # Optional: log if no ASN was found for an IP
                    #    logger.debug(f"({processed_count}/{total_count}) No ASN found for IP {ip}.")
                         
                except Exception as exc:
                    # Log errors that occur during the lookup itself
                    logger.error(f"({processed_count}/{total_count}) Error during WHOIS lookup thread for IP {ip}: {exc}")
                    result.add_warning(f"ASN Discovery (IPWhois): Error during lookup for {ip} - {exc}")

        logger.info(f"Checked {len(all_ips_to_check)} IPs for ASN origin, found {len(found_asns_from_ips)} new unique ASNs.")
        discovered_asns.update(found_asns_from_ips) # Add newly found ASNs

    # --- Placeholder for WHOIS Org Name Query --- 
    warning_msg_whois_org = "Organization Name -> WHOIS ASN discovery not yet implemented."
    logger.info(warning_msg_whois_org)
    # result.add_warning(warning_msg_whois)

    # Add discovered ASNs to the main result object
    for asn in discovered_asns:
         result.add_asn(asn)

    logger.info(f"Finished ASN discovery for {org_name}. Added {len(discovered_asns)} unique ASNs to result.")
    # No return value needed, modifies result object directly

# --- Helper function for parallel IP lookup --- 
def _lookup_asn_for_ip(ip_addr: str) -> Optional[ASN]:
     """Performs IPWhois lookup for a single IP and returns an ASN object or None."""
     try:
         logger.debug(f"Performing WHOIS lookup for IP: {ip_addr}")
         obj = IPWhois(ip_addr)
         results_whois = obj.lookup_whois(retry_count=2)

         if results_whois and results_whois.get('asn'):
             asn_num_str = results_whois.get('asn')
             if asn_num_str and asn_num_str.isdigit():
                 asn_number = int(asn_num_str)
                 asn_desc = results_whois.get('asn_description')
                 asn_country = results_whois.get('asn_country_code')
                 
                 return ASN(
                     number=asn_number, 
                     name=asn_desc, 
                     description=asn_desc, 
                     country=asn_country, 
                     data_source=f"IPWhois({ip_addr})"
                 )
             else:
                 logger.debug(f"Could not parse ASN number '{asn_num_str}' from WHOIS for IP {ip_addr}")
         else:
             logger.debug(f"No ASN information found in WHOIS results for IP {ip_addr}")
         return None # No ASN found or parsed

     except IPDefinedError:
         logger.debug(f"Skipping WHOIS lookup for defined private/internal IP: {ip_addr}")
         return None
     except ASNRegistryError as e:
         logger.warning(f"ASN registry error during WHOIS lookup for IP {ip_addr}: {e}")
         # Optionally add warning to result here if needed, but might be noisy
         return None
     except Exception as e:
         # Catch broader exceptions like timeouts
         # Log as warning as lookup failures for specific IPs are common
         logger.warning(f"Error during WHOIS lookup for IP {ip_addr}: {e}")
         # Optionally add warning to result here
         return None

# Example usage (for testing):
if __name__ == '__main__':
    import sys
    # Add project root to path for testing
    sys.path.insert(0, sys.path[0] + '/../..') 
    from src.utils.logging_config import setup_logging
    setup_logging(logging.DEBUG)
    # org = "Google LLC"
    # org = "Cloudflare, Inc."
    org = "Microsoft Corporation"
    domains = {"microsoft.com"} # Example domain
    # asns = find_asns_for_organization(org, domains)
    asns = find_asns_for_organization(org, None, ReconnaissanceResult())
    print(f"\n--- Found ASNs ({len(asns)}) ---")
    for asn in sorted(list(asns), key=lambda x: x.number):
        print(asn)

    # Test with a domain known to be on a specific ASN (e.g., cloudflare.com)
    # asns_cf = find_asns_for_organization("", {"cloudflare.com"})
    # print(f"\n--- Found ASNs for cloudflare.com ({len(asns_cf)}) ---")
    # for asn in sorted(list(asns_cf), key=lambda x: x.number):
    #     print(asn) 