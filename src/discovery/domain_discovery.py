"""Module for discovering domains and subdomains."""

import logging
import json
import re
import socket # For basic resolution fallback/checking
from typing import Set, Optional, Tuple
from urllib.parse import quote_plus
from concurrent.futures import ThreadPoolExecutor, as_completed # Import concurrent futures

# Attempt to import dns.resolver, but handle ImportError if dnspython is not installed
try:
    import dns.resolver
    import dns.exception
    DNSPYTHON_AVAILABLE = True
except ImportError:
    DNSPYTHON_AVAILABLE = False
    logger.warning("dnspython library not found. DNS resolution for status check will be limited.")

from src.core.models import Domain, Subdomain, ReconnaissanceResult
from src.utils.network import make_request
from src.core.exceptions import DataSourceError

logger = logging.getLogger(__name__)

CRTSH_URL = "https://crt.sh/"
DEFAULT_MAX_DNS_WORKERS = 20 # Add max workers for DNS resolution

def _parse_crtsh_json(json_content: str, query: str, result: ReconnaissanceResult) -> Set[str]:
    """Parses the JSON output from crt.sh to extract domain names."""
    found_names = set()
    try:
        # crt.sh returns a list of JSON objects
        certificates = json.loads(json_content)
        for cert in certificates:
            # Extract Common Name (CN) and Subject Alternative Names (SANs)
            common_name = cert.get('common_name')
            if common_name:
                found_names.add(common_name.strip().lower())
            
            name_value = cert.get('name_value')
            if name_value:
                # name_value often contains multiple names separated by newlines
                for name in name_value.split('\n'):
                    if name:
                         # Remove wildcard prefix if present (*.)
                        clean_name = re.sub(r"^\*\.", "", name.strip().lower())
                        found_names.add(clean_name)

    except json.JSONDecodeError as e:
        warning_msg = f"Failed to decode crt.sh JSON response for query '{query}': {e}"
        logger.error(warning_msg)
        result.add_warning(f"crt.sh Parser: {warning_msg}")
    except Exception as e:
        warning_msg = f"Error parsing crt.sh JSON for query '{query}': {e}"
        logger.exception(warning_msg)
        result.add_warning(f"crt.sh Parser: {warning_msg}")
    
    # Clean up results - remove entries that don't look like domains
    # and potentially filter based on the original query suffix?
    valid_domain_regex = re.compile(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
    cleaned_names = {name for name in found_names if valid_domain_regex.match(name)}
    
    logger.debug(f"Found {len(cleaned_names)} potential domains/subdomains from crt.sh for query '{query}'")
    return cleaned_names

def _query_crtsh(query: str, result: ReconnaissanceResult) -> Set[str]:
    """Queries crt.sh JSON endpoint for a given identity or domain."""
    # Use identity search (includes CN and SAN)
    search_url = f"{CRTSH_URL}?q={quote_plus(query)}&output=json"
    logger.info(f"Querying crt.sh for: {query}")
    try:
        response = make_request(search_url, source_name="crt.sh")
        response.raise_for_status()
        # Handle potentially empty response which is valid JSON (`[]`)
        if response.text.strip() == "[]":
             logger.debug(f"crt.sh returned empty results for query '{query}'")
             return set()
        return _parse_crtsh_json(response.text, query, result)
    except DataSourceError as e:
        warning_msg = f"Failed to query or parse crt.sh for '{query}': {e}"
        logger.error(warning_msg)
        result.add_warning(warning_msg)
    except Exception as e:
        warning_msg = f"Unexpected error during crt.sh query for '{query}': {e}"
        logger.exception(warning_msg)
        result.add_warning(warning_msg)
    return set()

# --- Add HackerTarget Passive DNS Query --- 
def _query_hackertarget_passive_dns(domain: str, result: ReconnaissanceResult) -> Set[str]:
    """Queries HackerTarget's Host Search endpoint for passive DNS data."""
    found_fqdns = set()
    # Simple API endpoint from HackerTarget
    # Note: Rate limits may apply. Be mindful of usage.
    # See: https://hackertarget.com/host-search/
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    logger.info(f"Querying HackerTarget Passive DNS for: {domain}")
    try:
        response = make_request(url, source_name="HackerTarget Passive DNS")
        response.raise_for_status()
        
        # Response is typically CSV-like: fqdn,ip
        if response.text:
             lines = response.text.strip().split('\n')
             if lines and "API count exceeded" in lines[0]:
                 warning_msg = f"HackerTarget API limit exceeded for query '{domain}'."
                 logger.warning(warning_msg)
                 result.add_warning(f"PassiveDNS (HackerTarget): {warning_msg}")
                 return set() # Stop if limit exceeded
             
             for line in lines:
                 parts = line.split(',')
                 if len(parts) > 0 and parts[0]:
                     fqdn = parts[0].strip().lower()
                     # Basic validation to avoid adding just the IP or malformed entries
                     if '.' in fqdn and fqdn != domain:
                         found_fqdns.add(fqdn)
                     # else: logger.debug(f"Skipping invalid/base FQDN from HackerTarget: {fqdn}")
        else:
            logger.debug(f"HackerTarget Passive DNS returned empty response for {domain}")

    except DataSourceError as e:
        # Log specific data source errors
        warning_msg = f"Failed query to HackerTarget Passive DNS for '{domain}': {e}"
        logger.error(warning_msg)
        result.add_warning(f"PassiveDNS (HackerTarget): {warning_msg}")
    except Exception as e:
        # Catch unexpected errors during the request or parsing
        warning_msg = f"Unexpected error processing HackerTarget Passive DNS for '{domain}': {e}"
        logger.exception(warning_msg)
        result.add_warning(f"PassiveDNS (HackerTarget): {warning_msg}")
        
    return found_fqdns

def _resolve_domain(fqdn: str, result: ReconnaissanceResult) -> Tuple[Optional[str], Set[str]]:
    """Attempt to resolve a domain name to get status and IPs."""
    if not DNSPYTHON_AVAILABLE:
        try:
            socket.gethostbyname(fqdn)
            return 'Active', set()
        except socket.gaierror:
             logger.debug(f"Socket resolution failed for {fqdn}: Non-existent domain?")
             return 'Inactive', set()
        except Exception as e:
             warning_msg = f"Socket resolution failed for {fqdn}: {e}"
             logger.warning(warning_msg)
             # result.add_warning(f"DNS (Socket): {warning_msg}") # Optional: Less critical
             return None, set()

    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.0
    resolved_ips = set()
    status = 'Inactive'

    try:
        a_records = resolver.resolve(fqdn, 'A', raise_on_no_answer=False)
        if a_records.response and a_records.response.answer:
            status = 'Active'
            for answer in a_records:
                resolved_ips.add(str(answer))
        aaaa_records = resolver.resolve(fqdn, 'AAAA', raise_on_no_answer=False)
        if aaaa_records.response and aaaa_records.response.answer:
            status = 'Active'
            for answer in aaaa_records:
                resolved_ips.add(str(answer))
    except dns.resolver.NXDOMAIN:
        logger.debug(f"DNS resolution failed for {fqdn}: NXDOMAIN")
        status = 'Inactive'
    except dns.resolver.NoAnswer:
        logger.debug(f"DNS resolution failed for {fqdn}: No Answer")
        status = 'Inactive'
    except dns.exception.Timeout:
        warning_msg = f"DNS resolution timed out for {fqdn}"
        logger.warning(warning_msg)
        result.add_warning(f"DNS: {warning_msg}")
        status = None
    except dns.resolver.NoNameservers:
         warning_msg = f"DNS resolution failed for {fqdn}: No nameservers available"
         logger.warning(warning_msg)
         result.add_warning(f"DNS: {warning_msg}")
         status = 'Inactive'
    except Exception as e:
        warning_msg = f"Unexpected DNS resolution error for {fqdn}: {e}"
        logger.error(warning_msg)
        result.add_warning(f"DNS: {warning_msg}")
        status = None
    return status, resolved_ips

def find_domains(
    org_name: Optional[str],
    base_domains: Optional[Set[str]],
    result: ReconnaissanceResult,
    max_workers: int = DEFAULT_MAX_DNS_WORKERS # Add max_workers arg
):
    """Find domains and subdomains and add them to the result object.
    
    Uses sources like crt.sh. Performs basic DNS resolution for status.
    Modifies the passed ReconnaissanceResult object directly.
    """
    all_found_fqdns: Set[str] = set()
    logger.info(f"Starting domain/subdomain discovery for org: '{org_name}', base_domains: {base_domains}")

    # --- crt.sh Query --- 
    crtsh_queries = set()
    if base_domains:
         crtsh_queries.update({f"%.{domain}" for domain in base_domains})
    if org_name:
         crtsh_queries.add(org_name)
         warning_msg_org = f"Querying crt.sh by org name '{org_name}' may yield unrelated results."
         logger.warning(warning_msg_org)
         result.add_warning(f"crt.sh: {warning_msg_org}")

    if crtsh_queries:
        logger.info(f"Preparing to query crt.sh for: {crtsh_queries}")
        # Use ThreadPoolExecutor to query crt.sh in parallel
        with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="CrtShQuery") as executor:
            future_to_query = {executor.submit(_query_crtsh, query, result): query for query in crtsh_queries}
            
            for future in as_completed(future_to_query):
                query = future_to_query[future]
                try:
                    fqdns_from_crtsh = future.result()
                    if fqdns_from_crtsh:
                        all_found_fqdns.update(fqdns_from_crtsh)
                        logger.info(f"Got {len(fqdns_from_crtsh)} results from crt.sh for query '{query}'")
                    else:
                        logger.debug(f"No results from crt.sh for query '{query}'")
                except Exception as exc:
                    warning_msg = f"crt.sh query '{query}' generated an exception: {exc}"
                    logger.error(warning_msg)
                    result.add_warning(f"crt.sh: {warning_msg}")
    else:
         warning_msg = "No organization name or base domains provided for crt.sh query."
         logger.warning(warning_msg)
         result.add_warning(f"crt.sh: {warning_msg}")

    # --- DNSDumpster Query (Placeholder) --- 
    if base_domains:
        warning_msg_dnsd = "DNSDumpster discovery not yet implemented."
        logger.info(warning_msg_dnsd)
        # result.add_warning(f"DNSDumpster: {warning_msg_dnsd}")

    # --- Passive DNS Query (Using HackerTarget) --- 
    passive_dns_fqdns = set()
    if base_domains:
        logger.info(f"Querying HackerTarget Passive DNS for base domains: {base_domains}")
        # Potentially parallelize this if many base_domains are common
        for domain in base_domains:
            try:
                pdns_results = _query_hackertarget_passive_dns(domain, result)
                if pdns_results:
                    passive_dns_fqdns.update(pdns_results)
                    logger.info(f"Found {len(pdns_results)} potential hosts via HackerTarget Passive DNS for {domain}")
            except Exception as e:
                warning_msg = f"Unexpected error querying HackerTarget Passive DNS for {domain}: {e}"
                logger.exception(warning_msg)
                result.add_warning(f"PassiveDNS (HackerTarget): {warning_msg}")
        all_found_fqdns.update(passive_dns_fqdns) # Add results to the main set
    else:
         logger.info("Skipping Passive DNS query as no base domains were provided.")

    # --- Organize FQDNs into Domains and Subdomains --- 
    organized_subdomains = 0
    domains_to_add = {} # Temp dict {base_domain_name: Domain}
    subdomains_to_resolve = set() # Collect FQDNs to resolve

    try:
        logger.info(f"Processing {len(all_found_fqdns)} unique FQDNs found...")
        
        # Ensure provided base domains exist first
        if base_domains:
            for bd in base_domains:
                if bd not in domains_to_add:
                    domains_to_add[bd] = Domain(name=bd, data_source="Input")

        # First pass: Identify base domains and subdomains
        for fqdn in all_found_fqdns:
            parts = fqdn.split('.')
            if len(parts) < 2:
                 warning_msg = f"Skipping invalid FQDN format: {fqdn}"
                 logger.warning(warning_msg)
                 result.add_warning(f"Domain Processing: {warning_msg}")
                 continue
            
            base_domain_name = '.'.join(parts[-2:]) 
            is_base_domain_itself = (fqdn == base_domain_name)

            # Ensure parent domain object exists
            if base_domain_name not in domains_to_add:
                 domains_to_add[base_domain_name] = Domain(name=base_domain_name, data_source="Discovered")
            
            if not is_base_domain_itself:
                 subdomains_to_resolve.add(fqdn)
            else:
                 # Optionally resolve base domain itself if needed?
                 # For now, we primarily resolve subdomains
                 pass
        
        logger.info(f"Identified {len(subdomains_to_resolve)} unique potential subdomains to resolve.")

        # Second pass: Resolve subdomains in parallel
        resolved_subdomain_objects = {} # {fqdn: Subdomain}
        with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="DNSResolve") as executor:
            future_to_fqdn = {executor.submit(_resolve_domain, fqdn, result): fqdn for fqdn in subdomains_to_resolve}
            
            processed_count = 0
            total_count = len(future_to_fqdn)
            for future in as_completed(future_to_fqdn):
                fqdn = future_to_fqdn[future]
                processed_count += 1
                try:
                    status, ips = future.result()
                    subdomain = Subdomain(fqdn=fqdn, status=status, resolved_ips=ips, data_source="Discovered")
                    resolved_subdomain_objects[fqdn] = subdomain
                    logger.debug(f"({processed_count}/{total_count}) Resolved {fqdn}: Status={status}, IPs={len(ips)}")
                except Exception as exc:
                    warning_msg = f"Subdomain {fqdn} generated an exception during resolution: {exc}"
                    logger.error(warning_msg)
                    result.add_warning(f"Domain Resolution: {warning_msg}")

        # Third pass: Add resolved subdomains to their parent Domain objects
        for fqdn, subdomain_obj in resolved_subdomain_objects.items():
            parts = fqdn.split('.')
            if len(parts) >= 2:
                 base_domain_name = '.'.join(parts[-2:])
                 if base_domain_name in domains_to_add:
                     domains_to_add[base_domain_name].subdomains.add(subdomain_obj)
                     organized_subdomains += 1
                 else:
                     # Should not happen if first pass worked correctly
                     logger.error(f"Internal error: Parent domain '{base_domain_name}' not found for resolved subdomain '{fqdn}'")
            else:
                 # Should not happen due to earlier check
                 logger.warning(f"Skipping addition of resolved subdomain with invalid FQDN: {fqdn}")

        # Final pass: Add all populated Domain objects to the main result
        for domain_obj in domains_to_add.values():
             result.add_domain(domain_obj) # add_domain handles merging if needed

    except Exception as e:
         warning_msg = f"Unexpected error during organization/resolution of FQDNs: {e}"
         logger.exception(warning_msg)
         result.add_warning(warning_msg)

    logger.info(f"Finished domain discovery. Result contains {len(result.domains)} domains and {organized_subdomains} subdomains resolved and added.")
    # No return needed

# Example usage (for testing):
if __name__ == '__main__':
    import sys
    sys.path.insert(0, sys.path[0] + '/../..') 
    from src.utils.logging_config import setup_logging
    setup_logging(logging.DEBUG)
    
    # domains_input = {"example.com", "example.net"}
    # found_domains = find_domains(org_name=None, base_domains=domains_input)

    domains_input = {"google.com"}
    # org = "Google LLC"
    org = None
    found_domains = find_domains(org_name=org, base_domains=domains_input)

    print(f"\n--- Found Domains ({len(found_domains)}) ---")
    for dom in sorted(list(found_domains), key=lambda d: d.name):
        print(f"Domain: {dom.name} (Source: {dom.data_source})")
        if dom.subdomains:
            print(f"  Subdomains: ({len(dom.subdomains)}) found")
            # Print only a sample if too many
            limit = 20
            count = 0
            for sub in sorted(list(dom.subdomains), key=lambda s: s.fqdn):
                print(f"  - {sub.fqdn} (Source: {sub.data_source})")
                count += 1
                if count >= limit:
                     print(f"  ... and {len(dom.subdomains) - limit} more.")
                     break
        else:
            print("  No subdomains found.") 