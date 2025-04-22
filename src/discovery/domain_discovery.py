"""Module for discovering domains and subdomains."""

import logging
import json
import re
import socket # For basic resolution fallback/checking
from typing import Set, Optional, Tuple, Callable, Dict, Any, List
from urllib.parse import quote_plus
from concurrent.futures import ThreadPoolExecutor, as_completed # Import concurrent futures
from datetime import datetime # Import datetime

# Attempt to import dns.resolver, but handle ImportError if dnspython is not installed
try:
    import dns.resolver
    import dns.exception
    DNSPYTHON_AVAILABLE = True
except ImportError:
    DNSPYTHON_AVAILABLE = False
    logging.getLogger(__name__).warning("dnspython library not found. DNS resolution for status check will be limited.")

from src.core.models import Domain, Subdomain, ReconnaissanceResult
from src.utils.network import make_request
from src.core.exceptions import DataSourceError
from src.utils.logging_config import get_logger, create_progress_logger

logger = get_logger(__name__)

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
        logger.warning(warning_msg)
        result.add_warning(warning_msg)
    except Exception as e:
        warning_msg = f"Unexpected error during crt.sh query for '{query}': {e}"
        logger.exception(warning_msg)
        result.add_warning(warning_msg)
    return set()

# --- Helper function to manage HackerTarget API limit state ---
# This dictionary will store the limit status per scan instance implicitly 
# (cleared when find_domains finishes). A more robust approach might involve 
# passing a state object, but this works for sequential calls within find_domains.
_hackertarget_limit_tracker: Dict[int, bool] = {}

def _check_and_query_hackertarget(domain: str, result: ReconnaissanceResult) -> Set[str]:
    """Checks the API limit state before querying HackerTarget.
    Manages the limit state tracker.
    """
    # Use the result object's hash or id as a proxy for the current scan instance
    # Note: This assumes the result object persists throughout the find_domains call.
    scan_instance_id = id(result) 

    if _hackertarget_limit_tracker.get(scan_instance_id, False):
        logger.debug(f"Skipping HackerTarget query for {domain}: API limit previously hit in this scan.")
        return set()

    found_fqdns = set()
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    logger.info(f"Querying HackerTarget Passive DNS for: {domain}")
    try:
        response = make_request(url, source_name="HackerTarget Passive DNS")
        response.raise_for_status()

        if response.text:
             lines = response.text.strip().split('\n')
             # Check for the specific limit message
             if lines and "API count exceeded" in lines[0]:
                 warning_msg = f"HackerTarget API limit exceeded (detected during query for '{domain}'). Subsequent queries in this scan will be skipped."
                 # Log warning only the first time the limit is hit for this scan instance
                 if not _hackertarget_limit_tracker.get(scan_instance_id, False):
                     logger.warning(warning_msg)
                     result.add_warning(f"PassiveDNS (HackerTarget): API limit exceeded.") # Add generic warning once
                     _hackertarget_limit_tracker[scan_instance_id] = True # Set limit hit flag for this scan
                 return set() # Stop processing for this domain

             # Process lines if limit not hit
             for line in lines:
                 parts = line.split(',')
                 if len(parts) > 0 and parts[0]:
                     fqdn = parts[0].strip().lower()
                     if '.' in fqdn and fqdn != domain:
                         found_fqdns.add(fqdn)
        else:
            logger.debug(f"HackerTarget Passive DNS returned empty response for {domain}")

    except DataSourceError as e:
        warning_msg = f"Failed query to HackerTarget Passive DNS for '{domain}': {e}"
        logger.warning(warning_msg)
        result.add_warning(f"PassiveDNS (HackerTarget): Query failed for {domain} - {e}")
    except Exception as e:
        warning_msg = f"Unexpected error processing HackerTarget Passive DNS for '{domain}': {e}"
        logger.exception(warning_msg)
        result.add_warning(f"PassiveDNS (HackerTarget): Error processing {domain} - {e}")

    return found_fqdns

def _resolve_domain(fqdn: str, result: ReconnaissanceResult) -> Tuple[Optional[str], Set[str], datetime]:
    """Attempt to resolve a domain name to get status and IPs. Returns status, IPs, and current time."""
    checked_time = datetime.now() # Record the time of the check
    
    if not DNSPYTHON_AVAILABLE:
        try:
            socket.gethostbyname(fqdn)
            return 'Active', set(), checked_time
        except socket.gaierror:
             logger.debug(f"Socket resolution failed for {fqdn}: Non-existent domain?")
             return 'Inactive', set(), checked_time
        except Exception as e:
             warning_msg = f"Socket resolution failed for {fqdn}: {e}"
             logger.warning(warning_msg)
             # result.add_warning(f"DNS (Socket): {warning_msg}") # Optional: Less critical
             return None, set(), checked_time

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
        
    return status, resolved_ips, checked_time

def find_domains(
    org_name: Optional[str],
    base_domains: Optional[Set[str]],
    result: ReconnaissanceResult,
    max_workers: int = DEFAULT_MAX_DNS_WORKERS,
    progress_callback: Optional[Callable[[float, str], None]] = None
):
    """
    Finds domains and subdomains associated with an organization and adds them to the result.
    
    Args:
        org_name: Organization name to search for
        base_domains: Optional set of known base domains
        result: ReconnaissanceResult to populate
        max_workers: Maximum number of concurrent workers for DNS resolution
        progress_callback: Optional callback for progress updates
    """
    logger.info(f"🔍 Finding domains for: {org_name if org_name else 'Unknown'}")
    
    # Create a terminal progress logger
    progress = create_progress_logger(__name__, total=100, prefix="Domain Discovery")
    progress.update(0, "Starting domain search...")
    
    # Update progress callback if provided
    def update_progress(percent: float, message: str):
        progress.update(percent, message)
        if progress_callback:
            progress_callback(percent, message)
    
    # Define base domains set
    if not base_domains:
        base_domains = set()
        logger.debug("No base domains provided, starting with empty set.")
    else:
        logger.info(f"Starting with {len(base_domains)} provided base domains")
    
    # Ensure valid base domains
    valid_domain_regex = re.compile(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
    base_domains = {domain.lower() for domain in base_domains if valid_domain_regex.match(domain)}
    
    # Add queries for base domains to crt.sh
    update_progress(10, "Searching certificate transparency logs...")
    
    # --- Parallelize crt.sh Queries --- 
    all_domains = set() # Start with an empty set for all domains/subdomains found
    crtsh_queries = set()
    if base_domains:
        # Add base domains themselves to the results immediately
        all_domains.update(base_domains)
        # Prepare queries for base domains
        crtsh_queries.update({f"%.{domain}" for domain in base_domains}) # Query subdomains
        # Also query the base domain itself in case it has direct certs
        # crtsh_queries.update(base_domains)
        # Let's rely on the org name query or direct addition for base domains
        
    if org_name:
        crtsh_queries.add(org_name)
        # Add a warning if querying only by org name
        if not base_domains:
             warning_msg_org = f"Querying crt.sh only by org name '{org_name}' might yield unrelated results."
             logger.warning(warning_msg_org)
             result.add_warning(f"crt.sh: {warning_msg_org}")
             
    if crtsh_queries:
        logger.info(f"Querying crt.sh in parallel for: {crtsh_queries}")
        crtsh_query_count = 0
        total_crtsh_queries = len(crtsh_queries)
        # Limit crt.sh workers to avoid potential blocking
        crtsh_workers = min(max_workers, 5) 
        with ThreadPoolExecutor(max_workers=crtsh_workers, thread_name_prefix="CrtShQuery") as executor:
            future_to_query = {executor.submit(_query_crtsh, query, result): query for query in crtsh_queries}
            for future in as_completed(future_to_query):
                query = future_to_query[future]
                crtsh_query_count += 1
                try:
                    fqdns_from_crtsh = future.result()
                    if fqdns_from_crtsh:
                        all_domains.update(fqdns_from_crtsh)
                        logger.info(f"Got {len(fqdns_from_crtsh)} results from crt.sh for query '{query}'")
                    # else: logger.debug(f"No results from crt.sh for query '{query}'")
                except Exception as exc:
                    warning_msg = f"crt.sh query '{query}' generated an exception: {exc}"
                    logger.warning(warning_msg) # Log as warning, not error
                    result.add_warning(f"crt.sh Query Error: {warning_msg}")
                
                # Update progress (scaling 10% -> 25%)
                progress_percent = 10 + (crtsh_query_count / total_crtsh_queries * 15) if total_crtsh_queries > 0 else 25
                update_progress(progress_percent, f"Queried CT logs {crtsh_query_count}/{total_crtsh_queries}")
    else:
         logger.info("No queries for crt.sh (no org name or base domains provided).")
         update_progress(25, "Skipped CT log search") # Mark phase complete
    
    # Log domain discovery results from CT
    logger.info(f"Found {len(all_domains)} potential domains/subdomains via certificate transparency logs")
    
    # Filter out potential invalid entries before proceeding (e.g., IP addresses, single labels)
    valid_domain_regex = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", re.IGNORECASE)
    initial_count = len(all_domains)
    all_domains = {name for name in all_domains if valid_domain_regex.match(name)}
    if initial_count != len(all_domains):
        logger.debug(f"Filtered {initial_count - len(all_domains)} invalid FQDN patterns found in CT logs.")

    # Sort domains by TLD+domain (second level) to group related domains
    # This sorting is less critical now as grouping handles it, but kept for consistency
    # sorted_domains = sorted(all_domains, key=lambda x: '.'.join(x.split('.')[-2:])) 
    
    # Process each domain (create Domain objects and start resolving subdomains)
    update_progress(25, f"Processing {len(all_domains)} unique FQDNs from CT logs...")
    
    # Prepare a list of HackerTarget passive DNS queries to run
    # Only query base domains (domain.tld) for passive DNS
    passive_dns_queries = set()
    for domain_name in all_domains:
        parts = domain_name.split('.')
        if len(parts) == 2:
            passive_dns_queries.add(domain_name)
        # Add explicitly provided base domains if not already included
        if base_domains:
             passive_dns_queries.update(base_domains)
             
    # Process each base domain for passive DNS (Sequentially)
    update_progress(30, f"Performing passive DNS queries for {len(passive_dns_queries)} base domains...")
    
    all_subdomains = set()
    # Reset HackerTarget limit tracker at the start of the passive DNS phase for this scan
    _hackertarget_limit_tracker[id(result)] = False 
    for idx, query_domain in enumerate(passive_dns_queries):
        # Query passive DNS using the helper function that manages the limit state
        passive_dns_results = _check_and_query_hackertarget(query_domain, result)
        all_subdomains.update(passive_dns_results)
        
        # Update progress proportionally (30-45%)
        progress_percent = 30 + (idx / len(passive_dns_queries) * 15) if passive_dns_queries else 45
        update_progress(progress_percent, f"Passive DNS query {idx+1}/{len(passive_dns_queries)}: found {len(passive_dns_results)} subdomains")
    
    # Add discovered subdomains to the all_domains set
    all_domains.update(all_subdomains)
    
    # Group discovered domains
    grouped_domains = {}
    for domain_name in sorted(all_domains):
        parts = domain_name.split('.')
        if len(parts) >= 2:
            base_domain = '.'.join(parts[-2:])  # e.g., "example.com"
            if base_domain not in grouped_domains:
                grouped_domains[base_domain] = set()
            
            if domain_name != base_domain:
                # It's a subdomain, add to the appropriate group
                grouped_domains[base_domain].add(domain_name)
            # else it's a base domain, already recorded as the key
    
    # Start DNS resolution for validation
    update_progress(45, "Starting DNS resolution of all domains and subdomains...")
    
    # Create Domain objects and add to result
    base_domain_objects = {}
    total_domains = len(grouped_domains)
    
    for i, (base_name, subdomains) in enumerate(grouped_domains.items()):
        # Create domain object for base domain
        domain_obj = Domain(
            name=base_name,
            registrar=None,  # We don't have registrar info yet
            creation_date=None,  # We don't have creation date yet
            data_source="Certificate Transparency & Passive DNS",
            subdomains=set()  # Initialize empty, will be filled below
        )
        base_domain_objects[base_name] = domain_obj
        
        # Update progress (45-60%)
        domain_progress = 45 + ((i / total_domains) * 15) if total_domains else 60
        update_progress(domain_progress, f"Processing domain {i+1}/{total_domains}: {base_name} with {len(subdomains)} subdomains")
    
    # Prepare all DNS resolution tasks (base domains + subdomains)
    all_resolution_tasks = []
    for base_name, subdomains in grouped_domains.items():
        # Add base domain resolution task
        all_resolution_tasks.append((base_name, base_domain_objects[base_name]))
        
        # Add all subdomain resolution tasks
        for subdomain_name in subdomains:
            all_resolution_tasks.append((subdomain_name, base_domain_objects[base_name]))
    
    # Resolve DNS for all domains and subdomains
    update_progress(60, f"Resolving DNS for {len(all_resolution_tasks)} domains and subdomains...")
    
    # Use ThreadPoolExecutor for parallel DNS resolution
    completed = 0
    total_to_resolve = len(all_resolution_tasks)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_domain = {}
        
        # Submit all resolution tasks
        for domain_name, domain_obj in all_resolution_tasks:
            future = executor.submit(_resolve_domain, domain_name, result)
            future_to_domain[future] = (domain_name, domain_obj)
        
        # Process results as they complete
        for future in as_completed(future_to_domain):
            completed += 1
            domain_name, domain_obj = future_to_domain[future]
            
            try:
                status, resolved_ips, checked_time = future.result()
                
                # For base domains, just add the Domain object to result
                if domain_name == domain_obj.name:
                    # Base domain resolution complete, add to result
                    result.add_domain(domain_obj)
                else:
                    # It's a subdomain, create Subdomain object and add to parent Domain
                    subdomain_obj = Subdomain(
                        fqdn=domain_name,
                        status=status or "unknown",
                        resolved_ips=resolved_ips,
                        data_source="DNS Resolution",
                        last_checked=checked_time
                    )
                    domain_obj.subdomains.add(subdomain_obj)
                
                # Update progress (60-95%)
                resolution_progress = 60 + ((completed / total_to_resolve) * 35)
                update_progress(resolution_progress, f"Resolved {completed}/{total_to_resolve}: {domain_name}")
                
            except Exception as e:
                logger.error(f"Error processing domain {domain_name}: {e}")
                result.add_warning(f"Domain Processing Error: {domain_name} - {e}")
    
    # Final progress update
    total_subdomains = sum(len(domain.subdomains) for domain in result.domains)
    update_progress(100, f"Completed with {len(result.domains)} domains and {total_subdomains} subdomains")
    
    logger.info(f"✅ Domain discovery completed. Added {len(result.domains)} domains with {total_subdomains} subdomains.")
    return result

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