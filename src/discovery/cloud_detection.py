import logging
import re # Make sure re is imported
from typing import Set, Dict # Add Dict
import ipaddress

# Use netaddr instead of iptree
try:
    from netaddr import IPNetwork, IPSet, AddrFormatError
    NETADDR_AVAILABLE = True
except ImportError:
    NETADDR_AVAILABLE = False
    # logger is not defined yet here, log in functions or main entry

from src.core.models import IPRange, Domain, CloudService, ReconnaissanceResult, Subdomain # Add ReconnaissanceResult and Subdomain
# ... other imports ...

logger = logging.getLogger(__name__)

# --- Cloud Data Definitions ---
# TODO: Populate these with actual cloud provider data
KNOWN_CLOUD_RANGES = {
    # Example structure: provider: [cidr1, cidr2, ...]
    "AWS": [
        "13.32.0.0/15", "18.200.0.0/13", "52.93.178.234/32", # Example subset + specific IP
        "3.5.140.0/22", "15.230.39.0/24", # More examples
        "54.239.0.0/17", "99.83.128.0/17", # CloudFront IPs
        "130.176.0.0/16", # Example AWS Global Accelerator
    ], 
    "Azure": [
        "13.64.0.0/11", "20.33.0.0/16", "20.38.98.0/24", # Example subset
        "40.64.0.0/10", "52.139.192.0/18", # More examples
        "104.40.0.0/13",
    ],
    "GCP": [
        "8.34.208.0/20", "35.184.0.0/13", "34.64.0.0/10", # Example subset
        "104.154.0.0/15", "104.196.0.0/14", # More examples
        "130.211.0.0/22",
    ],
    "Cloudflare": [
        "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18",
        "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
        "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
        "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
        # IPv6
        "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
        "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29",
        "2c0f:f248::/32"
    ],
    "Akamai": [
        # Akamai has a vast and dynamic range, these are just examples
        "2.16.0.0/16", "23.0.0.0/11", "23.64.0.0/14", "23.192.0.0/14",
        "95.100.0.0/15", "104.64.0.0/10", "184.24.0.0/13",
        "2600:1400::/24" # IPv6 example
    ],
    "Fastly": [
        "151.101.0.0/16", "151.101.64.0/18", "151.101.128.0/17",
        "151.101.192.0/18",
        "199.232.0.0/16", # Includes GitHub Pages often served via Fastly
        "2a04:4e42::/32" # IPv6 Example
    ],
    # Heroku IPs are mostly AWS EC2, so detecting via IP is less distinct
    # Usually detected via domain name (herokuapp.com)
}

CLOUD_DOMAIN_PATTERNS = {
    # Example structure: provider: [regex1, regex2, ...]
    "AWS": [
        r"\.amazonaws\.com$", 
        r"\.aws\.amazon\.com$", 
        r"\.cloudfront\.net$", # AWS CDN
        r"s3[.-][a-z0-9-]+\.amazonaws\.com$", # S3 bucket patterns
        r"elasticbeanstalk\.com$",
        r"elb\.amazonaws\.com$", # ELB
    ],
    "Azure": [
        r"\.azure\.com$", 
        r"\.windows\.net$", # Classic Azure Storage, etc.
        r"\.cloudapp\.net$", # Classic Cloud Services
        r"\.azurewebsites\.net$", # Azure App Service
        r"\.trafficmanager\.net$", # Azure Traffic Manager
        r"\.azure-api\.net$", # Azure API Management
    ],
    "GCP": [
        r"\.googleusercontent\.com$", 
        r"\.cloud\.google\.com$",
        r"\.appspot\.com$", # Google App Engine
        r"cloudfunctions\.net$", # Google Cloud Functions (newer URLs)
    ],
    "Cloudflare": [
        r"\.cloudflare\.com$", 
        r"\.cdn\.cloudflare\.net$",
        r"\.workers\.dev$", # Cloudflare Workers
    ],
    "Akamai": [
        r"\.akamai\.net$",
        r"\.akamaiedge\.net$",
        r"\.akamaized\.net$",
    ],
    "Fastly": [
        r"\.fastly\.net$",
        r"\.fastlylb\.net$",
    ],
    "Heroku": [
        r"\.herokuapp\.com$",
    ]
    # Add more providers and patterns as needed
}

# --- Cloud Data Initialization (using netaddr) ---
_CLOUD_IP_SETS_BY_PROVIDER: Dict[str, IPSet] = {}

def _initialize_cloud_ip_sets():
    """Builds IPSet objects for each cloud provider from KNOWN_CLOUD_RANGES."""
    global _CLOUD_IP_SETS_BY_PROVIDER
    if not NETADDR_AVAILABLE:
        logger.warning("netaddr library not found. Cannot perform efficient cloud detection from IP ranges.")
        return
        
    if _CLOUD_IP_SETS_BY_PROVIDER: # Avoid re-initialization
        return
        
    logger.info("Initializing Cloud IP Sets using netaddr...")
    temp_sets = {}
    for provider, cidr_list in KNOWN_CLOUD_RANGES.items():
        try:
            # Validate and filter CIDRs before creating the IPSet
            valid_cidrs = []
            for cidr in cidr_list:
                try:
                    # Basic validation with IPNetwork
                    IPNetwork(cidr)
                    valid_cidrs.append(cidr)
                except (AddrFormatError, ValueError, TypeError) as e:
                    logger.error(f"Invalid CIDR format '{cidr}' found for provider '{provider}'. Skipping. Error: {e}")
                    
            if valid_cidrs:
                temp_sets[provider] = IPSet(valid_cidrs)
                logger.debug(f"Created IPSet for {provider} with {len(valid_cidrs)} ranges.")
            else:
                 logger.warning(f"No valid CIDRs found for provider {provider}, skipping IPSet creation.")
                 
        except Exception as e:
            logger.exception(f"Unexpected error initializing IPSet for provider '{provider}': {e}")
            
    _CLOUD_IP_SETS_BY_PROVIDER = temp_sets
    logger.info(f"Initialized Cloud IP Sets for {len(_CLOUD_IP_SETS_BY_PROVIDER)} providers.")

# Initialize on module load
_initialize_cloud_ip_sets()

# --- Cloud Detection Functions ---

def detect_cloud_from_ips(ip_ranges: Set[IPRange], result: ReconnaissanceResult):
    """Detect cloud services based on known IP ranges using netaddr and add to result."""
    if not NETADDR_AVAILABLE:
        result.add_warning("Cloud Detection: netaddr library not available, cannot perform IP range detection.")
        return
        
    if not _CLOUD_IP_SETS_BY_PROVIDER:
        result.add_warning("Cloud Detection: Cloud IP Sets are not initialized or empty.")
        return

    logger.info(f"Checking {len(ip_ranges)} discovered IP ranges against known cloud provider ranges using netaddr...")
    found_count = 0
    
    for ipr in ip_ranges:
        ip_network_to_check = None
        try:
            # Create an IPNetwork object for the discovered range
            ip_network_to_check = IPNetwork(ipr.cidr)
        except (AddrFormatError, ValueError, TypeError) as e:
            warning_msg = f"Skipping invalid discovered CIDR for cloud check: {ipr.cidr}. Error: {e}"
            logger.warning(warning_msg)
            result.add_warning(f"Cloud Detection: {warning_msg}")
            continue
        except Exception as e:
             warning_msg = f"Unexpected error parsing IP range {ipr.cidr} for cloud check: {e}"
             logger.exception(warning_msg) # Log traceback
             result.add_warning(f"Cloud Detection: {warning_msg}")
             continue

        found_provider = None
        try:
            # Check for intersection against each provider's IPSet
            for provider, cloud_set in _CLOUD_IP_SETS_BY_PROVIDER.items():
                # Check if the discovered network intersects with the cloud provider's set
                # Convert the single IPNetwork to an IPSet before intersection
                if cloud_set.intersection(IPSet([ip_network_to_check])):
                    found_provider = provider
                    logger.debug(f"Found cloud match for {ipr.cidr} via netaddr IPSet: {provider}")
                    # Add the result and break if we only want the first match
                    result.add_cloud_service(CloudService(
                        provider=found_provider,
                        identifier=ipr.cidr,
                        resource_type="IP Range",
                        data_source="IPRangeMatch (netaddr)"
                    ))
                    found_count += 1
                    break # Stop checking providers for this IP range once a match is found
                    
        except Exception as e:
            # Catch errors during the intersection check itself
            warning_msg = f"Error checking intersection for IP range {ipr.cidr} against cloud sets: {e}"
            logger.exception(warning_msg)
            result.add_warning(f"Cloud Detection: {warning_msg}")
            # Continue to the next IP range
            continue

    logger.info(f"Finished cloud IP detection using netaddr. Found {found_count} matches.")

# --- Domain-based Detection (Remains Largely Unchanged) ---
def detect_cloud_from_domains(domains: Set[Domain], result: ReconnaissanceResult):
    """Detect cloud services based on domain patterns and add to result."""
    logger.info(f"Checking {len(domains)} domains and their subdomains against known cloud domain patterns...")
    compiled_patterns: Dict[str, list] = {}
    found_count = 0
    
    # Compile regex patterns only once
    for provider, patterns in CLOUD_DOMAIN_PATTERNS.items():
        try:
            compiled_patterns[provider] = [re.compile(p, re.IGNORECASE) for p in patterns]
        except re.error as e:
            warning_msg = f"Invalid regex pattern for {provider}: '{e.pattern}'. Error: {e}. Skipping provider."
            logger.error(warning_msg)
            result.add_warning(f"Cloud Detection: {warning_msg}")
            continue
            
    if not compiled_patterns:
        warning_msg = "No valid cloud domain regex patterns were compiled."
        logger.error(warning_msg)
        result.add_warning(f"Cloud Detection: {warning_msg}")
        return

    # Gather all FQDNs to check
    fqdns_to_check = set()
    for domain in domains:
        if domain.name: # Check domain name is not None/empty
             fqdns_to_check.add(domain.name)
        for sub in domain.subdomains:
            # Check if sub is a Subdomain object and has a non-empty fqdn
            # Access sub.fqdn instead of sub.name
            if isinstance(sub, Subdomain) and sub.fqdn:
                 fqdns_to_check.add(sub.fqdn)
            
    logger.info(f"Checking {len(fqdns_to_check)} unique FQDNs against cloud patterns...")
    
    # Check each FQDN against compiled patterns
    for fqdn in fqdns_to_check:
        if not fqdn: continue # Skip empty names
        
        found_provider = None
        for provider, regex_list in compiled_patterns.items():
            for pattern in regex_list:
                if pattern.search(fqdn):
                    found_provider = provider
                    logger.debug(f"Found cloud match for {fqdn} via domain pattern: {provider} ({pattern.pattern})")
                    # Add the result and break inner loops if only first match is needed
                    result.add_cloud_service(CloudService(
                        provider=found_provider,
                        identifier=fqdn,
                        resource_type="Domain",
                        data_source="DomainPatternMatch"
                    ))
                    found_count += 1
                    break # Stop checking patterns for this provider
            if found_provider:
                break # Stop checking providers for this FQDN
                
    logger.info(f"Finished cloud domain detection. Found {found_count} matches.")

# Example usage (for testing) - Requires adaptation if run directly
# if __name__ == '__main__':
#     import sys
#     sys.path.insert(0, sys.path[0] + '/../..') 
#     from src.utils.logging_config import setup_logging
#     setup_logging(logging.DEBUG)
#     
#     # Create dummy data for testing
#     test_result = ReconnaissanceResult("Test Org")
#     test_result.add_ip_range(IPRange(cidr="52.93.178.234/32", data_source="Test")) # AWS
#     test_result.add_ip_range(IPRange(cidr="20.38.98.10/32", data_source="Test")) # Azure
#     test_result.add_ip_range(IPRange(cidr="192.168.1.1/32", data_source="Test")) # Private
#     test_result.add_ip_range(IPRange(cidr="151.101.1.69/32", data_source="Test")) # Fastly
#     
#     test_domain = Domain(name="my-app.herokuapp.com")
#     test_domain.add_subdomain(Subdomain(name="assets.my-app.herokuapp.com"))
#     test_domain_aws = Domain(name="mybucket.s3.eu-west-1.amazonaws.com")
#     
#     test_result.add_domain(test_domain)
#     test_result.add_domain(test_domain_aws)
# 
#     print("--- Testing IP Detection ---")
#     detect_cloud_from_ips(test_result.ip_ranges, test_result)
#     
#     print("--- Testing Domain Detection ---")
#     detect_cloud_from_domains(test_result.domains, test_result)
#     
#     print("\n--- Final Cloud Results ---")
#     for svc in test_result.cloud_services:
#         print(svc)
#     
#     print("\n--- Warnings ---")
#     for warn in test_result.warnings:
#         print(warn)