"""Module for formatting and exporting discovered data.
Author: jnjambrino
"""

import logging
import csv
import io
from typing import Set, List, Dict, Any

from src.core.models import ReconnaissanceResult, ASN, IPRange, Domain, Subdomain, CloudService

logger = logging.getLogger(__name__)

def _get_csv_safe_string(value: Any) -> str:
    """Convert value to string, handling None and ensuring basic safety for CSV."""
    if value is None:
        return ""
    # Basic handling: coerce to string. More complex quoting/escaping might be needed
    # depending on the csv writer settings and data complexity.
    return str(value)

def format_results_to_csv(result: ReconnaissanceResult) -> Dict[str, str]:
    """Formats the reconnaissance results into multiple CSV strings, one per asset type.

    Args:
        result: The ReconnaissanceResult object.

    Returns:
        A dictionary where keys are asset types (e.g., 'asns', 'ip_ranges') 
        and values are CSV data as strings.
    """
    csv_outputs: Dict[str, str] = {}
    logger.info(f"Formatting results for {result.target_organization} into CSV...")

    # --- ASNs --- 
    if result.asns:
        logger.debug(f"Formatting {len(result.asns)} ASNs to CSV.")
        output = io.StringIO()
        writer = csv.writer(output)
        # Define header based on ASN model fields in PRD
        header = ['ASN Number', 'Name', 'Description', 'Country', 'Data Source']
        writer.writerow(header)
        for asn in sorted(list(result.asns), key=lambda x: x.number):
            writer.writerow([
                _get_csv_safe_string(asn.number),
                _get_csv_safe_string(asn.name),
                _get_csv_safe_string(asn.description),
                _get_csv_safe_string(asn.country),
                _get_csv_safe_string(asn.data_source)
            ])
        csv_outputs['asns'] = output.getvalue()
        output.close()

    # --- IP Ranges --- 
    if result.ip_ranges:
        logger.debug(f"Formatting {len(result.ip_ranges)} IP Ranges to CSV.")
        output = io.StringIO()
        writer = csv.writer(output)
        # Define header based on IPRange model fields in PRD
        header = ['CIDR', 'Version', 'Associated ASN', 'Country', 'Data Source']
        writer.writerow(header)
        # Sort for consistent output (optional, depends on desired order)
        # Sorting by network address requires ipaddress library
        try:
             import ipaddress
             sorted_ranges = sorted(list(result.ip_ranges), key=lambda x: (x.version, ipaddress.ip_network(x.cidr)))
        except ImportError:
             sorted_ranges = sorted(list(result.ip_ranges), key=lambda x: (x.version, x.cidr))

        for ipr in sorted_ranges:
            writer.writerow([
                _get_csv_safe_string(ipr.cidr),
                _get_csv_safe_string(ipr.version),
                _get_csv_safe_string(f"AS{ipr.asn.number}" if ipr.asn else None),
                _get_csv_safe_string(ipr.country), 
                _get_csv_safe_string(ipr.data_source)
            ])
        csv_outputs['ip_ranges'] = output.getvalue()
        output.close()

    # --- Domains --- 
    if result.domains:
        logger.debug(f"Formatting {len(result.domains)} Domains to CSV.")
        output = io.StringIO()
        writer = csv.writer(output)
        # Define header based on Domain model fields in PRD
        header = ['Domain Name', 'Registrar', 'Associated IPs', 'Subdomain Count', 'Data Source']
        writer.writerow(header)
        for dom in sorted(list(result.domains), key=lambda x: x.name):
            writer.writerow([
                _get_csv_safe_string(dom.name),
                _get_csv_safe_string(dom.registrar),
                _get_csv_safe_string(", ".join(sorted(list(dom.resolved_ips)))), # Join IPs
                _get_csv_safe_string(len(dom.subdomains)),
                _get_csv_safe_string(dom.data_source)
            ])
        csv_outputs['domains'] = output.getvalue()
        output.close()

    # --- Subdomains --- 
    all_subdomains = result.get_all_subdomains()
    if all_subdomains:
        logger.debug(f"Formatting {len(all_subdomains)} Subdomains to CSV.")
        output = io.StringIO()
        writer = csv.writer(output)
        # Define header based on Subdomain model fields in PRD
        header = ['Subdomain FQDN', 'Status', 'Resolved IPs', 'Data Source']
        writer.writerow(header)
        for sub in sorted(list(all_subdomains), key=lambda x: x.fqdn):
            writer.writerow([
                _get_csv_safe_string(sub.fqdn),
                _get_csv_safe_string(sub.status),
                _get_csv_safe_string(", ".join(sorted(list(sub.resolved_ips)))),
                _get_csv_safe_string(sub.data_source)
            ])
        csv_outputs['subdomains'] = output.getvalue()
        output.close()

    # --- Cloud Services --- 
    if result.cloud_services:
        logger.debug(f"Formatting {len(result.cloud_services)} Cloud Services to CSV.")
        output = io.StringIO()
        writer = csv.writer(output)
        header = ['Provider', 'Resource Type', 'Identifier', 'Data Source']
        writer.writerow(header)
        for svc in sorted(list(result.cloud_services), key=lambda x: (x.provider, x.identifier)):
             writer.writerow([
                 _get_csv_safe_string(svc.provider),
                 _get_csv_safe_string(svc.resource_type),
                 _get_csv_safe_string(svc.identifier),
                 _get_csv_safe_string(svc.data_source)
             ])
        csv_outputs['cloud_services'] = output.getvalue()
        output.close()

    logger.info("Finished formatting results to CSV.")
    return csv_outputs

def format_results_to_text(result: ReconnaissanceResult) -> str:
    """Formats the reconnaissance results into a simple plain text summary.

    Args:
        result: The ReconnaissanceResult object.

    Returns:
        A string containing the plain text report.
    """
    logger.info(f"Formatting results for {result.target_organization} into Plain Text...")
    output = io.StringIO()

    output.write(f"# Reconnaissance Report for: {result.target_organization}\n\n")

    # --- ASNs ---
    output.write(f"## Autonomous Systems (ASNs) ({len(result.asns)} found)\n")
    if result.asns:
        for asn in sorted(list(result.asns), key=lambda x: x.number):
            output.write(f"- AS{asn.number}: {asn.name or 'N/A'} ({asn.description or 'N/A'}) [Source: {asn.data_source or 'N/A'}]\n")
    else:
        output.write("- None discovered.\n")
    output.write("\n")

    # --- IP Ranges ---
    output.write(f"## IP Ranges ({len(result.ip_ranges)} found)\n")
    if result.ip_ranges:
        try:
             import ipaddress
             sorted_ranges = sorted(list(result.ip_ranges), key=lambda x: (x.version, ipaddress.ip_network(x.cidr)))
        except ImportError:
             sorted_ranges = sorted(list(result.ip_ranges), key=lambda x: (x.version, x.cidr))
        for ipr in sorted_ranges:
            asn_str = f" (AS{ipr.asn.number})" if ipr.asn else ""
            output.write(f"- {ipr.cidr} (v{ipr.version}){asn_str} [Country: {ipr.country or 'N/A'}, Source: {ipr.data_source or 'N/A'}]\n")
    else:
        output.write("- None discovered.\n")
    output.write("\n")

    # --- Domains & Subdomains ---
    output.write(f"## Domains ({len(result.domains)} found)\n")
    if result.domains:
        for dom in sorted(list(result.domains), key=lambda x: x.name):
            output.write(f"### {dom.name} [Source: {dom.data_source or 'N/A'}]\n")
            subdomains = sorted(list(dom.subdomains), key=lambda s: s.fqdn)
            if subdomains:
                 output.write("  Subdomains:\n")
                 for sub in subdomains:
                     status_str = f" (Status: {sub.status})" if sub.status else ""
                     ips_str = f" -> [{ ', '.join(sorted(list(sub.resolved_ips))) }]" if sub.resolved_ips else ""
                     output.write(f"  - {sub.fqdn}{status_str}{ips_str} [Source: {sub.data_source or 'N/A'}]\n")
            else:
                output.write("  - No subdomains discovered for this domain.\n")
    else:
         output.write("- None discovered.\n")
    output.write("\n")

    # --- Cloud Services ---
    output.write(f"## Cloud Services ({len(result.cloud_services)} found)\n")
    if result.cloud_services:
        for svc in sorted(list(result.cloud_services), key=lambda x: (x.provider, x.identifier)):
             output.write(f"- {svc.provider}: {svc.identifier} ({svc.resource_type or 'N/A'}) [Source: {svc.data_source or 'N/A'}]\n")
    else:
         output.write("- None discovered.\n")
    output.write("\n")

    logger.info("Finished formatting results to Plain Text.")
    report_content = output.getvalue()
    output.close()
    return report_content

# Example Usage (for testing)
if __name__ == '__main__':
    import sys
    sys.path.insert(0, sys.path[0] + '/../..')
    from src.utils.logging_config import setup_logging
    from src.orchestration.discovery_orchestrator import run_discovery # Use orchestrator to get results
    setup_logging(logging.INFO)

    target = "Example Corp" # Use a simple target for testing formatting
    # Create some dummy data
    dummy_result = ReconnaissanceResult(target_organization=target)
    asn1 = ASN(number=123, name="Dummy ASN 1", description="Desc 1", data_source="Test")
    dummy_result.add_asn(asn1)
    dummy_result.add_asn(ASN(number=456, name="Dummy ASN 2", data_source="Test"))
    dummy_result.add_ip_range(IPRange(cidr="192.0.2.0/28", version=4, asn=asn1, country="US", data_source="TestIP"))
    dummy_result.add_ip_range(IPRange(cidr="2001:db8::/120", version=6, asn=asn1, data_source="TestIP"))
    domain1 = Domain(name="example.com", data_source="Input")
    domain1.subdomains.add(Subdomain(fqdn="www.example.com", status="Active", resolved_ips={"192.0.2.1"}, data_source="TestSub"))
    domain1.subdomains.add(Subdomain(fqdn="mail.example.com", status="Inactive", data_source="TestSub"))
    dummy_result.add_domain(domain1)
    dummy_result.add_domain(Domain(name="example.org", data_source="Discovered"))
    dummy_result.add_cloud_service(CloudService(provider="AWS", identifier="s3.amazon.com", resource_type="Domain", data_source="TestCloud"))

    # Test CSV Formatting
    csv_data = format_results_to_csv(dummy_result)
    print("--- CSV Output ---")
    for asset_type, csv_string in csv_data.items():
        print(f"\n** {asset_type.upper()}.csv **\n")
        print(csv_string)
        
    # Test Text Formatting
    text_report = format_results_to_text(dummy_result)
    print("\n--- Text Report ---")
    print(text_report) 