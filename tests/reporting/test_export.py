"""Tests for the data export formatting functions."""

import pytest
import csv
import io

# Add project root to allow imports
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

from src.reporting import export
from src.core.models import ReconnaissanceResult, ASN, IPRange, Domain, Subdomain, CloudService

@pytest.fixture
def sample_result():
    """Provides a sample ReconnaissanceResult with diverse data."""
    result = ReconnaissanceResult(target_organization="Test Corp, Inc.")
    asn1 = ASN(number=100, name="ASN One", description="First ASN", country="US", data_source="SourceA")
    asn2 = ASN(number=200, name=None, description="Second ASN", data_source="SourceB")
    result.add_asn(asn1)
    result.add_asn(asn2)
    
    result.add_ip_range(IPRange(cidr="10.0.0.0/24", version=4, asn=asn1, country="US", data_source="SourceC"))
    result.add_ip_range(IPRange(cidr="2001:db8:1::/48", version=6, asn=None, country="CA", data_source="SourceD"))
    result.add_ip_range(IPRange(cidr="10.0.1.0/24", version=4, asn=asn2, data_source="SourceC"))
    
    dom1 = Domain(name="company.com", registrar="Reg Inc.", data_source="SourceE")
    dom1.subdomains.add(Subdomain(fqdn="www.company.com", status="Active", resolved_ips={"10.0.0.1", "10.0.0.2"}, data_source="SourceF"))
    dom1.subdomains.add(Subdomain(fqdn="mail.company.com", status="Inactive", data_source="SourceG"))
    dom1.resolved_ips = {"10.0.0.1"}
    result.add_domain(dom1)
    result.add_domain(Domain(name="other.net", data_source="SourceH")) # Domain with no subs
    
    result.add_cloud_service(CloudService(provider="AWS", identifier="www.company.com", resource_type="Domain", data_source="SourceI"))
    result.add_cloud_service(CloudService(provider="Azure", identifier="10.0.1.5", resource_type="IP", data_source="SourceJ"))
    return result

# --- Tests for format_results_to_csv --- 

def test_format_csv_asns(sample_result):
    csv_data = export.format_results_to_csv(sample_result)
    assert 'asns' in csv_data
    reader = csv.reader(io.StringIO(csv_data['asns']))
    rows = list(reader)
    assert len(rows) == 3 # Header + 2 ASNs
    assert rows[0] == ['ASN Number', 'Name', 'Description', 'Country', 'Data Source']
    assert rows[1] == ['100', 'ASN One', 'First ASN', 'US', 'SourceA']
    assert rows[2] == ['200', '', 'Second ASN', '', 'SourceB'] # Check None handling

def test_format_csv_ip_ranges(sample_result):
    csv_data = export.format_results_to_csv(sample_result)
    assert 'ip_ranges' in csv_data
    reader = csv.reader(io.StringIO(csv_data['ip_ranges']))
    rows = list(reader)
    assert len(rows) == 4 # Header + 3 IPs
    assert rows[0] == ['CIDR', 'Version', 'Associated ASN', 'Country', 'Data Source']
    # Order depends on sorting, assuming v4 then v6, then by network addr
    assert rows[1] == ['10.0.0.0/24', '4', 'AS100', 'US', 'SourceC'] 
    assert rows[2] == ['10.0.1.0/24', '4', 'AS200', '', 'SourceC'] 
    assert rows[3] == ['2001:db8:1::/48', '6', '', 'CA', 'SourceD'] # Check None ASN

def test_format_csv_domains(sample_result):
    csv_data = export.format_results_to_csv(sample_result)
    assert 'domains' in csv_data
    reader = csv.reader(io.StringIO(csv_data['domains']))
    rows = list(reader)
    assert len(rows) == 3 # Header + 2 Domains
    assert rows[0] == ['Domain Name', 'Registrar', 'Associated IPs', 'Subdomain Count', 'Data Source']
    assert rows[1] == ['company.com', 'Reg Inc.', '10.0.0.1', '2', 'SourceE'] # Check IP joining
    assert rows[2] == ['other.net', '', '', '0', 'SourceH']

def test_format_csv_subdomains(sample_result):
    csv_data = export.format_results_to_csv(sample_result)
    assert 'subdomains' in csv_data
    reader = csv.reader(io.StringIO(csv_data['subdomains']))
    rows = list(reader)
    assert len(rows) == 3 # Header + 2 Subdomains
    assert rows[0] == ['Subdomain FQDN', 'Status', 'Resolved IPs', 'Data Source']
    assert rows[1] == ['mail.company.com', 'Inactive', '', 'SourceG'] # Sorted alphabetically
    assert rows[2] == ['www.company.com', 'Active', '10.0.0.1, 10.0.0.2', 'SourceF'] # Check IP joining

def test_format_csv_cloud_services(sample_result):
    csv_data = export.format_results_to_csv(sample_result)
    assert 'cloud_services' in csv_data
    reader = csv.reader(io.StringIO(csv_data['cloud_services']))
    rows = list(reader)
    assert len(rows) == 3 # Header + 2 Services
    assert rows[0] == ['Provider', 'Resource Type', 'Identifier', 'Data Source']
    # Sorted by provider, then identifier
    assert rows[1] == ['AWS', 'Domain', 'www.company.com', 'SourceI']
    assert rows[2] == ['Azure', 'IP', '10.0.1.5', 'SourceJ']

def test_format_csv_empty_results():
    empty = ReconnaissanceResult(target_organization="Empty")
    csv_data = export.format_results_to_csv(empty)
    assert len(csv_data) == 0 # No keys if no data for that type

# --- Tests for format_results_to_text --- 

def test_format_text(sample_result):
    text_report = export.format_results_to_text(sample_result)
    assert "# Reconnaissance Report for: Test Corp, Inc." in text_report
    # Check ASN section
    assert "## Autonomous Systems (ASNs) (2 found)" in text_report
    assert "- AS100: ASN One (First ASN) [Source: SourceA]" in text_report
    assert "- AS200: N/A (Second ASN) [Source: SourceB]" in text_report # Check None name
    # Check IP Range section
    assert "## IP Ranges (3 found)" in text_report
    assert "- 10.0.0.0/24 (v4) (AS100) [Country: US, Source: SourceC]" in text_report
    assert "- 10.0.1.0/24 (v4) (AS200) [Country: N/A, Source: SourceC]" in text_report # Check None country
    assert "- 2001:db8:1::/48 (v6) [Country: CA, Source: SourceD]" in text_report # Check None ASN
    # Check Domain section
    assert "## Domains (2 found)" in text_report
    assert "### company.com [Source: SourceE]" in text_report
    assert "  - mail.company.com (Status: Inactive) [Source: SourceG]" in text_report
    assert "  - www.company.com (Status: Active) -> [10.0.0.1, 10.0.0.2] [Source: SourceF]" in text_report # Check IPs
    assert "### other.net [Source: SourceH]" in text_report
    assert "  - No subdomains discovered for this domain." in text_report
    # Check Cloud section
    assert "## Cloud Services (2 found)" in text_report
    assert "- AWS: www.company.com (Domain) [Source: SourceI]" in text_report
    assert "- Azure: 10.0.1.5 (IP) [Source: SourceJ]" in text_report

def test_format_text_empty_results():
    empty = ReconnaissanceResult(target_organization="Empty")
    text_report = export.format_results_to_text(empty)
    assert "# Reconnaissance Report for: Empty" in text_report
    assert "(0 found)" in text_report
    assert "- None discovered." in text_report 