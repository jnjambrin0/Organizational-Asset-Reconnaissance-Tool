"""Tests for core data models and result container."""

import pytest

# Add project root to allow imports
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

from src.core.models import ASN, IPRange, Domain, Subdomain, CloudService, ReconnaissanceResult

# --- Basic Model Tests (Hashing, Equality) --- 

def test_asn_equality_hash():
    asn1a = ASN(number=123, name="Test")
    asn1b = ASN(number=123, name="Different Name") # Equality based on number only
    asn2 = ASN(number=456)
    assert asn1a == asn1b
    assert asn1a != asn2
    assert hash(asn1a) == hash(asn1b)
    assert hash(asn1a) != hash(asn2)
    s = {asn1a, asn1b, asn2}
    assert len(s) == 2

def test_iprange_equality_hash():
    ip1a = IPRange(cidr="192.0.2.0/24", version=4)
    ip1b = IPRange(cidr="192.0.2.0/24", version=4, country="US") # Equality based on cidr only
    ip2 = IPRange(cidr="192.0.2.1/32", version=4)
    ip3 = IPRange(cidr="2001:db8::/32", version=6)
    assert ip1a == ip1b
    assert ip1a != ip2
    assert ip1a != ip3
    assert hash(ip1a) == hash(ip1b)
    assert hash(ip1a) != hash(ip2)
    s = {ip1a, ip1b, ip2, ip3}
    assert len(s) == 3

def test_subdomain_equality_hash():
    sub1a = Subdomain(fqdn="www.example.com")
    sub1b = Subdomain(fqdn="www.example.com", status="Active") # Equality based on fqdn only
    sub2 = Subdomain(fqdn="mail.example.com")
    assert sub1a == sub1b
    assert sub1a != sub2
    assert hash(sub1a) == hash(sub1b)
    assert hash(sub1a) != hash(sub2)
    s = {sub1a, sub1b, sub2}
    assert len(s) == 2

def test_domain_equality_hash():
    dom1a = Domain(name="example.com")
    dom1b = Domain(name="example.com", registrar="GoDaddy") # Equality based on name only
    dom2 = Domain(name="example.org")
    assert dom1a == dom1b
    assert dom1a != dom2
    assert hash(dom1a) == hash(dom1b)
    assert hash(dom1a) != hash(dom2)
    s = {dom1a, dom1b, dom2}
    assert len(s) == 2

def test_cloudservice_equality_hash():
    cs1a = CloudService(provider="AWS", identifier="1.2.3.4")
    cs1b = CloudService(provider="AWS", identifier="1.2.3.4", resource_type="IP") # Equality on provider, identifier
    cs2 = CloudService(provider="AWS", identifier="5.6.7.8")
    cs3 = CloudService(provider="GCP", identifier="1.2.3.4")
    assert cs1a == cs1b
    assert cs1a != cs2
    assert cs1a != cs3
    assert hash(cs1a) == hash(cs1b)
    assert hash(cs1a) != hash(cs2)
    assert hash(cs1a) != hash(cs3)
    s = {cs1a, cs1b, cs2, cs3}
    assert len(s) == 3

# --- ReconnaissanceResult Tests --- 

@pytest.fixture
def empty_result():
    return ReconnaissanceResult(target_organization="Test Org")

def test_recon_result_init(empty_result):
    assert empty_result.target_organization == "Test Org"
    assert len(empty_result.asns) == 0
    assert len(empty_result.ip_ranges) == 0
    assert len(empty_result.domains) == 0
    assert len(empty_result.cloud_services) == 0

def test_recon_result_add_asn(empty_result):
    asn1 = ASN(number=1) 
    asn2 = ASN(number=1) # Duplicate
    asn3 = ASN(number=2)
    empty_result.add_asn(asn1)
    empty_result.add_asn(asn2)
    empty_result.add_asn(asn3)
    assert len(empty_result.asns) == 2
    assert asn1 in empty_result.asns
    assert asn3 in empty_result.asns

def test_recon_result_add_ip_range(empty_result):
    ip1 = IPRange(cidr="1.1.1.0/24", version=4)
    ip2 = IPRange(cidr="1.1.1.0/24", version=4) # Duplicate
    ip3 = IPRange(cidr="2.2.2.0/24", version=4)
    empty_result.add_ip_range(ip1)
    empty_result.add_ip_range(ip2)
    empty_result.add_ip_range(ip3)
    assert len(empty_result.ip_ranges) == 2
    assert ip1 in empty_result.ip_ranges
    assert ip3 in empty_result.ip_ranges

def test_recon_result_add_domain_new(empty_result):
    dom1 = Domain(name="a.com")
    empty_result.add_domain(dom1)
    assert len(empty_result.domains) == 1
    assert dom1 in empty_result.domains

def test_recon_result_add_domain_existing_merge_subs(empty_result):
    sub1 = Subdomain(fqdn="www.a.com")
    sub2 = Subdomain(fqdn="mail.a.com")
    dom1_part1 = Domain(name="a.com", subdomains={sub1})
    dom1_part2 = Domain(name="a.com", subdomains={sub2})
    
    empty_result.add_domain(dom1_part1)
    assert len(empty_result.domains) == 1
    assert len(empty_result.domains.copy().pop().subdomains) == 1
    
    empty_result.add_domain(dom1_part2) # Add domain with same name again
    assert len(empty_result.domains) == 1 # Should not add a duplicate domain
    # Subdomains should be merged
    merged_domain = empty_result.domains.copy().pop()
    assert len(merged_domain.subdomains) == 2 
    assert sub1 in merged_domain.subdomains
    assert sub2 in merged_domain.subdomains

def test_recon_result_add_subdomain_new_parent(empty_result):
    sub1 = Subdomain(fqdn="www.b.com")
    empty_result.add_subdomain("b.com", sub1)
    assert len(empty_result.domains) == 1
    parent = empty_result.domains.copy().pop()
    assert parent.name == "b.com"
    assert len(parent.subdomains) == 1
    assert sub1 in parent.subdomains

def test_recon_result_add_subdomain_existing_parent(empty_result):
    dom_b = Domain(name="b.com")
    empty_result.add_domain(dom_b)
    sub1 = Subdomain(fqdn="www.b.com")
    sub2 = Subdomain(fqdn="api.b.com")
    empty_result.add_subdomain("b.com", sub1)
    empty_result.add_subdomain("b.com", sub2)
    assert len(empty_result.domains) == 1
    parent = empty_result.domains.copy().pop()
    assert len(parent.subdomains) == 2
    assert sub1 in parent.subdomains
    assert sub2 in parent.subdomains

def test_recon_result_add_cloud_service(empty_result):
    cs1 = CloudService(provider="A", identifier="1")
    cs2 = CloudService(provider="A", identifier="1") # Duplicate
    cs3 = CloudService(provider="B", identifier="2")
    empty_result.add_cloud_service(cs1)
    empty_result.add_cloud_service(cs2)
    empty_result.add_cloud_service(cs3)
    assert len(empty_result.cloud_services) == 2
    assert cs1 in empty_result.cloud_services
    assert cs3 in empty_result.cloud_services

def test_recon_result_get_all_subdomains(empty_result):
    dom_a = Domain(name="a.com", subdomains={Subdomain(fqdn="w.a.com"), Subdomain(fqdn="m.a.com")})
    dom_b = Domain(name="b.com", subdomains={Subdomain(fqdn="w.b.com")})
    dom_c = Domain(name="c.com") # No subdomains
    empty_result.add_domain(dom_a)
    empty_result.add_domain(dom_b)
    empty_result.add_domain(dom_c)
    all_subs = empty_result.get_all_subdomains()
    assert len(all_subs) == 3
    assert Subdomain(fqdn="w.a.com") in all_subs
    assert Subdomain(fqdn="m.a.com") in all_subs
    assert Subdomain(fqdn="w.b.com") in all_subs

def test_recon_result_get_all_subdomains_empty():
    result = ReconnaissanceResult(target_organization="E")
    assert len(result.get_all_subdomains()) == 0 