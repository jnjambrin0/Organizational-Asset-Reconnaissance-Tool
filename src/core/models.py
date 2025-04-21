from dataclasses import dataclass, field
from typing import List, Optional, Set
from datetime import datetime
import json

@dataclass(frozen=True)
class ASN:
    number: int
    name: Optional[str] = None
    description: Optional[str] = None
    country: Optional[str] = None # Added based on IP Range needs
    data_source: Optional[str] = None

    def __hash__(self):
        return hash(self.number)

    def __eq__(self, other):
        if not isinstance(other, ASN):
            return NotImplemented
        return self.number == other.number

@dataclass(frozen=True)
class IPRange:
    cidr: str
    version: int # 4 or 6
    asn: Optional[ASN] = None
    country: Optional[str] = None
    data_source: Optional[str] = None

    def __hash__(self):
        return hash(self.cidr)

    def __eq__(self, other):
        if not isinstance(other, IPRange):
            return NotImplemented
        return self.cidr == other.cidr


@dataclass(frozen=True, eq=True)
class Subdomain:
    """Represents a discovered subdomain."""
    fqdn: str
    status: str = "unknown" # e.g., active, inactive, unknown
    resolved_ips: Optional[Set[str]] = field(default_factory=set)
    data_source: Optional[str] = None
    last_checked: Optional[datetime] = None

    def __str__(self):
        ips_str = ', '.join(sorted(self.resolved_ips)) if self.resolved_ips else ""
        ips = f"({ips_str})" if ips_str else ""
        return f"{self.fqdn} [{self.status}] {ips}"

    def __hash__(self):
        return hash(self.fqdn)

    def __eq__(self, other):
        if not isinstance(other, Subdomain):
            return NotImplemented
        return self.fqdn == other.fqdn

@dataclass(frozen=True)
class Domain:
    name: str
    registrar: Optional[str] = None
    creation_date: Optional[datetime] = None
    subdomains: Set[Subdomain] = field(default_factory=set)
    data_source: Optional[str] = None

    def __hash__(self):
        return hash(self.name)

    def __eq__(self, other):
        if not isinstance(other, Domain):
            return NotImplemented
        return self.name == other.name

@dataclass(frozen=True)
class CloudService:
    provider: str
    identifier: str # IP or domain associated
    resource_type: Optional[str] = None
    region: Optional[str] = None # Added region attribute
    status: Optional[str] = None # Added status attribute for consistency
    data_source: Optional[str] = None

    def __hash__(self):
        return hash((self.provider, self.identifier))

    def __eq__(self, other):
        if not isinstance(other, CloudService):
            return NotImplemented
        return (self.provider, self.identifier) == (other.provider, other.identifier)

# Container for all discovered assets for a given target
@dataclass
class ReconnaissanceResult:
    target_organization: str
    asns: Set[ASN] = field(default_factory=set)
    ip_ranges: Set[IPRange] = field(default_factory=set)
    domains: Set[Domain] = field(default_factory=set)
    # Subdomains are stored within Domain objects
    cloud_services: Set[CloudService] = field(default_factory=set)
    warnings: List[str] = field(default_factory=list) # Add warnings list

    def add_asn(self, asn: ASN):
        self.asns.add(asn)

    def add_ip_range(self, ip_range: IPRange):
        self.ip_ranges.add(ip_range)

    def add_domain(self, domain: Domain):
        # Check if domain already exists and merge subdomains if necessary
        existing_domain = next((d for d in self.domains if d.name == domain.name), None)
        if existing_domain:
            existing_domain.subdomains.update(domain.subdomains)
            # Optionally update registrar/IPs if new info is better? Needs logic.
        else:
            self.domains.add(domain)

    def add_subdomain(self, parent_domain_name: str, subdomain: Subdomain):
        # Find the parent domain or create it if it doesn't exist
        parent_domain = next((d for d in self.domains if d.name == parent_domain_name), None)
        if not parent_domain:
            parent_domain = Domain(name=parent_domain_name)
            self.domains.add(parent_domain)
        parent_domain.subdomains.add(subdomain)

    def add_cloud_service(self, service: CloudService):
        self.cloud_services.add(service)

    def add_warning(self, message: str):
        """Adds a warning message to the result."""
        # Avoid duplicate warnings
        if message not in self.warnings:
             self.warnings.append(message)

    def get_all_subdomains(self) -> Set[Subdomain]:
        all_subs = set()
        for domain in self.domains:
            all_subs.update(domain.subdomains)
        return all_subs 