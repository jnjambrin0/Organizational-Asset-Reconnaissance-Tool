"""
Discovery Validators

Validation utilities for discovery candidates and results.
"""

import re
import socket
import ipaddress
import logging
from typing import Optional, Set, List, Dict, Any
from abc import ABC, abstractmethod

from .types import DiscoveryCandidate
from .exceptions import ValidationError

logger = logging.getLogger(__name__)


class DiscoveryValidator:
    """Main validator class for discovery candidates."""

    def __init__(self):
        self.domain_validator = DomainValidator()
        self.ip_validator = IPValidator()
        self.asn_validator = ASNValidator()
        self.cloud_validator = CloudValidator()

    def validate_candidate(self, candidate: DiscoveryCandidate) -> bool:
        """
        Validate a discovery candidate based on its type.

        Returns:
            True if valid, False otherwise
        """
        try:
            validator_map = {
                "domain": self.domain_validator,
                "subdomain": self.domain_validator,
                "ip": self.ip_validator,
                "asn": self.asn_validator,
                "cloud": self.cloud_validator,
            }

            validator = validator_map.get(candidate.discovery_type.lower())
            if not validator:
                logger.warning(f"No validator for type: {candidate.discovery_type}")
                return True  # Allow unknown types by default

            return validator.validate(candidate.identifier)

        except Exception as e:
            logger.error(f"Validation error for {candidate.identifier}: {e}")
            return False


class BaseValidator(ABC):
    """Base class for specific validators."""

    @abstractmethod
    def validate(self, identifier: str) -> bool:
        """Validate an identifier."""
        pass


class DomainValidator(BaseValidator):
    """Validates domain names and subdomains."""

    def __init__(self):
        # RFC compliant domain validation
        self.domain_pattern = re.compile(
            r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
            r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
        )

        # Valid TLDs (simplified set)
        self.valid_tlds = {
            "com",
            "org",
            "net",
            "edu",
            "gov",
            "mil",
            "int",
            "co",
            "io",
            "me",
            "tv",
            "cc",
            "ly",
            "gg",
            "ac",
            "uk",
            "de",
            "fr",
            "jp",
            "cn",
            "au",
            "ca",
            "br",
            "es",
            "it",
            "ru",
            "in",
            "mx",
            "nl",
            "pl",
            "se",
        }

    def validate(self, domain: str) -> bool:
        """Validate a domain name."""
        if not domain or len(domain) > 253:
            return False

        domain = domain.lower().strip()

        # Basic pattern check
        if not self.domain_pattern.match(domain):
            return False

        # Check each label
        labels = domain.split(".")
        if len(labels) < 2:  # Must have at least domain.tld
            return False

        for label in labels:
            if not label or len(label) > 63:
                return False
            if label.startswith("-") or label.endswith("-"):
                return False

        # Check TLD
        tld = labels[-1]
        if len(tld) < 2 or not tld.isalpha():
            return False

        # Optional: check against known TLD list
        # For now, accept any valid TLD format

        return True

    def is_subdomain(self, domain: str) -> bool:
        """Check if domain is a subdomain (has more than 2 labels)."""
        if not self.validate(domain):
            return False
        return len(domain.split(".")) > 2


class IPValidator(BaseValidator):
    """Validates IP addresses and ranges."""

    def validate(self, ip_or_range: str) -> bool:
        """Validate an IP address or CIDR range."""
        try:
            # Try as IP address first
            ipaddress.ip_address(ip_or_range)
            return True
        except ValueError:
            pass

        try:
            # Try as CIDR range
            ipaddress.ip_network(ip_or_range, strict=False)
            return True
        except ValueError:
            return False

    def is_private(self, ip: str) -> bool:
        """Check if IP is in private address space."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False

    def is_public(self, ip: str) -> bool:
        """Check if IP is public (not private, not reserved)."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return not (
                ip_obj.is_private
                or ip_obj.is_reserved
                or ip_obj.is_loopback
                or ip_obj.is_multicast
            )
        except ValueError:
            return False


class ASNValidator(BaseValidator):
    """Validates ASN numbers and descriptions."""

    def validate(self, asn: str) -> bool:
        """Validate an ASN."""
        try:
            # ASN can be just a number or prefixed with "AS"
            asn_str = asn.upper().strip()
            if asn_str.startswith("AS"):
                asn_num = int(asn_str[2:])
            else:
                asn_num = int(asn_str)

            # Valid ASN range (16-bit and 32-bit)
            return 1 <= asn_num <= 4294967295

        except (ValueError, TypeError):
            return False

    def normalize_asn(self, asn: str) -> Optional[int]:
        """Normalize ASN to integer format."""
        if self.validate(asn):
            asn_str = asn.upper().strip()
            if asn_str.startswith("AS"):
                return int(asn_str[2:])
            else:
                return int(asn_str)
        return None


class CloudValidator(BaseValidator):
    """Validates cloud service identifiers."""

    def __init__(self):
        # Known cloud providers
        self.providers = {
            "aws",
            "azure",
            "gcp",
            "google",
            "cloudflare",
            "akamai",
            "fastly",
            "heroku",
            "digitalocean",
        }

    def validate(self, identifier: str) -> bool:
        """Validate a cloud service identifier."""
        if not identifier or len(identifier) < 3:
            return False

        # For now, just basic validation
        # Could be enhanced with provider-specific validation
        return True

    def identify_provider(self, identifier: str) -> Optional[str]:
        """Try to identify the cloud provider from identifier."""
        identifier_lower = identifier.lower()

        # Provider-specific patterns
        if any(x in identifier_lower for x in ["amazonaws", "aws", "cloudfront"]):
            return "aws"
        elif any(
            x in identifier_lower for x in ["azure", "windows.net", "azurewebsites"]
        ):
            return "azure"
        elif any(
            x in identifier_lower
            for x in ["googleusercontent", "appspot", "googleapis"]
        ):
            return "gcp"
        elif "cloudflare" in identifier_lower:
            return "cloudflare"
        elif any(x in identifier_lower for x in ["akamai", "akamaized"]):
            return "akamai"
        elif "fastly" in identifier_lower:
            return "fastly"
        elif "herokuapp" in identifier_lower:
            return "heroku"
        elif "digitalocean" in identifier_lower:
            return "digitalocean"

        return None


class DNSValidator:
    """DNS-specific validation utilities."""

    @staticmethod
    def can_resolve(domain: str, timeout: float = 5.0) -> bool:
        """Check if domain can be resolved via DNS."""
        try:
            socket.setdefaulttimeout(timeout)
            socket.gethostbyname(domain)
            return True
        except (socket.gaierror, socket.timeout):
            return False
        finally:
            socket.setdefaulttimeout(None)

    @staticmethod
    def get_dns_records(domain: str, record_type: str = "A") -> List[str]:
        """Get DNS records for a domain (simplified)."""
        # This would need a proper DNS library like dnspython
        # For now, just return empty list
        return []


def validate_discovery_context(
    target_org: str, search_terms: Set[str], base_domains: Set[str]
) -> List[str]:
    """
    Validate discovery context parameters.

    Returns:
        List of validation errors (empty if valid)
    """
    errors = []

    if not target_org or len(target_org.strip()) < 2:
        errors.append(
            "Target organization name is required and must be at least 2 characters"
        )

    domain_validator = DomainValidator()
    for domain in base_domains:
        if not domain_validator.validate(domain):
            errors.append(f"Invalid base domain: {domain}")

    if not search_terms:
        errors.append("At least one search term is required")

    for term in search_terms:
        if not term or len(term.strip()) < 2:
            errors.append(f"Search term too short: '{term}'")

    return errors
