"""
ASN Discovery Sources

Various sources for discovering ASNs including BGP.HE.NET, WHOIS, and IP-to-ASN mapping.
"""

import logging
import re
import socket
import time
from typing import Set, List, Optional, Dict, Any
from dataclasses import dataclass
from urllib.parse import quote

from ..common.base import SourceDiscovery
from ..common.rate_limiting import DiscoveryRateLimiter
from src.core.models import ASN, ReconnaissanceResult
from src.utils.network import make_request
from src.utils.backoff import with_api_backoff

logger = logging.getLogger(__name__)


class RateLimiter:
    """Simple rate limiter for ASN sources."""

    def __init__(self, requests_per_second: float = 1.0):
        self.requests_per_second = requests_per_second
        self.last_request_time = 0.0

    def wait_if_needed(self):
        """Wait if needed to respect rate limits."""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        min_interval = 1.0 / self.requests_per_second

        if time_since_last < min_interval:
            wait_time = min_interval - time_since_last
            time.sleep(wait_time)

        self.last_request_time = time.time()


@dataclass
class ASNSourceResult:
    """Result from an ASN discovery source."""

    asns: Set[ASN]
    source_name: str
    confidence: float
    metadata: Dict[str, Any]


class BGPHESource(SourceDiscovery):
    """BGP.HE.NET ASN discovery source."""

    def __init__(self):
        super().__init__("BGP.HE.NET")
        self.rate_limiter = RateLimiter(requests_per_second=0.5)  # Be respectful
        self.base_url = "https://bgp.he.net"

    def discover(
        self,
        search_terms: Set[str],
        base_domains: Optional[Set[str]] = None,
        discovered_ips: Optional[Set[str]] = None,
        result: Optional[ReconnaissanceResult] = None,
        **kwargs,
    ) -> ASNSourceResult:
        """Discover ASNs using BGP.HE.NET search."""

        asns = set()

        # Search by organization names/terms
        for term in search_terms:
            try:
                self.rate_limiter.wait_if_needed()
                term_asns = self._search_bgp_he_net(term)
                asns.update(term_asns)

                if result:
                    result.add_warning(
                        f"BGP.HE.NET search for '{term}': {len(term_asns)} ASNs"
                    )

            except Exception as e:
                self.logger.warning(f"BGP.HE.NET search failed for '{term}': {e}")
                if result:
                    result.add_warning(f"BGP.HE.NET search failed for '{term}': {e}")

        # Search by base domains if provided
        if base_domains:
            for domain in base_domains:
                try:
                    self.rate_limiter.wait_if_needed()
                    domain_asns = self._search_bgp_he_net(domain)
                    asns.update(domain_asns)

                    if result:
                        result.add_warning(
                            f"BGP.HE.NET search for domain '{domain}': {len(domain_asns)} ASNs"
                        )

                except Exception as e:
                    self.logger.warning(
                        f"BGP.HE.NET domain search failed for '{domain}': {e}"
                    )
                    if result:
                        result.add_warning(
                            f"BGP.HE.NET domain search failed for '{domain}': {e}"
                        )

        self._log_source_result(len(asns), "ASNs")

        return ASNSourceResult(
            asns=asns,
            source_name=self.name,
            confidence=0.7,  # Medium-high confidence
            metadata={
                "search_terms": list(search_terms),
                "base_domains": list(base_domains) if base_domains else [],
                "search_method": "organization_search",
            },
        )

    @with_api_backoff
    def _search_bgp_he_net(self, query: str) -> Set[ASN]:
        """Search BGP.HE.NET for ASNs by organization name."""

        asns = set()

        try:
            # Construct search URL
            encoded_query = quote(query)
            search_url = f"{self.base_url}/search?search%5Bsearch%5D={encoded_query}&commit=Search"

            self.logger.debug(f"Searching BGP.HE.NET: {search_url}")

            # Make request
            response = make_request(search_url, timeout=30)
            if not response:
                return asns

            # Parse HTML response
            asns = self._parse_bgp_he_response(response.text, query)

        except Exception as e:
            self.logger.error(f"BGP.HE.NET search error for '{query}': {e}")
            raise

        return asns

    def _parse_bgp_he_response(self, html_content: str, query: str) -> Set[ASN]:
        """Parse BGP.HE.NET HTML response to extract ASN information."""

        asns = set()

        try:
            from bs4 import BeautifulSoup, Tag

            soup = BeautifulSoup(html_content, "html.parser")

            # Look for results table - try new structure first, then fallback
            results_table = soup.find("table", class_="w100p")
            if not results_table:
                results_table = soup.find("table", {"id": "search"})

            if not results_table or not isinstance(results_table, Tag):
                self.logger.debug(f"No results table found for query: {query}")
                return asns

            # Parse table rows
            rows = results_table.find_all("tr")

            for row in rows[1:]:  # Skip header row
                if not isinstance(row, Tag):
                    continue

                cells = row.find_all("td")
                if len(cells) >= 3:
                    try:
                        # Extract ASN number
                        asn_cell = cells[0]
                        if not isinstance(asn_cell, Tag):
                            continue

                        asn_link = asn_cell.find("a")
                        if asn_link and isinstance(asn_link, Tag):
                            asn_text = asn_link.get_text(strip=True)
                            asn_match = re.search(r"AS(\d+)", asn_text)
                            if asn_match:
                                asn_number = int(asn_match.group(1))

                                # Extract ASN name and description
                                name_cell = cells[1] if len(cells) > 1 else None
                                country_cell = cells[2] if len(cells) > 2 else None

                                asn_name = ""
                                country = ""

                                if name_cell and isinstance(name_cell, Tag):
                                    asn_name = name_cell.get_text(strip=True)
                                if country_cell and isinstance(country_cell, Tag):
                                    country = country_cell.get_text(strip=True)

                                # Create ASN object
                                asn = ASN(
                                    number=asn_number,
                                    name=asn_name,
                                    description=asn_name,  # Use name as description for now
                                    country=country,
                                    data_source="BGP.HE.NET",
                                )

                                asns.add(asn)
                                self.logger.debug(
                                    f"Found ASN: AS{asn_number} - {asn_name}"
                                )

                    except (ValueError, AttributeError) as e:
                        self.logger.debug(f"Failed to parse ASN row: {e}")
                        continue

        except Exception as e:
            self.logger.error(f"Failed to parse BGP.HE.NET response: {e}")

        return asns


class WHOISASNSource(SourceDiscovery):
    """WHOIS-based ASN discovery source (placeholder for future implementation)."""

    def __init__(self):
        super().__init__("WHOIS ASN")

    def discover(
        self,
        search_terms: Set[str],
        base_domains: Optional[Set[str]] = None,
        discovered_ips: Optional[Set[str]] = None,
        result: Optional[ReconnaissanceResult] = None,
        **kwargs,
    ) -> ASNSourceResult:
        """Placeholder for WHOIS ASN discovery."""

        # TODO: Implement WHOIS-based ASN discovery
        self.logger.info("WHOIS ASN discovery not yet implemented")

        return ASNSourceResult(
            asns=set(),
            source_name=self.name,
            confidence=0.8,
            metadata={"status": "not_implemented"},
        )


class IPToASNSource(SourceDiscovery):
    """IP-to-ASN mapping source for discovering ASNs from resolved IPs."""

    def __init__(self):
        super().__init__("IP-to-ASN")
        self.rate_limiter = RateLimiter(requests_per_second=2.0)

    def discover(
        self,
        search_terms: Set[str],
        base_domains: Optional[Set[str]] = None,
        discovered_ips: Optional[Set[str]] = None,
        result: Optional[ReconnaissanceResult] = None,
        **kwargs,
    ) -> ASNSourceResult:
        """Discover ASNs by resolving IPs from domains and mapping to ASNs."""

        asns = set()

        # Collect IPs to check
        ips_to_check = set()

        # Add provided discovered IPs
        if discovered_ips:
            ips_to_check.update(discovered_ips)

        # Resolve IPs from base domains (limited to avoid overwhelming)
        if base_domains:
            for domain in list(base_domains)[:10]:  # Limit domains
                try:
                    domain_ips = self._resolve_domain_ips(domain)
                    ips_to_check.update(domain_ips)
                except Exception as e:
                    self.logger.debug(f"Failed to resolve IPs for {domain}: {e}")

        # Limit total IPs to check
        ips_to_check = set(list(ips_to_check)[:20])

        # Map IPs to ASNs
        for ip in ips_to_check:
            try:
                self.rate_limiter.wait_if_needed()
                asn = self._ip_to_asn(ip)
                if asn:
                    asns.add(asn)

            except Exception as e:
                self.logger.debug(f"Failed to map IP {ip} to ASN: {e}")

        self._log_source_result(len(asns), "ASNs")

        return ASNSourceResult(
            asns=asns,
            source_name=self.name,
            confidence=0.9,  # High confidence from IP resolution
            metadata={"ips_checked": len(ips_to_check), "method": "ip_resolution"},
        )

    def _resolve_domain_ips(self, domain: str) -> Set[str]:
        """Resolve domain to IP addresses."""
        ips = set()

        try:
            # Get A records
            result = socket.getaddrinfo(domain, None, socket.AF_INET)
            for item in result:
                ip = item[4][0]
                ips.add(ip)

        except socket.gaierror:
            self.logger.debug(f"Failed to resolve domain: {domain}")

        return ips

    def _ip_to_asn(self, ip: str) -> Optional[ASN]:
        """Map IP address to ASN using WHOIS lookup."""

        try:
            # Use a simple WHOIS-based approach
            # This is a simplified implementation - could be enhanced with dedicated services

            import subprocess

            result = subprocess.run(
                ["whois", ip], capture_output=True, text=True, timeout=10
            )

            if result.returncode == 0:
                whois_output = result.stdout

                # Look for ASN information in WHOIS output
                asn_match = re.search(
                    r"(?:OriginAS|origin|ASN):\s*AS?(\d+)", whois_output, re.IGNORECASE
                )
                if asn_match:
                    asn_number = int(asn_match.group(1))

                    # Try to extract organization name
                    org_match = re.search(
                        r"(?:OrgName|org-name|descr):\s*(.+)",
                        whois_output,
                        re.IGNORECASE,
                    )
                    org_name = (
                        org_match.group(1).strip() if org_match else f"AS{asn_number}"
                    )

                    return ASN(
                        number=asn_number,
                        name=org_name,
                        description=org_name,
                        country="",  # Could be extracted from WHOIS if needed
                        data_source="IP-to-ASN WHOIS",
                    )

        except (
            subprocess.TimeoutExpired,
            subprocess.CalledProcessError,
            FileNotFoundError,
        ) as e:
            self.logger.debug(f"WHOIS lookup failed for {ip}: {e}")

        return None
