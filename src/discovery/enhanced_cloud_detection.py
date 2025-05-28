"""
Enhanced Cloud Detection with advanced provider recognition and intelligent analysis.

This module provides comprehensive cloud service detection with multiple detection methods,
rate limiting, configuration management, and detailed reporting.
"""

import logging
import re
import time
import asyncio
from typing import Set, Dict, Optional, Callable, List, Tuple, Any
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import ipaddress

# Initialize logger before any potential usage
logger = logging.getLogger(__name__)

# Enhanced netaddr support with fallback
try:
    from netaddr import IPNetwork, IPSet, IPAddress, AddrFormatError

    NETADDR_AVAILABLE = True
    NetAddrError = AddrFormatError
except ImportError:
    logger.warning("netaddr library not available - IP-based cloud detection disabled")
    NETADDR_AVAILABLE = False
    IPNetwork = None
    IPSet = None
    IPAddress = None
    AddrFormatError = None
    NetAddrError = ValueError  # Fallback exception

from src.core.models import (
    IPRange,
    Domain,
    CloudService,
    ReconnaissanceResult,
    Subdomain,
)
from src.config.settings import get_settings
from src.utils.rate_limiter import get_rate_limiter
from src.utils.backoff import with_exponential_backoff


@dataclass
class CloudProvider:
    """Enhanced cloud provider definition with metadata."""

    name: str
    display_name: str
    ip_ranges: List[str] = field(default_factory=list)
    domain_patterns: List[str] = field(default_factory=list)
    confidence_score: float = 1.0
    detection_methods: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CloudDetectionResult:
    """Result of cloud detection with confidence and metadata."""

    provider: str
    resource_identifier: str
    resource_type: str
    confidence_score: float
    detection_method: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


class EnhancedCloudDetection:
    """Enhanced cloud detection with multiple providers and detection methods."""

    def __init__(self, config=None):
        """Initialize enhanced cloud detection."""
        self.config = config or get_settings()
        self.rate_limiter = get_rate_limiter()

        # Initialize cloud providers
        self.providers = self._initialize_cloud_providers()
        self._cloud_ip_sets = {}

        # Initialize IP sets for efficient detection
        if NETADDR_AVAILABLE:
            self._initialize_ip_sets()
        else:
            logger.warning(
                "netaddr library not available. IP-based cloud detection will be limited."
            )

    def _initialize_cloud_providers(self) -> Dict[str, CloudProvider]:
        """Initialize comprehensive cloud provider definitions."""
        providers = {
            "aws": CloudProvider(
                name="aws",
                display_name="Amazon Web Services",
                ip_ranges=[
                    # EC2 ranges (examples - AWS publishes official JSON)
                    "13.32.0.0/15",
                    "18.200.0.0/13",
                    "52.93.178.234/32",
                    "3.5.140.0/22",
                    "15.230.39.0/24",
                    "54.239.0.0/17",
                    "99.83.128.0/17",
                    "130.176.0.0/16",
                    # CloudFront ranges
                    "13.224.0.0/14",
                    "13.249.0.0/16",
                    "18.238.0.0/15",
                    # Add more comprehensive ranges from AWS IP ranges JSON
                ],
                domain_patterns=[
                    r"\.amazonaws\.com$",
                    r"\.aws\.amazon\.com$",
                    r"\.cloudfront\.net$",
                    r"s3[.-][a-z0-9-]+\.amazonaws\.com$",
                    r"\.s3\.amazonaws\.com$",
                    r"\.s3-[a-z0-9-]+\.amazonaws\.com$",
                    r"\.elasticbeanstalk\.com$",
                    r"\.elb\.amazonaws\.com$",
                    r"\.execute-api\.[a-z0-9-]+\.amazonaws\.com$",
                    r"\.lambda-url\.[a-z0-9-]+\.on\.aws$",
                ],
                confidence_score=0.95,
                detection_methods=["ip_range", "domain_pattern", "ssl_certificate"],
                metadata={"provider_type": "major_cloud", "has_api": True},
            ),
            "azure": CloudProvider(
                name="azure",
                display_name="Microsoft Azure",
                ip_ranges=[
                    "13.64.0.0/11",
                    "20.33.0.0/16",
                    "20.38.98.0/24",
                    "40.64.0.0/10",
                    "52.139.192.0/18",
                    "104.40.0.0/13",
                    "13.107.42.14/32",
                    "13.107.43.14/32",
                ],
                domain_patterns=[
                    r"\.azure\.com$",
                    r"\.windows\.net$",
                    r"\.cloudapp\.net$",
                    r"\.azurewebsites\.net$",
                    r"\.trafficmanager\.net$",
                    r"\.azure-api\.net$",
                    r"\.database\.windows\.net$",
                    r"\.servicebus\.windows\.net$",
                    r"\.blob\.core\.windows\.net$",
                    r"\.table\.core\.windows\.net$",
                    r"\.queue\.core\.windows\.net$",
                    r"\.file\.core\.windows\.net$",
                ],
                confidence_score=0.95,
                detection_methods=["ip_range", "domain_pattern", "ssl_certificate"],
                metadata={"provider_type": "major_cloud", "has_api": True},
            ),
            "gcp": CloudProvider(
                name="gcp",
                display_name="Google Cloud Platform",
                ip_ranges=[
                    "8.34.208.0/20",
                    "35.184.0.0/13",
                    "34.64.0.0/10",
                    "104.154.0.0/15",
                    "104.196.0.0/14",
                    "130.211.0.0/22",
                    "35.235.240.0/20",
                    "35.247.128.0/18",
                ],
                domain_patterns=[
                    r"\.googleusercontent\.com$",
                    r"\.cloud\.google\.com$",
                    r"\.appspot\.com$",
                    r"\.cloudfunctions\.net$",
                    r"\.run\.app$",
                    r"\.firebase\.com$",
                    r"\.firebaseapp\.com$",
                    r"\.googleapis\.com$",
                ],
                confidence_score=0.95,
                detection_methods=["ip_range", "domain_pattern", "ssl_certificate"],
                metadata={"provider_type": "major_cloud", "has_api": True},
            ),
            "cloudflare": CloudProvider(
                name="cloudflare",
                display_name="Cloudflare",
                ip_ranges=[
                    "103.21.244.0/22",
                    "103.22.200.0/22",
                    "103.31.4.0/22",
                    "104.16.0.0/13",
                    "104.24.0.0/14",
                    "108.162.192.0/18",
                    "131.0.72.0/22",
                    "141.101.64.0/18",
                    "162.158.0.0/15",
                    "172.64.0.0/13",
                    "173.245.48.0/20",
                    "188.114.96.0/20",
                    "190.93.240.0/20",
                    "197.234.240.0/22",
                    "198.41.128.0/17",
                ],
                domain_patterns=[
                    r"\.cloudflare\.com$",
                    r"\.cdn\.cloudflare\.net$",
                    r"\.workers\.dev$",
                    r"\.pages\.dev$",
                ],
                confidence_score=0.90,
                detection_methods=["ip_range", "domain_pattern", "cdn_detection"],
                metadata={"provider_type": "cdn_provider", "has_api": True},
            ),
            "akamai": CloudProvider(
                name="akamai",
                display_name="Akamai Technologies",
                ip_ranges=[
                    "2.16.0.0/16",
                    "23.0.0.0/11",
                    "23.64.0.0/14",
                    "23.192.0.0/14",
                    "95.100.0.0/15",
                    "104.64.0.0/10",
                    "184.24.0.0/13",
                ],
                domain_patterns=[
                    r"\.akamai\.net$",
                    r"\.akamaiedge\.net$",
                    r"\.akamaized\.net$",
                    r"\.akamaitechnologies\.com$",
                ],
                confidence_score=0.85,
                detection_methods=["ip_range", "domain_pattern", "cdn_detection"],
                metadata={"provider_type": "cdn_provider", "has_api": False},
            ),
            "fastly": CloudProvider(
                name="fastly",
                display_name="Fastly",
                ip_ranges=[
                    "151.101.0.0/16",
                    "151.101.64.0/18",
                    "151.101.128.0/17",
                    "151.101.192.0/18",
                    "199.232.0.0/16",
                ],
                domain_patterns=[
                    r"\.fastly\.net$",
                    r"\.fastlylb\.net$",
                    r"\.fastlycdn\.com$",
                ],
                confidence_score=0.85,
                detection_methods=["ip_range", "domain_pattern", "cdn_detection"],
                metadata={"provider_type": "cdn_provider", "has_api": True},
            ),
            "heroku": CloudProvider(
                name="heroku",
                display_name="Heroku",
                ip_ranges=[],  # Heroku uses AWS infrastructure
                domain_patterns=[r"\.herokuapp\.com$", r"\.herokussl\.com$"],
                confidence_score=0.90,
                detection_methods=["domain_pattern"],
                metadata={"provider_type": "paas_provider", "has_api": True},
            ),
            "digitalocean": CloudProvider(
                name="digitalocean",
                display_name="DigitalOcean",
                ip_ranges=[
                    "104.131.0.0/16",
                    "138.197.0.0/16",
                    "159.89.0.0/16",
                    "165.227.0.0/16",
                    "167.71.0.0/16",
                    "167.172.0.0/16",
                    "188.166.0.0/16",
                    "206.189.0.0/16",
                ],
                domain_patterns=[
                    r"\.digitaloceanspaces\.com$",
                    r"\.ondigitalocean\.app$",
                ],
                confidence_score=0.85,
                detection_methods=["ip_range", "domain_pattern"],
                metadata={"provider_type": "cloud_provider", "has_api": True},
            ),
            "linode": CloudProvider(
                name="linode",
                display_name="Linode",
                ip_ranges=[
                    "45.33.0.0/16",
                    "45.56.0.0/16",
                    "50.116.0.0/16",
                    "66.175.208.0/20",
                    "69.164.192.0/18",
                    "72.14.176.0/20",
                    "96.126.96.0/19",
                    "139.162.0.0/16",
                    "172.104.0.0/15",
                ],
                domain_patterns=[r"\.members\.linode\.com$"],
                confidence_score=0.85,
                detection_methods=["ip_range", "domain_pattern"],
                metadata={"provider_type": "cloud_provider", "has_api": True},
            ),
            "netlify": CloudProvider(
                name="netlify",
                display_name="Netlify",
                ip_ranges=[],  # Netlify uses CDN infrastructure
                domain_patterns=[r"\.netlify\.app$", r"\.netlify\.com$"],
                confidence_score=0.90,
                detection_methods=["domain_pattern"],
                metadata={"provider_type": "static_hosting", "has_api": True},
            ),
            "vercel": CloudProvider(
                name="vercel",
                display_name="Vercel",
                ip_ranges=[],  # Vercel uses edge network
                domain_patterns=[r"\.vercel\.app$", r"\.vercel\.com$", r"\.now\.sh$"],
                confidence_score=0.90,
                detection_methods=["domain_pattern"],
                metadata={"provider_type": "static_hosting", "has_api": True},
            ),
        }

        logger.info(f"Initialized {len(providers)} cloud providers for detection")
        return providers

    def _initialize_ip_sets(self):
        """Initialize IPSet objects for efficient IP range matching."""
        if not NETADDR_AVAILABLE:
            logger.warning("Skipping IP set initialization - netaddr not available")
            return

        logger.info("Initializing cloud provider IP sets...")

        for provider_name, provider in self.providers.items():
            if not provider.ip_ranges:
                continue

            try:
                valid_ranges = []
                for ip_range in provider.ip_ranges:
                    try:
                        # Only call IPNetwork if it's available
                        if IPNetwork is not None:
                            IPNetwork(ip_range)  # Validate
                            valid_ranges.append(ip_range)
                    except (NetAddrError, ValueError) as e:
                        logger.warning(
                            f"Invalid IP range for {provider_name}: {ip_range} - {e}"
                        )

                if valid_ranges and IPSet is not None:
                    self._cloud_ip_sets[provider_name] = IPSet(valid_ranges)
                    logger.debug(
                        f"Created IP set for {provider_name} with {len(valid_ranges)} ranges"
                    )

            except Exception as e:
                logger.error(f"Failed to create IP set for {provider_name}: {e}")

    def detect_cloud_services(
        self,
        result: ReconnaissanceResult,
        progress_callback: Optional[Callable[[float, str], None]] = None,
        status_callback: Optional[Callable[[str, str], None]] = None,
    ) -> List[CloudDetectionResult]:
        """
        Enhanced cloud service detection with comprehensive analysis.

        Args:
            result: ReconnaissanceResult object containing discovered assets
            progress_callback: Optional callback for progress updates
            status_callback: Optional callback for status updates

        Returns:
            List of CloudDetectionResult objects
        """
        logger.info("🌤️ Starting enhanced cloud service detection")

        detection_results = []

        # Detection Phase 1: IP Range Analysis (if available)
        if result.ip_ranges:
            if progress_callback:
                progress_callback(10.0, "Analyzing IP ranges...")

            ip_results = self._detect_from_ip_ranges(
                result.ip_ranges, progress_callback
            )
            detection_results.extend(ip_results)

            logger.info(f"IP range analysis found {len(ip_results)} cloud matches")

        # Detection Phase 2: Resolved IPs from Subdomains
        if result.domains:
            if progress_callback:
                progress_callback(20.0, "Analyzing resolved IPs from subdomains...")

            resolved_ip_results = self._detect_from_resolved_ips(result.domains)
            detection_results.extend(resolved_ip_results)

            logger.info(
                f"Resolved IP analysis found {len(resolved_ip_results)} cloud matches"
            )

        # OPTIMIZED: Skip intensive domain analysis if too many FQDNs
        total_fqdns = len(result.domains) + sum(
            len(d.subdomains) for d in result.domains
        )

        if result.domains and total_fqdns <= 100:  # Only analyze if reasonable amount
            if progress_callback:
                progress_callback(30.0, "Analyzing domain patterns...")

            domain_results = self._detect_from_domains(
                result.domains, progress_callback
            )
            detection_results.extend(domain_results)

            logger.info(f"Domain analysis found {len(domain_results)} cloud matches")
        elif result.domains and total_fqdns > 100:
            # Fast fallback for large datasets
            if progress_callback:
                progress_callback(50.0, "Quick cloud pattern check...")

            fallback_results = self._fallback_cloud_detection(result.domains)
            detection_results.extend(fallback_results)

            logger.info(
                f"Quick cloud detection found {len(fallback_results)} indicators"
            )

        # SIMPLIFIED: Skip infrastructure analysis for better performance

        # Final processing: Deduplication and quality scoring
        final_results = self._process_and_deduplicate_results(detection_results)

        # Add to result object
        for detection in final_results:
            cloud_service = CloudService(
                provider=detection.provider,
                identifier=detection.resource_identifier,
                resource_type=detection.resource_type,
                data_source=f"Enhanced Cloud Detection ({detection.detection_method})",
            )
            result.add_cloud_service(cloud_service)

        if progress_callback:
            progress_callback(
                100.0,
                f"Enhanced cloud detection complete ({len(final_results)} services)",
            )

        logger.info(f"Added {len(final_results)} cloud service detections to results")
        logger.info(
            f"✅ Enhanced cloud detection complete: {len(final_results)} services found"
        )

        return final_results

    def _detect_from_ip_ranges(
        self,
        ip_ranges: Set[IPRange],
        progress_callback: Optional[Callable[[float, str], None]] = None,
    ) -> List[CloudDetectionResult]:
        """Detect cloud services from IP ranges."""

        results = []

        if not NETADDR_AVAILABLE or not self._cloud_ip_sets:
            logger.warning("IP-based cloud detection not available")
            if progress_callback:
                progress_callback(100.0, "Skipped (netaddr unavailable)")
            return results

        logger.info(f"Analyzing {len(ip_ranges)} IP ranges for cloud providers")
        processed = 0
        total = len(ip_ranges)

        for ip_range in ip_ranges:
            processed += 1

            try:
                # Apply rate limiting for IP analysis
                with self.rate_limiter.acquire(
                    "cloud_detection", f"ip_range_analysis_{ip_range.cidr}"
                ):
                    # Only proceed if IPNetwork is available
                    if IPNetwork is not None:
                        network = IPNetwork(ip_range.cidr)

                        # Check against each provider's IP sets
                        for provider_name, ip_set in self._cloud_ip_sets.items():
                            if IPSet is not None and ip_set.intersection(
                                IPSet([network])
                            ):
                                provider = self.providers[provider_name]

                                result = CloudDetectionResult(
                                    provider=provider.display_name,
                                    resource_identifier=ip_range.cidr,
                                    resource_type="IP Range",
                                    confidence_score=provider.confidence_score,
                                    detection_method="IP Range Matching",
                                    metadata={
                                        "provider_code": provider_name,
                                        "original_asn": (
                                            getattr(ip_range, "asn_number", None)
                                        ),
                                        "data_source": ip_range.data_source,
                                    },
                                )
                                results.append(result)

                                logger.debug(
                                    f"IP range {ip_range.cidr} matches {provider.display_name}"
                                )
                                break  # First match wins

            except Exception as e:
                logger.warning(f"Error analyzing IP range {ip_range.cidr}: {e}")

            if progress_callback:
                progress = (processed / total) * 100 if total > 0 else 100
                progress_callback(progress, f"Analyzed {processed}/{total} IP ranges")

        logger.info(f"IP range analysis complete: {len(results)} matches found")
        return results

    def _detect_from_domains(
        self,
        domains: Set[Domain],
        progress_callback: Optional[Callable[[float, str], None]] = None,
    ) -> List[CloudDetectionResult]:
        """Detect cloud services from domain patterns (OPTIMIZED VERSION)."""

        results = []

        # Calculate total FQDNs to analyze
        total_fqdns = len(domains) + sum(len(d.subdomains) for d in domains)
        processed = 0

        logger.info(
            f"Analyzing {total_fqdns} FQDNs for cloud service patterns (optimized)"
        )

        # OPTIMIZATION: Batch process all FQDNs without individual rate limiting
        all_fqdns = []

        for domain in domains:
            all_fqdns.append((domain.name, "Domain"))
            for subdomain in domain.subdomains:
                all_fqdns.append((subdomain.fqdn, "Subdomain"))

        # Process in batches for better performance
        batch_size = 50  # Process 50 FQDNs at a time
        total_batches = (len(all_fqdns) + batch_size - 1) // batch_size

        for i in range(0, len(all_fqdns), batch_size):
            batch = all_fqdns[i : i + batch_size]

            # Process batch
            for fqdn, resource_type in batch:
                try:
                    # REMOVED individual rate limiting for speed
                    fqdn_results = self._analyze_domain_patterns(fqdn, resource_type)
                    results.extend(fqdn_results)
                    processed += 1

                except Exception as e:
                    logger.warning(f"Error analyzing {fqdn}: {e}")
                    processed += 1

            # Update progress every batch
            if progress_callback:
                progress = (processed / total_fqdns) * 100 if total_fqdns > 0 else 100
                progress_callback(progress, f"Analyzed {processed}/{total_fqdns} FQDNs")

            # Small delay only between batches (not individual FQDNs)
            if i + batch_size < len(all_fqdns):
                time.sleep(0.1)  # 100ms delay between batches

        logger.info(f"Domain analysis complete: {len(results)} matches found")
        return results

    def _analyze_domain_patterns(
        self, fqdn: str, resource_type: str
    ) -> List[CloudDetectionResult]:
        """Analyze a single FQDN against cloud provider patterns."""

        results = []

        for provider_name, provider in self.providers.items():
            for pattern in provider.domain_patterns:
                try:
                    if re.search(pattern, fqdn, re.IGNORECASE):
                        result = CloudDetectionResult(
                            provider=provider.display_name,
                            resource_identifier=fqdn,
                            resource_type=resource_type,
                            confidence_score=provider.confidence_score,
                            detection_method=f"Domain Pattern Matching ({pattern})",
                            metadata={
                                "provider_code": provider_name,
                                "matched_pattern": pattern,
                                "provider_type": provider.metadata.get(
                                    "provider_type", "unknown"
                                ),
                            },
                        )
                        results.append(result)
                        logger.debug(
                            f"FQDN {fqdn} matches {provider.display_name} via pattern {pattern}"
                        )
                        break  # First pattern match wins

                except Exception as e:
                    logger.warning(
                        f"Error matching pattern {pattern} against {fqdn}: {e}"
                    )

        return results

    def _fallback_cloud_detection(
        self, domains: Set[Domain]
    ) -> List[CloudDetectionResult]:
        """Fallback detection for when primary methods find no results."""

        results = []

        # Common cloud indicators in FQDNs
        cloud_indicators = {
            "AWS/Amazon": [
                "amazonaws",
                "aws",
                "amazon",
                "cloudfront",
                "elasticbeanstalk",
                "ec2",
                "s3",
                "elb",
                "rds",
                "lambda",
                "apigateway",
            ],
            "Azure/Microsoft": [
                "azure",
                "azurewebsites",
                "azureedge",
                "windows",
                "office365",
                "sharepoint",
                "onmicrosoft",
                "microsoftonline",
                "msft",
            ],
            "Google Cloud": [
                "googleapis",
                "googleusercontent",
                "gstatic",
                "appspot",
                "cloudfunctions",
                "firebase",
                "firebaseapp",
                "googlevideo",
            ],
            "Cloudflare": ["cloudflare", "cf-", "workers", "pages"],
            "Akamai": [
                "akamai",
                "akamaized",
                "akamaitechnologies",
                "edgesuite",
                "edgekey",
            ],
            "Fastly": ["fastly", "fastlylb"],
            "DigitalOcean": ["digitalocean", "digitaloceanspaces"],
        }

        # Check all FQDNs for cloud indicators
        for domain in domains:
            # Check base domain
            self._check_fqdn_for_indicators(domain.name, cloud_indicators, results)

            # Check subdomains
            for subdomain in domain.subdomains:
                self._check_fqdn_for_indicators(
                    subdomain.fqdn, cloud_indicators, results
                )

        return results

    def _check_fqdn_for_indicators(
        self,
        fqdn: str,
        indicators: Dict[str, List[str]],
        results: List[CloudDetectionResult],
    ):
        """Check a single FQDN for cloud service indicators."""

        fqdn_lower = fqdn.lower()

        for provider, keywords in indicators.items():
            for keyword in keywords:
                if keyword in fqdn_lower:
                    result = CloudDetectionResult(
                        provider=provider,
                        resource_identifier=fqdn,
                        resource_type="Domain/Subdomain",
                        confidence_score=0.6,  # Medium confidence for fallback detection
                        detection_method="Fallback Pattern Detection",
                        metadata={"indicator_keyword": keyword},
                    )
                    results.append(result)
                    break  # Only one match per FQDN per provider

    def _detect_infrastructure_patterns(
        self, domains: Set[Domain]
    ) -> List[CloudDetectionResult]:
        """Detect infrastructure and CDN patterns in domains."""

        results = []

        # CDN and infrastructure patterns
        infrastructure_patterns = {
            "CDN Services": {
                "patterns": [
                    r"cdn[\d\-]*\.",
                    r"static[\d\-]*\.",
                    r"assets[\d\-]*\.",
                    r"media[\d\-]*\.",
                    r"img[\d\-]*\.",
                    r"cache[\d\-]*\.",
                    r"edge[\d\-]*\.",
                    r"content[\d\-]*\.",
                ],
                "confidence": 0.7,
            },
            "Load Balancers": {
                "patterns": [
                    r"lb[\d\-]*\.",
                    r"load[\d\-]*\.",
                    r"balance[\d\-]*\.",
                    r"proxy[\d\-]*\.",
                    r"gateway[\d\-]*\.",
                ],
                "confidence": 0.8,
            },
            "API Gateways": {
                "patterns": [
                    r"api[\d\-]*\.",
                    r"gateway[\d\-]*\.",
                    r"rest[\d\-]*\.",
                    r"service[\d\-]*\.",
                    r"webhook[\d\-]*\.",
                ],
                "confidence": 0.8,
            },
            "Cloud Storage": {
                "patterns": [
                    r"storage[\d\-]*\.",
                    r"files[\d\-]*\.",
                    r"backup[\d\-]*\.",
                    r"archive[\d\-]*\.",
                    r"blob[\d\-]*\.",
                ],
                "confidence": 0.7,
            },
        }

        for domain in domains:
            for subdomain in domain.subdomains:
                for service_type, config in infrastructure_patterns.items():
                    for pattern in config["patterns"]:
                        if re.search(pattern, subdomain.fqdn, re.IGNORECASE):
                            result = CloudDetectionResult(
                                provider=service_type,
                                resource_identifier=subdomain.fqdn,
                                resource_type="Infrastructure Pattern",
                                confidence_score=config["confidence"],
                                detection_method="Infrastructure Pattern Analysis",
                                metadata={"pattern_matched": pattern},
                            )
                            results.append(result)
                            break  # One match per subdomain per service type

        return results

    def _process_and_deduplicate_results(
        self, results: List[CloudDetectionResult]
    ) -> List[CloudDetectionResult]:
        """Process and deduplicate cloud detection results."""

        if not results:
            return results

        # Group by resource identifier and provider
        grouped = defaultdict(list)
        for result in results:
            key = (result.resource_identifier, result.provider)
            grouped[key].append(result)

        # Merge duplicates and keep the highest confidence
        deduplicated = []
        for (resource_id, provider), group in grouped.items():
            best_result = max(group, key=lambda r: r.confidence_score)

            # Merge detection methods if multiple
            all_methods = set(r.detection_method for r in group)
            if len(all_methods) > 1:
                best_result.detection_method = f"Multiple: {', '.join(all_methods)}"
                best_result.confidence_score = min(
                    best_result.confidence_score + 0.1, 1.0
                )

            deduplicated.append(best_result)

        # Sort by confidence score
        deduplicated.sort(key=lambda r: r.confidence_score, reverse=True)

        logger.info(
            f"Deduplicated {len(results)} results to {len(deduplicated)} unique detections"
        )
        return deduplicated

    def get_provider_statistics(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics about configured cloud providers."""

        stats = {}

        for provider_name, provider in self.providers.items():
            stats[provider_name] = {
                "display_name": provider.display_name,
                "ip_ranges_count": len(provider.ip_ranges),
                "domain_patterns_count": len(provider.domain_patterns),
                "detection_methods": provider.detection_methods,
                "confidence_score": provider.confidence_score,
                "has_ip_set": provider_name in self._cloud_ip_sets,
                "provider_type": provider.metadata.get("provider_type", "unknown"),
            }

        return stats

    def _detect_from_resolved_ips(
        self, domains: Set[Domain]
    ) -> List[CloudDetectionResult]:
        """Detect cloud services from resolved IPs of subdomains."""

        results = []

        if not NETADDR_AVAILABLE or not self._cloud_ip_sets:
            logger.warning(
                "IP-based cloud detection unavailable (netaddr not installed or no IP sets)"
            )
            return results

        # Collect all resolved IPs from subdomains
        resolved_ips = set()
        ip_to_fqdn = {}  # Map IP to FQDN for better reporting

        for domain in domains:
            for subdomain in domain.subdomains:
                if subdomain.resolved_ips:
                    for ip_str in subdomain.resolved_ips:
                        try:
                            # Validate and normalize IP only if IPAddress is available
                            if IPAddress is not None:
                                ip_obj = IPAddress(ip_str)
                                resolved_ips.add(ip_obj)
                                ip_to_fqdn[ip_obj] = subdomain.fqdn
                        except (NetAddrError, ValueError):
                            logger.debug(f"Invalid IP address: {ip_str}")
                            continue

        logger.info(
            f"Analyzing {len(resolved_ips)} resolved IPs for cloud provider matches"
        )

        # Check each IP against cloud provider ranges
        for ip in resolved_ips:
            for provider_name, ip_set in self._cloud_ip_sets.items():
                if ip in ip_set:
                    provider = self.providers[provider_name]
                    fqdn = ip_to_fqdn.get(ip, str(ip))

                    result = CloudDetectionResult(
                        provider=provider.display_name,
                        resource_identifier=f"{fqdn} ({ip})",
                        resource_type="Resolved IP",
                        confidence_score=provider.confidence_score,
                        detection_method="IP Range Matching",
                        metadata={
                            "provider_code": provider_name,
                            "ip_address": str(ip),
                            "fqdn": fqdn,
                            "provider_type": provider.metadata.get(
                                "provider_type", "unknown"
                            ),
                        },
                    )
                    results.append(result)
                    logger.info(
                        f"Detected {provider.display_name} service: {fqdn} -> {ip}"
                    )
                    break  # First match wins

        return results

    def _process_detection_results(
        self,
        detection_results: List[CloudDetectionResult],
        result: ReconnaissanceResult,
    ):
        """Process detection results and add them to the reconnaissance result."""
        for detection in detection_results:
            cloud_service = CloudService(
                provider=detection.provider,
                identifier=detection.resource_identifier,
                resource_type=detection.resource_type,
                data_source=f"Enhanced Cloud Detection ({detection.detection_method})",
            )
            result.add_cloud_service(cloud_service)


# Convenience functions for backward compatibility and external usage
def detect_cloud_from_ips(
    ip_ranges: Set[IPRange],
    result: ReconnaissanceResult,
    progress_callback: Optional[Callable[[float, str], None]] = None,
):
    """Legacy function for IP-based cloud detection."""
    detector = EnhancedCloudDetection()
    ip_results = detector._detect_from_ip_ranges(ip_ranges, progress_callback)
    detector._process_detection_results(ip_results, result)


def detect_cloud_from_domains(
    domains: Set[Domain],
    result: ReconnaissanceResult,
    progress_callback: Optional[Callable[[float, str], None]] = None,
):
    """Legacy function for domain-based cloud detection."""
    detector = EnhancedCloudDetection()
    domain_results = detector._detect_from_domains(domains, progress_callback)
    detector._process_detection_results(domain_results, result)


def get_enhanced_cloud_detector():
    """Get a singleton instance of the enhanced cloud detector."""
    if not hasattr(get_enhanced_cloud_detector, "_instance"):
        get_enhanced_cloud_detector._instance = EnhancedCloudDetection()
    return get_enhanced_cloud_detector._instance


# Main detection function
def detect_enhanced_cloud_services(
    result: ReconnaissanceResult,
    progress_callback: Optional[Callable[[float, str], None]] = None,
    status_callback: Optional[Callable[[str, str], None]] = None,
):
    """Main function for enhanced cloud service detection."""
    detector = get_enhanced_cloud_detector()
    detector.detect_cloud_services(result, progress_callback, status_callback)
