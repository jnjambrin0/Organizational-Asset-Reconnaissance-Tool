"""
Domain Discovery

Main domain discovery class that orchestrates multiple sources and applies intelligent filtering.
"""

import logging
import socket
from typing import Set, Optional, Callable, List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from ..common.base import BaseDiscovery, DiscoveryResult, DiscoveryConfig
from ..common.types import (
    DiscoveryCandidate,
    DiscoveryContext,
    ConfidenceScore,
    ConfidenceLevel,
)
from ..common.filters import create_default_filter_chain, DomainSpecificFilter
from ..common.validators import DomainValidator, DNSValidator
from .sources import (
    CertificateTransparencySource,
    PassiveDNSSource,
    DNSBruteForceSource,
    SourceResult,
)
from src.core.models import Domain, Subdomain, ReconnaissanceResult

logger = logging.getLogger(__name__)


@dataclass
class DomainDiscoveryResult:
    """Specialized result for domain discovery."""

    base_domains: Set[Domain]
    subdomains: Set[Subdomain]
    total_discovered: int
    sources_used: List[str]
    resolution_stats: Dict[str, int]


class DomainDiscovery(BaseDiscovery[Domain]):
    """
    Advanced domain discovery with multiple sources and intelligent filtering.

    Features:
    - Multiple discovery sources (CT logs, Passive DNS, DNS brute force)
    - Intelligent filtering and relevance scoring
    - DNS resolution and validation
    - Subdomain classification and prioritization
    """

    def __init__(self, config: Optional[DiscoveryConfig] = None):
        super().__init__(config)

        # Initialize sources
        self.sources = [
            CertificateTransparencySource(),
            PassiveDNSSource(),
            # DNSBruteForceSource(),  # Disabled for now
        ]

        # Initialize validators and filters
        self.domain_validator = DomainValidator()
        self.dns_validator = DNSValidator()
        self.filter_chain = create_default_filter_chain()

        # Domain-specific settings
        self.max_subdomains_per_domain = 1000
        self.enable_dns_resolution = True
        self.resolution_timeout = 5.0

    def discover(
        self,
        context: DiscoveryContext,
        result: ReconnaissanceResult,
        progress_callback: Optional[Callable[[float, str], None]] = None,
    ) -> DiscoveryResult[Domain]:
        """
        Main domain discovery method.

        Args:
            context: Discovery context with search terms and organization info
            result: Global reconnaissance result to update
            progress_callback: Optional callback for progress updates

        Returns:
            DiscoveryResult containing discovered domains
        """
        self._start_discovery("Domain Discovery")

        discovery_result = DiscoveryResult[Domain](context=context)

        try:
            # Phase 1: Multi-source domain collection
            self._update_progress(
                10.0, "Collecting domains from multiple sources...", progress_callback
            )
            raw_candidates = self._collect_from_sources(
                context, result, progress_callback
            )

            # Phase 2: Filtering and deduplication
            self._update_progress(
                40.0, "Filtering and scoring candidates...", progress_callback
            )
            filtered_candidates = self._apply_filtering(raw_candidates, context)

            # Phase 3: DNS resolution and validation
            self._update_progress(
                60.0, "Resolving and validating domains...", progress_callback
            )
            validated_candidates = self._resolve_and_validate(
                filtered_candidates, result, progress_callback
            )

            # Phase 4: Organization into final domain objects
            self._update_progress(
                80.0, "Organizing final domain structure...", progress_callback
            )
            final_domains = self._organize_domains(validated_candidates)

            # Add to results
            for domain in final_domains:
                discovery_result.add_asset(domain)
                result.add_domain(domain)

            self._update_progress(
                100.0,
                f"Domain discovery complete ({len(final_domains)} domains)",
                progress_callback,
            )

        except Exception as e:
            error_msg = f"Domain discovery failed: {str(e)}"
            self.logger.error(error_msg)
            discovery_result.add_error(error_msg)

            if not self._handle_error(e, "domain discovery", critical=False):
                raise

        finally:
            self._finish_discovery("Domain Discovery")
            self._log_discovery_summary(discovery_result, "Domain Discovery")

        return discovery_result

    def validate_candidate(self, candidate: DiscoveryCandidate) -> bool:
        """Validate a domain candidate."""
        return self.domain_validator.validate(candidate.identifier)

    def _collect_from_sources(
        self,
        context: DiscoveryContext,
        result: ReconnaissanceResult,
        progress_callback: Optional[Callable[[float, str], None]] = None,
    ) -> List[DiscoveryCandidate]:
        """Collect domain candidates from all sources."""

        all_candidates = []
        total_sources = len(self.sources)

        for i, source in enumerate(self.sources):
            try:
                self.logger.info(f"🔍 Querying {source.name}...")

                source_result = source.discover(
                    search_terms=context.search_terms,
                    base_domains=context.base_domains,
                    result=result,
                )

                # Convert to candidates
                candidates = self._convert_source_result(source_result)
                all_candidates.extend(candidates)

                self.logger.info(f"✅ {source.name}: {len(candidates)} candidates")

                # Update progress
                if progress_callback:
                    progress = 10.0 + (i + 1) / total_sources * 30.0
                    progress_callback(progress, f"Collected from {source.name}")

            except Exception as e:
                error_msg = f"Source {source.name} failed: {str(e)}"
                self.logger.warning(error_msg)
                result.add_warning(error_msg)

        self.logger.info(f"📊 Total candidates collected: {len(all_candidates)}")
        return all_candidates

    def _convert_source_result(
        self, source_result: SourceResult
    ) -> List[DiscoveryCandidate]:
        """Convert source result to discovery candidates."""
        candidates = []

        for domain in source_result.domains:
            confidence = ConfidenceScore(
                value=source_result.confidence,
                level=ConfidenceLevel.HIGH,
                reasons=[f"Discovered via {source_result.source_name}"],
            )

            candidate = DiscoveryCandidate(
                identifier=domain,
                discovery_type="domain",
                confidence=confidence,
                sources=[source_result.source_name],
                metadata=source_result.metadata,
            )
            candidates.append(candidate)

        return candidates

    def _apply_filtering(
        self, candidates: List[DiscoveryCandidate], context: DiscoveryContext
    ) -> List[DiscoveryCandidate]:
        """Apply intelligent filtering to candidates."""

        self.logger.info(f"🔧 Applying filters to {len(candidates)} candidates")

        # Apply domain-specific filters
        domain_filter = DomainSpecificFilter()
        filtered = domain_filter.filter_candidates(candidates)

        # Apply general filter chain
        filtered = self.filter_chain.filter_candidates(filtered)

        # Apply confidence threshold
        filtered = self._apply_confidence_threshold(filtered)

        self.logger.info(f"✅ Filtering complete: {len(filtered)} candidates remain")
        return filtered

    def _resolve_and_validate(
        self,
        candidates: List[DiscoveryCandidate],
        result: ReconnaissanceResult,
        progress_callback: Optional[Callable[[float, str], None]] = None,
    ) -> List[DiscoveryCandidate]:
        """Resolve and validate domain candidates."""

        if not self.enable_dns_resolution:
            return candidates

        self.logger.info(f"🌐 Resolving {len(candidates)} domain candidates")

        validated = []
        total_candidates = len(candidates)

        # Use threading for DNS resolution
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            # Submit resolution tasks
            future_to_candidate = {
                executor.submit(self._resolve_candidate, candidate): candidate
                for candidate in candidates
            }

            # Process results
            for i, future in enumerate(as_completed(future_to_candidate)):
                candidate = future_to_candidate[future]

                try:
                    resolved_candidate = future.result()
                    if resolved_candidate:
                        validated.append(resolved_candidate)

                except Exception as e:
                    self.logger.debug(
                        f"Resolution failed for {candidate.identifier}: {e}"
                    )

                # Update progress
                if progress_callback and i % 10 == 0:
                    progress = 60.0 + (i + 1) / total_candidates * 20.0
                    progress_callback(
                        progress, f"Resolved {i+1}/{total_candidates} domains"
                    )

        self.logger.info(
            f"✅ DNS resolution complete: {len(validated)} domains validated"
        )
        return validated

    def _resolve_candidate(
        self, candidate: DiscoveryCandidate
    ) -> Optional[DiscoveryCandidate]:
        """Resolve a single domain candidate."""
        try:
            # Basic DNS resolution
            if self.dns_validator.can_resolve(
                candidate.identifier, self.resolution_timeout
            ):
                # Boost confidence for resolvable domains
                candidate.confidence.value = min(1.0, candidate.confidence.value + 0.1)
                candidate.confidence.reasons.append("DNS resolution successful")
                return candidate
            else:
                # Lower confidence for non-resolvable domains
                candidate.confidence.value = max(0.1, candidate.confidence.value - 0.3)
                candidate.confidence.reasons.append("DNS resolution failed")

                # Still return if confidence is above threshold
                if candidate.confidence.value >= self.config.min_confidence_threshold:
                    return candidate

        except Exception as e:
            self.logger.debug(f"DNS resolution error for {candidate.identifier}: {e}")

        return None

    def _organize_domains(self, candidates: List[DiscoveryCandidate]) -> Set[Domain]:
        """Organize candidates into final domain objects."""

        self.logger.info(
            f"📋 Organizing {len(candidates)} candidates into domain structure"
        )

        domain_map: Dict[str, Domain] = {}

        for candidate in candidates:
            domain_name = candidate.identifier

            # Determine if this is a subdomain
            if self._is_subdomain(domain_name):
                # Extract base domain
                parts = domain_name.split(".")
                base_domain_name = ".".join(parts[-2:])  # Last two parts

                # Create or get base domain
                if base_domain_name not in domain_map:
                    domain_map[base_domain_name] = Domain(
                        name=base_domain_name, data_source="Domain Discovery"
                    )

                # Create subdomain
                subdomain = Subdomain(
                    fqdn=domain_name,
                    status="discovered",
                    data_source=", ".join(candidate.sources),
                )

                # Add to base domain
                domain_map[base_domain_name].subdomains.add(subdomain)

            else:
                # This is a base domain
                if domain_name not in domain_map:
                    domain_map[domain_name] = Domain(
                        name=domain_name, data_source="Domain Discovery"
                    )

        domains = set(domain_map.values())
        self.logger.info(f"✅ Organized into {len(domains)} base domains")

        return domains

    def _is_subdomain(self, domain: str) -> bool:
        """Check if domain is a subdomain (more than 2 labels)."""
        return len(domain.split(".")) > 2
