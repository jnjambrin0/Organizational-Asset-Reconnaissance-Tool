"""
ASN Discovery

Main ASN discovery class that orchestrates multiple sources and applies intelligent filtering.
"""

import logging
from typing import Set, Optional, Callable, List, Dict, Any
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..common.base import BaseDiscovery, DiscoveryResult, DiscoveryConfig
from ..common.types import (
    DiscoveryCandidate,
    DiscoveryContext,
    ConfidenceScore,
    ConfidenceLevel,
)
from ..common.filters import CompositeFilter
from .sources import BGPHESource, WHOISASNSource, IPToASNSource, ASNSourceResult
from .validators import ASNValidator, ASNDescriptionValidator
from .filters import create_asn_filter_chain
from src.core.models import ASN, ReconnaissanceResult

logger = logging.getLogger(__name__)


@dataclass
class ASNDiscoveryResult:
    """Specialized result for ASN discovery."""

    asns: Set[ASN]
    total_discovered: int
    sources_used: List[str]
    quality_scores: Dict[int, float]
    relevance_scores: Dict[int, float]


class ASNDiscovery(BaseDiscovery[ASN]):
    """
    Advanced ASN discovery with multiple sources and intelligent filtering.

    Features:
    - Multiple discovery sources (BGP.HE.NET, WHOIS, IP-to-ASN)
    - Intelligent filtering and relevance scoring
    - ASN validation and quality assessment
    - Organization name extraction from ASN descriptions
    """

    def __init__(self, config: Optional[DiscoveryConfig] = None):
        super().__init__(config)

        # Initialize sources
        self.sources = [
            BGPHESource(),
            # WHOISASNSource(),  # Disabled for now (placeholder)
            IPToASNSource(),
        ]

        # Initialize validators
        self.asn_validator = ASNValidator()
        self.description_validator = ASNDescriptionValidator()

        # ASN-specific settings
        self.max_asns_per_session = 100
        self.enable_parallel_processing = True

    def discover(
        self,
        context: DiscoveryContext,
        result: ReconnaissanceResult,
        progress_callback: Optional[Callable[[float, str], None]] = None,
    ) -> DiscoveryResult[ASN]:
        """
        Main ASN discovery method.

        Args:
            context: Discovery context with search terms and organization info
            result: Global reconnaissance result to update
            progress_callback: Optional callback for progress updates

        Returns:
            DiscoveryResult containing discovered ASNs
        """
        self._start_discovery("ASN Discovery")

        discovery_result = DiscoveryResult[ASN](context=context)

        try:
            # Phase 1: Multi-source ASN collection
            self._update_progress(
                10.0, "Collecting ASNs from multiple sources...", progress_callback
            )
            raw_candidates = self._collect_from_sources(
                context, result, progress_callback
            )

            # Phase 2: Filtering and scoring
            self._update_progress(
                40.0, "Filtering and scoring ASN candidates...", progress_callback
            )
            filtered_candidates = self._apply_filtering(raw_candidates, context)

            # Phase 3: Validation and enhancement
            self._update_progress(
                70.0, "Validating and enhancing ASN data...", progress_callback
            )
            validated_candidates = self._validate_and_enhance(
                filtered_candidates, result
            )

            # Phase 4: Convert to final ASN objects
            self._update_progress(
                90.0, "Creating final ASN objects...", progress_callback
            )
            final_asns = self._create_asn_objects(validated_candidates)

            # Add to results
            for asn in final_asns:
                discovery_result.add_asset(asn)
                result.add_asn(asn)

            self._update_progress(
                100.0,
                f"ASN discovery complete ({len(final_asns)} ASNs)",
                progress_callback,
            )

        except Exception as e:
            error_msg = f"ASN discovery failed: {str(e)}"
            self.logger.error(error_msg)
            discovery_result.add_error(error_msg)

            if not self._handle_error(e, "ASN discovery", critical=False):
                raise

        finally:
            self._finish_discovery("ASN Discovery")
            self._log_discovery_summary(discovery_result, "ASN Discovery")

        return discovery_result

    def validate_candidate(self, candidate: DiscoveryCandidate) -> bool:
        """Validate an ASN candidate."""
        return self.asn_validator.validate(candidate.identifier)

    def _collect_from_sources(
        self,
        context: DiscoveryContext,
        result: ReconnaissanceResult,
        progress_callback: Optional[Callable[[float, str], None]] = None,
    ) -> List[DiscoveryCandidate]:
        """Collect ASN candidates from all sources."""

        all_candidates = []
        total_sources = len(self.sources)

        # Prepare discovered IPs from context (if available)
        discovered_ips = (
            context.discovered_ips if hasattr(context, "discovered_ips") else set()
        )

        for i, source in enumerate(self.sources):
            try:
                self.logger.info(f"🔍 Querying {source.name}...")

                source_result = source.discover(
                    search_terms=context.search_terms,
                    base_domains=context.base_domains,
                    discovered_ips=discovered_ips,
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

        self.logger.info(f"📊 Total ASN candidates collected: {len(all_candidates)}")
        return all_candidates

    def _convert_source_result(
        self, source_result: ASNSourceResult
    ) -> List[DiscoveryCandidate]:
        """Convert source result to discovery candidates."""
        candidates = []

        for asn in source_result.asns:
            confidence = ConfidenceScore(
                value=source_result.confidence,
                level=ConfidenceLevel.HIGH,
                reasons=[f"Discovered via {source_result.source_name}"],
            )

            # Enhance metadata with ASN details
            metadata = source_result.metadata.copy()
            metadata.update(
                {
                    "name": asn.name,
                    "description": asn.description,
                    "country": asn.country,
                    "asn_object": asn,  # Store original ASN object
                }
            )

            candidate = DiscoveryCandidate(
                identifier=str(asn.number),
                discovery_type="asn",
                confidence=confidence,
                sources=[source_result.source_name],
                metadata=metadata,
            )
            candidates.append(candidate)

        return candidates

    def _apply_filtering(
        self, candidates: List[DiscoveryCandidate], context: DiscoveryContext
    ) -> List[DiscoveryCandidate]:
        """Apply intelligent filtering to ASN candidates."""

        self.logger.info(f"🔧 Applying filters to {len(candidates)} ASN candidates")

        # Create filter chain
        filters = create_asn_filter_chain(
            target_terms=context.search_terms,
            min_confidence=self.config.min_confidence_threshold,
            min_relevance=0.2,
            strict_mode=False,
        )

        # Apply filters sequentially
        filtered = candidates
        for filter_instance in filters:
            filtered = filter_instance.filter_candidates(filtered)
            self.logger.debug(
                f"{filter_instance.name}: {len(filtered)} candidates remain"
            )

        # Apply confidence threshold
        filtered = self._apply_confidence_threshold(filtered)

        self.logger.info(
            f"✅ Filtering complete: {len(filtered)} ASN candidates remain"
        )
        return filtered

    def _validate_and_enhance(
        self, candidates: List[DiscoveryCandidate], result: ReconnaissanceResult
    ) -> List[DiscoveryCandidate]:
        """Validate and enhance ASN candidates."""

        self.logger.info(
            f"🔍 Validating and enhancing {len(candidates)} ASN candidates"
        )

        enhanced = []

        for candidate in candidates:
            try:
                # Validate ASN number
                if not self.asn_validator.validate(candidate.identifier):
                    self.logger.debug(f"Invalid ASN format: {candidate.identifier}")
                    continue

                # Enhance with organization name extraction
                self._enhance_candidate_with_org_data(candidate)

                # Calculate quality scores
                self._calculate_quality_scores(candidate)

                enhanced.append(candidate)

            except Exception as e:
                self.logger.debug(f"Failed to enhance ASN {candidate.identifier}: {e}")
                continue

        self.logger.info(f"✅ Validation complete: {len(enhanced)} ASNs validated")
        return enhanced

    def _enhance_candidate_with_org_data(self, candidate: DiscoveryCandidate):
        """Enhance candidate with extracted organization data."""

        description = candidate.metadata.get("description")
        if description:
            # Extract organization name
            org_name = self.description_validator.extract_organization_name(description)
            if org_name:
                candidate.metadata["extracted_org_name"] = org_name
                candidate.confidence.value = min(1.0, candidate.confidence.value + 0.1)
                candidate.confidence.reasons.append("Organization name extracted")

    def _calculate_quality_scores(self, candidate: DiscoveryCandidate):
        """Calculate quality scores for ASN candidate."""

        description = candidate.metadata.get("description")
        if description:
            quality_score = self.description_validator.calculate_quality_score(
                description
            )
            candidate.metadata["quality_score"] = quality_score

            # Adjust confidence based on quality
            if quality_score > 0.7:
                candidate.confidence.value = min(1.0, candidate.confidence.value + 0.1)
                candidate.confidence.reasons.append("High-quality description")
            elif quality_score < 0.3:
                candidate.confidence.value = max(0.1, candidate.confidence.value - 0.1)
                candidate.confidence.reasons.append("Low-quality description")

    def _create_asn_objects(self, candidates: List[DiscoveryCandidate]) -> Set[ASN]:
        """Create final ASN objects from validated candidates."""

        self.logger.info(f"📋 Creating ASN objects from {len(candidates)} candidates")

        asns = set()

        for candidate in candidates:
            try:
                # Get ASN object from metadata or create new one
                asn_obj = candidate.metadata.get("asn_object")

                if asn_obj:
                    # Update data source
                    asn_obj.data_source = "ASN Discovery"
                    asns.add(asn_obj)
                else:
                    # Create new ASN object
                    asn_number = self.asn_validator.normalize_asn(candidate.identifier)
                    if asn_number:
                        asn = ASN(
                            number=asn_number,
                            name=candidate.metadata.get("name"),
                            description=candidate.metadata.get("description"),
                            country=candidate.metadata.get("country"),
                            data_source="ASN Discovery",
                        )
                        asns.add(asn)

            except Exception as e:
                self.logger.debug(
                    f"Failed to create ASN object for {candidate.identifier}: {e}"
                )
                continue

        self.logger.info(f"✅ Created {len(asns)} ASN objects")
        return asns
