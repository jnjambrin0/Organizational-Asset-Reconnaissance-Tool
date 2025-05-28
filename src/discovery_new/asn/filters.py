"""
ASN Filters

Specialized filters for ASN discovery quality and relevance.
"""

import re
import logging
from typing import Set, Optional

from ..common.filters import BaseFilter
from ..common.types import DiscoveryCandidate
from .validators import ASNValidator, ASNDescriptionValidator, ASNRelevanceValidator

logger = logging.getLogger(__name__)


class ASNQualityFilter(BaseFilter):
    """Quality filter specifically for ASNs."""

    def __init__(self, min_confidence: float = 0.3):
        super().__init__("ASNQualityFilter")
        self.min_confidence = min_confidence
        self.asn_validator = ASNValidator()
        self.description_validator = ASNDescriptionValidator()

        # Low-quality ASN indicators
        self.low_quality_patterns = [
            re.compile(r"^UNALLOCATED", re.IGNORECASE),
            re.compile(r"^RESERVED", re.IGNORECASE),
            re.compile(r"^PRIVATE", re.IGNORECASE),
            re.compile(r"^RFC\d+", re.IGNORECASE),
            re.compile(r"^TEST", re.IGNORECASE),
            re.compile(r"^DOCUMENTATION", re.IGNORECASE),
        ]

        # High-quality ASN indicators
        self.high_quality_patterns = [
            re.compile(r"\b(CORPORATION|CORP|COMPANY|ENTERPRISES?)\b", re.IGNORECASE),
            re.compile(r"\b(UNIVERSITY|COLLEGE|RESEARCH)\b", re.IGNORECASE),
            re.compile(
                r"\b(NETWORKS?|TELECOMMUNICATIONS?|TELECOM|INTERNET|ISP)\b",
                re.IGNORECASE,
            ),
            re.compile(r"\b(GOVERNMENT|GOV|FEDERAL|STATE)\b", re.IGNORECASE),
            re.compile(r"\b(CLOUD|HOSTING|DATACENTER)\b", re.IGNORECASE),
        ]

    def should_filter(self, candidate: DiscoveryCandidate) -> bool:
        """Check if ASN candidate should be filtered."""

        if candidate.discovery_type != "asn":
            return False

        # Check confidence threshold
        if candidate.confidence.value < self.min_confidence:
            return True

        # Validate ASN number format
        if not self.asn_validator.validate(candidate.identifier):
            logger.debug(f"Filtering ASN {candidate.identifier}: invalid format")
            return True

        # Check ASN description quality (if available in metadata)
        description = candidate.metadata.get("description") or candidate.metadata.get(
            "name"
        )
        if description:
            if not self._is_quality_description(description):
                logger.debug(
                    f"Filtering ASN {candidate.identifier}: low quality description"
                )
                return True

        return False

    def _is_quality_description(self, description: str) -> bool:
        """Check if ASN description indicates quality."""
        if not description or len(description.strip()) < 3:
            return False

        desc = description.strip()

        # Check for low-quality patterns
        for pattern in self.low_quality_patterns:
            if pattern.search(desc):
                return False

        # Boost confidence for high-quality patterns
        for pattern in self.high_quality_patterns:
            if pattern.search(desc):
                return True

        # Basic validation
        return self.description_validator.validate(description)


class ASNRelevanceFilter(BaseFilter):
    """Relevance filter specifically for ASNs."""

    def __init__(
        self,
        target_terms: Optional[Set[str]] = None,
        min_relevance: float = 0.2,
        strict_mode: bool = False,
    ):
        super().__init__("ASNRelevanceFilter")
        self.target_terms = {term.lower() for term in (target_terms or set())}
        self.min_relevance = min_relevance
        self.strict_mode = strict_mode
        self.relevance_validator = ASNRelevanceValidator(target_terms)

        # Country-based filtering (if needed)
        self.blocked_countries = set()  # Could be configured
        self.preferred_countries = set()  # Could be configured

    def should_filter(self, candidate: DiscoveryCandidate) -> bool:
        """Check if ASN candidate should be filtered based on relevance."""

        if candidate.discovery_type != "asn":
            return False

        # If no target terms, allow all (no relevance filtering)
        if not self.target_terms and not self.strict_mode:
            return False

        # Extract ASN metadata
        asn_number = int(candidate.identifier) if candidate.identifier.isdigit() else 0
        asn_name = candidate.metadata.get("name")
        asn_description = candidate.metadata.get("description")
        country = candidate.metadata.get("country")

        # Calculate relevance score
        relevance_score = self.relevance_validator.calculate_relevance_score(
            asn_number, asn_name, asn_description, country
        )

        if relevance_score < self.min_relevance:
            logger.debug(
                f"Filtering ASN {candidate.identifier}: low relevance score {relevance_score:.2f}"
            )
            return True

        # Country-based filtering
        if (
            country
            and self.blocked_countries
            and country.upper() in self.blocked_countries
        ):
            logger.debug(
                f"Filtering ASN {candidate.identifier}: blocked country {country}"
            )
            return True

        return False


class ASNNumberRangeFilter(BaseFilter):
    """Filter ASNs based on number ranges and characteristics."""

    def __init__(
        self,
        min_asn: int = 1,
        max_asn: int = 4294967295,
        allow_private: bool = True,
        prefer_16bit: bool = False,
    ):
        super().__init__("ASNNumberRangeFilter")
        self.min_asn = min_asn
        self.max_asn = max_asn
        self.allow_private = allow_private
        self.prefer_16bit = prefer_16bit
        self.asn_validator = ASNValidator()

        # Private ASN ranges
        self.private_asn_ranges = [
            (64512, 65534),  # 16-bit private
            (4200000000, 4294967294),  # 32-bit private
        ]

    def should_filter(self, candidate: DiscoveryCandidate) -> bool:
        """Check if ASN should be filtered based on number characteristics."""

        if candidate.discovery_type != "asn":
            return False

        try:
            asn_number = int(candidate.identifier)
        except ValueError:
            # Try to extract from AS format
            asn_number = self.asn_validator.normalize_asn(candidate.identifier)
            if asn_number is None:
                return True  # Invalid format

        # Check range
        if not (self.min_asn <= asn_number <= self.max_asn):
            return True

        # Check private ASN ranges
        if not self.allow_private and self._is_private_asn(asn_number):
            logger.debug(f"Filtering ASN {asn_number}: private ASN not allowed")
            return True

        # Prefer 16-bit ASNs if configured
        if self.prefer_16bit and not self.asn_validator.is_16bit_asn(asn_number):
            # Don't filter, but reduce confidence
            candidate.confidence.value *= 0.8
            candidate.confidence.reasons.append("32-bit ASN (lower preference)")

        return False

    def _is_private_asn(self, asn_number: int) -> bool:
        """Check if ASN is in private range."""
        for start, end in self.private_asn_ranges:
            if start <= asn_number <= end:
                return True
        return False


class ASNDuplicateFilter(BaseFilter):
    """Filter duplicate ASNs within the same discovery session."""

    def __init__(self):
        super().__init__("ASNDuplicateFilter")
        self.seen_asns: Set[int] = set()

    def should_filter(self, candidate: DiscoveryCandidate) -> bool:
        """Check if ASN is a duplicate."""

        if candidate.discovery_type != "asn":
            return False

        try:
            asn_number = int(candidate.identifier)
        except ValueError:
            asn_validator = ASNValidator()
            asn_number = asn_validator.normalize_asn(candidate.identifier)
            if asn_number is None:
                return True  # Invalid format

        if asn_number in self.seen_asns:
            logger.debug(f"Filtering duplicate ASN {asn_number}")
            return True

        self.seen_asns.add(asn_number)
        return False

    def reset(self):
        """Reset the seen ASNs set."""
        self.seen_asns.clear()


def create_asn_filter_chain(
    target_terms: Optional[Set[str]] = None,
    min_confidence: float = 0.3,
    min_relevance: float = 0.2,
    strict_mode: bool = False,
) -> list:
    """Create a comprehensive filter chain for ASN discovery."""

    filters = [
        ASNNumberRangeFilter(allow_private=True, prefer_16bit=False),
        ASNQualityFilter(min_confidence=min_confidence),
        ASNRelevanceFilter(
            target_terms=target_terms,
            min_relevance=min_relevance,
            strict_mode=strict_mode,
        ),
        ASNDuplicateFilter(),
    ]

    return filters
