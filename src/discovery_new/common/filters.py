"""
Discovery Filters

Quality and relevance filters for discovery candidates.
"""

import re
import logging
from typing import List, Set, Optional, Dict, Any
from abc import ABC, abstractmethod

from .types import DiscoveryCandidate, ConfidenceLevel
from .exceptions import ValidationError

logger = logging.getLogger(__name__)


class BaseFilter(ABC):
    """Base class for all discovery filters."""

    def __init__(self, name: str):
        self.name = name
        self.logger = logging.getLogger(f"{__class__.__module__}.{name}")

    @abstractmethod
    def should_filter(self, candidate: DiscoveryCandidate) -> bool:
        """
        Determine if a candidate should be filtered out.

        Returns:
            True if candidate should be filtered (removed), False to keep it
        """
        pass

    def filter_candidates(
        self, candidates: List[DiscoveryCandidate]
    ) -> List[DiscoveryCandidate]:
        """Filter a list of candidates."""
        filtered = []
        for candidate in candidates:
            if not self.should_filter(candidate):
                filtered.append(candidate)
            else:
                self.logger.debug(f"Filtered candidate: {candidate.identifier}")

        return filtered


class QualityFilter(BaseFilter):
    """Filters based on general quality metrics."""

    def __init__(
        self,
        min_confidence: float = 0.3,
        min_identifier_length: int = 3,
        max_identifier_length: int = 253,
        blocked_patterns: Optional[List[str]] = None,
    ):
        super().__init__("QualityFilter")
        self.min_confidence = min_confidence
        self.min_identifier_length = min_identifier_length
        self.max_identifier_length = max_identifier_length
        self.blocked_patterns = [re.compile(p) for p in (blocked_patterns or [])]

        # Common low-quality patterns
        self.default_blocked_patterns = [
            re.compile(r"^[0-9]+$"),  # Pure numeric
            re.compile(r"^[a-f0-9]{32,}$"),  # Hash-like strings
            re.compile(r"\.local$"),  # Local domains
            re.compile(r"^localhost"),  # Localhost variants
            re.compile(r"example\.(com|org|net)$"),  # Example domains
            re.compile(r"test\."),  # Test domains
            re.compile(r"\.test$"),  # .test TLD
        ]

    def should_filter(self, candidate: DiscoveryCandidate) -> bool:
        """Check if candidate meets quality standards."""

        # Check confidence threshold
        if candidate.confidence.value < self.min_confidence:
            return True

        # Check identifier length
        identifier = candidate.identifier.strip()
        if (
            len(identifier) < self.min_identifier_length
            or len(identifier) > self.max_identifier_length
        ):
            return True

        # Check against blocked patterns
        for pattern in self.blocked_patterns + self.default_blocked_patterns:
            if pattern.search(identifier.lower()):
                return True

        return False


class RelevanceFilter(BaseFilter):
    """Filters based on relevance to target organization."""

    def __init__(
        self,
        target_terms: Optional[Set[str]] = None,
        irrelevant_patterns: Optional[List[str]] = None,
        min_relevance_score: float = 0.1,
    ):
        super().__init__("RelevanceFilter")
        self.target_terms = {term.lower() for term in (target_terms or set())}
        self.min_relevance_score = min_relevance_score

        # Compile irrelevant patterns
        irrelevant_patterns = irrelevant_patterns or []
        self.irrelevant_patterns = [
            re.compile(p, re.IGNORECASE) for p in irrelevant_patterns
        ]

        # Default irrelevant patterns
        self.default_irrelevant_patterns = [
            re.compile(r"spam", re.IGNORECASE),
            re.compile(r"phishing", re.IGNORECASE),
            re.compile(r"malware", re.IGNORECASE),
            re.compile(r"temporary", re.IGNORECASE),
            re.compile(r"temp[0-9]*", re.IGNORECASE),
        ]

    def should_filter(self, candidate: DiscoveryCandidate) -> bool:
        """Check if candidate is relevant to target."""

        # Calculate relevance score
        relevance_score = self._calculate_relevance_score(candidate)

        if relevance_score < self.min_relevance_score:
            return True

        # Check against irrelevant patterns
        identifier = candidate.identifier.lower()
        for pattern in self.irrelevant_patterns + self.default_irrelevant_patterns:
            if pattern.search(identifier):
                return True

        return False

    def _calculate_relevance_score(self, candidate: DiscoveryCandidate) -> float:
        """Calculate relevance score based on target terms."""
        if not self.target_terms:
            return 1.0  # No filtering if no target terms

        identifier = candidate.identifier.lower()
        matches = 0

        for term in self.target_terms:
            if term in identifier:
                matches += 1

        # Base score on term matches
        score = matches / len(self.target_terms) if self.target_terms else 1.0

        # Boost score if multiple sources confirm
        if len(candidate.sources) > 1:
            score += 0.2

        # Boost score based on confidence
        score += candidate.confidence.value * 0.3

        return min(1.0, score)


class DuplicateFilter(BaseFilter):
    """Filters duplicate candidates."""

    def __init__(self, case_sensitive: bool = False):
        super().__init__("DuplicateFilter")
        self.case_sensitive = case_sensitive
        self.seen_identifiers: Set[str] = set()

    def should_filter(self, candidate: DiscoveryCandidate) -> bool:
        """Check if candidate is a duplicate."""
        identifier = candidate.identifier
        if not self.case_sensitive:
            identifier = identifier.lower()

        if identifier in self.seen_identifiers:
            return True

        self.seen_identifiers.add(identifier)
        return False

    def reset(self):
        """Reset the seen identifiers set."""
        self.seen_identifiers.clear()


class CompositeFilter(BaseFilter):
    """Combines multiple filters."""

    def __init__(self, filters: List[BaseFilter], name: str = "CompositeFilter"):
        super().__init__(name)
        self.filters = filters

    def should_filter(self, candidate: DiscoveryCandidate) -> bool:
        """Apply all filters - candidate is filtered if ANY filter says to filter."""
        for filter_instance in self.filters:
            if filter_instance.should_filter(candidate):
                return True
        return False

    def add_filter(self, filter_instance: BaseFilter):
        """Add a filter to the composite."""
        self.filters.append(filter_instance)


class DomainSpecificFilter(BaseFilter):
    """Domain-specific quality filters."""

    def __init__(self):
        super().__init__("DomainSpecificFilter")

        # High-value subdomain patterns
        self.high_value_patterns = [
            re.compile(r"^(www|mail|smtp|imap|pop3|ftp|sftp|ssh|vpn)\.", re.IGNORECASE),
            re.compile(r"^(api|admin|portal|dashboard|console)\.", re.IGNORECASE),
            re.compile(
                r"^(dev|staging|test|prod|production|beta|alpha)\.", re.IGNORECASE
            ),
            re.compile(r"^(app|apps|service|services|web|mobile)\.", re.IGNORECASE),
            re.compile(r"^(secure|auth|sso|oauth|login|signin)\.", re.IGNORECASE),
        ]

        # Low-value subdomain patterns
        self.low_value_patterns = [
            re.compile(r"^ssl\d+\.", re.IGNORECASE),
            re.compile(r"^[a-f0-9]{8,}\.", re.IGNORECASE),
            re.compile(r"^[0-9]{4,}\.", re.IGNORECASE),
            re.compile(r"^cache[0-9]*\.", re.IGNORECASE),
            re.compile(r"^cdn[0-9]*\.", re.IGNORECASE),
            re.compile(r"^edge[0-9]*\.", re.IGNORECASE),
        ]

    def should_filter(self, candidate: DiscoveryCandidate) -> bool:
        """Apply domain-specific filtering logic."""
        if candidate.discovery_type != "domain":
            return False

        identifier = candidate.identifier.lower()

        # Boost confidence for high-value patterns
        for pattern in self.high_value_patterns:
            if pattern.search(identifier):
                candidate.confidence.value = min(1.0, candidate.confidence.value + 0.1)
                candidate.confidence.reasons.append("High-value subdomain pattern")
                return False

        # Potentially filter low-value patterns (but not automatically)
        for pattern in self.low_value_patterns:
            if pattern.search(identifier):
                candidate.confidence.value = max(0.1, candidate.confidence.value - 0.2)
                candidate.confidence.reasons.append("Low-value subdomain pattern")
                # Don't auto-filter, just reduce confidence

        return False


def create_default_filter_chain(
    target_terms: Optional[Set[str]] = None, min_confidence: float = 0.3
) -> CompositeFilter:
    """Create a default filter chain for general use."""
    filters = [
        QualityFilter(min_confidence=min_confidence),
        RelevanceFilter(target_terms=target_terms),
        DuplicateFilter(case_sensitive=False),
        DomainSpecificFilter(),
    ]

    return CompositeFilter(filters, "DefaultFilterChain")
