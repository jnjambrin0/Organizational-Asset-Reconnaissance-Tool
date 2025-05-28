"""
Discovery System Types

Common types and data structures used across all discovery modules.
"""

from typing import List, Set, Optional, Dict, Any, Union
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


class ConfidenceLevel(Enum):
    """Confidence levels for discovery results."""

    VERY_LOW = 0.1
    LOW = 0.3
    MEDIUM = 0.5
    HIGH = 0.7
    VERY_HIGH = 0.9


@dataclass
class ConfidenceScore:
    """Represents a confidence score with reasoning."""

    value: float  # 0.0 to 1.0
    level: ConfidenceLevel
    reasons: List[str] = field(default_factory=list)

    def __post_init__(self):
        # Ensure value is between 0 and 1
        self.value = max(0.0, min(1.0, self.value))

        # Auto-determine level if not explicitly set
        if hasattr(self, "level") and self.level is None:
            self.level = self._calculate_level()

    def _calculate_level(self) -> ConfidenceLevel:
        """Calculate confidence level from numeric value."""
        if self.value >= 0.9:
            return ConfidenceLevel.VERY_HIGH
        elif self.value >= 0.7:
            return ConfidenceLevel.HIGH
        elif self.value >= 0.5:
            return ConfidenceLevel.MEDIUM
        elif self.value >= 0.3:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.VERY_LOW


@dataclass
class DiscoveryCandidate:
    """
    Base class for all discovery candidates.

    Represents a potential asset that has been discovered but not yet validated.
    """

    identifier: str  # Primary identifier (domain, IP, ASN, etc.)
    discovery_type: str  # Type of discovery (domain, asn, ip, cloud)
    confidence: ConfidenceScore
    sources: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    discovered_at: datetime = field(default_factory=datetime.now)

    def add_source(self, source: str, confidence_boost: float = 0.0):
        """Add a source and optionally boost confidence."""
        if source not in self.sources:
            self.sources.append(source)
            if confidence_boost > 0:
                self.confidence.value = min(
                    1.0, self.confidence.value + confidence_boost
                )


@dataclass
class DiscoveryMetrics:
    """Metrics for discovery operations."""

    candidates_found: int = 0
    candidates_filtered: int = 0
    candidates_validated: int = 0
    api_calls_made: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    duration_seconds: float = 0.0
    errors_encountered: int = 0

    @property
    def filter_rate(self) -> float:
        """Percentage of candidates that were filtered out."""
        if self.candidates_found == 0:
            return 0.0
        return (self.candidates_filtered / self.candidates_found) * 100

    @property
    def validation_rate(self) -> float:
        """Percentage of candidates that passed validation."""
        remaining = self.candidates_found - self.candidates_filtered
        if remaining == 0:
            return 0.0
        return (self.candidates_validated / remaining) * 100


@dataclass
class DiscoveryContext:
    """Context information for discovery operations."""

    target_organization: str
    search_terms: Set[str] = field(default_factory=set)
    base_domains: Set[str] = field(default_factory=set)
    discovered_asns: Set[str] = field(default_factory=set)
    discovered_ips: Set[str] = field(default_factory=set)
    iteration: int = 1
    max_iterations: int = 3

    def add_search_term(self, term: str):
        """Add a search term to the context."""
        if len(term.strip()) > 2:
            self.search_terms.add(term.strip().lower())

    def add_base_domain(self, domain: str):
        """Add a base domain to the context."""
        if domain and "." in domain:
            self.base_domains.add(domain.lower())


# Type aliases for clarity
SourceName = str
SearchTerm = str
DiscoveryKey = Union[str, int]
ValidationResult = bool
