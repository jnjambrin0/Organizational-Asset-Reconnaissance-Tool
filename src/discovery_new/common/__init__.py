"""
Discovery Common Module

Shared infrastructure and utilities for all discovery modules.
"""

from .base import BaseDiscovery, DiscoveryResult, DiscoveryConfig
from .types import DiscoveryCandidate, ConfidenceScore
from .validators import DiscoveryValidator
from .filters import QualityFilter, RelevanceFilter
from .rate_limiting import DiscoveryRateLimiter
from .exceptions import DiscoveryError, RateLimitExceeded, ValidationError

__all__ = [
    "BaseDiscovery",
    "DiscoveryResult",
    "DiscoveryConfig",
    "DiscoveryCandidate",
    "ConfidenceScore",
    "DiscoveryValidator",
    "QualityFilter",
    "RelevanceFilter",
    "DiscoveryRateLimiter",
    "DiscoveryError",
    "RateLimitExceeded",
    "ValidationError",
]
