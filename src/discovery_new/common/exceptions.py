"""
Discovery System Exceptions

Custom exceptions for the discovery system.
"""


class DiscoveryError(Exception):
    """Base exception for discovery operations."""

    pass


class RateLimitExceeded(DiscoveryError):
    """Raised when rate limits are exceeded."""

    def __init__(self, message: str, retry_after: float = 60.0):
        super().__init__(message)
        self.retry_after = retry_after


class ValidationError(DiscoveryError):
    """Raised when validation fails."""

    pass


class SourceError(DiscoveryError):
    """Raised when a discovery source fails."""

    pass


class ConfigurationError(DiscoveryError):
    """Raised when configuration is invalid."""

    pass
