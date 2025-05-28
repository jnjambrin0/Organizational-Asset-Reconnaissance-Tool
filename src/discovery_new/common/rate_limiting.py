"""
Discovery Rate Limiting

Simplified rate limiting for discovery operations.
"""

import time
import logging
from typing import Dict, Optional
from dataclasses import dataclass

from .exceptions import RateLimitExceeded

logger = logging.getLogger(__name__)


@dataclass
class RateLimit:
    """Rate limit configuration."""

    requests_per_minute: int = 60
    requests_per_hour: int = 1000
    burst_allowance: int = 10


class DiscoveryRateLimiter:
    """Simple rate limiter for discovery operations."""

    def __init__(self):
        self.service_limits: Dict[str, RateLimit] = {}
        self.request_history: Dict[str, list] = {}

        # Default limits
        self.default_limits = RateLimit()

        # Service-specific limits
        self.service_limits.update(
            {
                "bgp_he_net": RateLimit(requests_per_minute=30, requests_per_hour=1000),
                "crt_sh": RateLimit(requests_per_minute=60, requests_per_hour=2000),
                "hackertarget": RateLimit(
                    requests_per_minute=10, requests_per_hour=100
                ),
                "dns_resolution": RateLimit(
                    requests_per_minute=120, requests_per_hour=5000
                ),
            }
        )

    def check_rate_limit(self, service: str) -> bool:
        """
        Check if a request is allowed for the service.

        Returns:
            True if request is allowed, False if rate limited
        """
        current_time = time.time()
        limits = self.service_limits.get(service, self.default_limits)

        # Initialize history for new services
        if service not in self.request_history:
            self.request_history[service] = []

        history = self.request_history[service]

        # Clean old entries
        one_hour_ago = current_time - 3600
        one_minute_ago = current_time - 60

        history[:] = [timestamp for timestamp in history if timestamp > one_hour_ago]

        # Check hourly limit
        if len(history) >= limits.requests_per_hour:
            logger.warning(f"Hourly rate limit exceeded for {service}")
            return False

        # Check minute limit
        recent_requests = [t for t in history if t > one_minute_ago]
        if len(recent_requests) >= limits.requests_per_minute:
            logger.warning(f"Per-minute rate limit exceeded for {service}")
            return False

        return True

    def record_request(self, service: str):
        """Record a request for the service."""
        current_time = time.time()

        if service not in self.request_history:
            self.request_history[service] = []

        self.request_history[service].append(current_time)

    def wait_if_needed(self, service: str) -> float:
        """
        Wait if rate limited and return wait time.

        Returns:
            Time waited in seconds (0 if no wait needed)
        """
        if self.check_rate_limit(service):
            return 0.0

        # Calculate wait time (simplified - wait 1 minute for minute limits)
        wait_time = 60.0
        logger.info(f"Rate limited for {service}, waiting {wait_time}s")
        time.sleep(wait_time)
        return wait_time

    def get_remaining_requests(self, service: str) -> Dict[str, int]:
        """Get remaining requests for a service."""
        current_time = time.time()
        limits = self.service_limits.get(service, self.default_limits)

        if service not in self.request_history:
            return {
                "per_minute": limits.requests_per_minute,
                "per_hour": limits.requests_per_hour,
            }

        history = self.request_history[service]
        one_hour_ago = current_time - 3600
        one_minute_ago = current_time - 60

        # Count recent requests
        hourly_count = len([t for t in history if t > one_hour_ago])
        minute_count = len([t for t in history if t > one_minute_ago])

        return {
            "per_minute": max(0, limits.requests_per_minute - minute_count),
            "per_hour": max(0, limits.requests_per_hour - hourly_count),
        }


# Global rate limiter instance
_global_rate_limiter = DiscoveryRateLimiter()


def get_rate_limiter() -> DiscoveryRateLimiter:
    """Get the global rate limiter instance."""
    return _global_rate_limiter


def rate_limited(service: str):
    """Decorator for rate-limited functions."""

    def decorator(func):
        def wrapper(*args, **kwargs):
            limiter = get_rate_limiter()

            if not limiter.check_rate_limit(service):
                raise RateLimitExceeded(
                    f"Rate limit exceeded for {service}", retry_after=60.0
                )

            limiter.record_request(service)
            return func(*args, **kwargs)

        return wrapper

    return decorator
