"""
Robust rate limiting system for external API calls and data sources.

This module provides rate limiting capabilities using sliding window algorithm
with persistence support and monitoring metrics.
"""

import time
import json
import logging
import threading
import random
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from pathlib import Path
from collections import defaultdict, deque
from contextlib import contextmanager

logger = logging.getLogger(__name__)

@dataclass
class RateLimitConfig:
    """Configuration for rate limiting per service."""
    service: str
    requests_per_minute: int
    requests_per_hour: int
    burst_limit: Optional[int] = None  # Max burst requests
    backoff_factor: float = 1.5
    max_retries: int = 3
    jitter_max_seconds: float = 1.0

@dataclass
class RateLimitWindow:
    """Represents a time window for rate limiting."""
    window_start: float
    window_size: int  # seconds
    requests: deque
    
    def __post_init__(self):
        if not isinstance(self.requests, deque):
            self.requests = deque(self.requests) if self.requests else deque()

@dataclass
class RateLimitMetrics:
    """Metrics for rate limiting monitoring."""
    total_requests: int = 0
    blocked_requests: int = 0
    successful_requests: int = 0
    average_wait_time: float = 0.0
    last_request_time: Optional[float] = None
    last_blocked_time: Optional[float] = None

class RateLimiter:
    """
    Advanced rate limiter with sliding window algorithm.
    
    Features:
    - Sliding window rate limiting
    - Per-service configuration
    - Persistence across restarts
    - Exponential backoff with jitter
    - Comprehensive metrics
    """
    
    def __init__(self, persistence_file: str = "rate_limits.json"):
        """
        Initialize rate limiter.
        
        Args:
            persistence_file: File to persist rate limit state
        """
        self.persistence_file = Path(persistence_file)
        self.lock = threading.RLock()
        
        # Rate limit windows: service -> {minute: window, hour: window}
        self.windows: Dict[str, Dict[str, RateLimitWindow]] = defaultdict(lambda: {
            "minute": RateLimitWindow(time.time(), 60, deque()),
            "hour": RateLimitWindow(time.time(), 3600, deque())
        })
        
        # Metrics per service
        self.metrics: Dict[str, RateLimitMetrics] = defaultdict(RateLimitMetrics)
        
        # Service configurations
        self.configs: Dict[str, RateLimitConfig] = {}
        
        # Load default configurations
        self._load_default_configs()
        
        # Load persisted state
        self._load_state()
    
    def _load_default_configs(self):
        """Load default rate limiting configurations for known services."""
        default_configs = {
            "bgp_he_net": RateLimitConfig(
                service="bgp_he_net",
                requests_per_minute=30,
                requests_per_hour=1000,
                burst_limit=5
            ),
            "crt_sh": RateLimitConfig(
                service="crt_sh",
                requests_per_minute=60,
                requests_per_hour=2000,
                burst_limit=10
            ),
            "dnsdumpster": RateLimitConfig(
                service="dnsdumpster",
                requests_per_minute=10,
                requests_per_hour=100,
                burst_limit=3
            ),
            "shodan": RateLimitConfig(
                service="shodan",
                requests_per_minute=10,
                requests_per_hour=100,
                burst_limit=2
            ),
            "virustotal": RateLimitConfig(
                service="virustotal",
                requests_per_minute=4,
                requests_per_hour=500,
                burst_limit=1
            ),
            "censys": RateLimitConfig(
                service="censys",
                requests_per_minute=10,
                requests_per_hour=1000,
                burst_limit=3
            ),
            "securitytrails": RateLimitConfig(
                service="securitytrails",
                requests_per_minute=10,
                requests_per_hour=1000,
                burst_limit=3
            ),
            "alienvault_otx": RateLimitConfig(
                service="alienvault_otx",
                requests_per_minute=30,
                requests_per_hour=2000,
                burst_limit=5
            ),
            "cloud_detection": RateLimitConfig(
                service="cloud_detection",
                requests_per_minute=120,  # High limit for pattern matching
                requests_per_hour=5000,   # Local processing, no external API
                burst_limit=20
            )
        }
        
        for service, config in default_configs.items():
            self.set_rate_limit_config(service, config)
    
    def set_rate_limit_config(self, service: str, config: RateLimitConfig):
        """
        Set rate limiting configuration for a service.
        
        Args:
            service: Service name
            config: Rate limit configuration
        """
        with self.lock:
            self.configs[service] = config
            logger.info(f"Rate limit config set for {service}: {config.requests_per_minute}/min, {config.requests_per_hour}/hour")
    
    def get_rate_limit_config(self, service: str) -> Optional[RateLimitConfig]:
        """Get rate limiting configuration for a service."""
        return self.configs.get(service)
    
    @contextmanager
    def acquire(self, service: str, operation: str = "request"):
        """
        Context manager to acquire rate limit permission.
        
        Args:
            service: Service name
            operation: Operation description for logging
            
        Usage:
            with rate_limiter.acquire("shodan", "ip_search"):
                # Make API call
                response = requests.get(url)
        """
        start_time = time.time()
        
        try:
            # Wait for permission
            wait_time = self._wait_for_permission(service)
            
            # Record metrics
            with self.lock:
                metrics = self.metrics[service]
                metrics.total_requests += 1
                metrics.last_request_time = time.time()
                
                if wait_time > 0:
                    # Update average wait time
                    if metrics.average_wait_time == 0:
                        metrics.average_wait_time = wait_time
                    else:
                        metrics.average_wait_time = (metrics.average_wait_time + wait_time) / 2
            
            yield
            
            # Mark successful request
            with self.lock:
                self.metrics[service].successful_requests += 1
                
        except Exception as e:
            logger.error(f"Error during rate limited operation for {service}.{operation}: {e}")
            raise
        finally:
            # Record request completion
            self._record_request(service)
            
            # Save state periodically
            if time.time() % 60 < 1:  # Approximately once per minute
                self._save_state()
    
    def _wait_for_permission(self, service: str) -> float:
        """Wait until permission is granted to make a request."""
        start_wait = time.time()
        config = self.configs.get(service)
        
        # CRITICAL FIX: Add maximum wait time to prevent indefinite blocking
        MAX_WAIT_TIME = 120  # Maximum 2 minutes wait
        total_waited = 0.0
        
        with self.lock:
            while not self._can_make_request(service, time.time()):
                wait_time = self._calculate_wait_time(service, time.time())
                
                # CRITICAL: Check if we've waited too long
                if total_waited >= MAX_WAIT_TIME:
                    logger.warning(f"Rate limiter timeout after {MAX_WAIT_TIME}s for {service}")
                    # Instead of waiting indefinitely, raise an exception or break
                    from src.core.exceptions import RateLimitError
                    raise RateLimitError(
                        source=service,
                        message=f"Rate limiter timeout after {MAX_WAIT_TIME}s",
                        retry_after=30  # Suggest retry in 30 seconds
                    )
                
                # Limit individual wait time to reasonable maximum
                wait_time = min(wait_time, 30.0)  # Max 30 seconds per wait
                
                # Add jitter to prevent thundering herd
                jitter = random.uniform(0, config.jitter_max_seconds) if config else 0
                wait_time += jitter
                
                logger.debug(f"Rate limit hit for {service}, waiting {wait_time:.2f}s (total waited: {total_waited:.1f}s)")
                
                # Record blocked request
                self.metrics[service].blocked_requests += 1
                self.metrics[service].last_blocked_time = time.time()
                
                # Release lock while waiting
                self.lock.release()
                try:
                    time.sleep(wait_time)
                    total_waited += wait_time
                finally:
                    self.lock.acquire()
                
                current_time = time.time()
                self._clean_windows(service, current_time)
        
        return time.time() - start_wait
    
    def _can_make_request(self, service: str, current_time: float) -> bool:
        """Check if a request can be made given current rate limits."""
        config = self.configs.get(service)
        if not config:
            return True
        
        windows = self.windows[service]
        
        # Check minute window
        minute_window = windows["minute"]
        if len(minute_window.requests) >= config.requests_per_minute:
            return False
        
        # Check hour window
        hour_window = windows["hour"]
        if len(hour_window.requests) >= config.requests_per_hour:
            return False
        
        # Check burst limit if configured
        if config.burst_limit:
            # Count requests in last 10 seconds
            recent_requests = sum(1 for req_time in minute_window.requests 
                                if current_time - req_time <= 10)
            if recent_requests >= config.burst_limit:
                return False
        
        return True
    
    def _calculate_wait_time(self, service: str, current_time: float) -> float:
        """Calculate how long to wait before next request."""
        config = self.configs.get(service)
        if not config:
            return 0.0
        
        windows = self.windows[service]
        wait_times = []
        
        # Check minute window
        minute_window = windows["minute"]
        if len(minute_window.requests) >= config.requests_per_minute:
            oldest_request = minute_window.requests[0]
            wait_time = 60 - (current_time - oldest_request)
            if wait_time > 0:
                wait_times.append(wait_time)
        
        # Check hour window
        hour_window = windows["hour"]
        if len(hour_window.requests) >= config.requests_per_hour:
            oldest_request = hour_window.requests[0]
            wait_time = 3600 - (current_time - oldest_request)
            if wait_time > 0:
                wait_times.append(wait_time)
        
        # Check burst limit
        if config.burst_limit:
            recent_requests = [req_time for req_time in minute_window.requests 
                             if current_time - req_time <= 10]
            if len(recent_requests) >= config.burst_limit:
                oldest_recent = min(recent_requests)
                wait_time = 10 - (current_time - oldest_recent)
                if wait_time > 0:
                    wait_times.append(wait_time)
        
        return max(wait_times) if wait_times else 0.0
    
    def _clean_windows(self, service: str, current_time: float):
        """Remove old requests from sliding windows."""
        windows = self.windows[service]
        
        # Clean minute window
        minute_window = windows["minute"]
        while (minute_window.requests and 
               current_time - minute_window.requests[0] > 60):
            minute_window.requests.popleft()
        
        # Clean hour window
        hour_window = windows["hour"]
        while (hour_window.requests and 
               current_time - hour_window.requests[0] > 3600):
            hour_window.requests.popleft()
    
    def _record_request(self, service: str):
        """Record a completed request."""
        current_time = time.time()
        
        with self.lock:
            windows = self.windows[service]
            windows["minute"].requests.append(current_time)
            windows["hour"].requests.append(current_time)
    
    def get_current_usage(self, service: str) -> Dict[str, int]:
        """
        Get current rate limit usage for a service.
        
        Args:
            service: Service name
            
        Returns:
            Dictionary with current usage statistics
        """
        with self.lock:
            current_time = time.time()
            self._clean_windows(service, current_time)
            
            windows = self.windows[service]
            config = self.configs.get(service)
            
            usage = {
                "requests_last_minute": len(windows["minute"].requests),
                "requests_last_hour": len(windows["hour"].requests),
                "limit_per_minute": config.requests_per_minute if config else 0,
                "limit_per_hour": config.requests_per_hour if config else 0,
                "available_minute": (config.requests_per_minute - len(windows["minute"].requests)) if config else 0,
                "available_hour": (config.requests_per_hour - len(windows["hour"].requests)) if config else 0
            }
            
            if config and config.burst_limit:
                recent_requests = sum(1 for req_time in windows["minute"].requests 
                                    if current_time - req_time <= 10)
                usage.update({
                    "requests_last_10_seconds": recent_requests,
                    "burst_limit": config.burst_limit,
                    "available_burst": config.burst_limit - recent_requests
                })
            
            return usage
    
    def get_metrics(self, service: Optional[str] = None) -> Dict[str, Any]:
        """
        Get rate limiting metrics.
        
        Args:
            service: Specific service name, or None for all services
            
        Returns:
            Dictionary with metrics
        """
        with self.lock:
            if service:
                if service in self.metrics:
                    metrics = asdict(self.metrics[service])
                    metrics["current_usage"] = self.get_current_usage(service)
                    return {service: metrics}
                else:
                    return {}
            else:
                all_metrics = {}
                for svc in self.metrics:
                    metrics = asdict(self.metrics[svc])
                    metrics["current_usage"] = self.get_current_usage(svc)
                    all_metrics[svc] = metrics
                return all_metrics
    
    def reset_metrics(self, service: Optional[str] = None):
        """Reset metrics for a service or all services."""
        with self.lock:
            if service:
                if service in self.metrics:
                    self.metrics[service] = RateLimitMetrics()
                    logger.info(f"Reset metrics for {service}")
            else:
                self.metrics.clear()
                logger.info("Reset all rate limiting metrics")
    
    def _save_state(self):
        """Save rate limiting state to file."""
        try:
            state = {
                "timestamp": time.time(),
                "windows": {},
                "metrics": {}
            }
            
            # Save windows (convert deques to lists for JSON serialization)
            for service, windows in self.windows.items():
                state["windows"][service] = {
                    "minute": {
                        "window_start": windows["minute"].window_start,
                        "window_size": windows["minute"].window_size,
                        "requests": list(windows["minute"].requests)
                    },
                    "hour": {
                        "window_start": windows["hour"].window_start,
                        "window_size": windows["hour"].window_size,
                        "requests": list(windows["hour"].requests)
                    }
                }
            
            # Save metrics
            for service, metrics in self.metrics.items():
                state["metrics"][service] = asdict(metrics)
            
            with open(self.persistence_file, 'w') as f:
                json.dump(state, f, indent=2)
            
            logger.debug(f"Rate limiting state saved to {self.persistence_file}")
            
        except Exception as e:
            logger.error(f"Error saving rate limiting state: {e}")
    
    def _load_state(self):
        """Load rate limiting state from file."""
        if not self.persistence_file.exists():
            logger.info("No existing rate limiting state file found")
            return
        
        try:
            with open(self.persistence_file, 'r') as f:
                state = json.load(f)
            
            current_time = time.time()
            saved_time = state.get("timestamp", 0)
            
            # Only load if state is recent (within last hour)
            if current_time - saved_time > 3600:
                logger.info("Rate limiting state file is too old, starting fresh")
                return
            
            # Load windows
            for service, windows_data in state.get("windows", {}).items():
                self.windows[service] = {
                    "minute": RateLimitWindow(
                        windows_data["minute"]["window_start"],
                        windows_data["minute"]["window_size"],
                        deque(windows_data["minute"]["requests"])
                    ),
                    "hour": RateLimitWindow(
                        windows_data["hour"]["window_start"],
                        windows_data["hour"]["window_size"],
                        deque(windows_data["hour"]["requests"])
                    )
                }
                
                # Clean old requests
                self._clean_windows(service, current_time)
            
            # Load metrics
            for service, metrics_data in state.get("metrics", {}).items():
                self.metrics[service] = RateLimitMetrics(**metrics_data)
            
            logger.info(f"Rate limiting state loaded from {self.persistence_file}")
            
        except Exception as e:
            logger.error(f"Error loading rate limiting state: {e}")
    
    def shutdown(self):
        """Save state and clean up."""
        logger.info("Shutting down rate limiter")
        self._save_state()

# Global rate limiter instance
_rate_limiter: Optional[RateLimiter] = None

def get_rate_limiter() -> RateLimiter:
    """Get global rate limiter instance."""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter()
    return _rate_limiter

def rate_limit(service: str, operation: str = "request"):
    """
    Decorator for rate limiting function calls.
    
    Args:
        service: Service name
        operation: Operation description
    
    Usage:
        @rate_limit("shodan", "search")
        def search_shodan(query):
            return requests.get(f"https://api.shodan.io/search?q={query}")
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            limiter = get_rate_limiter()
            with limiter.acquire(service, operation):
                return func(*args, **kwargs)
        return wrapper
    return decorator 