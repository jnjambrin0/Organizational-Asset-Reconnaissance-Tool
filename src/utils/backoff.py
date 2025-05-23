"""
Exponential backoff and retry utilities for handling rate limits and transient errors.

This module provides decorators and utilities for implementing exponential backoff
with jitter to handle HTTP 429 errors and other rate limiting scenarios.
"""

import time
import random
import logging
import functools
from typing import Callable, Optional, Tuple, Type, Union
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class BackoffConfig:
    """Configuration for exponential backoff behavior."""
    initial_delay: float = 1.0
    max_delay: float = 300.0  # 5 minutes
    backoff_factor: float = 2.0
    max_retries: int = 5
    jitter: bool = True
    jitter_max: float = 1.0

class RateLimitError(Exception):
    """Exception raised when rate limit is hit."""
    
    def __init__(self, message: str, retry_after: Optional[float] = None, response_code: Optional[int] = None):
        super().__init__(message)
        self.retry_after = retry_after
        self.response_code = response_code

class BackoffManager:
    """Manages exponential backoff for rate limited operations."""
    
    def __init__(self, config: Optional[BackoffConfig] = None):
        """
        Initialize backoff manager.
        
        Args:
            config: Backoff configuration (uses defaults if None)
        """
        self.config = config or BackoffConfig()
    
    def calculate_delay(self, attempt: int, base_delay: Optional[float] = None) -> float:
        """
        Calculate delay for given attempt number.
        
        Args:
            attempt: Attempt number (0-based)
            base_delay: Base delay override (uses config if None)
            
        Returns:
            Delay in seconds
        """
        base = base_delay or self.config.initial_delay
        
        # Calculate exponential delay
        delay = base * (self.config.backoff_factor ** attempt)
        
        # Cap at max delay
        delay = min(delay, self.config.max_delay)
        
        # Add jitter if enabled
        if self.config.jitter:
            jitter = random.uniform(-self.config.jitter_max, self.config.jitter_max)
            delay = max(0, delay + jitter)
        
        return delay
    
    def should_retry(self, attempt: int, exception: Exception) -> bool:
        """
        Determine if operation should be retried.
        
        Args:
            attempt: Current attempt number (0-based)
            exception: Exception that occurred
            
        Returns:
            True if should retry, False otherwise
        """
        if attempt >= self.config.max_retries:
            return False
        
        # Always retry rate limit errors
        if isinstance(exception, RateLimitError):
            return True
        
        # Retry on specific HTTP errors
        if hasattr(exception, 'response'):
            status_code = getattr(exception.response, 'status_code', None)
            if status_code in [429, 502, 503, 504]:  # Rate limit, bad gateway, service unavailable, gateway timeout
                return True
        
        # Retry on connection errors
        if any(error_type in str(type(exception)) for error_type in ['ConnectionError', 'Timeout', 'ReadTimeout']):
            return True
        
        return False
    
    def extract_retry_after(self, exception: Exception) -> Optional[float]:
        """
        Extract retry-after header value from HTTP exception.
        
        Args:
            exception: Exception that occurred
            
        Returns:
            Retry-after value in seconds, or None if not found
        """
        if isinstance(exception, RateLimitError) and exception.retry_after:
            return exception.retry_after
        
        if hasattr(exception, 'response'):
            response = exception.response
            retry_after = getattr(response, 'headers', {}).get('Retry-After')
            
            if retry_after:
                try:
                    return float(retry_after)
                except ValueError:
                    # Retry-After might be in HTTP date format
                    logger.warning(f"Unable to parse Retry-After header: {retry_after}")
        
        return None
    
    def wait_with_backoff(self, attempt: int, exception: Optional[Exception] = None) -> float:
        """
        Wait with exponential backoff.
        
        Args:
            attempt: Current attempt number (0-based)
            exception: Exception that triggered the backoff (optional)
            
        Returns:
            Actual delay time used
        """
        # Check for explicit retry-after
        retry_after = None
        if exception:
            retry_after = self.extract_retry_after(exception)
        
        if retry_after:
            # Use server-specified delay
            delay = min(retry_after, self.config.max_delay)
        else:
            # Use exponential backoff
            delay = self.calculate_delay(attempt)
        
        logger.info(f"Backing off for {delay:.2f} seconds (attempt {attempt + 1})")
        time.sleep(delay)
        
        return delay

def with_exponential_backoff(
    config: Optional[BackoffConfig] = None,
    exceptions: Tuple[Type[Exception], ...] = (Exception,),
    on_retry: Optional[Callable] = None
):
    """
    Decorator for exponential backoff with retry logic.
    
    Args:
        config: Backoff configuration
        exceptions: Exception types to catch and retry
        on_retry: Callback function called on each retry attempt
    
    Usage:
        @with_exponential_backoff(BackoffConfig(max_retries=3))
        def api_call():
            response = requests.get("https://api.example.com/data")
            if response.status_code == 429:
                raise RateLimitError("Rate limit hit", retry_after=60)
            return response.json()
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            backoff_manager = BackoffManager(config)
            last_exception = None
            
            for attempt in range(backoff_manager.config.max_retries + 1):
                try:
                    result = func(*args, **kwargs)
                    
                    # Log successful retry
                    if attempt > 0:
                        logger.info(f"Operation succeeded after {attempt} retry attempts")
                    
                    return result
                    
                except exceptions as e:
                    last_exception = e
                    
                    # Check if we should retry
                    if not backoff_manager.should_retry(attempt, e):
                        logger.error(f"Max retries reached or non-retryable error: {e}")
                        raise
                    
                    # Call retry callback if provided
                    if on_retry:
                        try:
                            on_retry(attempt, e)
                        except Exception as callback_error:
                            logger.warning(f"Retry callback failed: {callback_error}")
                    
                    # Wait with backoff (except on last attempt)
                    if attempt < backoff_manager.config.max_retries:
                        backoff_manager.wait_with_backoff(attempt, e)
            
            # If we get here, all retries failed
            logger.error(f"All {backoff_manager.config.max_retries} retry attempts failed")
            raise last_exception
        
        return wrapper
    return decorator

def create_rate_limit_aware_session():
    """
    Create a requests session that automatically handles rate limits.
    
    Returns:
        Requests session configured with exponential backoff
    """
    import requests
    from requests.adapters import HTTPAdapter
    from requests.packages.urllib3.util.retry import Retry
    
    # Create retry strategy
    retry_strategy = Retry(
        total=5,
        status_forcelist=[429, 500, 502, 503, 504],
        method_whitelist=["HEAD", "GET", "OPTIONS"],
        backoff_factor=1.0
    )
    
    # Create session
    session = requests.Session()
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    return session

def handle_http_429(response) -> RateLimitError:
    """
    Convert HTTP 429 response to RateLimitError.
    
    Args:
        response: HTTP response object
        
    Returns:
        RateLimitError with extracted retry-after information
    """
    retry_after = response.headers.get('Retry-After')
    retry_after_seconds = None
    
    if retry_after:
        try:
            retry_after_seconds = float(retry_after)
        except ValueError:
            logger.warning(f"Unable to parse Retry-After header: {retry_after}")
    
    message = f"Rate limit exceeded (HTTP 429)"
    if retry_after_seconds:
        message += f" - retry after {retry_after_seconds} seconds"
    
    return RateLimitError(
        message=message,
        retry_after=retry_after_seconds,
        response_code=429
    )

# Pre-configured backoff decorators for common scenarios
def with_api_backoff(func: Callable) -> Callable:
    """Decorator with backoff configured for API calls."""
    config = BackoffConfig(
        initial_delay=1.0,
        max_delay=60.0,
        backoff_factor=2.0,
        max_retries=3
    )
    return with_exponential_backoff(config)(func)

def with_aggressive_backoff(func: Callable) -> Callable:
    """Decorator with aggressive backoff for critical operations."""
    config = BackoffConfig(
        initial_delay=2.0,
        max_delay=300.0,
        backoff_factor=3.0,
        max_retries=5
    )
    return with_exponential_backoff(config)(func)

def with_conservative_backoff(func: Callable) -> Callable:
    """Decorator with conservative backoff for non-critical operations."""
    config = BackoffConfig(
        initial_delay=0.5,
        max_delay=30.0,
        backoff_factor=1.5,
        max_retries=2
    )
    return with_exponential_backoff(config)(func) 