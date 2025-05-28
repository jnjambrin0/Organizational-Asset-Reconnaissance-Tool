import requests
import logging
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)
from typing import Any, Dict, Optional

from src.core.exceptions import DataSourceError, RateLimitError
from src.config.settings import get_settings

logger = logging.getLogger(__name__)

# Define exceptions that should trigger retries
RETRYABLE_EXCEPTIONS = (
    requests.exceptions.Timeout,
    requests.exceptions.ConnectionError,
    requests.exceptions.HTTPError,  # Retry on 5xx errors specifically below
    RateLimitError,  # Retry if we hit a rate limit, hoping it clears
)

# Define HTTP status codes that should trigger retries
RETRYABLE_STATUS_CODES = {500, 502, 503, 504, 429}  # Server errors and rate limiting

# Service unavailable status codes (503, 502) - require special handling
SERVICE_UNAVAILABLE_CODES = {502, 503}


# Custom retry condition: retry on specific HTTP status codes or specific exceptions
def should_retry(exception: BaseException) -> bool:
    if isinstance(exception, requests.exceptions.HTTPError):
        response = getattr(exception, "response", None)
        if response is not None and response.status_code in RETRYABLE_STATUS_CODES:
            logger.warning(f"Retrying due to HTTP status code: {response.status_code}")
            # If it's a rate limit error (429), raise our custom exception to handle specific wait times if needed
            if response.status_code == 429:
                raise RateLimitError(
                    source="Unknown", message="HTTP 429 Too Many Requests"
                )
            return True
        else:
            # Don't retry on other HTTP errors (e.g., 404 Not Found, 403 Forbidden)
            return False
    elif isinstance(exception, RETRYABLE_EXCEPTIONS):
        logger.warning(f"Retrying due to exception: {type(exception).__name__}")
        return True
    return False


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(
        multiplier=2, min=3, max=15
    ),  # Longer waits for service unavailable: 3s, 6s, 12s
    retry=retry_if_exception_type(RETRYABLE_EXCEPTIONS)
    | retry_if_exception_type(requests.exceptions.HTTPError),
    retry_error_callback=lambda retry_state: logger.error(
        f"Request failed after {retry_state.attempt_number} attempts: {retry_state.outcome.exception() if retry_state.outcome else 'Unknown error'}"
    ),
)
def make_request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, Any]] = None,
    data: Optional[Dict[str, Any]] = None,
    json_payload: Optional[Dict[str, Any]] = None,
    timeout: Optional[int] = None,
    source_name: str = "Unknown Source",
) -> requests.Response:
    """Makes an HTTP request with retry logic and improved service unavailable handling.

    Args:
        url: The URL to request.
        method: HTTP method (GET, POST, etc.).
        headers: Optional request headers.
        params: Optional URL parameters (for GET requests).
        data: Optional form data (for POST requests).
        json_payload: Optional JSON data (for POST requests).
        timeout: Request timeout in seconds (uses config default if None).
        source_name: Name of the data source for error reporting.

    Returns:
        The requests.Response object.

    Raises:
        DataSourceError: If the request fails after retries or encounters a non-retryable error.
        RateLimitError: If a 429 status code is encountered.
    """
    # CRITICAL FIX: Implement absolute maximum timeout to prevent infinite hangs
    ABSOLUTE_MAX_TIMEOUT = 30  # 30 seconds absolute maximum
    SAFE_DEFAULT_TIMEOUT = 15  # 15 seconds safe default

    # Get timeout from configuration if not provided
    if timeout is None:
        try:
            settings = get_settings()
            configured_timeout = getattr(
                settings.recon, "timeout_seconds", SAFE_DEFAULT_TIMEOUT
            )
            # Apply safety limits
            timeout = (
                min(configured_timeout, ABSOLUTE_MAX_TIMEOUT)
                if configured_timeout
                else SAFE_DEFAULT_TIMEOUT
            )
        except Exception as e:
            # Fallback to safe default if config fails
            timeout = SAFE_DEFAULT_TIMEOUT
    else:
        # Even if timeout is provided, enforce absolute maximum
        timeout = min(timeout, ABSOLUTE_MAX_TIMEOUT)

    logger.debug(
        f"Making {method} request to {url} from {source_name} with timeout {timeout}s"
    )

    common_headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    if headers:
        common_headers.update(headers)

    try:
        response = requests.request(
            method=method,
            url=url,
            headers=common_headers,
            params=params,
            data=data,
            json=json_payload,
            timeout=timeout,  # Now guaranteed to be <= ABSOLUTE_MAX_TIMEOUT
        )

        # Handle service unavailable errors with better messaging
        if response.status_code in SERVICE_UNAVAILABLE_CODES:
            error_msg = f"Service temporarily unavailable ({response.status_code}) for {source_name} at {url}"
            logger.warning(error_msg)
            # Raise HTTPError to trigger retry logic
            response.raise_for_status()

        # Raise RateLimitError specifically for 429
        if response.status_code == 429:
            logger.warning(f"Rate limit hit for {source_name} at {url}")
            raise RateLimitError(
                source=source_name, message="HTTP 429 Too Many Requests"
            )

        # Raise HTTPError for other bad responses (4xx, 5xx) to potentially trigger retry or fail
        response.raise_for_status()
        logger.debug(f"Request to {url} successful (Status: {response.status_code})")
        return response

    except requests.exceptions.Timeout as e:
        error_msg = f"Request timeout ({timeout}s) for {source_name} at {url}: {e}"
        logger.error(error_msg)
        raise DataSourceError(source=source_name, message=error_msg) from e
    except requests.exceptions.RequestException as e:
        # This catches base RequestException and its subclasses (like ConnectionError, Timeout, HTTPError)
        logger.error(f"Request failed for {source_name} at {url}: {e}")
        # If it's a rate limit error we raised, re-raise it
        if isinstance(e, RateLimitError):
            raise e
        # For service unavailable errors, provide more specific messaging
        if (
            hasattr(e, "response")
            and e.response is not None
            and e.response.status_code in SERVICE_UNAVAILABLE_CODES
        ):
            error_msg = f"Service {source_name} is temporarily unavailable (HTTP {e.response.status_code}). This is likely temporary - please try again later."
            raise DataSourceError(source=source_name, message=error_msg) from e
        # Wrap other request exceptions in DataSourceError
        raise DataSourceError(source=source_name, message=str(e)) from e
    except Exception as e:
        # Catch any other unexpected exceptions
        logger.exception(
            f"Unexpected error during request to {source_name} at {url}: {e}"
        )  # Use logger.exception to include traceback
        raise DataSourceError(
            source=source_name, message=f"Unexpected error: {e}"
        ) from e
