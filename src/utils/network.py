import requests
import logging
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from typing import Any, Dict, Optional

from src.core.exceptions import DataSourceError, RateLimitError
from src.config.settings import get_settings

logger = logging.getLogger(__name__)

# Define exceptions that should trigger retries
RETRYABLE_EXCEPTIONS = (
    requests.exceptions.Timeout,
    requests.exceptions.ConnectionError,
    requests.exceptions.HTTPError, # Retry on 5xx errors specifically below
    RateLimitError # Retry if we hit a rate limit, hoping it clears
)

# Define HTTP status codes that should trigger retries
RETRYABLE_STATUS_CODES = {500, 502, 503, 504, 429} # Server errors and rate limiting

# Custom retry condition: retry on specific HTTP status codes or specific exceptions
def should_retry(exception: BaseException) -> bool:
    if isinstance(exception, requests.exceptions.HTTPError):
        response = getattr(exception, 'response', None)
        if response is not None and response.status_code in RETRYABLE_STATUS_CODES:
            logger.warning(f"Retrying due to HTTP status code: {response.status_code}")
            # If it's a rate limit error (429), raise our custom exception to handle specific wait times if needed
            if response.status_code == 429:
                 raise RateLimitError(source="Unknown", message="HTTP 429 Too Many Requests")
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
    wait=wait_exponential(multiplier=1, min=2, max=10), # Exponential backoff: 2s, 4s
    retry=retry_if_exception_type(RETRYABLE_EXCEPTIONS) | retry_if_exception_type(requests.exceptions.HTTPError), # Need HTTPError here for the custom logic below
    retry_error_callback=lambda retry_state: logger.error(f"Request failed after {retry_state.attempt_number} attempts: {retry_state.outcome.exception()}")
)
def make_request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, Any]] = None,
    data: Optional[Dict[str, Any]] = None,
    json_payload: Optional[Dict[str, Any]] = None,
    timeout: Optional[int] = None,
    source_name: str = "Unknown Source"
) -> requests.Response:
    """Makes an HTTP request with retry logic.

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
    # Get timeout from configuration if not provided
    if timeout is None:
        settings = get_settings()
        timeout = settings.recon.timeout_seconds
    
    logger.debug(f"Making {method} request to {url} from {source_name}")
    common_headers = {
        'User-Agent': 'OrgReconTool/1.0 (+https://github.com/your_repo_here)' # Be a good internet citizen
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
            timeout=timeout
        )

        # Raise RateLimitError specifically for 429
        if response.status_code == 429:
             logger.warning(f"Rate limit hit for {source_name} at {url}")
             raise RateLimitError(source=source_name, message="HTTP 429 Too Many Requests")

        # Raise HTTPError for other bad responses (4xx, 5xx) to potentially trigger retry or fail
        response.raise_for_status()
        logger.debug(f"Request to {url} successful (Status: {response.status_code})")
        return response

    except requests.exceptions.RequestException as e:
        # This catches base RequestException and its subclasses (like ConnectionError, Timeout, HTTPError)
        logger.error(f"Request failed for {source_name} at {url}: {e}")
        # If it's a rate limit error we raised, re-raise it
        if isinstance(e, RateLimitError):
             raise e
        # Wrap other request exceptions in DataSourceError
        raise DataSourceError(source=source_name, message=str(e)) from e
    except Exception as e:
        # Catch any other unexpected exceptions
        logger.exception(f"Unexpected error during request to {source_name} at {url}: {e}") # Use logger.exception to include traceback
        raise DataSourceError(source=source_name, message=f"Unexpected error: {e}") from e 