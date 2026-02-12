import time
import random
import logging
import requests

logger = logging.getLogger(__name__)


def api_request_with_retry(method, url, headers=None, params=None, json=None,
                           max_retries=5, timeout=30, max_backoff=300):
    """Make an HTTP request with exponential backoff + jitter on failure.

    Args:
        max_retries: Number of attempts (default 5 → retries over ~5-10 minutes).
        timeout: Per-request timeout in seconds.
        max_backoff: Cap on backoff delay in seconds (default 300 = 5 min).

    Retry policy:
        - Retries on: network errors, 429 rate limits, 5xx server errors.
        - Does NOT retry on 4xx client errors (except 429) — they won't succeed.
        - Exponential backoff: 2^attempt seconds + random jitter (0-2s).
        - Backoff sequence: ~1s, ~2s, ~4s, ~8s, ~16s ... capped at max_backoff.
        - Respects Retry-After header on 429 responses.
        - Raises on exhausted retries instead of returning None.
    """
    # Import Sentry if available
    try:
        import sentry_sdk
        sentry_available = True
    except ImportError:
        sentry_available = False

    # Add breadcrumb for the API request
    if sentry_available:
        # Determine API service from URL
        service = 'unknown'
        if 'shopify.com' in url:
            service = 'shopify'
        elif 'parcelpanel.com' in url:
            service = 'parcelpanel'
        elif 'sendgrid.com' in url:
            service = 'sendgrid'

        sentry_sdk.add_breadcrumb(
            category='http',
            message=f'{method} {service}',
            level='info',
            data={
                'url': url.split('?')[0],  # Remove query params
                'method': method,
                'service': service,
            }
        )

    last_exception = None
    for attempt in range(max_retries):
        try:
            resp = requests.request(
                method, url,
                headers=headers,
                params=params,
                json=json,
                timeout=timeout,
            )
            if resp.status_code == 429:
                # Parse Retry-After header (can be seconds or HTTP-date per RFC 7231)
                try:
                    retry_after = float(resp.headers.get('Retry-After', min(2 ** attempt, max_backoff)))
                except (ValueError, TypeError):
                    # Fall back to exponential backoff if Retry-After is malformed (e.g., HTTP-date)
                    retry_after = min(2 ** attempt, max_backoff)
                    logger.warning("Malformed Retry-After header, using exponential backoff")

                jitter = random.uniform(0, 2)
                wait = max(0, retry_after) + jitter  # Ensure wait is never negative
                logger.warning("Rate limited on %s (attempt %d/%d), retrying in %.1fs",
                               url, attempt + 1, max_retries, wait)
                time.sleep(wait)
                last_exception = requests.HTTPError(
                    f"429 Too Many Requests for url: {url}", response=resp
                )
                continue
            if resp.status_code >= 500:
                if attempt < max_retries - 1:
                    wait = min(2 ** attempt, max_backoff) + random.uniform(0, 2)
                    logger.warning("Server error %d on %s (attempt %d/%d), retrying in %.1fs",
                                   resp.status_code, url, attempt + 1, max_retries, wait)
                    time.sleep(wait)
                    continue
                resp.raise_for_status()
            resp.raise_for_status()
            return resp
        except requests.RequestException as e:
            last_exception = e
            if attempt == max_retries - 1:
                raise
            # Only retry on connection/timeout errors, not 4xx HTTP errors
            if isinstance(e, requests.HTTPError) and e.response is not None:
                if 400 <= e.response.status_code < 500 and e.response.status_code != 429:
                    raise  # Don't retry client errors
            wait = min(2 ** attempt, max_backoff) + random.uniform(0, 2)
            logger.warning("Request to %s failed (attempt %d/%d): %s — retrying in %.1fs",
                           url, attempt + 1, max_retries, e, wait)
            time.sleep(wait)

    # If we exhausted retries (e.g., all 429s), raise instead of returning None
    if last_exception:
        raise last_exception
    raise requests.RequestException(f"Request to {url} failed after {max_retries} retries")
