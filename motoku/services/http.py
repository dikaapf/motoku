"""HTTP helpers shared by providers: retry with exponential backoff."""

import time

import requests

RETRY_STATUSES = (429, 500, 502, 503, 504)


def get_with_retry(url, *, attempts=3, backoff=2.0, retry_statuses=RETRY_STATUSES, **kwargs):
    """``requests.get`` that retries transient failures.

    Honours ``Retry-After`` (capped at 30s). The last response is returned even
    if it still has a retryable status, so callers keep normal error handling.
    """
    last_exc = None
    for attempt in range(attempts):
        try:
            resp = requests.get(url, **kwargs)
        except (requests.ConnectionError, requests.Timeout) as e:
            last_exc = e
            resp = None
        if resp is not None and resp.status_code not in retry_statuses:
            return resp
        if attempt == attempts - 1:
            if resp is not None:
                return resp
            raise last_exc
        delay = backoff * (2 ** attempt)
        if resp is not None:
            retry_after = resp.headers.get('Retry-After', '')
            if retry_after.isdigit():
                delay = min(30, int(retry_after))
        time.sleep(delay)
    raise last_exc  # pragma: no cover
