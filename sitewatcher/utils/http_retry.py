# sitewatcher/utils/http_retry.py
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from random import random
from typing import Any, Iterable, Optional

import httpx


# Exceptions considered transient and worth retrying for idempotent requests.
# (We only expose GET here, so idempotency is guaranteed by design.)
_RETRYABLE_EXC: tuple[type[Exception], ...] = (
    httpx.ConnectTimeout,
    httpx.ReadTimeout,
    httpx.WriteTimeout,
    httpx.PoolTimeout,
    httpx.ConnectError,
    httpx.ReadError,
    httpx.WriteError,
    httpx.ProtocolError,  # covers RemoteProtocolError / LocalProtocolError
)


def _clamp(x: float, lo: float, hi: float) -> float:
    return lo if x < lo else hi if x > hi else x


def _parse_retry_after(header: Optional[str]) -> Optional[float]:
    """
    Parse Retry-After header into seconds.
    Supports both delta-seconds and HTTP-date per RFC 7231.
    """
    if not header:
        return None
    s = header.strip()
    # delta-seconds
    try:
        return float(s)
    except ValueError:
        pass
    # HTTP-date
    try:
        dt = parsedate_to_datetime(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        secs = (dt - datetime.now(timezone.utc)).total_seconds()
        return max(0.0, secs)
    except Exception:
        return None


async def get_with_retries(
    client: httpx.AsyncClient,
    url: str,
    *,
    headers: Optional[dict[str, str]] = None,
    timeout_s: float = 5.0,
    retries: int = 2,
    backoff_s: float = 0.3,
    retry_on_status: Iterable[int] = (408, 429, 500, 502, 503, 504),
    follow_redirects: bool = False,
    max_backoff_s: float = 5.0,
    jitter: float = 0.1,
    **kwargs: Any,
) -> httpx.Response:
    """
    Perform a GET with bounded retries and exponential backoff.

    Behavior:
      - Retries on a curated set of transient transport errors (timeouts, protocol/IO) and
        on selected HTTP status codes (408, 429, 5xx).
      - Exponential backoff with small jitter; capped by `max_backoff_s`.
      - If 429/503 contains a valid Retry-After header, we honor it (capped).
      - Connections are closed promptly before sleeping to free the pool.

    Args:
        client: httpx.AsyncClient configured by caller.
        url: Request URL.
        headers: Optional HTTP headers.
        timeout_s: Total per-request timeout (seconds) passed to httpx.
        retries: Number of retry *attempts* after the initial try.
        backoff_s: Initial backoff (seconds).
        retry_on_status: Status codes to retry.
        follow_redirects: Whether to follow redirects.
        max_backoff_s: Upper bound for any single sleep.
        jitter: Random multiplier in [0, jitter] applied to backoff.

    Returns:
        httpx.Response (caller is responsible for reading/closing if needed).

    Raises:
        httpx.RequestError / httpx.HTTPStatusError (after exhausted retries).
    """
    attempt = 0
    delay = float(backoff_s)

    while True:
        try:
            resp = await client.get(
                url,
                headers=headers,
                timeout=timeout_s,
                follow_redirects=follow_redirects,
                **kwargs,
            )

            # Retry on specific status codes
            if attempt < retries and resp.status_code in retry_on_status:
                retry_after_hdr = resp.headers.get("Retry-After")
                retry_after = _parse_retry_after(retry_after_hdr) if retry_after_hdr else None

                # Proactively release connection before sleeping
                try:
                    await resp.aclose()
                except Exception:
                    pass

                if retry_after is not None and resp.status_code in (429, 503):
                    sleep_for = _clamp(retry_after, 0.0, max_backoff_s)
                else:
                    sleep_for = _clamp(delay * (1.0 + random() * jitter), 0.0, max_backoff_s)

                await asyncio.sleep(sleep_for)
                attempt += 1
                delay = _clamp(delay * 2.0, backoff_s, max_backoff_s)
                continue

            return resp

        except _RETRYABLE_EXC as e:
            # Give up if no retries left
            if attempt >= retries:
                raise

            # Async cancellation should not be masked
            if isinstance(e, asyncio.CancelledError):  # defensive; not in tuple above
                raise

            # Sleep with backoff + jitter, then retry
            sleep_for = _clamp(delay * (1.0 + random() * jitter), 0.0, max_backoff_s)
            await asyncio.sleep(sleep_for)
            attempt += 1
            delay = _clamp(delay * 2.0, backoff_s, max_backoff_s)