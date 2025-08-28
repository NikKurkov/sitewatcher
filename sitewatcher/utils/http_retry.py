# sitewatcher/utils/http_retry.py
from __future__ import annotations

import asyncio
import random
from typing import Iterable, Optional, Any
import httpx

# Exceptions that are considered transient and worth retrying.
_RETRYABLE_EXC = (
    httpx.ConnectTimeout,
    httpx.ReadTimeout,
    httpx.PoolTimeout,
    httpx.ConnectError,
    httpx.RemoteProtocolError,
)

async def get_with_retries(
    client: httpx.AsyncClient,
    url: str,
    *,
    headers: Optional[dict[str, str]] = None,
    timeout_s: float = 5.0,
    retries: int = 2,
    backoff_s: float = 0.3,
    retry_on_status: Iterable[int] = (502, 503, 504),
    follow_redirects: bool = False,
    **kwargs: Any,
) -> httpx.Response:
    """Perform GET with bounded retries and exponential backoff.

    Retries only for transient network errors and selected HTTP status codes.
    Time budget grows as: backoff_s * 2^attempt with small jitter.
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
            if resp.status_code in retry_on_status and attempt < retries:
                await asyncio.sleep(delay + random.random() * 0.1)
                attempt += 1
                delay *= 2
                continue
            return resp
        except _RETRYABLE_EXC:
            if attempt >= retries:
                raise
            await asyncio.sleep(delay + random.random() * 0.1)
            attempt += 1
            delay *= 2
