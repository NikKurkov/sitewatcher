# sitewatcher/utils/http_retry.py
from __future__ import annotations

import asyncio
import random
from typing import Iterable
import httpx

# исключения, которые считаем временными
_RETRYABLE_EXC = (
    httpx.ConnectTimeout,
    httpx.ReadTimeout,
    httpx.PoolTimeout,
    httpx.ConnectError,
)

async def get_with_retries(
    client: httpx.AsyncClient,
    url: str,
    *,
    timeout_s: float,
    retries: int = 2,
    backoff_s: float = 0.3,
    retry_on_status: Iterable[int] = (502, 503, 504),
    follow_redirects: bool = True,
    **kwargs,
) -> httpx.Response:
    """
    Идемпотентный GET с небольшим числом повторов на таймауты/502-504.
    retries=2 => всего до 3 попыток. Бэк-офф экспоненциальный с небольшим джиттером.
    """
    attempt = 0
    delay = float(backoff_s)

    while True:
        try:
            resp = await client.get(
                url,
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
