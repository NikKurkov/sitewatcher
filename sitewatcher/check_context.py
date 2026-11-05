"""Bounded, in-memory network observations owned by one monitoring cycle."""
from __future__ import annotations

import asyncio
import socket
import time
from collections.abc import Awaitable, Callable, Hashable
from dataclasses import dataclass
from typing import Any

import httpx

from .utils.http_body import BodyReadError
from .utils.http_retry import get_with_retries


@dataclass(frozen=True)
class PageObservation:
    initial: httpx.Response
    final: httpx.Response
    initial_ms: int
    total_ms: int
    redirect_error: httpx.RequestError | None = None

    def content_response(self) -> httpx.Response:
        if self.redirect_error is not None:
            raise self.redirect_error
        return self.final


class CheckContext:
    """Coalesce equivalent work; discard every observation on context exit.

    Callers must close the context at the cycle boundary. Waiters shield shared
    work from individual cancellation; the last departing waiter cancels it.
    """

    def __init__(self) -> None:
        self._tasks: dict[Hashable, asyncio.Task] = {}
        self._waiters: dict[Hashable, int] = {}
        self._closed = False

    async def __aenter__(self) -> CheckContext:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        self._closed = True
        tasks = list(self._tasks.values())
        for task in tasks:
            if not task.done():
                task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._tasks.clear()
        self._waiters.clear()

    async def run_probe(self, key: Hashable, factory: Callable[[], Awaitable[Any]]) -> Any:
        if self._closed:
            raise RuntimeError('check context is closed')
        task = self._tasks.get(key)
        if task is None:
            task = asyncio.create_task(factory())
            self._tasks[key] = task
        self._waiters[key] = self._waiters.get(key, 0) + 1
        try:
            return await asyncio.shield(task)
        finally:
            remaining = self._waiters.get(key, 1) - 1
            if remaining:
                self._waiters[key] = remaining
            else:
                self._waiters.pop(key, None)
                if not task.done():
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                    self._tasks.pop(key, None)

    async def resolve(self, domain: str, family: int = socket.AF_UNSPEC) -> list:
        name = domain.lower().rstrip('.')
        broad_key = ('dns', name, socket.AF_UNSPEC)
        if family != socket.AF_UNSPEC and broad_key in self._tasks:
            infos = await self.run_probe(broad_key, lambda: self._resolve(name, socket.AF_UNSPEC))
            return [info for info in infos if info[0] == family]
        return await self.run_probe(('dns', name, family), lambda: self._resolve(name, family))

    @staticmethod
    async def _resolve(domain: str, family: int) -> list:
        return await asyncio.get_running_loop().getaddrinfo(
            domain, 80, family=family, type=socket.SOCK_STREAM,
        )

    async def fetch_page(
        self, client: httpx.AsyncClient, url: str, *, timeout_s: float,
        max_response_bytes: int, owner_id: int | None = None, domain: str = '',
        proxy: str | None = None,
    ) -> PageObservation:
        key = ('page', owner_id, domain, id(client), proxy, url, timeout_s, max_response_bytes)
        return await self.run_probe(key, lambda: self._fetch_page(
            client, url, timeout_s=timeout_s, max_response_bytes=max_response_bytes,
        ))

    @staticmethod
    async def _fetch_page(
        client: httpx.AsyncClient, url: str, *, timeout_s: float, max_response_bytes: int,
    ) -> PageObservation:
        options = dict(
            timeout_s=timeout_s, max_response_bytes=max_response_bytes,
            retries=2, backoff_s=0.3,
            headers={'User-Agent': 'sitewatcher/0.2 (+https://github.com/NikKurkov/sitewatcher)'},
        )
        start = time.perf_counter()
        initial = await get_with_retries(client, url, follow_redirects=False, **options)
        initial_ms = int((time.perf_counter() - start) * 1000)
        final = initial
        error = None
        if 300 <= initial.status_code < 400 and 'location' in initial.headers:
            target = str(initial.url.join(initial.headers['location']))
            try:
                final = await get_with_retries(
                    client, target, follow_redirects=True,
                    prior_body_bytes=initial.extensions.get('body_bytes', (0, 0)), **options,
                )
                final.history = [initial, *final.history]
            except BodyReadError:
                raise
            except httpx.RequestError as exc:
                error = exc
        total_ms = int((time.perf_counter() - start) * 1000)
        final.extensions['cycle_latency_ms'] = total_ms
        return PageObservation(initial, final, initial_ms, total_ms, error)
