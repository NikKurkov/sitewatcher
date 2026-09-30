import asyncio

import httpx

from sitewatcher.checks.base import Status
from sitewatcher.checks.http_basic import HttpBasicCheck
from sitewatcher.config import AppConfig, HttpClientConfig
from sitewatcher.dispatcher import Dispatcher


def test_global_proxy_can_create_dispatcher_client():
    cfg = AppConfig(http=HttpClientConfig(proxy="http://127.0.0.1:12345"))

    async def run():
        async with Dispatcher(cfg):
            pass

    asyncio.run(run())


def test_domain_proxy_can_run_http_check(monkeypatch):
    created = []

    class ProxyClient:
        def __init__(self, *, proxy, **kwargs):
            created.append(proxy)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            pass

        async def get(self, url, **kwargs):
            return httpx.Response(200, request=httpx.Request("GET", url))

    monkeypatch.setattr("sitewatcher.checks.http_basic.httpx.AsyncClient", ProxyClient)
    check = HttpBasicCheck("example.com", client=None, proxy="http://127.0.0.1:12345")
    result = asyncio.run(check.run())

    assert result.status is Status.OK
    assert created == ["http://127.0.0.1:12345"]
