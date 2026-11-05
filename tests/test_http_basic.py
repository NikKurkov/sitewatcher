import asyncio

import httpx
import pytest

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

    class ProxyClient(httpx.AsyncClient):
        def __init__(self, *, proxy, **kwargs):
            created.append(proxy)
            super().__init__(transport=httpx.MockTransport(
                lambda request: httpx.Response(200),
            ), **kwargs)

    monkeypatch.setattr("sitewatcher.checks.http_basic.httpx.AsyncClient", ProxyClient)
    check = HttpBasicCheck("example.com", client=None, proxy="http://127.0.0.1:12345")
    result = asyncio.run(check.run())

    assert result.status is Status.OK
    assert created == ["http://127.0.0.1:12345"]


def test_standalone_http_redirect_count_keeps_existing_metric():
    async def run():
        def respond(request):
            if request.url.path == '/':
                return httpx.Response(302, headers={'location': '/middle'})
            if request.url.path == '/middle':
                return httpx.Response(302, headers={'location': '/landing'})
            return httpx.Response(200)

        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            result = await HttpBasicCheck('example.test', client).run()
        assert result.metrics['redirects'] == 1
        assert result.metrics['final_url'] == 'https://example.test/landing'

    asyncio.run(run())


@pytest.mark.parametrize('outcome', ['success', 'request', 'body', 'cancel'])
def test_standalone_http_context_closes_after_completion(monkeypatch, outcome):
    from sitewatcher.check_context import CheckContext

    contexts = []

    class RecordingContext(CheckContext):
        def __init__(self):
            super().__init__()
            contexts.append(self)

    monkeypatch.setattr('sitewatcher.checks.http_basic.CheckContext', RecordingContext)

    async def run():
        started = asyncio.Event()

        async def respond(request):
            if outcome == 'success':
                return httpx.Response(200)
            if outcome == 'request':
                raise httpx.TooManyRedirects('loop', request=request)
            if outcome == 'body':
                return httpx.Response(200, content=b'x' * 30)
            started.set()
            await asyncio.Event().wait()

        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            task = asyncio.create_task(HttpBasicCheck(
                'example.test', client, max_response_bytes=20,
            ).run())
            if outcome == 'cancel':
                await started.wait()
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
            else:
                result = await task
                assert result.status is {
                    'success': Status.OK, 'request': Status.CRIT, 'body': Status.UNKNOWN,
                }[outcome]
        assert len(contexts) == 1
        assert contexts[0]._closed
        assert not contexts[0]._tasks

    asyncio.run(run())
