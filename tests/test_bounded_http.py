import asyncio
import gzip
import zlib

import httpx
import pytest

from sitewatcher.checks.base import Status
from sitewatcher.checks.deface import DefaceCheck
from sitewatcher.checks.http_basic import HttpBasicCheck
from sitewatcher.checks.keywords import KeywordsCheck
from sitewatcher.utils.http_retry import get_with_retries


class CountingStream(httpx.AsyncByteStream):
    def __init__(self, chunks):
        self.chunks = chunks
        self.reads = 0
        self.closed = False

    async def __aiter__(self):
        for chunk in self.chunks:
            self.reads += 1
            yield chunk

    async def aclose(self):
        self.closed = True


@pytest.mark.parametrize('encoding', ['identity', 'gzip', 'deflate', 'raw-deflate'])
def test_bounded_get_reads_complete_supported_body(encoding):
    body = b'welcome ' * 100
    headers = {}
    wire = body
    if encoding == 'gzip':
        wire = gzip.compress(body)
        headers['Content-Encoding'] = 'gzip'
    elif encoding in {'deflate', 'raw-deflate'}:
        wire = zlib.compress(body)
        if encoding == 'raw-deflate':
            wire = wire[2:-4]
        headers['Content-Encoding'] = 'deflate'
    stream = CountingStream([wire[:1], wire[1:]])
    async def scenario():
        def handler(request):
            assert request.headers['accept-encoding'] == 'gzip, deflate'
            return httpx.Response(200, headers=headers, stream=stream,
                                  extensions={"http_version": b"HTTP/2"})
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await get_with_retries(client, 'https://example.test/', max_response_bytes=1024)
            assert result.content == body
            assert result.http_version == 'HTTP/2'
    asyncio.run(scenario())
    assert stream.closed


@pytest.mark.parametrize('encoding', ['identity', 'gzip', 'deflate'])
def test_bounded_get_stops_large_wire_or_decoded_body_without_retry(encoding):
    wire = b'x' * 1024
    headers = {}
    chunks = [wire, wire, b'unread']
    if encoding != 'identity':
        wire = gzip.compress(b'x' * 1_000_000) if encoding == 'gzip' else zlib.compress(b'x' * 1_000_000)
        headers['Content-Encoding'] = encoding
        chunks = [wire, b'unread']
    stream = CountingStream(chunks)
    calls = []
    async def scenario():
        def handler(request):
            calls.append(request)
            return httpx.Response(200, headers=headers, stream=stream)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(httpx.RequestError, match='body'):
                await get_with_retries(client, 'https://example.test/', max_response_bytes=1500)
    asyncio.run(scenario())
    assert len(calls) == 1
    assert stream.closed
    assert stream.reads < len(chunks)


@pytest.mark.parametrize('encoding', ['br', 'gzip, deflate', 'gzip-truncated', 'deflate-truncated'])
def test_bounded_get_rejects_unsupported_or_incomplete_encodings(encoding):
    wire = b'example'
    header = encoding
    if encoding.endswith('-truncated'):
        header = encoding.split('-')[0]
        wire = (gzip.compress(wire) if header == 'gzip' else zlib.compress(wire))[:-3]
    stream = CountingStream([wire])
    async def scenario():
        async with httpx.AsyncClient(transport=httpx.MockTransport(
            lambda request: httpx.Response(200, headers={'Content-Encoding': header}, stream=stream),
        )) as client:
            with pytest.raises(httpx.RequestError, match='body'):
                await get_with_retries(client, 'https://example.test/', max_response_bytes=1024)
    asyncio.run(scenario())
    assert stream.closed


@pytest.mark.parametrize('compressed', [False, True])
def test_bounded_redirect_chain_has_cumulative_budget_and_closes_hops(compressed):
    headers = {'Content-Encoding': 'gzip'} if compressed else {}
    encode = gzip.compress if compressed else lambda body: body
    streams = [CountingStream([encode(b'x' * 600)]), CountingStream([encode(b'y' * 600)])]
    async def scenario():
        def handler(request):
            if request.url.path == '/':
                return httpx.Response(302, headers={**headers, 'Location': '/next'}, stream=streams[0])
            return httpx.Response(200, headers=headers, stream=streams[1])
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(httpx.RequestError, match='body'):
                await get_with_retries(client, 'https://example.test/',
                                       max_response_bytes=1024, follow_redirects=True)
    asyncio.run(scenario())
    assert all(stream.closed for stream in streams)


@pytest.mark.parametrize('name', ['http_basic', 'keywords', 'deface'])
@pytest.mark.parametrize('status_code', [200, 503])
def test_page_checks_do_not_report_complete_inspection_after_body_limit(name, status_code):
    async def scenario():
        stream = CountingStream([b'welcome ' + b'x' * 2000])
        async with httpx.AsyncClient(transport=httpx.MockTransport(
            lambda request: httpx.Response(status_code, stream=stream),
        )) as client:
            if name == 'http_basic':
                check = HttpBasicCheck('example.test', client, max_response_bytes=1024)
            elif name == 'keywords':
                check = KeywordsCheck('example.test', client=client, keywords=['welcome'], max_response_bytes=1024)
            else:
                check = DefaceCheck('example.test', client=client, max_response_bytes=1024)
            result = await check.run()
            expected = Status.CRIT if status_code >= 400 and name != 'deface' else Status.UNKNOWN
            assert result.status is expected
        assert stream.closed
    asyncio.run(scenario())


def test_http_basic_budget_includes_its_initial_redirect_body():
    streams = [CountingStream([b'x' * 600]), CountingStream([b'y' * 600])]
    async def scenario():
        def handler(request):
            if request.url.path == '/':
                return httpx.Response(302, headers={'Location': '/next'}, stream=streams[0])
            return httpx.Response(200, stream=streams[1])
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await HttpBasicCheck('example.test', client, max_response_bytes=1024).run()
            assert result.status is Status.UNKNOWN
    asyncio.run(scenario())
    assert all(stream.closed for stream in streams)


def test_incomplete_wire_body_is_unknown_and_closed():
    class TruncatedStream(CountingStream):
        async def __aiter__(self):
            yield b'welcome'
            raise httpx.RemoteProtocolError('peer closed before completing message body')
    streams = []
    async def scenario():
        def handler(request):
            stream = TruncatedStream([])
            streams.append(stream)
            return httpx.Response(200, headers={'Content-Length': '100'}, stream=stream)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await KeywordsCheck('example.test', client=client, keywords=['welcome'],
                                         max_response_bytes=1024).run()
            assert result.status is Status.UNKNOWN
    asyncio.run(scenario())
    assert all(stream.closed for stream in streams)


def test_bounded_get_cancellation_closes_stream():
    async def scenario():
        started = asyncio.Event()
        class StalledStream(CountingStream):
            async def __aiter__(self):
                yield b'partial'
                started.set()
                await asyncio.Future()
        stream = StalledStream([])
        async with httpx.AsyncClient(transport=httpx.MockTransport(
            lambda request: httpx.Response(200, stream=stream),
        )) as client:
            task = asyncio.create_task(get_with_retries(client, 'https://example.test/',
                                                       max_response_bytes=1024))
            await started.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        assert stream.closed
    asyncio.run(scenario())


def test_bounded_get_preserves_native_redirect_limit_and_closes_responses():
    streams = []
    async def scenario():
        def handler(request):
            stream = CountingStream([b'redirect'])
            streams.append(stream)
            return httpx.Response(302, headers={'Location': '/again'}, stream=stream)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler), max_redirects=1) as client:
            with pytest.raises(httpx.TooManyRedirects):
                await get_with_retries(client, 'https://example.test/',
                                       max_response_bytes=1024, follow_redirects=True)
    asyncio.run(scenario())
    assert len(streams) == 2
    assert all(stream.closed for stream in streams)


def test_bounded_get_preserves_successful_retry_and_final_redirect_metadata():
    streams = []
    async def scenario():
        def handler(request):
            stream = CountingStream([b'x' * 600])
            streams.append(stream)
            if len(streams) == 1:
                return httpx.Response(503, stream=stream)
            if request.url.path == '/':
                return httpx.Response(302, headers={'Location': '/end'}, stream=stream)
            return httpx.Response(200, stream=stream)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            response = await get_with_retries(client, 'https://example.test/', retries=1,
                                             backoff_s=0, jitter=0, max_response_bytes=1500,
                                             follow_redirects=True)
            assert response.status_code == 200
            assert response.url.path == '/end'
            assert [hop.status_code for hop in response.history] == [302]
            assert response.content == b'x' * 600
    asyncio.run(scenario())
    assert len(streams) == 3
    assert all(stream.closed for stream in streams)


def test_bounded_page_waits_for_complete_body():
    async def scenario():
        started = asyncio.Event()
        release = asyncio.Event()
        class DelayedStream(CountingStream):
            async def __aiter__(self):
                yield b'welcome'
                started.set()
                await release.wait()
                yield b' remaining body'
        stream = DelayedStream([])
        async with httpx.AsyncClient(transport=httpx.MockTransport(
            lambda request: httpx.Response(200, stream=stream),
        )) as client:
            task = asyncio.create_task(KeywordsCheck('example.test', client=client,
                                                     keywords=['welcome']).run())
            await started.wait()
            assert not task.done()
            release.set()
            result = await task
            assert result.status is Status.OK
            assert result.metrics['bytes'] == len(b'welcome remaining body')
        assert stream.closed
    asyncio.run(scenario())


def test_operator_body_limit_is_positive_and_propagated_only_to_page_checks():
    from pydantic import ValidationError
    from sitewatcher.config import AppConfig, HttpClientConfig, ChecksModel, resolve_settings
    from sitewatcher.dispatcher import Dispatcher
    with pytest.raises(ValidationError):
        HttpClientConfig(max_response_bytes=0)
    async def scenario():
        cfg = AppConfig(http=HttpClientConfig(max_response_bytes=4096))
        cfg.defaults.checks = ChecksModel(**{
            name: name in {'http_basic', 'keywords', 'deface', 'whois', 'rkn_block', 'malware'}
            for name in ChecksModel.model_fields
        })
        async with Dispatcher(cfg) as dispatcher:
            checks = dispatcher._build_checks(resolve_settings(cfg, 'example.test'))
            for check in checks:
                if check.name in {'http_basic', 'keywords', 'deface'}:
                    assert check.max_response_bytes == 4096
                else:
                    assert not hasattr(check, 'max_response_bytes')
    asyncio.run(scenario())
