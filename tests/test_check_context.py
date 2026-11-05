import asyncio
import socket
from types import SimpleNamespace

import httpx
import pytest

from sitewatcher.check_context import CheckContext
from sitewatcher.checks.http_basic import HttpBasicCheck
from sitewatcher.checks.keywords import KeywordsCheck
from sitewatcher.checks.deface import DefaceCheck


def test_page_checks_share_one_redirect_chain():
    async def run():
        calls = []

        def respond(request):
            calls.append(str(request.url))
            if request.url.path == '/':
                return httpx.Response(302, headers={'location': '/landing'})
            return httpx.Response(200, text='welcome')

        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            async with CheckContext() as context:
                common = dict(client=client, cycle_context=context)
                results = await asyncio.gather(
                    HttpBasicCheck('example.test', **common).run(),
                    KeywordsCheck('example.test', keywords=['welcome'], **common).run(),
                    DefaceCheck('example.test', **common).run(),
                )
            assert calls == ['https://example.test/', 'https://example.test/landing']
            assert results[0].metrics['code_initial'] == 302
            assert results[0].metrics['final_code'] == 200
            assert results[0].metrics['redirects'] == 1
            assert results[1].metrics['redirects'] == 1
            assert results[2].metrics['redirects'] == 1
    asyncio.run(run())


def test_context_dns_coalesces_and_keeps_family_requests(monkeypatch):
    async def run():
        calls = []
        async def resolve(domain, port, **kwargs):
            calls.append(kwargs['family'])
            await asyncio.sleep(0)
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.0.2.1', 80))]
        monkeypatch.setattr(asyncio.get_running_loop(), 'getaddrinfo', resolve)
        async with CheckContext() as context:
            results = await asyncio.gather(context.resolve('example.test'),
                                           context.resolve('example.test'))
            assert results[0] == results[1]
            await context.resolve('example.test', family=socket.AF_INET)
        assert calls == [socket.AF_UNSPEC]
    asyncio.run(run())


def test_cancelled_waiter_leaves_other_consumer_and_close_cancels_orphans():
    async def run():
        started, finish, stopped = asyncio.Event(), asyncio.Event(), asyncio.Event()
        async def probe():
            started.set()
            try:
                await finish.wait()
                return 42
            finally:
                stopped.set()
        async with CheckContext() as context:
            one = asyncio.create_task(context.run_probe('probe', probe))
            two = asyncio.create_task(context.run_probe('probe', probe))
            await started.wait()
            one.cancel()
            with pytest.raises(asyncio.CancelledError):
                await one
            assert not stopped.is_set()
            finish.set()
            assert await two == 42
        finish.clear()
        stopped.clear()
        started.clear()
        async with CheckContext() as context:
            orphan = asyncio.create_task(context.run_probe('orphan', probe))
            await started.wait()
        with pytest.raises(asyncio.CancelledError):
            await orphan
        assert stopped.is_set()
    asyncio.run(run())


def test_page_reuse_respects_scope_client_url_limits_and_owner():
    async def run():
        calls = []
        def respond(request):
            calls.append(str(request.url))
            return httpx.Response(200, text='ok')
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            async with CheckContext() as context:
                async def fetch(**changes):
                    options = dict(timeout_s=1, max_response_bytes=20, owner_id=1)
                    options.update(changes)
                    return await context.fetch_page(client, 'https://example.test/', **options)
                assert await fetch() is await fetch()
                await fetch(owner_id=2)
                await fetch(max_response_bytes=21)
                await fetch(timeout_s=2)
                await fetch(proxy='http://proxy.test:80')
                await context.fetch_page(client, 'https://example.test/other',
                                         timeout_s=1, max_response_bytes=20, owner_id=1)
                async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as other:
                    await context.fetch_page(other, 'https://example.test/',
                                             timeout_s=1, max_response_bytes=20, owner_id=1)
            async with CheckContext() as context:
                await context.fetch_page(client, 'https://example.test/',
                                         timeout_s=1, max_response_bytes=20, owner_id=1)
        assert len(calls) == 8
    asyncio.run(run())


def test_shared_redirect_byte_budget_and_content_status():
    async def run():
        calls = []
        def respond(request):
            calls.append(request.url.path)
            if request.url.path == '/':
                return httpx.Response(302, headers={'location': '/landing'}, text='123')
            return httpx.Response(404, text='welcome')
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            async with CheckContext() as context:
                common = dict(client=client, cycle_context=context, max_response_bytes=9)
                results = await asyncio.gather(
                    HttpBasicCheck('example.test', **common).run(),
                    KeywordsCheck('example.test', keywords=['welcome'], **common).run(),
                    DefaceCheck('example.test', **common).run(),
                )
            assert len(calls) == 2
            assert all(r.metrics['status_code'] == 404 for r in results)
            assert [r.status.value for r in results] == ['CRIT', 'CRIT', 'UNKNOWN']
            calls.clear()
            async with CheckContext() as context:
                common = dict(client=client, cycle_context=context, max_response_bytes=20)
                results = await asyncio.gather(
                    HttpBasicCheck('example.test', **common).run(),
                    KeywordsCheck('example.test', keywords=['welcome'], **common).run(),
                    DefaceCheck('example.test', **common).run(),
                )
            assert len(calls) == 2
            assert results[0].metrics['final_code'] == 404
            assert results[1].metrics['status_code'] == 404
            assert results[2].status.value == 'UNKNOWN'
    asyncio.run(run())


def test_shared_failure_has_only_one_retry_budget(monkeypatch):
    async def run():
        calls = []
        def respond(request):
            calls.append(str(request.url))
            raise httpx.ConnectError('offline', request=request)
        async def no_sleep(delay):
            pass
        monkeypatch.setattr('sitewatcher.utils.http_retry.asyncio.sleep', no_sleep)
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            async with CheckContext() as context:
                common = dict(client=client, cycle_context=context,
                              http_url='https://example.test/')
                results = await asyncio.gather(
                    HttpBasicCheck('example.test', **common).run(),
                    KeywordsCheck('example.test', keywords=['welcome'], **common).run(),
                    DefaceCheck('example.test', **common).run(),
                )
            assert len(calls) == 3
            assert [r.status.value for r in results] == ['CRIT', 'CRIT', 'UNKNOWN']
    asyncio.run(run())


def test_dns_families_do_not_reuse_incomplete_observations(monkeypatch):
    async def run():
        calls = []
        async def resolve(domain, port, **kwargs):
            family = kwargs['family']
            calls.append(family)
            if family == socket.AF_INET:
                return [(family, socket.SOCK_STREAM, 6, '', ('192.0.2.1', 80))]
            return [(socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('2001:db8::1', 80))]
        monkeypatch.setattr(asyncio.get_running_loop(), 'getaddrinfo', resolve)
        async with CheckContext() as context:
            v4 = await context.resolve('example.test', socket.AF_INET)
            v6 = await context.resolve('example.test', socket.AF_INET6)
            both = await context.resolve('example.test')
            assert v4[0][0] == socket.AF_INET
            assert v6[0][0] == socket.AF_INET6
            assert both[0][0] == socket.AF_INET6
        assert calls == [socket.AF_INET, socket.AF_INET6, socket.AF_UNSPEC]
    asyncio.run(run())


def test_shared_observation_keeps_first_and_total_latency(monkeypatch):
    async def run():
        ticks = iter([1.0, 1.1, 1.4])
        monkeypatch.setattr('sitewatcher.check_context.time',
                            SimpleNamespace(perf_counter=lambda: next(ticks)))
        def respond(request):
            if request.url.path == '/':
                return httpx.Response(302, headers={'location': '/landing'})
            return httpx.Response(200, text='welcome')
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            async with CheckContext() as context:
                observation = await context.fetch_page(client, 'https://example.test/',
                                                       timeout_s=1, max_response_bytes=20)
                assert 99 <= observation.initial_ms <= 100
                assert 399 <= observation.total_ms <= 400
                assert str(observation.initial.url) == 'https://example.test/'
                assert str(observation.final.url) == 'https://example.test/landing'
    asyncio.run(run())


def test_last_cancelled_waiter_stops_network_probe():
    async def run():
        started, stopped = asyncio.Event(), asyncio.Event()
        async def probe():
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                stopped.set()
        async with CheckContext() as context:
            waiter = asyncio.create_task(context.run_probe('probe', probe))
            await started.wait()
            waiter.cancel()
            with pytest.raises(asyncio.CancelledError):
                await waiter
            assert stopped.is_set()
    asyncio.run(run())


def test_redirect_failure_keeps_initial_fact_without_repeating_requests():
    async def run():
        calls = []
        def respond(request):
            calls.append(request.url.path)
            if request.url.path == '/':
                return httpx.Response(302, headers={'location': '/landing'})
            raise httpx.TooManyRedirects('redirect loop', request=request)
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            async with CheckContext() as context:
                common = dict(client=client, cycle_context=context,
                              http_url='https://example.test/')
                results = await asyncio.gather(
                    HttpBasicCheck('example.test', **common).run(),
                    KeywordsCheck('example.test', keywords=['welcome'], **common).run(),
                    DefaceCheck('example.test', **common).run(),
                )
            assert calls == ['/', '/landing']
            assert results[0].metrics['code_initial'] == 302
            assert results[0].metrics['redirect_error'] == 'TooManyRedirects'
            assert [r.status.value for r in results] == ['CRIT', 'CRIT', 'UNKNOWN']
    asyncio.run(run())


@pytest.mark.parametrize('include_ipv6,expected_family', [
    (False, socket.AF_INET), (True, socket.AF_UNSPEC),
])
def test_ip_change_requests_only_needed_dns_family(include_ipv6, expected_family):
    from sitewatcher.checks.ip_change import IpChangeCheck
    async def run():
        families = []
        class Context:
            async def resolve(self, domain, family=socket.AF_UNSPEC):
                families.append(family)
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.0.2.1', 80))]
        check = IpChangeCheck('example.test', cfg=SimpleNamespace(include_ipv6=include_ipv6),
                              cycle_context=Context())
        assert await check._resolve_ips() == (['192.0.2.1'], [])
        assert families == [expected_family]
    asyncio.run(run())


def test_ip_change_reuses_same_cycle_ipv4_observation(monkeypatch):
    from sitewatcher.checks.ip_change import IpChangeCheck
    async def run():
        calls = []
        async def resolve(domain, port, **kwargs):
            calls.append(kwargs['family'])
            await asyncio.sleep(0)
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.0.2.1', 80))]
        monkeypatch.setattr(asyncio.get_running_loop(), 'getaddrinfo', resolve)
        async with CheckContext() as context:
            check = IpChangeCheck('example.test', cfg=SimpleNamespace(include_ipv6=False),
                                  cycle_context=context)
            ip_change, reputation = await asyncio.gather(
                check._resolve_ips(), context.resolve('example.test', family=socket.AF_INET),
            )
            assert ip_change == (['192.0.2.1'], [])
            assert reputation[0][4][0] == '192.0.2.1'
        assert calls == [socket.AF_INET]
    asyncio.run(run())
