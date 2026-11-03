import asyncio

import httpx
import pytest

from sitewatcher.config import AppConfig, ChecksModel, HttpClientConfig, resolve_settings
from sitewatcher.dispatcher import Dispatcher


def proxy_config():
    cfg = AppConfig()
    cfg.defaults.proxy = 'http://target-proxy.example:3128'
    cfg.defaults.keywords = ['welcome']
    cfg.defaults.checks = ChecksModel(**{
        key: key in {'http_basic', 'keywords', 'deface'}
        for key in ChecksModel.model_fields
    })
    cfg.http = HttpClientConfig()
    cfg.http.read_timeout = 17
    cfg.http.max_connections = 7
    cfg.http.max_keepalive_connections = 3
    return cfg


@pytest.fixture
def client_factory(monkeypatch):
    from sitewatcher import dispatcher
    original = httpx.AsyncClient
    made = []
    def factory(**kwargs):
        options = dict(kwargs)
        kwargs.pop('proxy', None)
        kwargs.pop('mounts', None)
        client = original(transport=httpx.MockTransport(
            lambda request: httpx.Response(200, text='welcome to this site'),
        ), **kwargs)
        made.append((options, client))
        return client
    monkeypatch.setattr(dispatcher.httpx, 'AsyncClient', factory)
    return made


def test_dispatcher_target_checks_share_domain_proxy_client(client_factory):
    cfg = proxy_config()
    cfg.defaults.checks.whois = True
    cfg.defaults.checks.rkn_domain = True
    cfg.defaults.checks.rkn_ip = True
    cfg.defaults.checks.malware = True
    async def scenario():
        async with Dispatcher(cfg) as dispatcher:
            checks = {check.name: check for check in dispatcher._build_checks(
                resolve_settings(cfg, 'example.test'),
            )}
            basic = checks['http_basic']
            assert basic.client is checks['keywords'].client is checks['deface'].client
            assert basic.client is not dispatcher._client
            assert basic.proxy is None
            for name in ('whois', 'rkn_domain', 'rkn_ip', 'malware'):
                assert checks[name].client is dispatcher._client
    asyncio.run(scenario())
    assert len(client_factory) == 2
    assert all(client.is_closed for _, client in client_factory)


def test_dispatcher_reuses_proxy_client_across_domain_runs(client_factory):
    cfg = proxy_config()
    async def scenario():
        async with Dispatcher(cfg) as dispatcher:
            first = await dispatcher.run_for(0, 'first.example', ephemeral=True)
            second = await dispatcher.run_for(0, 'second.example', ephemeral=True)
            assert {r.status.value for r in first + second} == {'OK'}
            assert len(client_factory) == 2
            options, _ = client_factory[1]
            assert options['proxy'] == cfg.defaults.proxy
            assert options['http2'] is True
            assert options['timeout'].read == 17
            assert options['limits'].max_connections == 7
            assert options['limits'].max_keepalive_connections == 3
            assert options['headers'] == client_factory[0][0]['headers']
            assert options['trust_env'] is True
    asyncio.run(scenario())
    assert all(client.is_closed for _, client in client_factory)


@pytest.mark.parametrize('failure', [RuntimeError, asyncio.CancelledError])
def test_dispatcher_closes_proxy_and_global_clients_on_exit_failure(client_factory, failure):
    cfg = proxy_config()
    async def scenario():
        with pytest.raises(failure):
            async with Dispatcher(cfg) as dispatcher:
                dispatcher._build_checks(resolve_settings(cfg, 'example.test'))
                raise failure
    asyncio.run(scenario())
    assert len(client_factory) == 2
    assert all(client.is_closed for _, client in client_factory)


def test_dispatcher_invalid_proxy_does_not_create_domain_client(client_factory, monkeypatch):
    from sitewatcher import storage
    cfg = proxy_config()
    monkeypatch.setattr(storage, 'get_domain_override', lambda *args: {'proxy': 'invalid'})
    async def scenario():
        async with Dispatcher(cfg) as dispatcher:
            with pytest.raises(ValueError):
                await dispatcher.run_for(1, 'example.test')
            assert len(client_factory) == 1
    asyncio.run(scenario())


def test_dispatcher_different_proxy_domains_keep_separate_clients(client_factory):
    cfg = proxy_config()
    async def scenario():
        async with Dispatcher(cfg) as dispatcher:
            first = resolve_settings(cfg, 'first.example')
            second = resolve_settings(cfg, 'second.example', {
                'proxy': 'http://second-proxy.example:3128',
            })
            initial = dispatcher._build_checks(first)[0].client
            other = dispatcher._build_checks(second)[0].client
            repeated = dispatcher._build_checks(first)[0].client
            assert initial is repeated
            assert other is not initial
            assert len(client_factory) == 3
    asyncio.run(scenario())
    assert all(client.is_closed for _, client in client_factory)


def test_dispatcher_without_domain_proxy_uses_global_client(client_factory):
    cfg = proxy_config()
    cfg.defaults.proxy = None
    cfg.http.proxy = 'http://global-proxy.example:3128'
    async def scenario():
        async with Dispatcher(cfg) as dispatcher:
            checks = dispatcher._build_checks(resolve_settings(cfg, 'example.test'))
            assert all(check.client is dispatcher._client for check in checks)
            assert len(client_factory) == 1
            assert client_factory[0][0]['proxy'] == cfg.http.proxy
    asyncio.run(scenario())


def test_dispatcher_target_proxy_overrides_global_proxy(client_factory):
    cfg = proxy_config()
    cfg.http.proxy = 'http://global-proxy.example:3128'
    async def scenario():
        async with Dispatcher(cfg) as dispatcher:
            dispatcher._build_checks(resolve_settings(cfg, 'example.test'))
            assert client_factory[0][0]['proxy'] == cfg.http.proxy
            assert client_factory[1][0]['proxy'] == cfg.defaults.proxy
            assert 'mounts' not in client_factory[1][0]
    asyncio.run(scenario())


def test_dispatcher_mapping_transports_preserve_http_tuning(monkeypatch):
    from sitewatcher import dispatcher as dispatcher_module
    original = httpx.AsyncHTTPTransport
    options = []
    def transport(**kwargs):
        options.append(kwargs)
        return original(**kwargs)
    monkeypatch.setattr(dispatcher_module.httpx, 'AsyncHTTPTransport', transport)
    cfg = proxy_config()
    cfg.http.proxies = {
        'http': 'http://127.0.0.1:3128', 'https': 'http://127.0.0.1:3129',
    }
    async def scenario():
        async with Dispatcher(cfg):
            pass
    asyncio.run(scenario())
    assert len(options) == 2
    for supplied in options:
        assert supplied['http2'] is True
        assert supplied['limits'].max_connections == cfg.http.max_connections
        assert supplied['limits'].max_keepalive_connections == cfg.http.max_keepalive_connections
