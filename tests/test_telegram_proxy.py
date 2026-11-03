"""Native Telegram request clients must both use the configured proxy."""
import asyncio
import json
import stat

import pytest
from contextlib import asynccontextmanager, suppress
from urllib.parse import urlsplit

from telegram.ext import Application

from sitewatcher import storage
from sitewatcher.bot.app import run_bot
from sitewatcher.config import AppConfig


@asynccontextmanager
async def local_telegram_api(calls):
    tasks = set()

    async def respond(reader, writer):
        task = asyncio.current_task()
        tasks.add(task)
        try:
            request = await reader.readuntil(b'\r\n\r\n')
            request_line, *headers = request.decode('ascii').split('\r\n')
            method = urlsplit(request_line.split()[1]).path.rsplit('/', 1)[-1]
            content_length = next((int(header.split(':', 1)[1]) for header in headers
                                   if header.lower().startswith('content-length:')), 0)
            await reader.readexactly(content_length)
            calls.append(method)
            if method == 'getMe':
                result = {'id': 123, 'is_bot': True, 'first_name': 'Offline bot',
                          'username': 'sitewatcher_test_bot'}
            elif method == 'getUpdates':
                result = []
            else:
                raise AssertionError('Unexpected local Telegram method')
            body = json.dumps({'ok': True, 'result': result}).encode('utf-8')
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n'
                         b'Connection: close\r\nContent-Length: ' + str(len(body)).encode()
                         + b'\r\n\r\n' + body)
            await writer.drain()
        finally:
            writer.close()
            with suppress(ConnectionError):
                await writer.wait_closed()
            tasks.discard(task)

    server = await asyncio.start_server(respond, '127.0.0.1', 0)
    try:
        yield server.sockets[0].getsockname()[1]
    finally:
        server.close()
        await server.wait_closed()
        if tasks:
            await asyncio.wait_for(asyncio.gather(*list(tasks)), timeout=3)


@pytest.mark.parametrize('source', ['environment', 'saved'])
def test_telegram_proxy_routes_ordinary_calls_and_polling_through_same_proxy(monkeypatch, source):
    for key in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY',
                'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy'):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv('TELEGRAM_TOKEN', '123:offline-only')
    monkeypatch.setenv('TELEGRAM_ALLOWED_USER_IDS', '7')
    original_builder = Application.builder
    applications = []
    monkeypatch.setattr(Application, 'run_polling',
                        lambda self, **kwargs: applications.append(self))

    async def scenario():
        direct_calls = []
        proxy_calls = []
        async with local_telegram_api(direct_calls) as origin_port:
            async with local_telegram_api(proxy_calls) as proxy_port:
                if source == 'environment':
                    monkeypatch.setenv('TELEGRAM_PROXY', f'http://127.0.0.1:{proxy_port}')
                else:
                    from sitewatcher.telegram_proxy import save_proxy
                    monkeypatch.delenv('TELEGRAM_PROXY', raising=False)
                    save_proxy(f'http://127.0.0.1:{proxy_port}')
                monkeypatch.setattr(Application, 'builder', staticmethod(
                    lambda: original_builder().base_url(f'http://127.0.0.1:{origin_port}/bot')
                ))
                cfg = AppConfig()
                cfg.scheduler.enabled = False
                run_bot(cfg)
                application = applications[0]
                async with application:
                    updates = await application.bot.get_updates(timeout=0, read_timeout=2,
                                                                connect_timeout=2)
                    assert not updates
        assert direct_calls == []
        assert proxy_calls == ['getMe', 'getUpdates']

    asyncio.run(scenario())




@pytest.mark.parametrize(('value', 'expected'), [
    (' http://user:password@proxy.example:3128 ', 'http://user:password@proxy.example:3128'),
    ('https://proxy.example:443', 'https://proxy.example:443'),
    ('socks5h://proxy.example:1080', 'socks5://proxy.example:1080'),
    ('https://t.me/socks?server=proxy.example&port=1080&user=a%40b&pass=p%26q',
     'socks5://a%40b:p%26q@proxy.example:1080'),
    ('tg://socks?server=::1&port=1080', 'socks5://[::1]:1080'),
])
def test_normalizes_supported_proxy_and_telegram_links(value, expected):
    from sitewatcher.telegram_proxy import normalize_proxy
    assert normalize_proxy(value) == expected


@pytest.mark.parametrize('value', [
    'https://t.me/proxy?server=example.com&port=443&secret=private',
    'tg://proxy?server=example.com&port=443&secret=private',
    'http://user:private@proxy.example:0', 'socks5://proxy.example:70000',
    'http://proxy.example:80/path', 'http://proxy.example:80?password=private',
    'tg://socks?server=example.com&port=1080&port=80',
    'tg://socks?server=example.com&port=1080&secret=private',
    'ftp://user:private@proxy.example:80', 'http://proxy.example\n:80',
])
def test_rejects_invalid_proxy_without_echoing_secrets(value):
    from sitewatcher.telegram_proxy import normalize_proxy
    with pytest.raises(ValueError) as error:
        normalize_proxy(value)
    assert 'private' not in str(error.value)


def test_proxy_private_atomic_storage_override_remove_and_security(tmp_path, monkeypatch):
    from sitewatcher.telegram_proxy import load_proxy, save_proxy, remove_proxy, proxy_path
    monkeypatch.setattr(storage, 'DEFAULT_DB', tmp_path / 'monitor.db')
    monkeypatch.delenv('TELEGRAM_PROXY', raising=False)
    assert load_proxy() is None
    save_proxy('tg://socks?server=proxy.example&port=1080')
    assert load_proxy() == 'socks5://proxy.example:1080'
    assert stat.S_IMODE(proxy_path().stat().st_mode) == 0o600
    monkeypatch.setenv('TELEGRAM_PROXY', 'https://deployment.example:443')
    assert load_proxy() == 'https://deployment.example:443'
    remove_proxy()
    assert load_proxy() == 'https://deployment.example:443'
    monkeypatch.delenv('TELEGRAM_PROXY')
    assert load_proxy() is None
    save_proxy('http://proxy.example:80')
    with pytest.raises(ValueError):
        save_proxy('invalid-private')
    assert load_proxy() == 'http://proxy.example:80'
    proxy_path().chmod(0o644)
    with pytest.raises(ValueError, match='0600'):
        load_proxy()
    proxy_path().unlink()
    target = tmp_path / 'other'
    target.write_text('http://proxy.example:80')
    target.chmod(0o600)
    proxy_path().symlink_to(target)
    with pytest.raises(ValueError):
        load_proxy()


def test_connection_checks_use_saved_normalized_proxy(tmp_path, monkeypatch):
    import asyncio
    import httpx
    from sitewatcher.telegram_proxy import save_proxy
    from sitewatcher.telegram_connection import send_test_notification
    monkeypatch.setattr(storage, 'DEFAULT_DB', tmp_path / 'monitor.db')
    monkeypatch.delenv('TELEGRAM_PROXY', raising=False)
    save_proxy('https://t.me/socks?server=proxy.example&port=1080')
    original = httpx.AsyncClient
    seen = []

    def client(**kwargs):
        seen.append(kwargs['proxy'])
        return original(transport=httpx.MockTransport(lambda request: httpx.Response(
            200, json={'ok': True, 'result': {}})))

    monkeypatch.setattr(httpx, 'AsyncClient', client)
    asyncio.run(send_test_notification('123:fake', 5))
    assert seen == ['socks5://proxy.example:1080']


def test_socks_debug_logs_never_expose_proxy_authentication(caplog):
    import logging
    from sitewatcher import telegram_connection  # noqa: F401 - installs client log filters
    caplog.set_level('DEBUG')
    logging.getLogger('httpcore.socks').debug(
        "setup_socks5_connection.started host='api.telegram.org' auth=%r",
        (b'private-proxy-user', b'private-proxy-password'))
    assert 'private-proxy' not in caplog.text
