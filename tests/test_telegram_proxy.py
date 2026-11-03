"""Native Telegram request clients must both use the configured proxy."""
import asyncio
import json
from contextlib import asynccontextmanager, suppress
from urllib.parse import urlsplit

from telegram.ext import Application

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


def test_telegram_proxy_routes_ordinary_calls_and_polling_through_same_proxy(monkeypatch):
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
                monkeypatch.setenv('TELEGRAM_PROXY', f'http://127.0.0.1:{proxy_port}')
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
