import asyncio
import json
import os
import shutil
import ssl
import subprocess
from contextlib import asynccontextmanager, suppress

import pytest

from sitewatcher.config import AppConfig, ChecksModel, HttpClientConfig
from sitewatcher.dispatcher import Dispatcher


@pytest.fixture
def local_certificate(tmp_path, monkeypatch):
    openssl = shutil.which('openssl')
    if openssl is None:
        pytest.skip('loopback TLS integration requires openssl to create a temporary test certificate')
    certificate = tmp_path / 'test-ca.pem'
    key = tmp_path / 'test-key.pem'
    subprocess.run([
        openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
        '-subj', '/CN=target.example',
        '-addext', 'subjectAltName=DNS:target.example,DNS:external.example',
        '-keyout', str(key), '-out', str(certificate),
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    os.chmod(key, 0o600)
    monkeypatch.setenv('SSL_CERT_FILE', str(certificate))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)
    return context


@asynccontextmanager
async def local_server(handler, *, ssl_context=None):
    tasks = set()
    writers = set()
    errors = []

    async def accepted(reader, writer):
        task = asyncio.current_task()
        tasks.add(task)
        writers.add(writer)
        try:
            await handler(reader, writer)
        except (ConnectionError, ssl.SSLError):
            # Closing a tunnel may race with its peer finishing TLS shutdown.
            pass
        except Exception as error:
            errors.append(error)
        finally:
            writers.discard(writer)
            writer.close()
            with suppress(ConnectionError, ssl.SSLError):
                await writer.wait_closed()
            tasks.discard(task)

    server = await asyncio.start_server(accepted, '127.0.0.1', 0, ssl=ssl_context)
    try:
        yield server.sockets[0].getsockname()[1]
    finally:
        server.close()
        await server.wait_closed()
        for writer in list(writers):
            writer.close()
        if tasks:
            await asyncio.wait_for(asyncio.gather(*list(tasks)), timeout=5)
    assert not errors, [type(error).__name__ for error in errors]


async def serve_page(reader, writer):
    request = await reader.readuntil(b'\r\n\r\n')
    target = request.split(b' ', 2)[1]
    if target.startswith(b'/domain/'):
        body = json.dumps({'events': [{
            'eventAction': 'expiration', 'eventDate': '2099-01-01T00:00:00Z',
        }]}).encode()
    else:
        body = b'welcome to our healthy test site'
    writer.write(
        b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(body)).encode()
        + b'\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n' + body,
    )
    await writer.drain()


def tunnel_proxy(origin_port, seen):
    async def proxy(reader, writer):
        request = await reader.readuntil(b'\r\n\r\n')
        method, target, _ = request.split(b'\r\n', 1)[0].split(b' ')
        assert method == b'CONNECT'
        assert target in {b'target.example:443', b'external.example:443'}
        seen.append(target.decode())
        # All connections stay on loopback. DNS for the advertised target is
        # deliberately never resolved; the proxy routes it to our local origin.
        remote_reader, remote_writer = await asyncio.open_connection('127.0.0.1', origin_port)
        writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
        await writer.drain()

        async def copy(source, destination):
            while data := await source.read(65536):
                destination.write(data)
                await destination.drain()

        copies = [asyncio.create_task(copy(reader, remote_writer)),
                  asyncio.create_task(copy(remote_reader, writer))]
        try:
            await asyncio.wait(copies, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in copies:
                task.cancel()
            await asyncio.gather(*copies, return_exceptions=True)
            remote_writer.close()
            with suppress(ConnectionError):
                await remote_writer.wait_closed()
    return proxy


def test_dispatcher_routes_target_checks_and_external_service_through_selected_proxies(
    tmp_path, local_certificate,
):
    async def scenario():
        target_routes = []
        global_routes = []
        async with local_server(serve_page, ssl_context=local_certificate) as origin_port:
            async with local_server(tunnel_proxy(origin_port, target_routes)) as target_port:
                async with local_server(tunnel_proxy(origin_port, global_routes)) as global_port:
                    cfg = AppConfig()
                    cfg.http = HttpClientConfig(proxy=f'http://127.0.0.1:{global_port}')
                    cfg.defaults.proxy = f'http://127.0.0.1:{target_port}'
                    cfg.defaults.keywords = ['welcome']
                    cfg.defaults.checks = ChecksModel(**{
                        name: name in {'http_basic', 'keywords', 'deface', 'whois'}
                        for name in ChecksModel.model_fields
                    })
                    cfg.whois.db_path = str(tmp_path / 'whois.db')
                    cfg.whois.rdap_endpoint = 'https://external.example/domain/{domain}'
                    async with Dispatcher(cfg) as dispatcher:
                        results = await dispatcher.run_for(0, 'target.example', ephemeral=True)
                        clients = [dispatcher._client, *dispatcher._proxy_clients.values()]
                    assert all(client.is_closed for client in clients)
        assert {result.check for result in results} == {'http_basic', 'keywords', 'deface', 'whois'}
        assert {result.status.value for result in results} == {'OK'}
        assert target_routes == ['target.example:443'] * 3
        assert global_routes == ['external.example:443']
    asyncio.run(scenario())


def test_dispatcher_cancellation_closes_real_proxy_tunnel(local_certificate):
    async def scenario():
        request_started = asyncio.Event()
        origin_disconnected = asyncio.Event()

        async def stalled_page(reader, writer):
            await reader.readuntil(b'\r\n\r\n')
            request_started.set()
            assert await reader.read() == b''
            origin_disconnected.set()

        routes = []
        async with local_server(stalled_page, ssl_context=local_certificate) as origin_port:
            async with local_server(tunnel_proxy(origin_port, routes)) as proxy_port:
                cfg = AppConfig()
                cfg.defaults.proxy = f'http://127.0.0.1:{proxy_port}'
                cfg.defaults.checks = ChecksModel(**{
                    name: name == 'http_basic' for name in ChecksModel.model_fields
                })
                dispatcher = Dispatcher(cfg)
                clients = []

                async def run():
                    async with dispatcher:
                        try:
                            await dispatcher.run_for(0, 'target.example', ephemeral=True)
                        finally:
                            clients.extend([dispatcher._client, *dispatcher._proxy_clients.values()])

                task = asyncio.create_task(run())
                try:
                    await asyncio.wait_for(request_started.wait(), timeout=5)
                    task.cancel()
                    with pytest.raises(asyncio.CancelledError):
                        await task
                    await asyncio.wait_for(origin_disconnected.wait(), timeout=5)
                    assert all(client.is_closed for client in clients)
                finally:
                    if not task.done():
                        task.cancel()
                        await asyncio.gather(task, return_exceptions=True)
        assert routes == ['target.example:443']
    asyncio.run(scenario())


def test_mapping_proxy_enforces_configured_connection_limit(local_certificate):
    import httpx

    async def scenario():
        started = asyncio.Event()
        release = asyncio.Event()
        calls = 0

        async def origin(reader, writer):
            nonlocal calls
            await reader.readuntil(b'\r\n\r\n')
            calls += 1
            if calls == 1:
                started.set()
                await release.wait()
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK')
            await writer.drain()

        routes = []
        async with local_server(origin, ssl_context=local_certificate) as origin_port:
            async with local_server(tunnel_proxy(origin_port, routes)) as proxy_port:
                cfg = AppConfig()
                cfg.http = HttpClientConfig(
                    proxies={'https': f'http://127.0.0.1:{proxy_port}'},
                    max_connections=1, max_keepalive_connections=1, pool_timeout=0.1,
                )
                async with Dispatcher(cfg) as dispatcher:
                    first = asyncio.create_task(dispatcher._client.get('https://target.example/'))
                    try:
                        await asyncio.wait_for(started.wait(), timeout=5)
                        with pytest.raises(httpx.PoolTimeout):
                            await dispatcher._client.get('https://target.example/')
                    finally:
                        release.set()
                        response = await first
                        assert response.status_code == 200
        assert routes == ['target.example:443']
    asyncio.run(scenario())
