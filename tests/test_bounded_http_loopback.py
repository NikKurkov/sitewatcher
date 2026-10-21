"""Exercise the resource limit through HTTPX's real socket transport."""
import asyncio
import gzip
from contextlib import suppress

import httpx
import pytest

from sitewatcher.utils.http_retry import get_with_retries


@pytest.mark.parametrize('encoding', ['identity', 'gzip', 'br'])
def test_stream_limit_closes_socket_and_releases_single_connection_pool(encoding):
    async def scenario():
        disconnected = asyncio.Event()
        tasks = set()
        errors = []

        async def accepted(reader, writer):
            task = asyncio.current_task()
            tasks.add(task)
            try:
                request = await reader.readuntil(b'\r\n\r\n')
                if request.split(b' ', 2)[1] == b'/small':
                    writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n'
                                 b'Connection: close\r\n\r\nOK')
                    await writer.drain()
                    return
                payload = gzip.compress(b'x' * (2 * 1024 * 1024)) if encoding == 'gzip' else b'x' * 5000
                writer.write(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n'
                             + b'Content-Encoding: ' + encoding.encode() + b'\r\n\r\n'
                             + f'{len(payload):x}\r\n'.encode() + payload + b'\r\n')
                await writer.drain()
                # Deliberately never finish the message. The resource guard must
                # close it immediately, rather than await EOF or retain the pool.
                assert await reader.read() == b''
                disconnected.set()
            except (ConnectionError, asyncio.IncompleteReadError):
                disconnected.set()
            except Exception as error:
                errors.append(error)
            finally:
                writer.close()
                with suppress(ConnectionError):
                    await writer.wait_closed()
                tasks.discard(task)

        server = await asyncio.start_server(accepted, '127.0.0.1', 0)
        port = server.sockets[0].getsockname()[1]
        try:
            async with httpx.AsyncClient(
                limits=httpx.Limits(max_connections=1), timeout=2, trust_env=False,
            ) as client:
                with pytest.raises(httpx.RequestError, match='body'):
                    await asyncio.wait_for(get_with_retries(
                        client, f'http://127.0.0.1:{port}/large', max_response_bytes=4096,
                    ), timeout=5)
                await asyncio.wait_for(disconnected.wait(), timeout=5)
                result = await get_with_retries(
                    client, f'http://127.0.0.1:{port}/small', max_response_bytes=4096,
                )
                assert result.content == b'OK'
        finally:
            server.close()
            for task in list(tasks):
                task.cancel()
            if tasks:
                await asyncio.wait_for(
                    asyncio.gather(*list(tasks), return_exceptions=True), timeout=5,
                )
            await server.wait_closed()
        assert not errors

    asyncio.run(scenario())
