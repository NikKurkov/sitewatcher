import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from sitewatcher.checks import ping, tls_cert
from sitewatcher.checks.base import Status


NOW = datetime(2026, 10, 21, 12, tzinfo=timezone.utc)


class FixedDatetime(datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW.astimezone(tz) if tz else NOW.replace(tzinfo=None)


@pytest.mark.parametrize(('days', 'sans', 'expected'), [
    (-1, ['example.test'], Status.CRIT),
    (0, ['example.test'], Status.CRIT),
    (3, ['example.test'], Status.CRIT),
    (4, ['example.test'], Status.WARN),
    (30, ['example.test'], Status.WARN),
    (31, ['example.test'], Status.OK),
    (31, ['other.test'], Status.WARN),
    (31, [], Status.WARN),
    (-1, [], Status.CRIT),
])
def test_tls_expiry_and_identity_policy(monkeypatch, days, sans, expected):
    monkeypatch.setattr(tls_cert, 'datetime', FixedDatetime)
    expiration = NOW + timedelta(days=days)
    cert = {
        'notAfter': expiration.strftime('%b %d %H:%M:%S %Y GMT'),
        'subjectAltName': [('DNS', name) for name in sans],
    }
    check = tls_cert.TlsCertCheck('example.test')
    monkeypatch.setattr(check, '_fetch_peer_cert', AsyncMock(return_value=tls_cert._TlsResult(
        cert=cert, fetched_at=NOW,
    )))
    result = asyncio.run(check.run())
    assert result.status is expected
    assert result.metrics['days_left'] == days
    assert result.metrics['host_matches'] is ('example.test' in sans)
    assert result.metrics['san_present'] is bool(sans)


@pytest.mark.parametrize('expiration', [None, 'not a date'])
def test_tls_missing_or_invalid_expiry_is_unknown(monkeypatch, expiration):
    check = tls_cert.TlsCertCheck('example.test')
    monkeypatch.setattr(check, '_fetch_peer_cert', AsyncMock(return_value=tls_cert._TlsResult(
        cert={'notAfter': expiration, 'subjectAltName': [('DNS', 'example.test')]}, fetched_at=NOW,
    )))
    assert asyncio.run(check.run()).status is Status.UNKNOWN


@pytest.mark.parametrize('expiration', ['2026-11-21T12:00:00', '2026-11-21T15:00:00+03:00'])
def test_tls_iso_expiry_is_normalized_to_utc(monkeypatch, expiration):
    monkeypatch.setattr(tls_cert, 'datetime', FixedDatetime)
    check = tls_cert.TlsCertCheck('example.test')
    monkeypatch.setattr(check, '_fetch_peer_cert', AsyncMock(return_value=tls_cert._TlsResult(
        cert={'notAfter': expiration, 'subjectAltName': [('DNS', 'example.test')]}, fetched_at=NOW,
    )))
    result = asyncio.run(check.run())
    assert result.status is Status.OK
    assert result.metrics['days_left'] == 31
    assert result.metrics['expires_at'] == '2026-11-21T12:00:00+00:00'


@pytest.mark.parametrize(('alive', 'expected'), [(True, Status.OK), (False, Status.CRIT)])
def test_ping_icmp_response_is_authoritative(monkeypatch, alive, expected):
    monkeypatch.setattr(ping, 'HAVE_ICMP', True)
    monkeypatch.setattr(ping, 'icmp_async_ping', AsyncMock(return_value=SimpleNamespace(
        is_alive=alive, avg_rtt=12.345,
    )))
    check = ping.PingCheck('example.test')
    async def unexpected(**kwargs):
        pytest.fail('a completed ICMP probe must not trigger a TCP fallback')
    monkeypatch.setattr(check, '_tcp_ping', unexpected)
    result = asyncio.run(check.run())
    assert result.status is expected
    assert result.metrics['method'] == 'icmp'
    if alive:
        assert result.metrics['avg_rtt_ms'] == 12.35


@pytest.mark.parametrize('icmp_available', [True, False])
def test_ping_tcp_fallback_connects_and_closes_loopback(monkeypatch, icmp_available):
    monkeypatch.setattr(ping, 'HAVE_ICMP', icmp_available)
    monkeypatch.setattr(ping, 'icmp_async_ping', AsyncMock(side_effect=PermissionError))
    async def scenario():
        disconnected = asyncio.Event()
        async def accepted(reader, writer):
            try:
                assert await reader.read() == b''
                disconnected.set()
            finally:
                writer.close()
                await writer.wait_closed()
        server = await asyncio.start_server(accepted, '127.0.0.1', 0)
        try:
            port = server.sockets[0].getsockname()[1]
            result = await ping.PingCheck('127.0.0.1', tcp_port=port).run()
            await asyncio.wait_for(disconnected.wait(), timeout=5)
            assert result.status is Status.OK
            assert result.metrics['method'] == 'tcp'
            assert result.metrics['port'] == port
            assert result.metrics['rtt_ms'] >= 0
        finally:
            server.close()
            await server.wait_closed()
    asyncio.run(scenario())


@pytest.mark.parametrize('error', [ConnectionRefusedError, TimeoutError])
def test_ping_failed_tcp_fallback_is_critical(monkeypatch, error):
    monkeypatch.setattr(ping, 'HAVE_ICMP', False)
    monkeypatch.setattr(asyncio, 'open_connection', AsyncMock(side_effect=error))
    result = asyncio.run(ping.PingCheck('example.test').run())
    assert result.status is Status.CRIT
    assert result.metrics['method'] == 'tcp'


def test_ping_icmp_cancellation_does_not_fallback(monkeypatch):
    monkeypatch.setattr(ping, 'HAVE_ICMP', True)
    monkeypatch.setattr(ping, 'icmp_async_ping', AsyncMock(side_effect=asyncio.CancelledError))
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(ping.PingCheck('example.test').run())


def test_ping_tcp_cancellation_closes_writer(monkeypatch):
    monkeypatch.setattr(ping, 'HAVE_ICMP', False)
    closed = []
    writer = SimpleNamespace(
        close=lambda: closed.append(True),
        wait_closed=AsyncMock(side_effect=asyncio.CancelledError),
    )
    monkeypatch.setattr(asyncio, 'open_connection', AsyncMock(return_value=(None, writer)))
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(ping.PingCheck('example.test').run())
    assert closed


def test_ping_connect_cancellation_propagates(monkeypatch):
    monkeypatch.setattr(ping, 'HAVE_ICMP', False)
    async def scenario():
        connecting = asyncio.Event()
        async def connect(*args):
            connecting.set()
            await asyncio.Future()
        monkeypatch.setattr(asyncio, 'open_connection', connect)
        task = asyncio.create_task(ping.PingCheck('example.test').run())
        await connecting.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    asyncio.run(scenario())
