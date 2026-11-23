import asyncio
import ssl
from datetime import datetime,timedelta,timezone
from unittest.mock import AsyncMock

from sitewatcher import probe_cache, storage
from sitewatcher.checks.tls_cert import TlsCertCheck,_TlsResult
from sitewatcher.checks.base import Status


def certificate():
    return {'notAfter':(datetime.now(timezone.utc)+timedelta(days=90)).strftime('%b %d %H:%M:%S %Y GMT'),
            'subjectAltName':(('DNS','cache.example'),)}


def test_tls_cache_persists_between_instances_and_explicit_refresh_is_debounced(monkeypatch):
    fetch=AsyncMock(side_effect=lambda *a: _TlsResult(certificate(),datetime.now(timezone.utc)))
    monkeypatch.setattr(TlsCertCheck,'_fetch_peer_cert',fetch)
    async def run():
        first=await TlsCertCheck('cache.example',owner_id=7).run()
        second=await TlsCertCheck('cache.example',owner_id=7).run()
        assert first.status is second.status is Status.OK
        assert second.cached and fetch.await_count==1
        forced=await TlsCertCheck('cache.example',owner_id=7,force_refresh=True).run()
        assert forced.cached and fetch.await_count==1
        from sitewatcher import storage
        with storage._write_connection() as conn:
            conn.execute("UPDATE probe_cache SET fetched_at=fetched_at-120 WHERE namespace='tls-cert'")
        forced=await TlsCertCheck('cache.example',owner_id=7,force_refresh=True).run()
        assert not forced.cached and fetch.await_count==2
    asyncio.run(run())


def test_cached_tls_facts_recompute_expiry_without_network(monkeypatch):
    check=TlsCertCheck('cache.example',owner_id=7)
    now=datetime.now(timezone.utc)
    probe_cache.seed('tls-cert',check.cache_key,{'status':'OK','message':'old','metrics':{
        'expires_at':(now+timedelta(days=2)).isoformat(),'host_matches':True}},
        fetched_at=now-timedelta(hours=2),ttl_s=86400)
    fetch=AsyncMock(side_effect=AssertionError('must reuse certificate'))
    monkeypatch.setattr(check,'_fetch_peer_cert',fetch)
    result=asyncio.run(check.run())
    assert result.status is Status.CRIT and result.cached
    assert result.metrics['days_left']<=2 and fetch.await_count==0


def test_failed_tls_refresh_retains_known_expired_certificate(monkeypatch):
    check=TlsCertCheck('cache.example',owner_id=7)
    now=datetime.now(timezone.utc)
    probe_cache.seed('tls-cert',check.cache_key,{'status':'CRIT','message':'expired','metrics':{
        'expires_at':(now-timedelta(days=1)).isoformat(),'host_matches':True}},
        fetched_at=now-timedelta(hours=25),ttl_s=86400)
    fetch=AsyncMock(side_effect=OSError('synthetic timeout'))
    monkeypatch.setattr(check,'_fetch_peer_cert',fetch)
    result=asyncio.run(check.run())
    assert result.status is Status.CRIT and result.metrics['source_stale']
    assert result.metrics['next_refresh_at']
    assert datetime.fromisoformat(result.metrics['observed_at']) == now-timedelta(hours=25)
    again=asyncio.run(TlsCertCheck('cache.example',owner_id=7,force_refresh=True).run())
    assert again.status is Status.CRIT and fetch.await_count==1


def test_tls_verification_failure_keeps_previous_expiry_and_retries_in_fifteen_minutes(monkeypatch):
    now = datetime.now(timezone.utc)
    fetch = AsyncMock(side_effect=[
        _TlsResult(certificate(), now),
        ssl.SSLCertVerificationError(1, 'untrusted certificate'),
        TimeoutError(),
        _TlsResult(certificate(), now),
    ])
    monkeypatch.setattr(TlsCertCheck, '_fetch_peer_cert', fetch)

    async def run():
        check = TlsCertCheck('cache.example', owner_id=7)
        first = await check.run()
        assert first.status is Status.OK
        with storage._write_connection() as conn:
            conn.execute("UPDATE probe_cache SET fetched_at=fetched_at-120 WHERE namespace='tls-cert'")

        forced = TlsCertCheck('cache.example', owner_id=7, force_refresh=True)
        failed = await forced.run()
        assert failed.status is Status.CRIT
        assert failed.metrics['source_stale']
        assert failed.metrics['expires_at'] == first.metrics['expires_at']
        assert 'certificate verification failed' in failed.message
        retry_at = datetime.fromisoformat(failed.metrics['next_refresh_at'])
        assert timedelta(minutes=14) < retry_at - datetime.now(timezone.utc) <= timedelta(minutes=15)
        assert (await forced.run()).cached
        assert fetch.await_count == 2

        with storage._write_connection() as conn:
            conn.execute("UPDATE probe_cache SET expires_at=expires_at-901 WHERE namespace='tls-cert'")
        stale = await check.run()
        assert stale.status is Status.CRIT and stale.metrics['source_stale']
        assert stale.metrics['expires_at'] == first.metrics['expires_at']
        assert stale.metrics['observed_at'] == failed.metrics['observed_at']
        assert 'certificate verification failed' in stale.message
        assert 'TLS refresh unavailable' in stale.message

        with storage._write_connection() as conn:
            conn.execute("UPDATE probe_cache SET expires_at=expires_at-901 WHERE namespace='tls-cert'")
        recovered = await check.run()
        assert recovered.status is Status.OK and not recovered.metrics.get('source_stale')

    asyncio.run(run())


def test_cached_legacy_verification_failure_uses_short_retry(monkeypatch):
    check = TlsCertCheck('cache.example', owner_id=7, force_refresh=True)
    now = datetime.now(timezone.utc)
    previous = now - timedelta(minutes=2)
    probe_cache.seed('tls-cert', check.cache_key, {
        'status': 'CRIT',
        'message': 'certificate verification failed: certificate rejected',
        'metrics': {'verify_code': 10},
    }, fetched_at=previous, ttl_s=86400)
    fetch = AsyncMock(return_value=_TlsResult(certificate(), now))
    monkeypatch.setattr(TlsCertCheck, '_fetch_peer_cert', fetch)

    cached = asyncio.run(check.run())
    assert cached.status is Status.CRIT and cached.cached
    assert cached.metrics['next_refresh_at'] == (previous + timedelta(minutes=15)).isoformat()
    assert fetch.await_count == 0

    with storage._write_connection() as conn:
        conn.execute("UPDATE probe_cache SET fetched_at=fetched_at-900 WHERE namespace='tls-cert'")

    recovered = asyncio.run(TlsCertCheck('cache.example', owner_id=7).run())
    assert recovered.status is Status.OK and not recovered.cached
    assert fetch.await_count == 1
