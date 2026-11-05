import asyncio
from datetime import datetime,timedelta,timezone
from unittest.mock import AsyncMock

from sitewatcher import probe_cache
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
