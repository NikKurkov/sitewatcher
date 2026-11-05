from datetime import datetime,timedelta,timezone
import asyncio
from unittest.mock import AsyncMock

from sitewatcher import storage
from sitewatcher.config import AppConfig,ChecksModel
from sitewatcher.scheduler import due_checks
from sitewatcher.reporting import build_snapshot
from sitewatcher.bot.alerts import _is_fresh_ok_for_all
from sitewatcher.dispatcher import Dispatcher
from sitewatcher.checks.base import CheckOutcome,Status


def configuration(check):
    cfg=AppConfig()
    cfg.defaults.checks=ChecksModel.model_validate({name:name==check for name in ChecksModel.model_fields})
    storage.add_domain(7,'policy.example')
    storage.set_domain_override(7,'policy.example',{'interval_minutes':5})
    return cfg


def test_daily_vt_cache_is_not_rescheduled_or_reported_overdue_and_confirms_recovery():
    cfg=configuration('malware')
    observed=datetime.now(timezone.utc)-timedelta(hours=2)
    storage.save_history(7,'policy.example','malware','OK','VT: harmless=1',{
        'observed_at':observed.isoformat(),
        'next_refresh_at':(observed+timedelta(days=1)).isoformat()})
    with storage._write_connection() as conn:
        conn.execute('UPDATE history SET created_at=?',(observed.isoformat(),))
    assert due_checks(cfg,7,'policy.example')==[]
    row=build_snapshot(cfg,7)['domains'][0]
    assert row['overall']=='OK' and not row['overdue']
    assert _is_fresh_ok_for_all(cfg,7,'policy.example',['malware'],[])


def test_fresh_metadata_is_reused_before_activity_even_when_general_cache_is_disabled(monkeypatch):
    cfg=configuration('tls_cert')
    storage.save_history(7,'policy.example','tls_cert','OK','valid',{})
    probe=type('FakeTls',(),{'name':'tls_cert','run':AsyncMock(side_effect=AssertionError('must use daily evidence'))})()
    dispatcher=Dispatcher(cfg);dispatcher._client=object()
    monkeypatch.setattr(dispatcher,'_build_checks',lambda *a,**kw:[probe])
    result=asyncio.run(dispatcher.run_for(7,'policy.example',use_cache=False))
    assert result[0].cached and probe.run.await_count==0
    with storage._connect() as conn:
        assert conn.execute('SELECT COUNT(*) FROM check_activity').fetchone()[0]==0


def test_local_cached_expiry_change_is_recorded_once_with_original_evidence_time(monkeypatch):
    cfg=configuration('tls_cert');observed=datetime.now(timezone.utc)-timedelta(hours=2)
    metrics={'observed_at':observed.isoformat(),'expires_at':(datetime.now(timezone.utc)+timedelta(days=2)).isoformat(),
             'next_refresh_at':(observed+timedelta(days=1)).isoformat()}
    storage.save_history(7,'policy.example','tls_cert','OK','old assessment',metrics)
    probe=type('FakeTls',(),{'name':'tls_cert','run':AsyncMock(return_value=CheckOutcome(
        'tls_cert',Status.CRIT,'expires soon',metrics,cached=True))})()
    dispatcher=Dispatcher(cfg);dispatcher._client=object()
    monkeypatch.setattr(dispatcher,'_build_checks',lambda *a,**kw:[probe])
    assert due_checks(cfg,7,'policy.example')==['tls_cert']
    result=asyncio.run(dispatcher.run_for(7,'policy.example',use_cache=False))
    assert result[0].cached and result[0].assessment_changed
    storage.save_histories(7,'policy.example',result)
    storage.save_histories(7,'policy.example',result)
    assert storage.last_history_for_check(7,'policy.example','tls_cert')['status']=='CRIT'
    assert due_checks(cfg,7,'policy.example')==[]
    with storage._connect() as conn:
        assert conn.execute('SELECT COUNT(*) FROM history').fetchone()[0]==2


def test_changed_operational_ip_invalidates_only_address_dependent_daily_evidence():
    cfg=configuration('ip_blacklist');now=datetime.now(timezone.utc)
    storage.set_domain_override(7,'policy.example',{'checks':{'ip_change':True}})
    data={'dnsbl_version':3,'zones':cfg.ipbl.zones,'dns_servers':cfg.ipbl.dns_servers,
          'check_ipv6':cfg.ipbl.check_ipv6,'ips_v4':['192.0.2.1']}
    storage.save_history(7,'policy.example','ip_blacklist','OK','clean',data)
    storage.save_history(7,'policy.example','ip_change','OK','changed',{'ips_v4':['192.0.2.2']})
    with storage._write_connection() as conn:
        conn.execute('UPDATE history SET created_at=? WHERE check_name=?',
                     ((now-timedelta(minutes=1)).isoformat(),'ip_blacklist'))
    assert 'ip_blacklist' in due_checks(cfg,7,'policy.example')


def test_reused_older_ip_evidence_is_saved_for_changed_address(monkeypatch):
    cfg = configuration('ip_blacklist')
    now = datetime.now(timezone.utc)
    base = {'dnsbl_version': 3, 'zones': cfg.ipbl.zones,
            'dns_servers': cfg.ipbl.dns_servers, 'check_ipv6': cfg.ipbl.check_ipv6,
            'next_refresh_at': (now + timedelta(hours=20)).isoformat()}
    storage.save_history(7, 'policy.example', 'ip_blacklist', 'OK', 'clean', {
        **base, 'ips_v4': ['192.0.2.1'], 'observed_at': (now-timedelta(hours=1)).isoformat()})
    storage.save_history(7, 'policy.example', 'ip_change', 'OK', 'changed',
                         {'ips_v4': ['192.0.2.2']})
    with storage._write_connection() as conn:
        conn.execute('UPDATE history SET created_at=? WHERE check_name=?',
                     ((now-timedelta(minutes=1)).isoformat(), 'ip_blacklist'))
    reused = {**base, 'ips_v4': ['192.0.2.2'],
              'observed_at': (now-timedelta(hours=2)).isoformat()}
    probe = type('FakeDNSBL', (), {'name': 'ip_blacklist', 'run': AsyncMock(
        return_value=CheckOutcome('ip_blacklist', Status.OK, 'clean', reused, cached=True))})()
    dispatcher = Dispatcher(cfg)
    dispatcher._client = object()
    monkeypatch.setattr(dispatcher, '_build_checks', lambda *a, **kw: [probe])
    results = asyncio.run(dispatcher.run_for(7, 'policy.example'))
    assert results[0].assessment_changed
    storage.save_histories(7, 'policy.example', results)
    assert 'ip_blacklist' not in due_checks(cfg, 7, 'policy.example')
    # Same source timestamp/status, different IP must not be lost by atomic dedupe.
    storage.save_history(7, 'policy.example', 'ip_blacklist', 'OK', 'clean',
                         {**reused, 'ips_v4': ['192.0.2.3']})
    from sitewatcher.check_policy import metrics_from
    assert metrics_from(storage.last_history_for_check(7, 'policy.example',
                        'ip_blacklist'))['ips_v4'] == ['192.0.2.3']


def test_registry_refresh_does_not_hold_operational_domain_slots(monkeypatch):
    from sitewatcher.scheduler import run_tick
    cfg = configuration('http_basic')
    cfg.defaults.checks.rkn_domain = True
    cfg.scheduler.domains_concurrency = 1
    storage.add_domain(7, 'second.example')
    async def scenario():
        started, release = asyncio.Event(), asyncio.Event()
        persisted = []
        async def slow_registry(*args):
            started.set()
            await release.wait()
        monkeypatch.setattr('sitewatcher.dispatcher.prepare_registry', slow_registry)
        monkeypatch.setattr('sitewatcher.dispatcher.current_registry_generation', lambda _: None)
        monkeypatch.setattr('sitewatcher.scheduler.current_registry_generation', lambda _: None)
        monkeypatch.setattr(Dispatcher, '_build_checks', lambda *a, **kw: [
            type('HTTP', (), {'name': 'http_basic', 'run': AsyncMock(return_value=
                CheckOutcome('http_basic', Status.OK, 'online', {}))})(),
            type('RKN', (), {'name': 'rkn_domain', 'run': AsyncMock(return_value=
                CheckOutcome('rkn_domain', Status.UNKNOWN, 'registry refreshing', {}))})()])
        async def on_results(owner, domain, results, **kwargs):
            persisted.append(domain)
        task = asyncio.create_task(run_tick(cfg, warmup=False, on_results=on_results))
        await started.wait()
        try:
            for _ in range(100):
                if len(persisted) == 2:
                    break
                await asyncio.sleep(.01)
            assert len(persisted) == 2
            assert storage.last_history_for_check(7, 'second.example', 'http_basic')['status'] == 'OK'
        finally:
            release.set()
            await task
    asyncio.run(scenario())


def test_concurrent_dispatchers_coalesce_operational_ping_and_ports(monkeypatch):
    cfg = configuration('ping')
    cfg.defaults.checks.ports = True
    async def scenario():
        calls = []
        async def probe(name):
            calls.append(name)
            await asyncio.sleep(.08)
            return CheckOutcome(name, Status.OK, 'online', {})
        monkeypatch.setattr(Dispatcher, '_build_checks', lambda *a, **kw: [
            type('Probe', (), {'name': name, 'run': lambda self: probe(self.name)})()
            for name in ('ping', 'ports')])
        async with Dispatcher(cfg) as first, Dispatcher(cfg) as second:
            results = await asyncio.gather(first.run_for(7, 'policy.example'),
                                           second.run_for(7, 'policy.example'))
        assert sorted(calls) == ['ping', 'ports']
        assert all(item.status is Status.OK for batch in results for item in batch)
        assert sum(item.cached for batch in results for item in batch) == 2
    asyncio.run(scenario())


def test_cancelled_vt_attempt_does_not_create_activity_every_tick(monkeypatch):
    cfg = configuration('malware')
    old = datetime.now(timezone.utc)-timedelta(hours=25)
    metrics = {'url': 'https://policy.example/', 'providers': {'virustotal': {}},
               'observed_at': old.isoformat(),
               'next_refresh_at': (old+timedelta(days=1)).isoformat()}
    storage.save_history(7, 'policy.example', 'malware', 'OK', 'previous clean', metrics)
    claim, _ = storage.claim_virustotal_report(7, metrics['url'], now=old)
    storage.save_virustotal_report(7, metrics['url'], claim,
                                  {'status': 'OK', 'message': 'previous clean', 'metrics': metrics})
    storage.claim_virustotal_report(7, metrics['url'])  # Leader dies before completing.
    assert due_checks(cfg, 7, 'policy.example') == []
    assert build_snapshot(cfg, 7)['domains'][0]['overdue']  # No fabricated fresh clean.
    # Release the attempt's daily guard: the provider must become due again.
    with storage._write_connection() as conn:
        conn.execute('UPDATE virustotal_reports SET requested_at=?', (old.timestamp(),))
    assert due_checks(cfg, 7, 'policy.example') == ['malware']
