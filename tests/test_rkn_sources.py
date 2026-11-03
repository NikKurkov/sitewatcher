"""Current complete provider bundles replace the frozen z-i snapshot safely."""
import asyncio
import sqlite3
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

import httpx
import pytest

from sitewatcher.checks import rkn_block_sqlite as rkn
from sitewatcher.checks.base import Status
from sitewatcher.config import RknConfig


@pytest.fixture(autouse=True)
def small_sources(monkeypatch):
    monkeypatch.setattr(rkn, '_MIN_DOMAINS', 1, raising=False)
    monkeypatch.setattr(rkn, '_MIN_IPS', 1, raising=False)


def transport(*, fail_primary=False, bad_primary=None, stale_primary=False,
              fail_backup=False, stamp=None, stale_backup_component=False,
              future_primary_component=False):
    stamp = stamp or datetime.now(timezone.utc)
    calls = []
    def handle(request):
        url = str(request.url)
        calls.append(url)
        if 'api.github.com' in url:
            date = (stamp - timedelta(days=30) if stale_backup_component
                    and 'path=reestr_hostname.txt' in url else stamp)
            return httpx.Response(200, json=[{'sha': 'a' * 40,
                'commit': {'committer': {'date': date.isoformat()}}}])
        primary = 'antifilter.download' in url
        if primary and fail_primary or not primary and fail_backup:
            return httpx.Response(503)
        if primary and bad_primary is not None:
            body = bad_primary
        elif url.endswith(('domains.lst', 'reestr_hostname.txt')):
            body = 'c.t-p.cc\nпример.рф\n*.blocked.example\n'
        elif url.endswith(('subnet.lst', 'reestr_ipban4.txt')):
            body = '198.51.100.0/24\n'
        else:
            body = '192.0.2.1\n'
        updated = stamp - timedelta(days=30) if primary and stale_primary else stamp
        if primary and future_primary_component and url.endswith('subnet.lst'):
            updated = stamp + timedelta(days=30)
        return httpx.Response(200, text=body,
                              headers={'Last-Modified': format_datetime(updated, usegmt=True)})
    return httpx.MockTransport(handle), calls


def run_check(tmp_path, mock_transport, *, cls=None, domain='c.t-p.cc', config=None):
    async def run():
        async with httpx.AsyncClient(transport=mock_transport) as client:
            check = (cls or rkn.RknBlockCheck)(domain, client, config or RknConfig(
                index_db_path=str(tmp_path / 'index.db')))
            return await check.run(), check
    return asyncio.run(run())


def test_defaults_and_legacy_z_i_config_use_current_providers():
    assert RknConfig().source == 'antifilter'
    assert RknConfig(source='z-i').source == 'antifilter'
    assert RknConfig(z_i_url='https://old.example/dump.csv.gz').source == 'antifilter'
    with pytest.raises(ValueError):
        RknConfig(cache_ttl_hours=0)
    with pytest.raises(ValueError):
        RknConfig(max_source_age_hours=0)


def test_primary_domain_match_records_provider_and_source_date(tmp_path):
    mock, calls = transport()
    result, check = run_check(tmp_path, mock)
    assert result.status is Status.CRIT and result.metrics['matched'] == 'c.t-p.cc'
    assert result.metrics['source'] == 'antifilter'
    assert result.metrics['source_updated_at']
    assert all('zapret-info' not in url for url in calls)
    assert not any('github' in url for url in calls)
    assert len(calls) == 3
    with sqlite3.connect(check.db_path) as con:
        assert dict(con.execute('SELECT key,value FROM meta'))['source'] == 'antifilter'


@pytest.mark.parametrize('options', [
    {'fail_primary': True}, {'bad_primary': ''},
    {'bad_primary': '<html><a href="https://c.t-p.cc/">error</a></html>'},
    {'stale_primary': True},
])
def test_bad_primary_uses_complete_backup(tmp_path, options):
    mock, calls = transport(**options)
    result, _ = run_check(tmp_path, mock)
    assert result.status is Status.CRIT and result.metrics['source'] == 'bol-van'
    assert any('reestr_hostname.txt' in url for url in calls)
    assert any('reestr_ipban4.txt' in url for url in calls)
    assert any('reestr_resolved_ip4.txt' in url for url in calls)


def test_domain_and_parent_normalization_in_plain_lists(tmp_path):
    for domain, match in [('пример.рф', 'xn--e1afmkfd.xn--p1ai'),
                          ('www.blocked.example', 'blocked.example')]:
        mock, _ = transport()
        result, _ = run_check(tmp_path, mock, domain=domain)
        assert result.status is Status.CRIT and result.metrics['matched'] == match


@pytest.mark.parametrize(('address', 'status'), [
    ('192.0.2.1', Status.WARN), ('198.51.100.200', Status.WARN),
    ('198.51.101.1', Status.OK), ('192.0.2.2', Status.OK),
])
def test_ipv4_membership_in_exact_addresses_and_cidr(tmp_path, monkeypatch, address, status):
    async def resolve(self, domain):
        return [address]
    monkeypatch.setattr(rkn.RknIpCheck, '_resolve_ipv4', resolve)
    mock, _ = transport()
    result, _ = run_check(tmp_path, mock, cls=rkn.RknIpCheck)
    assert result.status is status and result.metrics['source'] == 'antifilter'


def test_both_failed_sources_keep_last_index_and_return_unknown(tmp_path):
    mock, _ = transport()
    _, check = run_check(tmp_path, mock)
    with sqlite3.connect(check.db_path) as con:
        con.execute("UPDATE meta SET value=? WHERE key='fetched_at'",
                    ((datetime.now(timezone.utc) - timedelta(days=2)).isoformat(),))
        before = dict(con.execute('SELECT key,value FROM meta'))
    mock, _ = transport(fail_primary=True, fail_backup=True)
    result, check = run_check(tmp_path, mock)
    assert result.status is Status.UNKNOWN
    with sqlite3.connect(check.db_path) as con:
        assert dict(con.execute('SELECT key,value FROM meta')) == before
        assert con.execute("SELECT 1 FROM domains WHERE domain='c.t-p.cc'").fetchone()


def test_old_index_version_forces_current_provider_refresh(tmp_path):
    path = tmp_path / 'index.db'
    with sqlite3.connect(path) as con:
        con.executescript('CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT);'
                          'CREATE TABLE domains(domain TEXT PRIMARY KEY);'
                          'CREATE TABLE ips(ip TEXT PRIMARY KEY);')
        con.executemany('INSERT INTO meta VALUES (?,?)', [
            ('parser_version', '2'), ('fetched_at', datetime.now(timezone.utc).isoformat())])
    mock, calls = transport()
    result, _ = run_check(tmp_path, mock)
    assert result.status is Status.CRIT and len(calls) == 3


def test_stale_source_timestamps_cannot_be_made_current_by_redownloading(tmp_path):
    old = datetime.now(timezone.utc) - timedelta(days=30)
    mock, _ = transport(stamp=old)
    result, check = run_check(tmp_path, mock)
    assert result.status is Status.UNKNOWN and not check.db_path.exists()


def test_single_failed_component_cannot_publish_a_partial_primary(tmp_path):
    mock, calls = transport()
    def handle(request):
        if str(request.url).endswith('/ip.lst'):
            return httpx.Response(503)
        return mock.handler(request)
    result, _ = run_check(tmp_path, httpx.MockTransport(handle))
    assert result.status is Status.CRIT and result.metrics['source'] == 'bol-van'
    assert any('/' + 'a' * 40 + '/reestr_hostname.txt' in url for url in calls)


def test_suspicious_reduction_uses_backup_instead_of_truncated_primary(tmp_path):
    mock, _ = transport()
    _, check = run_check(tmp_path, mock)
    with sqlite3.connect(check.db_path) as con:
        con.execute("UPDATE meta SET value='10000' WHERE key='domain_count'")
        con.execute("UPDATE meta SET value=? WHERE key='fetched_at'",
                    ((datetime.now(timezone.utc) - timedelta(days=2)).isoformat(),))
    mock, _ = transport()
    result, _ = run_check(tmp_path, mock)
    assert result.status is Status.CRIT and result.metrics['source'] == 'bol-van'


def test_configured_backup_can_be_primary_without_contacting_antifilter(tmp_path):
    mock, calls = transport()
    result, _ = run_check(tmp_path, mock, config=RknConfig(
        source='bol-van', index_db_path=str(tmp_path / 'index.db')))
    assert result.status is Status.CRIT and result.metrics['source'] == 'bol-van'
    assert not any('antifilter.download' in url for url in calls)


def test_source_without_a_freshness_timestamp_falls_back(tmp_path):
    mock, _ = transport()
    def handle(request):
        response = mock.handler(request)
        if 'antifilter.download' in str(request.url):
            response.headers.pop('Last-Modified', None)
        return response
    result, _ = run_check(tmp_path, httpx.MockTransport(handle))
    assert result.status is Status.CRIT and result.metrics['source'] == 'bol-van'


def test_future_component_cannot_hide_behind_current_component_dates(tmp_path):
    mock, _ = transport(future_primary_component=True)
    result, _ = run_check(tmp_path, mock)
    assert result.status is Status.CRIT and result.metrics['source'] == 'bol-van'


def test_new_repository_commit_cannot_refresh_old_registry_artifacts(tmp_path):
    mock, _ = transport(fail_primary=True, stale_backup_component=True)
    result, check = run_check(tmp_path, mock)
    assert result.status is Status.UNKNOWN and not check.db_path.exists()


def test_current_failure_keeps_attempt_timestamp_and_configured_schedule(tmp_path):
    from sitewatcher import storage
    from sitewatcher.config import AppConfig, ChecksModel
    from sitewatcher.reporting import build_snapshot
    from sitewatcher.scheduler import due_checks
    mock, _ = transport(fail_primary=True, fail_backup=True)
    result, _ = run_check(tmp_path, mock)
    cfg = AppConfig.model_validate({'defaults': {'checks': {
        **dict.fromkeys(ChecksModel.model_fields, False), 'rkn_domain': True}}})
    storage.add_domain(1, 'c.t-p.cc')
    storage.save_histories(1, 'c.t-p.cc', [result])
    assert due_checks(cfg, 1, 'c.t-p.cc') == []
    row = build_snapshot(cfg, 1)['domains'][0]['checks'][0]
    assert row['status'] == 'UNKNOWN' and row['checked_at'] is not None and not row['missing']


def test_legacy_rkn_result_is_not_current_cache_or_scheduling_evidence(tmp_path):
    from sitewatcher import storage
    from sitewatcher.config import AppConfig, ChecksModel
    from sitewatcher.dispatcher import Dispatcher
    from sitewatcher.reporting import build_snapshot
    from sitewatcher.scheduler import due_checks
    from sitewatcher.bot.alerts import _complete_results, _overall_from_results
    cfg = AppConfig.model_validate({'defaults': {'checks': {
        **dict.fromkeys(ChecksModel.model_fields, False), 'rkn_domain': True}}})
    storage.add_domain(1, 'c.t-p.cc')
    storage.save_history(1, 'c.t-p.cc', 'rkn_domain', 'OK', 'Domain not listed', {'source': 'z-i'})
    assert Dispatcher(cfg)._maybe_cached_result(1, 'c.t-p.cc', 'rkn_domain', lambda _: 1440) is None
    assert due_checks(cfg, 1, 'c.t-p.cc') == ['rkn_domain']
    assert build_snapshot(cfg, 1)['domains'][0]['overall'] != 'OK'
    assert _overall_from_results(_complete_results(cfg, 1, 'c.t-p.cc', [])) != 'OK'
