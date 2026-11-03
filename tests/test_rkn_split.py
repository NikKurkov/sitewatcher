"""RKN domain and shared-hosting IP listings have independent identities and severity."""
import asyncio
import csv
import io
import ipaddress
import socket
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from sitewatcher import storage, web_actions
from sitewatcher.checks import rkn_block_sqlite as rkn
from sitewatcher.checks.base import Status
from sitewatcher.config import AppConfig, ChecksModel, RknConfig, resolve_settings
from sitewatcher.dispatcher import Dispatcher
from sitewatcher.reporting import build_snapshot
from sitewatcher.scheduler import due_checks
from sitewatcher.utils.domains_csv import HEADERS, export_domains_csv, import_domains_csv


def split_config(**extra):
    return AppConfig.model_validate({
        'defaults': {'checks': {**dict.fromkeys(ChecksModel.model_fields, False),
                                'rkn_domain': True, 'rkn_ip': True}}, **extra,
    })


@pytest.mark.parametrize(('dump', 'domain_status', 'ip_status'), [
    ('other.example;192.0.2.1', Status.OK, Status.WARN),
    ('example.com;192.0.2.2', Status.CRIT, Status.OK),
    ('example.com;192.0.2.1', Status.CRIT, Status.WARN),
])
def test_rkn_domain_and_ip_results_are_independent(tmp_path, monkeypatch, dump,
                                                  domain_status, ip_status):
    cfg = RknConfig(index_db_path=str(tmp_path / 'rkn.sqlite3'))
    domain = rkn.RknBlockCheck('example.com', None, cfg)
    ip = rkn.RknIpCheck('example.com', None, cfg)
    domain_name, ip_address = dump.split(';')
    domain._rebuild_index(rkn.RegistryData({domain_name}, {ipaddress.IPv4Network(ip_address)},
                                          'antifilter', datetime.now(timezone.utc)),
                          datetime.now(timezone.utc))
    monkeypatch.setattr(domain, '_resolve_ipv4', AsyncMock(side_effect=AssertionError('No DNS')))
    monkeypatch.setattr(ip, '_resolve_ipv4', AsyncMock(return_value=['192.0.2.1']))
    async def run():
        return await asyncio.gather(domain.run(), ip.run())
    domain_result, ip_result = asyncio.run(run())
    assert (domain_result.check, domain_result.status) == ('rkn_domain', domain_status)
    assert (ip_result.check, ip_result.status) == ('rkn_ip', ip_status)
    if ip_status is Status.WARN:
        assert ip_result.metrics['matched'] == ['192.0.2.1']
        assert 'shared' in ip_result.message.lower()


@pytest.mark.parametrize('answer', [[], socket.gaierror('DNS unavailable')])
def test_ip_without_dns_evidence_is_unknown(tmp_path, monkeypatch, answer):
    check = rkn.RknIpCheck('example.com', None, RknConfig(
        index_db_path=str(tmp_path / 'rkn.sqlite3')))
    check._rebuild_index(rkn.RegistryData({'other.example'},
        {ipaddress.IPv4Network('192.0.2.1')}, 'antifilter', datetime.now(timezone.utc)),
        datetime.now(timezone.utc))
    resolver = (AsyncMock(side_effect=answer) if isinstance(answer, Exception)
                else AsyncMock(return_value=answer))
    monkeypatch.setattr(check, '_resolve_ipv4', resolver)
    assert asyncio.run(check.run()).status is Status.UNKNOWN


def test_legacy_flags_schedules_and_global_ip_disable_remain_supported():
    cfg = AppConfig.model_validate({
        'defaults': {'checks': {'rkn_block': True}},
        'schedules': {'rkn_block': {'interval_minutes': 37, 'cache_ttl_minutes': 11}},
    })
    settings = resolve_settings(cfg, 'example.com')
    assert settings.checks.rkn_domain is settings.checks.rkn_ip is True
    assert cfg.schedules.rkn_domain.interval_minutes == 37
    assert cfg.schedules.rkn_ip.cache_ttl_minutes == 11
    cfg.rkn.check_ip = False
    assert resolve_settings(cfg, 'example.com').checks.rkn_ip is False
    assert resolve_settings(cfg, 'example.com').checks.rkn_domain is True


def test_explicit_new_settings_override_the_legacy_alias():
    from sitewatcher.main import _parse_only
    cfg = AppConfig.model_validate({
        'defaults': {'checks': {'rkn_block': True, 'rkn_domain': False}},
        'schedules': {'rkn_block': {'interval_minutes': 37},
                      'rkn_ip': {'interval_minutes': 60}},
    })
    checks = resolve_settings(cfg, 'example.com').checks
    assert checks.rkn_domain is False and checks.rkn_ip is True
    assert cfg.schedules.rkn_domain.interval_minutes == 37
    assert cfg.schedules.rkn_ip.interval_minutes == 60
    assert _parse_only('rkn_block') == ['rkn_domain', 'rkn_ip']


def test_legacy_override_edit_preserves_checks_and_allows_independent_flags():
    cfg = AppConfig()
    storage.add_domain(1, 'example.com')
    storage.set_domain_override(1, 'example.com', {'checks': {'rkn_block': True}})
    context = web_actions.settings_context(cfg, 1, 'example.com')
    assert context['values']['check.rkn_domain'] == context['values']['check.rkn_ip'] == 'on'
    web_actions.save_domain(cfg, 1, {**context['values'], 'check.rkn_ip': 'off'})
    checks = resolve_settings(cfg, 'example.com', storage.get_domain_override(1, 'example.com')).checks
    assert checks.rkn_domain is True and checks.rkn_ip is False


def test_legacy_combined_critical_does_not_seed_current_status_cache_or_schedule():
    cfg = split_config()
    storage.add_domain(1, 'example.com')
    storage.save_history(1, 'example.com', 'rkn_block', 'CRIT', 'legacy IP hit', {'type': 'ip'})
    assert set(due_checks(cfg, 1, 'example.com')) == {'rkn_domain', 'rkn_ip'}
    assert build_snapshot(cfg, 1)['domains'][0]['overall'] == 'UNKNOWN'
    dispatcher = Dispatcher(cfg)
    for name in ('rkn_domain', 'rkn_ip'):
        assert dispatcher._maybe_cached_result(1, 'example.com', name, lambda _: 1440) is None
    metrics = {'source': 'antifilter', 'source_updated_at': datetime.now(timezone.utc).isoformat()}
    storage.save_history(1, 'example.com', 'rkn_domain', 'OK', 'not listed', metrics)
    storage.save_history(1, 'example.com', 'rkn_ip', 'WARN', 'shared IP listed', metrics)
    assert build_snapshot(cfg, 1)['domains'][0]['overall'] == 'WARN'
    assert due_checks(cfg, 1, 'example.com') == []
    assert dispatcher._maybe_cached_result(2, 'example.com', 'rkn_ip', lambda _: 1440) is None


def test_dispatcher_builds_independent_rkn_checks_with_shared_index(tmp_path, monkeypatch):
    cfg = split_config(rkn={'index_db_path': str(tmp_path / 'rkn.sqlite3')})
    download = AsyncMock(return_value=rkn.RegistryData({'example.com'},
        {ipaddress.IPv4Network('192.0.2.1')}, 'antifilter', datetime.now(timezone.utc)))
    monkeypatch.setattr(rkn.RknBlockCheck, '_download_with_fallback', download)
    monkeypatch.setattr(rkn.RknBlockCheck, '_resolve_ipv4', AsyncMock(return_value=['192.0.2.1']))
    async def run():
        async with Dispatcher(cfg) as dispatcher:
            return await dispatcher.run_for(0, 'example.com', ephemeral=True)
    # Web manual runs create a fresh asyncio loop for each request.
    for _ in range(2):
        results = asyncio.run(run())
        assert {item.check: item.status for item in results} == {
            'rkn_domain': Status.CRIT, 'rkn_ip': Status.WARN}
    assert download.await_count == 1


@pytest.mark.parametrize('legacy', [True, False])
def test_csv_preserves_legacy_and_independent_rkn_controls(legacy):
    assert 'checks.rkn_domain' in HEADERS and 'checks.rkn_ip' in HEADERS
    headers = tuple(key for key in HEADERS if not legacy or key not in {
        'checks.rkn_domain', 'checks.rkn_ip'})
    stream = io.StringIO()
    writer = csv.DictWriter(stream, fieldnames=headers, delimiter=';')
    writer.writeheader()
    flags = ({'checks.rkn_block': 'true'} if legacy
             else {'checks.rkn_domain': 'false', 'checks.rkn_ip': 'true'})
    writer.writerow({'domain': 'example.com', **flags})
    result = import_domains_csv(1, stream.getvalue().encode())
    assert result.added == 1 and not result.errors
    result = import_domains_csv(2, export_domains_csv(1))
    assert result.added == 1 and not result.errors
    for owner in (1, 2):
        checks = resolve_settings(AppConfig(), 'example.com',
                                  storage.get_domain_override(owner, 'example.com')).checks
        assert checks.rkn_domain is legacy and checks.rkn_ip is True
