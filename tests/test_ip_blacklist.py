import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import dns.exception
import dns.resolver
import pytest

from sitewatcher.checks.base import Status
from sitewatcher.checks.ip_blacklist import IpBlacklistCheck
from sitewatcher.config import AppConfig
from sitewatcher import storage
from sitewatcher.dispatcher import Dispatcher


def test_default_sources_are_available_without_yaml_and_explicit_empty_is_preserved():
    assert AppConfig().ipbl.zones == [
        'dnsbl.dronebl.org', 'bl.blocklist.de', 'psbl.surriel.com',
    ]
    assert AppConfig.model_validate({'ipbl': {'zones': []}}).ipbl.zones == []


def check_with_dns(monkeypatch, *, positive='127.0.0.2', negative=None,
                   target=None, zones=None):
    check = IpBlacklistCheck('example.test', zones=zones or ['bl.example'])
    monkeypatch.setattr(check, '_resolve_ips', AsyncMock(return_value=(['192.0.2.1'], [])))
    queried = []

    async def resolve(name, record, **kwargs):
        queried.append((name, record))
        if record == 'TXT':
            raise dns.resolver.NoAnswer
        answer = (positive if name.startswith('2.0.0.127.') else
                  negative if name.startswith('1.0.0.127.') else target)
        if isinstance(answer, Exception):
            raise answer
        if answer is None:
            raise dns.resolver.NXDOMAIN
        return [SimpleNamespace(address=value) for value in answer.split(',')]

    monkeypatch.setattr(check.resolver, 'resolve', resolve)
    return check, queried


@pytest.mark.parametrize('code', ['127.255.255.254', '127.255.255.255', '192.0.2.5',
                                 '127.0.1.255', 'not-an-address'])
def test_dnsbl_service_errors_never_become_listings(monkeypatch, code):
    check, _ = check_with_dns(monkeypatch, target=code)
    result = asyncio.run(check.run())
    assert result.status is Status.UNKNOWN
    assert result.metrics['hits_count'] == 0
    assert result.metrics['errors_count'] == 1
    assert code in result.metrics['query_errors'][0]['error']


@pytest.mark.parametrize(('positive', 'negative'), [
    (None, None), ('127.255.255.254', None),
    ('127.0.0.2', '127.0.0.2'), (dns.exception.Timeout(), None),
])
def test_unhealthy_sources_cannot_report_clean_or_listed(monkeypatch, positive, negative):
    check, queried = check_with_dns(monkeypatch, positive=positive, negative=negative,
                                  target='127.0.0.2')
    result = asyncio.run(check.run())
    assert result.status is Status.UNKNOWN
    assert result.metrics['zones_checked'] == 0
    assert len(result.metrics['zone_errors']) == 1
    assert not any(name.startswith('1.2.0.192.') for name, _ in queried)


def test_dronebl_test_code_is_accepted(monkeypatch):
    check, _ = check_with_dns(monkeypatch, positive='127.0.0.1',
                             zones=['dnsbl.dronebl.org'])
    result = asyncio.run(check.run())
    assert result.status is Status.OK
    assert result.metrics['zones_checked'] == 1


def test_one_completed_clean_source_is_ok_with_incomplete_coverage(monkeypatch):
    check = IpBlacklistCheck('example.test', zones=['good.example', 'dead.example'])
    monkeypatch.setattr(check, '_resolve_ips', AsyncMock(return_value=(['192.0.2.1'], [])))

    async def resolve(name, record, **kwargs):
        if name.startswith('2.0.0.127.good.'):
            return [SimpleNamespace(address='127.0.0.2')]
        raise dns.resolver.NXDOMAIN

    monkeypatch.setattr(check.resolver, 'resolve', resolve)
    result = asyncio.run(check.run())
    assert result.status is Status.OK
    assert result.message == 'Not listed; incomplete DNSBL coverage'
    assert result.metrics['partial_coverage'] is True
    assert result.metrics['zones_completed'] == 1
    assert result.metrics['queries_total'] == 1
    assert result.metrics['zones_checked'] == 1
    assert result.metrics['zones_total'] == 2


def test_multi_address_hits_retain_codes_and_partial_failures(monkeypatch):
    check, _ = check_with_dns(monkeypatch, target='127.0.0.2,127.0.0.3')
    result = asyncio.run(check.run())
    assert result.status is Status.CRIT
    assert result.metrics['hits'][0]['a'] == ['127.0.0.2', '127.0.0.3']


def test_empty_sources_explain_missing_configuration():
    result = asyncio.run(IpBlacklistCheck('example.test', zones=[]).run())
    assert result.status is Status.UNKNOWN
    assert result.message == 'IP blocklists are not configured'


def test_zones_are_normalized_and_deduplicated():
    check = IpBlacklistCheck('example.test', zones=[' BL.EXAMPLE. ', 'bl.example', '.', ''])
    assert check.zones == ['bl.example']


@pytest.mark.parametrize(('status', 'metrics', 'reuse'), [
    ('OK', {}, False),
    ('CRIT', {}, False),
    ('OK', {'dnsbl_version': 3, 'zones': ['other.example']}, False),
    ('UNKNOWN', {'dnsbl_version': 3, 'zones': ['bl.example']}, False),
    ('UNKNOWN', {'dnsbl_version': 2, 'zones': ['bl.example'],
                 'dns_servers': None, 'check_ipv6': False}, False),
    ('OK', {'dnsbl_version': 3, 'zones': ['bl.example'],
            'dns_servers': None, 'check_ipv6': False}, True),
])
def test_cache_rejects_unverified_stale_or_incomplete_coverage(status, metrics, reuse):
    storage.add_domain(41, 'example.test')
    storage.save_history(41, 'example.test', 'ip_blacklist', status, 'saved', metrics)
    cfg = AppConfig.model_validate({'ipbl': {'zones': ['bl.example']}})
    result = Dispatcher(cfg)._maybe_cached_result(41, 'example.test', 'ip_blacklist', lambda _: 60)
    assert (result is not None) is reuse
    cfg.ipbl.dns_servers = ['1.1.1.1']
    assert Dispatcher(cfg)._maybe_cached_result(
        41, 'example.test', 'ip_blacklist', lambda _: 60) is None


def test_known_provider_rejects_undocumented_return_code(monkeypatch):
    check, _ = check_with_dns(monkeypatch, target='127.0.0.99', zones=['bl.spamcop.net'])
    assert asyncio.run(check.run()).status is Status.UNKNOWN


def test_scheduler_rechecks_legacy_dnsbl_results_without_waiting_a_day():
    from sitewatcher.scheduler import due_checks
    storage.add_domain(41, 'example.test')
    storage.set_domain_override(41, 'example.test', {'checks': {'ip_blacklist': True}})
    storage.save_history(41, 'example.test', 'ip_blacklist', 'UNKNOWN', 'no zones configured', {})
    cfg = AppConfig()
    assert 'ip_blacklist' in due_checks(cfg, 41, 'example.test')


def test_confirmed_hit_survives_a_failed_control_from_another_source(monkeypatch):
    check = IpBlacklistCheck('example.test', zones=['good.example', 'dead.example'])
    monkeypatch.setattr(check, '_resolve_ips', AsyncMock(return_value=(['192.0.2.1'], [])))

    async def resolve(name, record, **kwargs):
        if (name.endswith('.good.example.') and record == 'A'
                and not name.startswith('1.0.0.127.')):
            return [SimpleNamespace(address='127.0.0.2')]
        raise dns.resolver.NXDOMAIN

    monkeypatch.setattr(check.resolver, 'resolve', resolve)
    result = asyncio.run(check.run())
    assert result.status is Status.CRIT
    assert result.metrics['zones_checked'] == 1
    assert result.metrics['errors_count'] == 1
    assert 'incomplete coverage' in result.message


@pytest.mark.parametrize('clean', [True, False])
def test_query_timeout_requires_at_least_one_fully_completed_source(monkeypatch, clean):
    check = IpBlacklistCheck('example.test', zones=['good.example', 'slow.example'])
    monkeypatch.setattr(check, '_resolve_ips', AsyncMock(return_value=(['192.0.2.1'], [])))

    async def resolve(name, record, **kwargs):
        if name.startswith('2.0.0.127.'):
            return [SimpleNamespace(address='127.0.0.2')]
        if name.startswith('1.0.0.127.'):
            raise dns.resolver.NXDOMAIN
        if clean and name.endswith('.good.example.'):
            raise dns.resolver.NXDOMAIN
        raise dns.exception.Timeout

    monkeypatch.setattr(check.resolver, 'resolve', resolve)
    result = asyncio.run(check.run())
    assert result.status is (Status.OK if clean else Status.UNKNOWN)
    assert result.metrics['zones_completed'] == int(clean)
    assert result.metrics['partial_coverage'] is True


def test_partial_ip_answers_do_not_count_as_a_completed_source(monkeypatch):
    check = IpBlacklistCheck('example.test', zones=['bl.example'])
    monkeypatch.setattr(check, '_resolve_ips', AsyncMock(
        return_value=(['192.0.2.1', '192.0.2.2'], [])))

    async def resolve(name, record, **kwargs):
        if name.startswith('2.0.0.127.'):
            return [SimpleNamespace(address='127.0.0.2')]
        if name.startswith('1.0.0.127.') or name.startswith('1.2.0.192.'):
            raise dns.resolver.NXDOMAIN
        raise dns.exception.Timeout

    monkeypatch.setattr(check.resolver, 'resolve', resolve)
    result = asyncio.run(check.run())
    assert result.status is Status.UNKNOWN
    assert result.metrics['zones_completed'] == 0
