import asyncio
import json
import ssl
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from sitewatcher import storage
from sitewatcher.checks.base import Status
from sitewatcher.checks.ip_change import IpChangeCheck
from sitewatcher.checks.tls_cert import TlsCertCheck, _hostname_matches
from sitewatcher.checks.whois_info import WhoisInfoCheck, registrable_domain
from sitewatcher.config import WhoisConfig


@pytest.fixture(autouse=True)
def isolated_default_database(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DEFAULT_DB", tmp_path / "default.db")


@pytest.mark.parametrize(('hostname', 'patterns', 'matches'), [
    ('a.example.com', ['*.example.com'], True),
    ('a.b.example.com', ['*.example.com'], False),
    ('example.com', ['*.example.com'], False),
    ('badexample.com', ['*.example.com'], False),
    ('ПРИМЕР.РФ.', ['xn--e1afmkfd.xn--p1ai'], True),
    ('www.пример.рф', ['*.xn--e1afmkfd.xn--p1ai'], True),
])
def test_tls_hostname_matches_one_label_and_idna(hostname, patterns, matches):
    assert _hostname_matches(hostname, patterns) is matches


def test_tls_invalid_certificate_is_critical(monkeypatch):
    check = TlsCertCheck('example.com')
    monkeypatch.setattr(check, '_fetch_peer_cert', AsyncMock(
        side_effect=ssl.SSLCertVerificationError(1, 'certificate has expired')))
    result = asyncio.run(check.run())
    assert result.status is Status.CRIT
    assert 'certificate' in result.message


def test_dns_default_cache_survives_new_checker(tmp_path, monkeypatch):
    db = tmp_path / 'persistent' / 'sitewatcher.db'
    monkeypatch.setattr(storage, 'DEFAULT_DB', db)
    monkeypatch.chdir(tmp_path)
    check = IpChangeCheck('example.com', cfg=SimpleNamespace())
    check._maybe_upsert(['192.0.2.1'], [], datetime.now(timezone.utc), None, True)
    following = IpChangeCheck('example.com', cfg=SimpleNamespace())
    assert json.loads(following._db_get().snapshot_json)['ips_v4'] == ['192.0.2.1']
    assert db.exists()
    assert not (tmp_path / 'ipchange_cache.sqlite').exists()


def test_whois_honors_configured_database(tmp_path, monkeypatch):
    default = tmp_path / 'default.db'
    custom = tmp_path / 'custom' / 'whois.db'
    monkeypatch.setattr(storage, 'DEFAULT_DB', default)
    check = WhoisInfoCheck('example.com', None, WhoisConfig(db_path=str(custom)))
    check._db_upsert({'expires_at': None}, datetime.now(timezone.utc))
    assert custom.exists()
    assert not default.exists()
    assert check._db_get() is not None


@pytest.mark.parametrize('domain', ['example.ru', 'example.su', 'пример.рф'])
@pytest.mark.parametrize('missing', ['expiry', 'rdap404'])
def test_whois_falls_back_for_supported_tlds(domain, missing, tmp_path, monkeypatch):
    check = WhoisInfoCheck(domain, None, WhoisConfig(db_path=str(tmp_path / 'whois.db')))
    rdap = AsyncMock(return_value=({'events': []}, 1))
    if missing == 'rdap404':
        request = httpx.Request('GET', 'https://rdap.invalid/domain')
        response = httpx.Response(404, request=request)
        rdap.side_effect = httpx.HTTPStatusError('not found', request=request, response=response)
    monkeypatch.setattr(check, '_fetch_rdap', rdap)
    monkeypatch.setattr(check, '_whois_query', AsyncMock(
        return_value='registrar: EXAMPLE\npaid-till: 2099-01-01T00:00:00Z\n'))
    result = asyncio.run(check.run())
    assert result.status is Status.OK
    assert result.metrics['whois_host'] == 'whois.tcinet.ru'
    assert result.metrics['expires_at'].startswith('2099-01-01')


@pytest.mark.parametrize('cfg', [
    WhoisConfig(fallback_whois_if_missing_expiry=False),
    WhoisConfig(tld_overrides={'ru': {'method': 'rdap'}}),
])
def test_whois_fallback_respects_opt_out_and_override(cfg, tmp_path, monkeypatch):
    cfg.db_path = str(tmp_path / 'whois.db')
    check = WhoisInfoCheck('example.ru', None, cfg)
    monkeypatch.setattr(check, '_fetch_rdap', AsyncMock(return_value=({'events': []}, 1)))
    async def unexpected(*args):
        pytest.fail('explicit RDAP preference must not query WHOIS')
    monkeypatch.setattr(check, '_whois_query', unexpected)
    assert asyncio.run(check.run()).status is Status.UNKNOWN


def test_whois_failed_fallback_is_not_healthy(tmp_path, monkeypatch):
    check = WhoisInfoCheck('example.ru', None, WhoisConfig(db_path=str(tmp_path / 'whois.db')))
    monkeypatch.setattr(check, '_fetch_rdap', AsyncMock(return_value=({'events': []}, 1)))
    monkeypatch.setattr(check, '_whois_query', AsyncMock(side_effect=OSError('unreachable')))
    assert asyncio.run(check.run()).status is Status.UNKNOWN
    assert check._db_get() is None


def test_registrable_domain_uses_bundled_suffixes(monkeypatch):
    import requests
    def forbidden(*args, **kwargs):
        pytest.fail('suffix extraction must not make network requests')
    monkeypatch.setattr(requests.Session, 'get', forbidden)
    assert registrable_domain('api.example.co.uk') == 'example.co.uk'
    assert registrable_domain('www.пример.рф') == 'xn--e1afmkfd.xn--p1ai'


def test_tls_cleanup_preserves_cancellation(monkeypatch):
    cert = {'notAfter': 'Jan 01 00:00:00 2099 GMT'}
    ssl_object = SimpleNamespace(getpeercert=lambda: cert)
    writer = SimpleNamespace(
        get_extra_info=lambda name: ssl_object,
        close=lambda: None,
        wait_closed=AsyncMock(side_effect=asyncio.CancelledError),
    )
    monkeypatch.setattr(asyncio, 'open_connection', AsyncMock(return_value=(None, writer)))
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(TlsCertCheck('example.com')._fetch_peer_cert('example.com', 443))


def test_whois_truncated_response_does_not_become_healthy(monkeypatch):
    reader = SimpleNamespace(read=AsyncMock(side_effect=[
        b'paid-till: 2099-01-01T00:00:00Z\n', asyncio.TimeoutError,
    ]))
    writer = SimpleNamespace(
        write=lambda data: None, drain=AsyncMock(), close=lambda: None, wait_closed=AsyncMock(),
    )
    monkeypatch.setattr(asyncio, 'open_connection', AsyncMock(return_value=(reader, writer)))
    check = WhoisInfoCheck('example.ru', None, WhoisConfig(
        tld_overrides={'ru': {'method': 'whois', 'host': 'whois.tcinet.ru'}},
    ))
    result = asyncio.run(check.run())
    assert result.status is Status.UNKNOWN
    assert check._db_get() is None


def test_dns_honors_explicit_cache_path(tmp_path):
    custom = tmp_path / 'dns' / 'cache.db'
    check = IpChangeCheck('example.com', cfg=SimpleNamespace(db_path=str(custom)))
    check._maybe_upsert(['192.0.2.1'], [], datetime.now(timezone.utc), None, True)
    assert custom.exists()
    assert check._db_get() is not None


def test_whois_zero_expiry_thresholds_are_preserved():
    check = WhoisInfoCheck('example.com', None, WhoisConfig(expiry_crit_days=0, expiry_warn_days=0))
    from datetime import timedelta
    expiration = (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()
    assert check._expiry_status(expiration)[0] is Status.OK


def test_dns_zero_refresh_is_preserved():
    check = IpChangeCheck('example.com', cfg=SimpleNamespace(refresh_hours=0))
    assert check.cfg.refresh_hours == 0


def test_whois_zero_refresh_fetches_every_time(tmp_path, monkeypatch):
    check = WhoisInfoCheck('example.com', None, WhoisConfig(
        db_path=str(tmp_path / 'whois.db'), refresh_hours=0,
    ))
    check._db_upsert({'expires_at': '2099-01-01T00:00:00+00:00'}, datetime.now(timezone.utc))
    monkeypatch.setattr(check, '_fetch_rdap', AsyncMock(side_effect=OSError('offline')))
    assert asyncio.run(check.run()).status is Status.UNKNOWN
