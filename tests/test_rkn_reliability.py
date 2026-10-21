import asyncio
import socket
import sqlite3
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import httpx
import pytest

from sitewatcher.checks.base import Status
from sitewatcher.checks.rkn_block_sqlite import RknBlockCheck
from sitewatcher.config import RknConfig


def checker(tmp_path, **options):
    return RknBlockCheck('example.test', None, RknConfig(
        index_db_path=str(tmp_path / 'index.db'), check_ip=False, **options,
    ))


def test_rkn_parser_preserves_idna_aliases_and_wildcard_domains():
    domains, ips = RknBlockCheck._parse_dump(
        '192.0.2.1;example.xn--p1ai|пример.рф|*.wild.пример.рф;'
        'https://пример.рф/path;EXAMPLE.COM.;invalid_name.com\n'
    )
    assert domains == {
        'example.xn--p1ai', 'xn--e1afmkfd.xn--p1ai',
        'wild.xn--e1afmkfd.xn--p1ai', 'example.com',
    }
    assert ips == {'192.0.2.1'}


def test_rkn_unicode_target_matches_ascii_index(tmp_path):
    check = checker(tmp_path)
    check.domain = 'пример.рф'
    check._rebuild_index('xn--e1afmkfd.xn--p1ai', datetime.now(timezone.utc))
    result = asyncio.run(check.run())
    assert result.status is Status.CRIT
    assert result.metrics['matched'] == 'xn--e1afmkfd.xn--p1ai'


def test_rkn_rebuild_failure_preserves_previous_index(tmp_path, monkeypatch):
    check = checker(tmp_path)
    fetched = datetime.now(timezone.utc)
    check._rebuild_index('old.example;192.0.2.1', fetched)
    monkeypatch.setattr(check, '_parse_dump', lambda text: ({object()}, set()))
    with pytest.raises(sqlite3.ProgrammingError):
        check._rebuild_index('new.example', fetched + timedelta(hours=1))
    assert check._query_domain_match('old.example', False) == 'old.example'
    assert check._query_ip_matches(['192.0.2.1']) == ['192.0.2.1']
    assert check._read_meta_fetched_at() == fetched


def test_rkn_stale_index_does_not_confirm_clean_on_refresh_failure(tmp_path, monkeypatch):
    check = checker(tmp_path)
    check._rebuild_index('old.example', datetime.now(timezone.utc) - timedelta(days=2))
    monkeypatch.setattr(check, '_download_dump_with_fallbacks', AsyncMock(
        side_effect=RuntimeError('offline'),
    ))
    assert asyncio.run(check.run()).status is Status.UNKNOWN
    assert check._query_domain_match('old.example', False) == 'old.example'


@pytest.mark.parametrize('text', ['', '<html>maintenance</html>', 'domain;ip;date'])
def test_rkn_empty_or_unusable_dump_keeps_existing_index(tmp_path, text):
    check = checker(tmp_path)
    fetched = datetime.now(timezone.utc)
    check._rebuild_index('old.example', fetched)
    with pytest.raises(ValueError):
        check._rebuild_index(text, fetched + timedelta(hours=1))
    assert check._query_domain_match('old.example', False) == 'old.example'
    assert check._read_meta_fetched_at() == fetched


def test_rkn_incomplete_parts_use_mirror_instead_of_partial_index(tmp_path, monkeypatch):
    check = checker(tmp_path)
    async def response(client, url, **kwargs):
        request = httpx.Request('GET', url)
        if url.endswith('dump-00.csv'):
            return httpx.Response(200, text='partial.example', request=request)
        if url.endswith('mirrors.txt'):
            return httpx.Response(200, text='https://mirror.example', request=request)
        if url.startswith('https://mirror.example/'):
            return httpx.Response(200, text='complete.example', request=request)
        return httpx.Response(404, request=request)
    from sitewatcher.checks import rkn_block_sqlite
    monkeypatch.setattr(rkn_block_sqlite, 'get_with_retries', response)
    assert asyncio.run(check._download_dump_with_fallbacks()) == 'complete.example'


def test_rkn_dns_failure_does_not_confirm_clean(tmp_path, monkeypatch):
    check = checker(tmp_path)
    check.cfg.check_ip = True
    check._rebuild_index('other.example', datetime.now(timezone.utc))
    async def scenario():
        loop = asyncio.get_running_loop()
        monkeypatch.setattr(loop, 'getaddrinfo', AsyncMock(side_effect=socket.gaierror('offline')))
        return await check.run()
    assert asyncio.run(scenario()).status is Status.UNKNOWN


@pytest.mark.parametrize('compressed', [False, True])
def test_rkn_primary_decodes_cp1251_without_losing_domains(tmp_path, monkeypatch, compressed):
    import gzip
    check = checker(tmp_path)
    body = 'пример.рф'.encode('cp1251')
    if compressed:
        body = gzip.compress(body)
    async def response(client, url, **kwargs):
        return httpx.Response(200, content=body, request=httpx.Request('GET', url))
    from sitewatcher.checks import rkn_block_sqlite
    monkeypatch.setattr(rkn_block_sqlite, 'get_with_retries', response)
    text = asyncio.run(check._download_dump_with_fallbacks())
    assert check._parse_dump(text)[0] == {'xn--e1afmkfd.xn--p1ai'}


def test_rkn_missing_index_download_failure_is_unknown(tmp_path, monkeypatch):
    check = checker(tmp_path)
    monkeypatch.setattr(check, '_download_dump_with_fallbacks', AsyncMock(side_effect=OSError))
    assert asyncio.run(check.run()).status is Status.UNKNOWN
    assert not check.db_path.exists()


def test_rkn_successful_small_index_can_confirm_clean(tmp_path):
    check = checker(tmp_path)
    check._rebuild_index('other.example', datetime.now(timezone.utc))
    assert asyncio.run(check.run()).status is Status.OK


def test_rkn_refresh_cancellation_propagates(tmp_path, monkeypatch):
    check = checker(tmp_path)
    monkeypatch.setattr(check, '_download_dump_with_fallbacks', AsyncMock(
        side_effect=asyncio.CancelledError,
    ))
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(check.run())


def test_rkn_legacy_parser_index_is_rebuilt_before_confirming_clean(tmp_path, monkeypatch):
    check = checker(tmp_path)
    check._rebuild_index('other.example', datetime.now(timezone.utc))
    with sqlite3.connect(check.db_path) as connection:
        connection.execute("DELETE FROM meta WHERE key='parser_version'")
    monkeypatch.setattr(check, '_download_dump_with_fallbacks', AsyncMock(
        return_value='example.test',
    ))
    assert asyncio.run(check.run()).status is Status.CRIT


@pytest.mark.parametrize('html', [
    '<!doctype html><html><a href=https://example.com>error</a></html>',
    '<HTML><a href="https://example.com">maintenance</a></HTML>',
    '\ufeff \n<!DOCTYPE HTML><html><a href="https://example.com">error</a></html>',
])
def test_rkn_html_error_page_does_not_replace_registry_index(tmp_path, monkeypatch, html):
    check = checker(tmp_path)
    fetched = datetime.now(timezone.utc) - timedelta(days=2)
    check._rebuild_index('old.example;192.0.2.1', fetched)
    monkeypatch.setattr(check, '_download_dump_with_fallbacks', AsyncMock(return_value=html))
    result = asyncio.run(check.run())
    assert result.status is Status.UNKNOWN
    assert check._query_domain_match('old.example', False) == 'old.example'
    assert check._query_ip_matches(['192.0.2.1']) == ['192.0.2.1']
    assert check._read_meta_fetched_at() == fetched


def test_direct_rkn_index_path_cannot_target_main_storage(tmp_path, monkeypatch):
    from sitewatcher import storage
    from sitewatcher.checks.rkn_block_sqlite import rkn_index_path
    main = tmp_path / 'monitor.db'
    monkeypatch.setattr(storage, 'DEFAULT_DB', main)
    with pytest.raises(ValueError):
        rkn_index_path(RknConfig(index_db_path=str(main)))
    assert not main.exists()
