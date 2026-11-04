"""Provider failures must never replace a complete index or confirm a clean result."""
import asyncio
from datetime import datetime, timedelta, timezone
import sqlite3
from unittest.mock import AsyncMock

import pytest

from sitewatcher.checks.base import Status
from sitewatcher.checks.rkn_block_sqlite import RknBlockCheck, _parse_lines, rkn_index_path
from sitewatcher.config import RknConfig
from rkn_helpers import registry_data


def checker(tmp_path):
    return RknBlockCheck('example.test', None, RknConfig(index_db_path=str(tmp_path / 'index.db')))


def data(tmp_path, domains=None):
    return registry_data(tmp_path, domains or {'example.test'})


def test_plain_domain_parser_preserves_idna_aliases_and_wildcards():
    assert _parse_lines('пример.рф\n*.wild.пример.рф\nEXAMPLE.COM.\n', 'domains') == {
        'xn--e1afmkfd.xn--p1ai', 'wild.xn--e1afmkfd.xn--p1ai', 'example.com'}


def test_rkn_rebuild_failure_preserves_previous_index(tmp_path):
    check = checker(tmp_path)
    fetched = datetime.now(timezone.utc)
    check._rebuild_index(data(tmp_path, {'old.example'}), fetched)
    broken = data(tmp_path, {'new.example'})
    with sqlite3.connect(broken.path) as db:
        db.execute('DROP TABLE domains')
    with pytest.raises(sqlite3.Error):
        check._rebuild_index(broken, fetched + timedelta(hours=1))
    assert check._query(domain='old.example')[0] == 'old.example'
    assert check._query(ips=['192.0.2.1'])[0] == ['192.0.2.1']
    assert check._read_meta()['fetched_at'] == fetched.isoformat()


def test_stale_index_does_not_confirm_clean_on_refresh_failure(tmp_path, monkeypatch):
    check = checker(tmp_path)
    fetched = datetime.now(timezone.utc) - timedelta(days=2)
    check._rebuild_index(data(tmp_path, {'old.example'}), fetched)
    monkeypatch.setattr(check, '_download_with_fallback', AsyncMock(side_effect=RuntimeError))
    assert asyncio.run(check.run()).status is Status.UNKNOWN
    assert check._query(domain='old.example')[0] == 'old.example'


@pytest.mark.parametrize('text', ['', '<html>maintenance</html>', 'domain;ip;date',
                                 '<!DOCTYPE HTML><a href=https://example.com>error</a>'])
def test_unusable_domain_list_is_not_treated_as_registry(text):
    with pytest.raises(ValueError):
        _parse_lines(text, 'domains')


def test_refresh_cancellation_propagates_without_creating_index(tmp_path, monkeypatch):
    check = checker(tmp_path)
    monkeypatch.setattr(check, '_download_with_fallback', AsyncMock(side_effect=asyncio.CancelledError))
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(check.run())
    assert not check.db_path.exists()


def test_complete_small_test_index_can_confirm_clean(tmp_path):
    check = checker(tmp_path)
    check._rebuild_index(data(tmp_path, {'other.example'}), datetime.now(timezone.utc))
    assert asyncio.run(check.run()).status is Status.OK


def test_direct_rkn_index_path_cannot_target_main_storage(tmp_path, monkeypatch):
    from sitewatcher import storage
    main = tmp_path / 'monitor.db'
    monkeypatch.setattr(storage, 'DEFAULT_DB', main)
    with pytest.raises(ValueError):
        rkn_index_path(RknConfig(index_db_path=str(main)))
    assert not main.exists()
