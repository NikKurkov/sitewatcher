"""Web and worker share an RKN index and must tolerate each other's long writes."""
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime, timedelta, timezone
import sqlite3

from sitewatcher.checks.rkn_block_sqlite import RknBlockCheck
from rkn_helpers import registry_data
from sitewatcher.config import RknConfig


def dataset(tmp_path, domain, *, age_days=0):
    return registry_data(tmp_path, {domain},
                         updated=datetime.now(timezone.utc) - timedelta(days=age_days))


def test_index_writer_waits_for_another_process_longer_than_sqlite_default(tmp_path):
    check = RknBlockCheck('c.t-p.cc', None, RknConfig(index_db_path=str(tmp_path / 'index.db')))
    check._rebuild_index(dataset(tmp_path, 'old.example', age_days=2),
                          datetime.now(timezone.utc) - timedelta(days=2))
    blocker = sqlite3.connect(check.db_path)
    blocker.execute('BEGIN IMMEDIATE')
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(check._rebuild_index, dataset(tmp_path, 'c.t-p.cc'),
                                     datetime.now(timezone.utc))
            # A real full index write takes longer than SQLite's default five seconds.
            wait([future], timeout=6)
            blocker.rollback()
            future.result(timeout=5)
    finally:
        blocker.close()
    assert check._query(domain='c.t-p.cc')[0] == 'c.t-p.cc'


def test_slower_writer_does_not_replace_an_already_published_newer_snapshot(tmp_path):
    check = RknBlockCheck('c.t-p.cc', None, RknConfig(index_db_path=str(tmp_path / 'index.db')))
    check._rebuild_index(dataset(tmp_path, 'c.t-p.cc'), datetime.now(timezone.utc))
    check._rebuild_index(dataset(tmp_path, 'outdated.example', age_days=1), datetime.now(timezone.utc))
    assert check._query(domain='c.t-p.cc')[0] == 'c.t-p.cc'
