from contextlib import closing
from datetime import datetime, timedelta, timezone
import json
import sqlite3

import pytest

from sitewatcher import storage
from sitewatcher.config import AppConfig
from sitewatcher.reporting import SnapshotError, build_snapshot

NOW = datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def database(tmp_path, monkeypatch):
    path = tmp_path / 'reporting.db'
    monkeypatch.setattr(storage, 'DEFAULT_DB', path)
    storage._ensure_initialized()
    return path


def config(**values):
    return AppConfig.model_validate({
        'defaults': {'checks': {name: name in {'ping', 'tls_cert'}
                               for name in type(AppConfig().defaults.checks).model_fields}},
        **values,
    })


def save(owner, domain, check, status='OK', message='up', timestamp='2026-10-21 11:59:00'):
    storage.save_history(owner, domain, check, status, message, {'private': 'secret-metric'})
    with closing(sqlite3.connect(storage.DEFAULT_DB)) as conn, conn:
        conn.execute('UPDATE history SET created_at=? WHERE owner_id=? AND domain=? '
                     'AND check_name=?', (timestamp, owner, domain, check))


def test_snapshot_is_owner_scoped_and_excludes_disabled_checks_and_private_fields(database):
    save(1, 'example.com', 'ping', message='<script>alert("x")</script> 😀')
    save(1, 'example.com', 'tls_cert')
    save(1, 'example.com', 'keywords', 'CRIT', 'disabled check')
    save(2, 'private.example', 'ping', 'CRIT', 'other-owner-message')
    storage.set_domain_override(1, 'example.com', {'proxy': 'http://user:password@proxy.example'})
    snapshot = build_snapshot(config(), 1, now=NOW)
    assert snapshot['generated_at'] == '2026-10-21T12:00:00+00:00'
    assert snapshot['summary'] == {
        'total': 1, 'ok': 1, 'warn': 0, 'crit': 0, 'unknown': 0, 'paused': 0, 'stale': 0,
    }
    domain = snapshot['domains'][0]
    assert domain['name'] == 'example.com' and domain['overall'] == 'OK'
    assert domain['last_checked_at'] == '2026-10-21T11:59:00+00:00'
    assert domain['next_due_at'] == '2026-10-21T12:04:00+00:00'
    assert {check['name'] for check in domain['checks']} == {'ping', 'tls_cert'}
    assert next(check for check in domain['checks'] if check['name'] == 'ping')['message'] == (
        '<script>alert("x")</script> 😀'
    )
    serialized = json.dumps(snapshot)
    for private in ('other-owner-message', 'private.example', 'secret-metric', 'password', 'proxy'):
        assert private not in serialized


def test_missing_enabled_checks_are_unknown_and_due_immediately(database):
    storage.add_domain(1, 'example.com')
    snapshot = build_snapshot(config(), 1, now=NOW)
    domain = snapshot['domains'][0]
    assert domain['overall'] == 'UNKNOWN' and domain['stale'] is True
    assert domain['last_checked_at'] is None
    assert domain['next_due_at'] == snapshot['generated_at']
    assert all(check['missing'] and check['status'] == 'UNKNOWN' for check in domain['checks'])
    save(1, 'example.com', 'ping')
    assert build_snapshot(config(), 1, now=NOW)['domains'][0]['overall'] == 'WARN'


def test_stale_ok_contributes_unknown_without_downgrading_problems(database):
    save(1, 'healthy.example', 'ping', timestamp='2026-10-21 11:00:00')
    save(1, 'healthy.example', 'tls_cert')
    save(1, 'broken.example', 'ping', 'CRIT', timestamp='2026-10-21 11:00:00')
    save(1, 'broken.example', 'tls_cert')
    snapshot = build_snapshot(config(), 1, now=NOW)
    domains = {domain['name']: domain for domain in snapshot['domains']}
    healthy = domains['healthy.example']
    assert healthy['overall'] == 'WARN' and healthy['stale']
    ping = next(check for check in healthy['checks'] if check['name'] == 'ping')
    assert ping['status'] == 'OK' and ping['stale'] and not ping['missing']
    assert healthy['next_due_at'] == '2026-10-21T11:05:00+00:00'
    assert domains['broken.example']['overall'] == 'CRIT'
    assert snapshot['summary']['stale'] == 2


@pytest.mark.parametrize('global_disabled', [False, True])
def test_paused_results_keep_their_status_without_becoming_stale(database, global_disabled):
    save(1, 'example.com', 'ping', timestamp='2026-10-01 00:00:00')
    save(1, 'example.com', 'tls_cert', timestamp='2026-10-01 00:00:00')
    if not global_disabled:
        storage.set_domain_override(1, 'example.com', {'interval_minutes': 0})
    snapshot = build_snapshot(config(scheduler={'enabled': not global_disabled}), 1, now=NOW)
    domain = snapshot['domains'][0]
    assert domain['paused'] and not domain['stale'] and domain['overall'] == 'OK'
    assert domain['next_due_at'] is None
    assert all(not check['stale'] for check in domain['checks'])
    assert snapshot['summary']['paused'] == 1


def test_yaml_settings_drive_enabled_checks_and_next_due_time(database):
    save(1, 'example.com', 'ping', timestamp='2026-10-21 11:58:00')
    cfg = config(domains=[{'name': 'HTTPS://example.com/path', 'interval_minutes': 7,
                          'checks': {'tls_cert': False}}])
    domain = build_snapshot(cfg, 1, now=NOW)['domains'][0]
    assert domain['overall'] == 'OK'
    assert domain['next_due_at'] == '2026-10-21T12:05:00+00:00'
    assert [check['name'] for check in domain['checks']] == ['ping']


@pytest.mark.parametrize('raw', ['{broken', '[]', '{"http_timeout_s":0}',
                               '{"proxy":"bad://user:secret@host"}',
                               pytest.param('[' * 20000 + ']' * 20000, id='excessive-nesting')])
def test_invalid_stored_settings_are_isolated_and_sanitized(database, raw):
    storage.add_domain(1, 'broken.example')
    save(1, 'good.example', 'ping')
    save(1, 'good.example', 'tls_cert')
    with closing(sqlite3.connect(database)) as conn, conn:
        conn.execute('INSERT INTO domain_overrides(owner_id,domain,data_json) VALUES(1,?,?)',
                     ('broken.example', raw))
    snapshot = build_snapshot(config(), 1, now=NOW)
    domains = {domain['name']: domain for domain in snapshot['domains']}
    assert domains['broken.example']['overall'] == 'UNKNOWN'
    assert domains['broken.example']['error'] == 'Invalid domain settings'
    assert domains['good.example']['overall'] == 'OK'
    assert 'secret' not in json.dumps(snapshot)


def test_missing_database_is_not_created(tmp_path, monkeypatch):
    path = tmp_path / 'missing.db'
    monkeypatch.setattr(storage, 'DEFAULT_DB', path)
    with pytest.raises(SnapshotError, match='Monitoring database is unavailable'):
        build_snapshot(config(), 1, now=NOW)
    assert not path.exists()


def test_incompatible_database_is_not_initialized(tmp_path, monkeypatch):
    path = tmp_path / 'empty.db'
    path.touch()
    monkeypatch.setattr(storage, 'DEFAULT_DB', path)
    before = path.read_bytes()
    with pytest.raises(SnapshotError, match='Monitoring database is unavailable'):
        build_snapshot(config(), 1, now=NOW)
    assert path.read_bytes() == before


@pytest.mark.parametrize('owner', [None, 0, -1, True, '1'])
def test_owner_must_be_an_explicit_positive_integer(owner, tmp_path, monkeypatch):
    path = tmp_path / 'missing.db'
    monkeypatch.setattr(storage, 'DEFAULT_DB', path)
    with pytest.raises(ValueError, match='positive owner'):
        build_snapshot(config(), owner, now=NOW)
    assert not path.exists()


def test_snapshot_uses_bounded_queries_and_does_not_initialize_or_write(database, monkeypatch):
    for index in range(25):
        save(1, f'domain{index}.example', 'ping')
    original_connect = sqlite3.connect
    statements = []

    def connect(*args, **kwargs):
        conn = original_connect(*args, **kwargs)
        conn.set_trace_callback(statements.append)
        return conn

    def forbidden_initialization(*args):
        raise AssertionError('Snapshot must never initialize a database')

    monkeypatch.setattr(sqlite3, 'connect', connect)
    monkeypatch.setattr(storage, '_ensure_initialized', forbidden_initialization)
    assert build_snapshot(config(), 1, now=NOW)['summary']['total'] == 25
    assert len([sql for sql in statements if sql.startswith(('SELECT', 'WITH', 'PRAGMA'))]) == 4
    assert all(sql.startswith(('SELECT', 'WITH', 'PRAGMA', 'BEGIN', 'ROLLBACK')) for sql in statements)


def test_snapshot_remains_consistent_when_a_writer_commits_between_queries(database, monkeypatch):
    save(1, 'example.com', 'ping', message='before concurrent update')
    original_connect = sqlite3.connect
    updated = False

    class ReadConnection(sqlite3.Connection):
        def execute(self, sql, parameters=()):
            nonlocal updated
            result = super().execute(sql, parameters)
            if sql.startswith('SELECT d.name') and not updated:
                updated = True
                with closing(original_connect(database)) as writer, writer:
                    writer.execute("UPDATE history SET message='after concurrent update'")
                    writer.execute("INSERT INTO domains(owner_id,name) VALUES(1,'new.example')")
            return result

    def connect(*args, **kwargs):
        return original_connect(*args, **kwargs, factory=ReadConnection)

    monkeypatch.setattr(sqlite3, 'connect', connect)
    snapshot = build_snapshot(config(), 1, now=NOW)
    assert snapshot['summary']['total'] == 1
    ping = next(check for check in snapshot['domains'][0]['checks'] if check['name'] == 'ping')
    assert ping['message'] == 'before concurrent update'
    assert build_snapshot(config(), 1, now=NOW)['summary']['total'] == 2


def test_large_indexed_history_snapshot_has_bounded_sql_work(database, monkeypatch):
    storage.add_domain(1, 'example.com')
    with closing(sqlite3.connect(database)) as conn, conn:
        conn.executemany(
            'INSERT INTO history(owner_id,domain,check_name,status,message,created_at) '
            'VALUES(1,?,?,?,?,?)',
            [('example.com', 'ping', 'OK', 'older', '2026-10-21 11:59:00')] * 10000,
        )
        conn.execute(
            'INSERT INTO history(owner_id,domain,check_name,status,message,created_at) '
            "VALUES(1,'example.com','ping','WARN','newest id','2020-01-01 00:00:00')"
        )
    original_connect = sqlite3.connect

    def connect(*args, **kwargs):
        conn = original_connect(*args, **kwargs)
        steps = 0

        def bounded_work():
            nonlocal steps
            steps += 1000
            return int(steps > 30000)

        conn.set_progress_handler(bounded_work, 1000)
        return conn

    monkeypatch.setattr(sqlite3, 'connect', connect)
    row = build_snapshot(config(), 1, now=NOW)['domains'][0]
    ping = next(check for check in row['checks'] if check['name'] == 'ping')
    assert ping['status'] == 'WARN' and ping['message'] == 'newest id'
    assert ping['checked_at'] == '2020-01-01T00:00:00+00:00'


def test_legacy_database_without_latest_index_remains_readable_and_unmodified(database):
    save(1, 'example.com', 'ping')
    before = build_snapshot(config(), 1, now=NOW)
    with closing(sqlite3.connect(database)) as conn:
        conn.execute('DROP INDEX IF EXISTS idx_history_owner_domain_check_id')
        indexes_before = conn.execute("PRAGMA index_list('history')").fetchall()
    assert build_snapshot(config(), 1, now=NOW) == before
    with closing(sqlite3.connect(database)) as conn:
        assert conn.execute("PRAGMA index_list('history')").fetchall() == indexes_before


def test_snapshot_legacy_domains_without_favorites_stays_read_only(database):
    storage.add_domain(1, 'example.com')
    with sqlite3.connect(database) as conn:
        conn.execute('ALTER TABLE domains DROP COLUMN favorite')
    snapshot = build_snapshot(config(), 1, now=NOW)
    assert snapshot['domains'][0]['favorite'] is False
    with sqlite3.connect(database) as conn:
        columns = {row[1] for row in conn.execute('PRAGMA table_info(domains)')}
    assert 'favorite' not in columns


@pytest.mark.parametrize(('interval', 'age_seconds', 'expected'), [
    (None, 300, False), (None, 599, False), (None, 600, True),
    (7, 600, False), (7, 839, False), (7, 840, True), (0, 3600, False),
])
def test_overdue_notice_waits_for_two_intervals(database, interval, age_seconds, expected):
    save(1, 'example.com', 'ping', timestamp=(NOW - timedelta(seconds=age_seconds)).isoformat())
    save(1, 'example.com', 'tls_cert')
    if interval is not None:
        storage.set_domain_override(1, 'example.com', {'interval_minutes': interval})
    row = build_snapshot(config(), 1, now=NOW)['domains'][0]
    assert row['overdue'] is expected
    if interval != 0:
        assert row['stale']  # Freshness remains conservative; only the notice has a grace period.
