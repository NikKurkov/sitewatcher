import sqlite3

from sitewatcher.reporting import SnapshotError

from sitewatcher import storage


def active(owner=7):
    from sitewatcher.critical_incidents import read
    from sitewatcher.config import AppConfig
    return read(AppConfig(), owner)


def save(check='http_basic', status='CRIT', owner=7, domain='example.test'):
    storage.save_history(owner, domain, check, status, 'private diagnostic', {})


def test_persistent_per_check_lifecycle_and_owner_isolation():
    save()
    save('tls_cert')
    save(owner=8)
    first = active()[0]['checks'][0]['opened_at']
    save(status='CRIT')
    save('ping', 'OK')
    save(status='UNKNOWN')
    assert len(active()) == 1
    checks = {row['name']: row for row in active()[0]['checks']}
    assert set(checks) == {'http_basic', 'tls_cert'}
    assert checks['http_basic']['opened_at'] == first
    assert checks['http_basic']['status'] == 'UNKNOWN'
    save(status='WARN')
    assert len(active()[0]['checks']) == 2
    save(status='OK')
    assert [row['name'] for row in active()[0]['checks']] == ['tls_cert']
    save('tls_cert', 'OK')
    assert active() == []
    assert len(active(8)) == 1


def test_history_cleanup_restart_and_disabled_checks_do_not_clear_incident():
    from sitewatcher.critical_incidents import read
    from sitewatcher.config import AppConfig
    save()
    with storage._write_connection() as connection:
        connection.execute('DELETE FROM history')
    storage._INITIALIZED_PATHS.discard(storage.DEFAULT_DB)
    storage._ensure_initialized()
    assert len(active()) == 1
    storage.set_domain_override(7, 'example.test', {'checks': {'http_basic': False}})
    assert read(AppConfig(), 7) == []
    storage.set_domain_override(7, 'example.test', {'checks': {'http_basic': True}})
    assert len(active()) == 1
    storage.remove_domain(7, 'example.test')
    assert active() == []


def test_existing_history_backfill_and_rename_never_attach_old_host_incidents():
    save()
    save(status='UNKNOWN')
    save('tls_cert')
    save('tls_cert', 'OK')
    with storage._write_connection() as connection:
        connection.execute('DROP TABLE critical_incidents')
    storage._INITIALIZED_PATHS.discard(storage.DEFAULT_DB)
    storage._ensure_initialized()
    assert [row['name'] for row in active()[0]['checks']] == ['http_basic']
    revision = storage.domain_override_revision(storage.get_domain_override(7, 'example.test'))
    storage.rename_domain(7, 'example.test', 'new.test', {}, expected_revision=revision)
    storage._INITIALIZED_PATHS.discard(storage.DEFAULT_DB)
    storage._ensure_initialized()
    assert active() == []


def test_missing_database_is_not_created(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, 'DEFAULT_DB', tmp_path / 'absent.db')
    try:
        active()
    except (sqlite3.Error, SnapshotError):
        pass
    assert not storage.DEFAULT_DB.exists()


def test_backfill_opening_time_starts_after_host_rename():
    save()
    with storage._write_connection() as connection:
        connection.execute("UPDATE history SET created_at='2020-01-01 00:00:00'")
    revision = storage.domain_override_revision(storage.get_domain_override(7, 'example.test'))
    storage.rename_domain(7, 'example.test', 'new.test', {}, expected_revision=revision)
    save(domain='new.test')
    expected = active()[0]['checks'][0]['opened_at']
    with storage._write_connection() as connection:
        connection.execute('DROP TABLE critical_incidents')
    storage._INITIALIZED_PATHS.discard(storage.DEFAULT_DB)
    storage._ensure_initialized()
    assert active()[0]['checks'][0]['opened_at'] == expected


def test_incident_and_history_are_one_transaction(monkeypatch):
    import pytest
    from sitewatcher import critical_incidents
    storage.add_domain(7, 'example.test')

    def fail(*args):
        raise RuntimeError('synthetic write failure')

    monkeypatch.setattr(critical_incidents, 'record', fail)
    with pytest.raises(RuntimeError, match='synthetic write failure'):
        save()
    assert storage.last_results(7, 'example.test') == []
    assert active() == []


def test_cached_ok_does_not_acknowledge_recovery_and_pause_retains_problem():
    from sitewatcher.checks.base import CheckOutcome, Status
    save()
    storage.save_histories(7, 'example.test', [CheckOutcome(
        'http_basic', Status.OK, 'old cache', {}, cached=True)])
    storage.set_domain_override(7, 'example.test', {'interval_minutes': 0})
    assert active()[0]['paused']
    assert len(active()[0]['checks']) == 1
