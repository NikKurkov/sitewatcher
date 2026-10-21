from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import sqlite3
from threading import Barrier

import pytest

from sitewatcher import storage
from sitewatcher.checks.base import CheckOutcome, Status


@pytest.fixture
def database(tmp_path, monkeypatch):
    path = tmp_path / "integrity.db"
    monkeypatch.setattr(storage, "DEFAULT_DB", path)
    storage._ensure_initialized()
    return path


def test_nested_unset_preserves_siblings_and_other_owner(database):
    for owner in (1, 2):
        storage.add_domain(owner, "example.com")
        storage.set_domain_override(owner, "example.com", {
            "checks": {"ping": False, "tls_cert": True}, "ports": [443],
        })

    storage.unset_domain_override(1, "example.com", "checks.ping")

    assert storage.get_domain_override(1, "example.com") == {
        "checks": {"tls_cert": True}, "ports": [443],
    }
    assert storage.get_domain_override(2, "example.com")["checks"]["ping"] is False
    storage.unset_domain_override(1, "example.com", None)
    assert storage.get_domain_override(1, "example.com") is None
    assert storage.get_domain_override(2, "example.com") is not None


def test_failed_history_batch_rolls_back_rows_and_new_domain(database):
    with closing(sqlite3.connect(database)) as conn:
        conn.execute("""
            CREATE TRIGGER reject_history BEFORE INSERT ON history
            WHEN NEW.check_name = 'reject'
            BEGIN SELECT RAISE(ABORT, 'rejected history'); END
        """)
    results = [
        CheckOutcome("ping", Status.OK, "up", {}),
        CheckOutcome("reject", Status.CRIT, "down", {}),
    ]

    with pytest.raises(sqlite3.IntegrityError, match="rejected history"):
        storage.save_histories(1, "example.com", results)

    assert storage.last_results(1, "example.com") == []
    assert not storage.domain_exists(1, "example.com")
    assert storage.list_users() == []


def test_failed_domain_insert_rolls_back_new_user(database):
    with closing(sqlite3.connect(database)) as conn:
        conn.execute("""
            CREATE TRIGGER reject_domain BEFORE INSERT ON domains
            BEGIN SELECT RAISE(ABORT, 'rejected domain'); END
        """)
    with pytest.raises(sqlite3.IntegrityError, match="rejected domain"):
        storage.add_domain(42, "example.com")
    assert storage.list_users() == []


def test_concurrent_override_patches_preserve_disjoint_nested_keys(database):
    storage.add_domain(1, "example.com")
    storage.set_domain_override(1, "example.com", {"checks": {"old": False}})
    barrier = Barrier(12)

    def patch(index):
        barrier.wait(timeout=10)
        storage.set_domain_override(1, "example.com", {"checks": {str(index): True}})

    with ThreadPoolExecutor(max_workers=12) as pool:
        list(pool.map(patch, range(12)))

    assert storage.get_domain_override(1, "example.com") == {
        "checks": {"old": False, **{str(index): True for index in range(12)}},
    }


def test_late_bot_writes_do_not_resurrect_removed_domain(database):
    storage.add_domain(1, "example.com")
    storage.add_domain(2, "example.com")
    storage.remove_domain(1, "example.com")

    storage.save_histories(1, "example.com", [
        CheckOutcome("ping", Status.OK, "up", {}),
    ], create_missing=False)
    assert storage.set_domain_override(1, "example.com", {"ports": [443]}) == {}
    storage.unset_domain_override(1, "example.com", "ports")
    storage.upsert_alert_state(1, "example.com", "CRIT", None)

    assert not storage.domain_exists(1, "example.com")
    assert storage.last_results(1, "example.com") == []
    assert storage.get_domain_override(1, "example.com") is None
    assert storage.get_alert_state(1, "example.com") is None
    assert storage.domain_exists(2, "example.com")


def test_missing_single_history_can_be_skipped_without_creating_user(database):
    storage.save_history(9, "example.com", "ping", "OK", "up", {}, create_missing=False)
    assert storage.list_users() == []
    assert not storage.domain_exists(9, "example.com")


def test_concurrent_nested_unset_and_patches_preserve_every_change(database):
    storage.add_domain(1, "example.com")
    storage.set_domain_override(1, "example.com", {"checks": {"remove": False, "keep": True}})
    barrier = Barrier(12)

    def edit(index):
        barrier.wait(timeout=10)
        if index == 0:
            storage.unset_domain_override(1, "example.com", "checks.remove")
        else:
            storage.set_domain_override(1, "example.com", {"checks": {str(index): True}})

    with ThreadPoolExecutor(max_workers=12) as pool:
        list(pool.map(edit, range(12)))

    assert storage.get_domain_override(1, "example.com") == {
        "checks": {"keep": True, **{str(index): True for index in range(1, 12)}},
    }


@pytest.mark.parametrize("raw", ["[]", "false", '"text"', "{invalid"])
def test_invalid_stored_override_is_ignored_and_can_be_replaced(database, raw):
    storage.add_domain(1, "example.com")
    with closing(sqlite3.connect(database)) as conn, conn:
        conn.execute(
            "INSERT INTO domain_overrides(owner_id, domain, data_json) VALUES(?, ?, ?)",
            (1, "example.com", raw),
        )
    assert storage.get_domain_override(1, "example.com") is None
    storage.unset_domain_override(1, "example.com", "checks.ping")
    assert storage.set_domain_override(1, "example.com", {"ports": [443]}) == {"ports": [443]}


@pytest.mark.parametrize('cutoff', [
    '2026-10-21T12:00:00+00:00', '2026-10-21T15:00:00+03:00', '2026-10-21T12:00:00',
])
def test_history_since_uses_utc_and_includes_matching_rows_on_same_day(database, cutoff):
    from datetime import datetime

    for owner in (1, 2):
        storage.save_history(owner, 'example.com', 'ping', 'OK', 'recent', {})
    with closing(sqlite3.connect(database)) as conn, conn:
        conn.execute("UPDATE history SET created_at='2026-10-21 12:30:00'")
    storage.save_history(1, 'old.example', 'ping', 'OK', 'old', {})
    with closing(sqlite3.connect(database)) as conn, conn:
        conn.execute("UPDATE history SET created_at='2026-10-21 11:59:59' "
                     "WHERE domain='old.example'")
    rows = list(storage.iter_history(1, since=datetime.fromisoformat(cutoff)))
    assert len(rows) == 1 and rows[0]['domain'] == 'example.com'


@pytest.mark.parametrize('batch_size', [0, -1])
def test_cleanup_rejects_nonpositive_batch_size(database, batch_size):
    with pytest.raises(ValueError, match='batch_size'):
        storage.cleanup_history(30, batch_size=batch_size)


def test_cleanup_deletes_old_history_in_batches_and_preserves_fresh_rows(database):
    storage.save_history(1, 'fresh.example', 'ping', 'OK', 'fresh', {})
    for _ in range(5):
        storage.save_history(1, 'old.example', 'ping', 'OK', 'old', {})
    with closing(sqlite3.connect(database)) as conn, conn:
        conn.execute("UPDATE history SET created_at=datetime('now', '-31 days') "
                     "WHERE domain='old.example'")
    assert storage.cleanup_history(30, batch_size=2) == 5
    assert storage.last_results(1, 'old.example') == []
    assert len(storage.last_results(1, 'fresh.example')) == 1
    assert storage.domain_exists(1, 'old.example')
