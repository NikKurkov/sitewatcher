from sitewatcher import storage
from sitewatcher.checks.base import CheckOutcome, Status


def test_history_ages_are_owner_scoped_and_database_can_change(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DEFAULT_DB", tmp_path / "first.db")
    storage.save_history(1, "example.com", "ping", "OK", "ok", {})
    storage.save_history(2, "example.com", "tls_cert", "WARN", "warn", {})
    assert set(storage.last_check_ages(1, "example.com")) == {"ping"}

    monkeypatch.setattr(storage, "DEFAULT_DB", tmp_path / "second.db")
    assert storage.last_check_ages(1, "example.com") == {}


def test_saving_multiple_results_keeps_owner_and_check_data(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DEFAULT_DB", tmp_path / "checks.db")
    storage.save_histories(7, "example.com", [
        CheckOutcome("ping", Status.OK, "up", {"latency_ms": 2}),
        CheckOutcome("tls_cert", Status.WARN, "expiring", {}),
    ])

    assert [row["check_name"] for row in storage.last_results(7, "example.com")] == ["tls_cert", "ping"]
    assert storage.last_results(8, "example.com") == []


def test_cached_result_does_not_extend_cache_lifetime(tmp_path, monkeypatch):
    import asyncio

    from sitewatcher.bot.formatting import _format_results
    from sitewatcher.config import AppConfig
    from sitewatcher.dispatcher import Dispatcher

    monkeypatch.setattr(storage, "DEFAULT_DB", tmp_path / "cache.db")
    storage.save_history(1, "example.com", "ping", Status.OK, "up", {})
    dispatcher = Dispatcher(AppConfig())
    cached = dispatcher._maybe_cached_result(1, "example.com", "ping", lambda name: 5)

    assert cached is not None
    storage.save_histories(1, "example.com", [cached])
    asyncio.run(_format_results(1, "example.com", [cached], persist=True))
    assert len(storage.last_results(1, "example.com")) == 1


def test_two_databases_are_initialized_only_once(tmp_path, monkeypatch):
    main = tmp_path / "main.db"
    whois = tmp_path / "whois.db"
    monkeypatch.setattr(storage, "DEFAULT_DB", main)
    storage.save_history(1, "example.com", "ping", "OK", "up", {})
    storage._ensure_initialized(whois)
    monkeypatch.setattr(storage, "SCHEMA_SQL", "invalid schema statement")

    assert len(storage.last_results(1, "example.com")) == 1
    storage._ensure_initialized(whois)


def test_favorite_migration_preserves_existing_domains_and_is_owner_scoped(tmp_path, monkeypatch):
    import sqlite3
    path = tmp_path / 'legacy-favorites.db'
    monkeypatch.setattr(storage, 'DEFAULT_DB', path)
    with sqlite3.connect(path) as conn:
        conn.executescript('''
            CREATE TABLE users (telegram_id INTEGER PRIMARY KEY);
            CREATE TABLE domains (owner_id INTEGER NOT NULL, name TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now')), PRIMARY KEY(owner_id,name));
            INSERT INTO users VALUES(1), (2);
            INSERT INTO domains(owner_id,name) VALUES(1,'example.com'), (2,'example.com');
        ''')
    storage._ensure_initialized()
    storage._ensure_initialized()
    assert storage.set_domain_favorite(1, 'example.com', True)
    assert not storage.set_domain_favorite(1, 'missing.example', True)
    with sqlite3.connect(path) as conn:
        rows = conn.execute('SELECT owner_id,name,favorite FROM domains ORDER BY owner_id').fetchall()
    assert rows == [(1, 'example.com', 1), (2, 'example.com', 0)]
