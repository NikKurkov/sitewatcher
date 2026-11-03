"""Bootstrap contracts: private defaults, shared schema and installed resources."""
import importlib.util
from pathlib import Path

import pytest


def test_django_application_is_available():
    assert importlib.util.find_spec('sitewatcher.webapp') is not None


def test_private_health_and_hosts(web_database, client, settings):
    from sitewatcher import storage

    storage.ensure_user(4821)
    storage.add_domain(4821, 'private.example')
    assert settings.DEBUG is False
    assert Path(settings.DATABASES['default']['NAME']) == storage.DEFAULT_DB
    response = client.get('/healthz', HTTP_HOST='localhost')
    assert response.status_code == 200
    assert response.json() == {'status': 'ok'}
    assert response['X-Frame-Options'] == 'DENY'
    assert response['X-Content-Type-Options'] == 'nosniff'
    assert "default-src 'self'" in response['Content-Security-Policy']
    assert "frame-ancestors 'none'" in response['Content-Security-Policy']
    assert client.get('/healthz', HTTP_HOST='attacker.example').status_code == 400
    assert client.get('/', HTTP_HOST='localhost').status_code == 302
    assert settings.SECRET_KEY.encode() not in response.content


@pytest.mark.django_db(transaction=True)
def test_migrations_preserve_monitoring_rows(web_database):
    import sqlite3

    from sitewatcher import storage
    from sitewatcher.webapp.bootstrap import migrate_web_database

    storage.ensure_user(4821)
    storage.add_domain(4821, 'private.example')
    with sqlite3.connect(storage.DEFAULT_DB) as conn:
        conn.execute(
            'INSERT INTO history(owner_id, domain, status, message) VALUES (?, ?, ?, ?)',
            (4821, 'private.example', 'OK', 'fixture observation'),
        )
        before = {table: conn.execute(f'SELECT * FROM {table}').fetchall()
                  for table in ('users', 'domains', 'history')}
    migrate_web_database()
    migrate_web_database()
    with sqlite3.connect(storage.DEFAULT_DB) as conn:
        after = {table: conn.execute(f'SELECT * FROM {table}').fetchall()
                 for table in ('users', 'domains', 'history')}
        assert conn.execute("SELECT name FROM sqlite_master WHERE name='django_session'").fetchone()
    assert after == before


def test_packaged_template_and_allowlisted_assets(web_database, client, monkeypatch, tmp_path):
    from django.template.loader import render_to_string

    monkeypatch.chdir(tmp_path)
    assert '<title>SiteWatcher</title>' in render_to_string('sitewatcher/base.html')
    response = client.get('/assets/workspace.css', HTTP_HOST='localhost')
    assert response.status_code == 200
    assert b'color-scheme' in response.content
    assert response['Content-Type'] == 'text/css; charset=utf-8'
    for name, mime, signature in (
        ('logo-light.svg', 'image/svg+xml', b'<svg'),
        ('logo-dark.svg', 'image/svg+xml', b'<svg'),
        ('favicon.svg', 'image/svg+xml', b'<svg'),
        ('favicon.ico', 'image/x-icon', b'\x00\x00\x01\x00'),
        ('apple-touch-icon.png', 'image/png', b'\x89PNG'),
    ):
        response = client.get('/assets/' + name, HTTP_HOST='localhost')
        assert response.status_code == 200
        assert response['Content-Type'] == mime
        assert signature in response.content
    for name in ('../settings.py', 'settings.py', 'unknown.js'):
        assert client.get('/assets/' + name, HTTP_HOST='localhost').status_code == 404


def test_secret_is_persistent_private_and_not_overwritten(tmp_path, monkeypatch):
    from sitewatcher.webapp.bootstrap import load_secret_key

    monkeypatch.delenv('SITEWATCHER_WEB_SECRET_KEY', raising=False)
    database = tmp_path / 'monitor.db'
    first = load_secret_key(database)
    assert len(first) >= 50
    assert load_secret_key(database) == first
    secret_path = database.with_name('monitor.db.web-secret')
    assert secret_path.stat().st_mode & 0o777 == 0o600
    monkeypatch.setenv('SITEWATCHER_WEB_SECRET_KEY', 'explicit-deployment-key')
    assert load_secret_key(database) == 'explicit-deployment-key'
    assert secret_path.read_text() == first


def test_existing_insecure_or_empty_secret_is_rejected(tmp_path, monkeypatch):
    from sitewatcher.webapp.bootstrap import load_secret_key

    monkeypatch.delenv('SITEWATCHER_WEB_SECRET_KEY', raising=False)
    database = tmp_path / 'monitor.db'
    secret_path = database.with_name('monitor.db.web-secret')
    secret_path.write_text('existing-secret')
    secret_path.chmod(0o644)
    with pytest.raises(ValueError, match='permissions'):
        load_secret_key(database)
    secret_path.chmod(0o600)
    secret_path.write_text('')
    with pytest.raises(ValueError, match='empty'):
        load_secret_key(database)


def test_concurrent_startup_publishes_one_complete_secret(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from sitewatcher.webapp.bootstrap import load_secret_key

    monkeypatch.delenv('SITEWATCHER_WEB_SECRET_KEY', raising=False)
    with ThreadPoolExecutor(max_workers=8) as pool:
        keys = list(pool.map(load_secret_key, [tmp_path / 'monitor.db'] * 16))
    assert len(set(keys)) == 1
    assert len(keys[0]) >= 50
    assert not list(tmp_path.glob('.web-secret-*'))


def test_first_migration_installs_framework_alongside_existing_storage(tmp_path):
    import os
    import subprocess
    import sys

    database = tmp_path / 'existing.sqlite3'
    program = '''
import sqlite3
from sitewatcher import storage
from sitewatcher.config import AppConfig
from sitewatcher.webapp.bootstrap import configure_web, migrate_web_database
storage.ensure_user(4821)
storage.add_domain(4821, 'private.example')
with sqlite3.connect(storage.DEFAULT_DB) as conn:
    conn.execute("INSERT INTO history(owner_id,domain,status,message) "
                 "VALUES (4821,'private.example','OK','fixture observation')")
    before = {table: conn.execute(f'SELECT * FROM {table}').fetchall()
              for table in ('users','domains','history')}
    assert not conn.execute("SELECT name FROM sqlite_master WHERE name='django_session'").fetchone()
configure_web(AppConfig())
migrate_web_database()
with sqlite3.connect(storage.DEFAULT_DB) as conn:
    after = {table: conn.execute(f'SELECT * FROM {table}').fetchall()
             for table in ('users','domains','history')}
    assert conn.execute("SELECT name FROM sqlite_master WHERE name='django_session'").fetchone()
assert before == after
'''
    result = subprocess.run(
        [sys.executable, '-c', program],
        env={**os.environ, 'DATABASE_PATH': str(database)},
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr


def test_health_checks_monitoring_and_web_schema_without_disclosure(web_database, client):
    from sitewatcher import storage
    with storage._write_connection() as conn:
        conn.execute('ALTER TABLE domains RENAME TO unavailable_domains')
    try:
        response = client.get('/healthz', HTTP_HOST='localhost')
        assert response.status_code == 503
        assert response.json() == {'status': 'unavailable'}
        assert b'domains' not in response.content
    finally:
        with storage._write_connection() as conn:
            conn.execute('ALTER TABLE unavailable_domains RENAME TO domains')


def test_health_does_not_create_a_missing_database(web_database, client, monkeypatch, tmp_path):
    from sitewatcher import storage
    path = tmp_path / 'missing.sqlite'
    with monkeypatch.context() as patch:
        patch.setattr(storage, 'DEFAULT_DB', path)
        response = client.get('/healthz', HTTP_HOST='localhost')
        assert response.status_code == 503
        assert not path.exists()
