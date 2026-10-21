import json
import sqlite3
from contextlib import closing

import pytest

from sitewatcher import storage


@pytest.fixture
def diagnostic_environment(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, 'DEFAULT_DB', tmp_path / 'monitor.db')
    monkeypatch.delenv('TELEGRAM_TOKEN', raising=False)
    monkeypatch.delenv('TELEGRAM_ALLOWED_USER_IDS', raising=False)
    config_path = tmp_path / 'config.yaml'
    config_path.write_text('{}', encoding='utf-8')
    return config_path


def test_missing_database_is_informational_and_never_created(diagnostic_environment):
    from sitewatcher.diagnostics import diagnose, format_diagnostics

    report = diagnose(diagnostic_environment)
    assert report['ok'] is True
    assert report['database']['exists'] is False
    assert report['database']['parent_writable'] is True
    assert report['telegram']['token_present'] is False
    assert report['telegram']['access']['mode'] == 'open'
    assert report['python'] and report['sqlite']
    assert not storage.DEFAULT_DB.exists()
    assert 'Database' in format_diagnostics(report)


def test_valid_database_checked_without_private_content_or_mutation(diagnostic_environment):
    from sitewatcher.diagnostics import diagnose, format_diagnostics

    with closing(sqlite3.connect(storage.DEFAULT_DB)) as connection:
        connection.executescript(storage.SCHEMA_SQL)
        connection.execute("INSERT INTO users(telegram_id, username) VALUES(7, 'private-user')")
        connection.commit()
    before = storage.DEFAULT_DB.read_bytes()
    files_before = set(storage.DEFAULT_DB.parent.iterdir())
    report = diagnose(diagnostic_environment)
    assert report['ok'] is True
    assert report['database']['integrity'] == 'ok'
    assert report['database']['schema'] == 'ok'
    assert 'private-user' not in json.dumps(report) + format_diagnostics(report)
    assert storage.DEFAULT_DB.read_bytes() == before
    assert set(storage.DEFAULT_DB.parent.iterdir()) == files_before


@pytest.mark.parametrize('contents', [b'not a sqlite database', b''])
def test_corrupt_or_incompatible_database_fails_safely(diagnostic_environment, contents):
    from sitewatcher.diagnostics import diagnose

    storage.DEFAULT_DB.write_bytes(contents)
    report = diagnose(diagnostic_environment)
    assert report['ok'] is False
    assert report['database']['ok'] is False
    assert storage.DEFAULT_DB.read_bytes() == contents


def test_incompatible_columns_fail_diagnostics(diagnostic_environment):
    from sitewatcher.diagnostics import diagnose

    with closing(sqlite3.connect(storage.DEFAULT_DB)) as connection:
        connection.executescript(storage.SCHEMA_SQL)
        connection.execute('ALTER TABLE users RENAME COLUMN telegram_id TO incompatible_id')
    report = diagnose(diagnostic_environment)
    assert report['ok'] is False
    assert report['database']['schema'] == 'incompatible'


def test_token_and_invalid_config_values_are_redacted(diagnostic_environment, monkeypatch):
    from sitewatcher.diagnostics import diagnose, format_diagnostics

    secret = 'sensitive-not-for-output'
    monkeypatch.setenv('TELEGRAM_TOKEN', secret)
    diagnostic_environment.write_text(f'defaults:\n  http_timeout_s: {secret}\n', encoding='utf-8')
    report = diagnose(diagnostic_environment)
    assert report['ok'] is False
    assert report['config']['ok'] is False
    assert report['telegram']['token_present'] is True
    assert secret not in json.dumps(report) + format_diagnostics(report)


@pytest.mark.parametrize('contents', [
    'defaults: [private-yaml: [',
    'scheduler:\n  interval_minutes: 0\n',
    'deface:\n  phrases_path: /sensitive-path-do-not-echo\n',
])
def test_yaml_and_runtime_validation_errors_are_sanitized(diagnostic_environment, contents):
    from sitewatcher.diagnostics import diagnose, format_diagnostics

    diagnostic_environment.write_text(contents, encoding='utf-8')
    report = diagnose(diagnostic_environment)
    assert report['ok'] is False
    assert report['config']['ok'] is False
    assert contents not in json.dumps(report) + format_diagnostics(report)
    assert '/sensitive-path-do-not-echo' not in json.dumps(report)


def test_allowlist_is_restricted_by_count_and_malformed_fails_closed(
    diagnostic_environment, monkeypatch,
):
    from sitewatcher.diagnostics import diagnose

    monkeypatch.setenv('TELEGRAM_ALLOWED_USER_IDS', '12345,67890')
    report = diagnose(diagnostic_environment)
    assert report['telegram']['access'] == {'ok': True, 'mode': 'restricted', 'count': 2}
    assert '12345' not in json.dumps(report)
    monkeypatch.setenv('TELEGRAM_ALLOWED_USER_IDS', 'secret-invalid-id')
    report = diagnose(diagnostic_environment)
    assert report['ok'] is False
    assert report['telegram']['access']['ok'] is False
    assert 'secret-invalid-id' not in json.dumps(report)


def test_missing_parent_directory_is_not_created(diagnostic_environment, monkeypatch):
    from sitewatcher.diagnostics import diagnose

    path = diagnostic_environment.parent / 'absent' / 'monitor.db'
    monkeypatch.setattr(storage, 'DEFAULT_DB', path)
    report = diagnose(diagnostic_environment)
    assert report['ok'] is False
    assert report['database']['parent_writable'] is False
    assert not path.parent.exists()


def test_live_wal_database_is_checked_without_changing_database_bytes(diagnostic_environment):
    from sitewatcher.diagnostics import diagnose

    with closing(sqlite3.connect(storage.DEFAULT_DB)) as writer:
        writer.execute('PRAGMA journal_mode=WAL')
        writer.executescript(storage.SCHEMA_SQL)
        wal_path = storage.DEFAULT_DB.with_name(storage.DEFAULT_DB.name + '-wal')
        before = storage.DEFAULT_DB.read_bytes(), wal_path.read_bytes()
        report = diagnose(diagnostic_environment)
        assert report['ok'] is True
        assert (storage.DEFAULT_DB.read_bytes(), wal_path.read_bytes()) == before


def test_missing_wal_metadata_does_not_create_sidecars(diagnostic_environment):
    from sitewatcher.diagnostics import diagnose

    storage.DEFAULT_DB.write_bytes(b'example database')
    wal_path = storage.DEFAULT_DB.with_name(storage.DEFAULT_DB.name + '-wal')
    wal_path.write_bytes(b'example journal')
    files_before = set(storage.DEFAULT_DB.parent.iterdir())
    report = diagnose(diagnostic_environment)
    assert report['ok'] is False
    assert set(storage.DEFAULT_DB.parent.iterdir()) == files_before
def test_doctor_cli_json_is_sanitized_and_does_not_initialize_database(tmp_path):
    import json
    import os
    import subprocess
    import sys

    env = os.environ.copy()
    env.update(DATABASE_PATH=str(tmp_path / "absent.db"), TELEGRAM_TOKEN="private-test-value",
               TELEGRAM_ALLOWED_USER_IDS="7")
    run = subprocess.run([sys.executable, "-m", "sitewatcher.main", "doctor", "--json"],
                         cwd=tmp_path, env=env, capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    report = json.loads(run.stdout)
    assert report["ok"] and report["telegram"]["token_present"]
    assert "private-test-value" not in run.stdout + run.stderr
    assert not (tmp_path / "absent.db").exists()


def test_existing_database_requires_file_write_access(tmp_path, monkeypatch):
    from sitewatcher import storage
    from sitewatcher import diagnostics

    path = tmp_path / "readonly.db"
    monkeypatch.setattr(storage, "DEFAULT_DB", path)
    storage._ensure_initialized()
    real_access = diagnostics.os.access
    monkeypatch.setattr(diagnostics.os, "access", lambda candidate, mode:
        False if candidate == path and mode == diagnostics.os.W_OK else real_access(candidate, mode))
    report = diagnostics.diagnose()
    assert report["ok"] is False
    assert report["database"]["file_writable"] is False


