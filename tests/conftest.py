"""Every test starts with isolated storage and working-directory side effects."""
import pytest

from sitewatcher import storage


@pytest.fixture(autouse=True)
def isolated_workspace(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(storage, 'DEFAULT_DB', tmp_path / 'sitewatcher.db')


@pytest.fixture(scope='session')
def django_db_modify_db_settings(django_db_modify_db_settings_parallel_suffix, tmp_path_factory):
    """Raw SQLite connections require a real shared file, never Django's memory URI."""
    from django.conf import settings

    settings.DATABASES['default']['TEST']['NAME'] = str(
        tmp_path_factory.mktemp('django-db') / 'web-tests.sqlite3'
    )


@pytest.fixture
def web_database(isolated_workspace, transactional_db, monkeypatch):
    """Opt-in web tests align raw monitoring writes with Django's committed database."""
    from pathlib import Path
    from django.db import connection
    from sitewatcher.config import AppConfig
    from sitewatcher.webapp.bootstrap import configure_web

    monkeypatch.setattr(storage, 'DEFAULT_DB', Path(connection.settings_dict['NAME']))
    storage._ensure_initialized()
    configure_web(AppConfig())
    yield storage.DEFAULT_DB
    # pytest-django flushes its own tables; legacy tables are deliberately unmanaged.
    with storage._write_connection() as conn:
        for table in ('users', 'whois_state', 'dns_state', 'owner_dns_state',
                      'virustotal_submissions', 'virustotal_reports'):
            conn.execute(f'DELETE FROM {table}')


@pytest.fixture
def expire_vt_report():
    """Advance the daily provider cache without changing credentials/network behavior."""
    def expire():
        with storage._write_connection() as conn:
            conn.execute('UPDATE virustotal_reports SET requested_at=requested_at-86400')
    return expire
