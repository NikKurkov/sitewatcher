"""Local startup diagnostics without network calls or application database writes."""
from __future__ import annotations

import os
import platform
import sqlite3
from contextlib import closing
from pathlib import Path

from . import storage
from .bot.utils import _parse_allowed_user_ids
from .config import get_bot_token_from_env, load_config, validate_config, validation_message

# Check only known metadata; never include monitored domains or user rows in output.
_REQUIRED_SCHEMA = {
    'users': {'telegram_id', 'username', 'first_name', 'last_name', 'alert_chat_id', 'alerts_enabled'},
    'domains': {'owner_id', 'name', 'created_at'},
    'domain_overrides': {'owner_id', 'domain', 'data_json', 'updated_at'},
    'history': {'owner_id', 'domain', 'check_name', 'status', 'message', 'metrics_json', 'created_at'},
    'alert_state': {'owner_id', 'domain', 'last_overall', 'last_sent_at'},
    'whois_state': {'domain', 'snapshot_json', 'fetched_at', 'updated_at'},
    'dns_state': {'domain', 'snapshot_json', 'fetched_at', 'updated_at'},
}


def _database_report() -> dict:
    path = Path(storage.DEFAULT_DB).absolute()
    parent_writable = path.parent.is_dir() and os.access(path.parent, os.W_OK | os.X_OK)
    file_writable = not path.exists() or os.access(path, os.W_OK)
    result = {'ok': parent_writable and file_writable, 'path': str(path), 'exists': path.exists(),
              'file_writable': file_writable,
              'parent_writable': parent_writable, 'integrity': 'not_checked',
              'schema': 'not_checked'}
    if not parent_writable:
        result['error'] = 'Database parent directory is missing or not writable'
    elif not file_writable:
        result['error'] = 'Database file is not writable'
    if not result['exists']:
        return result
    try:
        # Native read-only locking permits SQLite WAL/SHM reader metadata, never data writes.
        uri = path.as_uri() + '?mode=ro'
        with closing(sqlite3.connect(uri, uri=True, timeout=3)) as connection:
            connection.execute('PRAGMA query_only=ON')
            healthy = connection.execute('PRAGMA quick_check').fetchall() == [('ok',)]
            compatible = all(
                columns <= {row[1] for row in connection.execute(f'PRAGMA table_info({table})')}
                for table, columns in _REQUIRED_SCHEMA.items()
            )
        result.update(integrity='ok' if healthy else 'failed',
                      schema='ok' if compatible else 'incompatible',
                      ok=parent_writable and file_writable and healthy and compatible)
        if not healthy or not compatible:
            result['error'] = 'Database integrity or required schema check failed'
    except (OSError, sqlite3.Error):
        result.update(ok=False, integrity='failed', error='SQLite database could not be read')
    return result


def diagnose(config_path=None) -> dict:
    """Return JSON-compatible local readiness checks; never load .env or initialize storage."""
    try:
        cfg = load_config(config_path)
        validate_config(cfg)
        config = {'ok': True}
    except Exception as error:
        config = {'ok': False, 'error': validation_message(error)}
    try:
        allowed = _parse_allowed_user_ids()
        access = {'ok': True, 'mode': 'restricted' if allowed else 'open', 'count': len(allowed)}
    except ValueError:
        access = {'ok': False, 'mode': 'invalid', 'count': 0,
                  'error': 'TELEGRAM_ALLOWED_USER_IDS must contain positive numeric user IDs'}
    try:
        with closing(sqlite3.connect(':memory:')) as connection:
            json1 = connection.execute("SELECT json_valid('{}')").fetchone()[0] == 1
        analytics = {'ok': sqlite3.sqlite_version_info >= (3, 35, 0) and json1}
    except sqlite3.Error:
        analytics = {'ok': False}
    if not analytics['ok']:
        analytics['error'] = 'Analytics requires SQLite 3.35 or newer with JSON1 support'
    database = _database_report()
    telegram = {'token_present': False, 'access': access}
    try:
        telegram['token_present'] = bool(get_bot_token_from_env())
    except (OSError, ValueError):
        telegram['error'] = ('Telegram token file is invalid or unreadable; '
                             'check its contents and mode 0600 permissions.')
    return {
        'ok': config['ok'] and database['ok'] and access['ok'] and analytics['ok']
              and 'error' not in telegram,
        'python': platform.python_version(),
        'sqlite': sqlite3.sqlite_version,
        'analytics': analytics,
        'config': config,
        'database': database,
        'telegram': telegram,
    }


def format_diagnostics(report: dict) -> str:
    """Render the same sanitized report for humans without dumping raw settings."""
    database = report['database']
    config = report['config']
    telegram = report['telegram']
    access = telegram['access']
    lines = [
        'Diagnostics: ' + ('OK' if report['ok'] else 'FAILED'),
        f"Python: {report['python']}; SQLite: {report['sqlite']}",
        'Analytics: ' + ('OK' if report['analytics']['ok'] else report['analytics']['error']),
        'Configuration: ' + ('OK' if config['ok'] else config['error']),
        f"Database: {database['path']} ({'existing' if database['exists'] else 'not created'})",
        f"Database parent writable: {'yes' if database['parent_writable'] else 'no'}",
        f"Database integrity: {database['integrity']}; schema: {database['schema']}",
        f"Telegram token present: {'yes' if telegram['token_present'] else 'no (needed for bot mode)'}",
        f"Telegram access: {access['mode']}; allowed user count: {access['count']}",
    ]
    if database.get('error'):
        lines.append(database['error'])
    if access.get('error'):
        lines.append(access['error'])
    if telegram.get('error'):
        lines.append(telegram['error'])
    return '\n'.join(lines)
