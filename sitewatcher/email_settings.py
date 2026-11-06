"""Private installation SMTP settings and account-scoped notification recipients."""
from __future__ import annotations

from contextlib import closing
from email.errors import HeaderParseError
from email.headerregistry import Address
import json
from pathlib import Path
import sqlite3

from . import storage
from .utils.private_file import load_private_file, save_private_file


def smtp_path() -> Path:
    database = storage.DEFAULT_DB.resolve()
    return database.with_name(database.name + '.smtp.json')


def validate_address(value: str) -> str:
    value = value.strip()
    if not value or any(char in value for char in '\r\n'):
        raise ValueError('Enter a valid email address.')
    try:
        address = Address(addr_spec=value)
    except (ValueError, IndexError, HeaderParseError):
        raise ValueError('Enter a valid email address.') from None
    if not address.username or not address.domain or address.addr_spec != value:
        raise ValueError('Enter a valid email address.')
    return value


def validate_smtp_config(config: dict) -> dict:
    keys = {'host', 'port', 'security', 'username', 'password', 'from_email'}
    if not isinstance(config, dict) or set(config) != keys:
        raise ValueError('Invalid SMTP settings.')
    if any(not isinstance(config[key], str) for key in keys - {'port'}):
        raise ValueError('Invalid SMTP settings.')
    host = config['host'].strip()
    if (not host or len(host) > 253 or any(c.isspace() or c in '/\\@' for c in host)
            or type(config['port']) is not int or not 1 <= config['port'] <= 65535
            or config['security'] not in {'tls', 'starttls'}
            or len(config['username']) > 254 or len(config['password']) > 2048
            or any(c in config['username'] + config['password'] for c in '\r\n\x00')):
        raise ValueError('Invalid SMTP settings.')
    if config['password'] and not config['username']:
        raise ValueError('Enter an SMTP username for the saved password.')
    return {**config, 'host': host, 'from_email': validate_address(config['from_email'])}


def _decode_config(value: str) -> str:
    validate_smtp_config(json.loads(value))
    return value


def load_smtp_config() -> dict | None:
    value = load_private_file(
        smtp_path(), _decode_config, 16384,
        read_error='SMTP settings could not be read securely.',
        invalid_error='Saved SMTP settings are invalid.',
    )
    return json.loads(value) if value else None


def save_smtp_config(config: dict) -> None:
    save_private_file(smtp_path(), json.dumps(validate_smtp_config(config)), '.smtp-')


def get_notification_email(owner_id: int) -> str | None:
    """Read without Django setup, creating a database, or changing storage pragmas."""
    if type(owner_id) is not int or owner_id <= 0:
        return None
    try:
        uri = storage.DEFAULT_DB.resolve().as_uri() + '?mode=ro'
        with closing(sqlite3.connect(uri, uri=True, timeout=3)) as connection:
            row = connection.execute(
                'SELECT notification_email FROM webapp_workspace WHERE owner_id=?', (owner_id,),
            ).fetchone()
        return validate_address(row[0]) if row and row[0] else None
    except (sqlite3.Error, OSError, ValueError):
        return None


def email_ready(owner_id: int) -> bool:
    try:
        return bool(get_notification_email(owner_id) and load_smtp_config())
    except (OSError, ValueError):
        return False
