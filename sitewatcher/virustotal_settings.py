"""Private installation-wide VirusTotal key, refreshed for each passive probe."""
from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
import stat
import tempfile
from urllib.parse import urlsplit

from . import storage
from .telegram_proxy import normalize_proxy


KEY_ERROR = 'Enter a VirusTotal API key without spaces or control characters.'
KEY_FILE_ERROR = 'VirusTotal configuration could not be read securely'
MAX_KEY_LENGTH = 2048


def validate_api_key(value: str) -> str:
    """Accept opaque HTTP header credentials without assuming a provider key format."""
    if not isinstance(value, str):
        raise ValueError(KEY_ERROR)
    value = value.strip()
    if not value or len(value) > MAX_KEY_LENGTH or any(not 33 <= ord(c) <= 126 for c in value):
        raise ValueError(KEY_ERROR)
    return value


def key_path() -> Path:
    database = storage.DEFAULT_DB.resolve()
    return database.with_name(database.name + '.virustotal-key')


def load_api_key(configured: str | None = None) -> str | None:
    """Environment > existing YAML configuration > saved key; never initialize storage."""
    explicit = os.getenv('VIRUSTOTAL_API_KEY', '').strip()
    if explicit:
        return validate_api_key(explicit)
    if configured:
        return validate_api_key(configured)
    return _load_secret(key_path(), validate_api_key)


def _load_secret(path: Path, validate: Callable[[str], str | None]) -> str | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    except OSError:
        raise ValueError(KEY_FILE_ERROR) from None
    with os.fdopen(fd, encoding='utf-8') as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise ValueError(KEY_FILE_ERROR)
        try:
            value = stream.read(MAX_KEY_LENGTH + 1)
            if len(value) > MAX_KEY_LENGTH:
                raise ValueError(KEY_FILE_ERROR)
            return validate(value)
        except (ValueError, UnicodeError):
            raise ValueError(KEY_FILE_ERROR) from None


def save_api_key(value: str) -> None:
    _save_secret(key_path(), validate_api_key(value), '.virustotal-key-')


def _save_secret(path: Path, value: str, prefix: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=prefix, dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def remove_api_key() -> None:
    key_path().unlink(missing_ok=True)


def validate_vt_proxy(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        if (not isinstance(value, str) or
                urlsplit(value).scheme not in {'http', 'https', 'socks5', 'socks5h'}):
            raise ValueError
        normalized = normalize_proxy(value)
        if len(normalized) > MAX_KEY_LENGTH:
            raise ValueError
        return normalized
    except (ValueError, UnicodeError):
        raise ValueError('Enter an HTTP(S) or SOCKS5 proxy URL.') from None


def vt_proxy_path() -> Path:
    database = storage.DEFAULT_DB.resolve()
    return database.with_name(database.name + '.virustotal-proxy')


def load_vt_proxy(configured: str | None = None) -> str | None:
    explicit = os.getenv('VIRUSTOTAL_PROXY', '').strip()
    if explicit:
        return validate_vt_proxy(explicit)
    if configured:
        return validate_vt_proxy(configured)
    return _load_secret(vt_proxy_path(), validate_vt_proxy)


def save_vt_proxy(value: str) -> None:
    normalized = validate_vt_proxy(value)
    if not normalized:
        raise ValueError('Enter an HTTP(S) or SOCKS5 proxy URL.')
    _save_secret(vt_proxy_path(), normalized, '.virustotal-proxy-')


def remove_vt_proxy() -> None:
    vt_proxy_path().unlink(missing_ok=True)
