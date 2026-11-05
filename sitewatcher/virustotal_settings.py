"""Private installation-wide VirusTotal credentials, refreshed for each probe."""
from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlsplit

from . import storage
from .utils.private_file import load_private_file, save_private_file
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
    def validate_bounded(value: str) -> str | None:
        if len(value) > MAX_KEY_LENGTH:
            raise ValueError(KEY_FILE_ERROR)
        return validate(value)

    return load_private_file(
        path, validate_bounded, MAX_KEY_LENGTH + 1, read_error=KEY_FILE_ERROR,
    )


def save_api_key(value: str) -> None:
    save_private_file(key_path(), validate_api_key(value), '.virustotal-key-')


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
    save_private_file(vt_proxy_path(), normalized, '.virustotal-proxy-')


def remove_vt_proxy() -> None:
    vt_proxy_path().unlink(missing_ok=True)
    vt_proxy_enabled_path().unlink(missing_ok=True)


def vt_proxy_enabled_path() -> Path:
    return vt_proxy_path().with_name(vt_proxy_path().name + '-enabled')


def _validate_proxy_switch(value: str) -> str:
    if value not in {'0', '1'}:
        raise ValueError(KEY_FILE_ERROR)
    return value


def load_vt_proxy_enabled() -> bool | None:
    """An absent switch preserves older installations' configured-proxy behavior."""
    state = _load_secret(vt_proxy_enabled_path(), _validate_proxy_switch)
    return None if state is None else state == '1'


def save_vt_proxy_enabled(enabled: bool) -> None:
    save_private_file(vt_proxy_enabled_path(), '1' if enabled else '0', '.vt-proxy-enabled-')
