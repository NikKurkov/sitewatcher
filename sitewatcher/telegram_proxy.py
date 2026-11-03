"""Validated Telegram proxy settings stored privately beside the monitoring database."""
from __future__ import annotations

import ipaddress
import os
from pathlib import Path
import re
import stat
import tempfile
from urllib.parse import parse_qs, quote, unquote, urlsplit

from . import storage


PROXY_ERROR = 'Enter an HTTP(S) or SOCKS5 proxy URL, or a Telegram SOCKS link.'
MTPROTO_ERROR = 'MTProto proxy links are not supported. Use an HTTP(S) or SOCKS5 proxy.'


def _host(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
        return f'[{address}]' if address.version == 6 else str(address)
    except ValueError:
        value = value.encode('idna').decode('ascii').lower()
        if len(value) > 253 or not all(
            re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
            for label in value.rstrip('.').split('.')
        ):
            raise ValueError(PROXY_ERROR) from None
        return value


def normalize_proxy(value: str) -> str:
    """Convert supported links locally; validation errors never contain the input."""
    value = value.strip()
    try:
        if not value or len(value) > 2048 or any(ord(c) < 33 or ord(c) == 127 for c in value):
            raise ValueError
        parsed = urlsplit(value)
        link = (parsed.scheme == 'tg' or
                parsed.scheme == 'https' and parsed.hostname == 't.me')
        if link:
            kind = parsed.netloc if parsed.scheme == 'tg' else parsed.path.strip('/')
            if kind == 'proxy':
                raise ValueError(MTPROTO_ERROR)
            if (kind != 'socks' or parsed.fragment or
                    parsed.scheme == 'tg' and parsed.path not in ('', '/') or
                    parsed.scheme == 'https' and parsed.netloc != 't.me'):
                raise ValueError
            query = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True,
                             max_num_fields=4, errors='strict')
            if (set(query) - {'server', 'port', 'user', 'pass'} or
                    not {'server', 'port'} <= set(query) or
                    any(len(item) != 1 for item in query.values())):
                raise ValueError
            host = _host(query['server'][0])
            port = int(query['port'][0])
            user, password = query.get('user', [''])[0], query.get('pass', [''])[0]
            scheme = 'socks5'
            if password and not user:
                raise ValueError
        else:
            scheme = parsed.scheme
            if (scheme not in {'http', 'https', 'socks5', 'socks5h'} or
                    parsed.path not in ('', '/') or parsed.query or parsed.fragment or
                    not parsed.hostname):
                raise ValueError
            host = _host(parsed.hostname)
            port = parsed.port
            user = unquote(parsed.username or '', errors='strict')
            password = unquote(parsed.password or '', errors='strict')
            if parsed.username is not None and not user:
                raise ValueError
            if scheme == 'socks5h':
                scheme = 'socks5'
        if port is not None and not 1 <= port <= 65535:
            raise ValueError
        if scheme == 'socks5' and port is None:
            raise ValueError
        if any(ord(c) < 32 or ord(c) == 127 for c in user + password):
            raise ValueError
        auth = f'{quote(user, safe="")}:{quote(password, safe="")}@' if user else ''
        return f'{scheme}://{auth}{host}' + (f':{port}' if port is not None else '')
    except (ValueError, UnicodeError) as error:
        message = MTPROTO_ERROR if str(error) == MTPROTO_ERROR else PROXY_ERROR
        raise ValueError(message) from None


def proxy_path() -> Path:
    database = storage.DEFAULT_DB.resolve()
    return database.with_name(database.name + '.telegram-proxy')


def load_proxy() -> str | None:
    explicit = os.getenv('TELEGRAM_PROXY', '').strip()
    if explicit:
        return normalize_proxy(explicit)
    try:
        fd = os.open(proxy_path(), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None  # Preserve HTTPX's existing standard proxy environment fallback.
    except OSError:
        raise ValueError('Telegram proxy file could not be read securely.') from None
    with os.fdopen(fd, encoding='utf-8') as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise ValueError('Telegram proxy file requires mode 0600 permissions.')
        try:
            return normalize_proxy(stream.read(2049))
        except (ValueError, UnicodeError):
            raise ValueError('Telegram proxy file is invalid. Save a new proxy or remove it.') from None


def save_proxy(value: str) -> None:
    value = normalize_proxy(value)
    path = proxy_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.telegram-proxy-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def remove_proxy() -> None:
    proxy_path().unlink(missing_ok=True)
