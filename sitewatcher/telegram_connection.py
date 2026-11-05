"""Private Telegram credentials and explicit, bounded owner connection checks."""
from __future__ import annotations

import logging
import os
from pathlib import Path
import re

import httpx

from . import storage
from .utils.private_file import load_private_file, save_private_file
from .telegram_proxy import load_proxy

TOKEN_RE = re.compile(r'[0-9]{3,20}:[A-Za-z0-9_-]{20,200}\Z')


def token_path() -> Path:
    database = storage.DEFAULT_DB.resolve()
    return database.with_name(database.name + '.telegram-token')


def validate_bot_token(token: str) -> str:
    token = token.strip()
    if not TOKEN_RE.fullmatch(token):
        raise ValueError('Enter the complete bot token from BotFather.')
    return token


def load_bot_token() -> str | None:
    """An explicit deployment token overrides the private workspace connection file."""
    explicit = os.getenv('TELEGRAM_TOKEN', '').strip()
    if explicit:
        return explicit
    return load_private_file(
        token_path(), validate_bot_token, 256,
        read_error='Telegram token file could not be read securely.',
        permissions_error='Telegram token file requires mode 0600 permissions.',
        invalid_error='Telegram token file is invalid.',
    )


def save_bot_token(token: str) -> None:
    """Publish a complete mode-0600 file atomically, including concurrent saves."""
    token = validate_bot_token(token)
    save_private_file(token_path(), token, '.telegram-token-')


class TelegramConnectionError(ValueError):
    """Safe, user-facing diagnostics that never include a Bot API URL or response."""


class _HideBotUrl(logging.Filter):
    """HTTP clients can log the Bot API credential in their request URL."""

    def filter(self, record):
        # HTTPcore's SOCKS handshake traces include the raw username/password tuple.
        if record.name == 'httpcore.socks':
            record.msg = '[Telegram proxy transport]'
            record.args = ()
            record.exc_info = None
            record.exc_text = None
            return True
        record.msg = re.sub(r'https?://api\.telegram\.org/[^\s"\']+',
                            '[Telegram API]', record.getMessage())
        record.args = ()
        return True


# Client loggers emit before propagation to root handlers, including debug deployments.
for _name in ('httpx', 'httpcore.connection', 'httpcore.http11', 'httpcore.http2',
              'httpcore.proxy', 'httpcore.socks'):
    logging.getLogger(_name).addFilter(_HideBotUrl())


async def _call(token: str, method: str, payload: dict):
    try:
        async with httpx.AsyncClient(timeout=10.0, proxy=load_proxy(),
                                     follow_redirects=False) as client:
            response = await client.post(f'https://api.telegram.org/bot{token}/{method}',
                                         json=payload)
            if response.status_code == 409:
                raise TelegramConnectionError(
                    'Another bot process is polling, or a webhook is enabled. '
                    'Use Advanced to enter a chat ID, or stop polling before finding chats.')
            if response.status_code == 401:
                raise TelegramConnectionError('Telegram rejected the bot token. Check BotFather.')
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, dict) or data.get('ok') is not True:
                raise TelegramConnectionError('Telegram could not complete the request.')
            return data.get('result')
    except TelegramConnectionError:
        raise
    except Exception:
        # Exception messages may contain the full token-bearing URL or proxy credentials.
        raise TelegramConnectionError(
            'Telegram connection failed. Check the token, destination and connection, then retry.') from None


async def send_test_notification(token: str, chat_id: int) -> None:
    await _call(token, 'sendMessage', {
        'chat_id': chat_id, 'text': 'SiteWatcher test notification: your connection works.',
    })


async def find_chats(token: str) -> list[dict]:
    # No offset: discovery never acknowledges/consumes another bot process's updates.
    updates = await _call(token, 'getUpdates', {'timeout': 0, 'limit': 100})
    if not isinstance(updates, list):
        raise TelegramConnectionError('Telegram returned no usable chats. Enter a chat ID in Advanced.')
    chats = {}
    for update in updates:
        if not isinstance(update, dict):
            continue
        message = update.get('message') or update.get('channel_post') or {}
        chat = message.get('chat', {}) if isinstance(message, dict) else {}
        chat_id = chat.get('id')
        if type(chat_id) is int and chat_id and -2**63 < chat_id < 2**63:
            label = chat.get('title') or chat.get('first_name') or 'Telegram chat'
            chats[chat_id] = {'id': chat_id, 'label': str(label)[:100]}
    return list(chats.values())[:30]
