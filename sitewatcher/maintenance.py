"""Shared UTC history retention for both monitoring entry points."""
from __future__ import annotations

import asyncio
import datetime
import logging

from . import storage
from .config import AppConfig

log = logging.getLogger(__name__)


def cleanup_time(cfg: AppConfig) -> datetime.time:
    """Return the configured UTC cleanup time, retaining the bot's fallback."""
    try:
        hour, minute = [int(part) for part in cfg.history.cleanup_time.split(':', 1)]
        return datetime.time(hour, minute, tzinfo=datetime.timezone.utc)
    except (ValueError, TypeError, AttributeError):
        return datetime.time(3, 30, tzinfo=datetime.timezone.utc)


async def _sqlite_call(function, *args):
    # A cancelled to_thread await does not stop SQLite; retain ownership until it finishes.
    task = asyncio.create_task(asyncio.to_thread(function, *args))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        await task
        raise


async def cleanup_history(cfg: AppConfig) -> None:
    """Purge history off-loop and optionally optimize on UTC Sunday."""
    try:
        deleted = await _sqlite_call(storage.cleanup_history, cfg.history.retention_days)
        if cfg.history.vacuum_weekly and datetime.datetime.now(datetime.timezone.utc).weekday() == 6:
            await _sqlite_call(storage.vacuum_and_optimize)
        log.info('maintenance.cleanup_history.done', extra={
            'event': 'maintenance.cleanup_history.done', 'deleted': int(deleted),
            'retention_days': cfg.history.retention_days,
        })
    except Exception as error:
        log.exception('maintenance.cleanup_history.failed', extra={
            'event': 'maintenance.cleanup_history.failed', 'etype': type(error).__name__,
        })
