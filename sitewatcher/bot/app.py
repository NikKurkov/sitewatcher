# /bot/app.py
from __future__ import annotations

import logging
import os
import asyncio
from contextlib import nullcontext

from telegram.ext import Application
from telegram.request import HTTPXRequest

from .. import scheduler_lock, storage
from ..config import AppConfig, get_bot_token_from_env
from .alerts import AlertDeduper
from .router import register_handlers
from .jobs import register_jobs
from .utils import _parse_allowed_user_ids, BUSY_USERS_KEY, BUSY_USERS_LOCK_KEY

# Use module-level logger; global logging is configured in main.setup_logging(...)
log = logging.getLogger(__name__)


def run_bot(cfg: AppConfig) -> None:
    token = get_bot_token_from_env()
    if not token:
        raise RuntimeError("Telegram is not configured; connect a bot in workspace Settings or set TELEGRAM_TOKEN")

    ownership = scheduler_lock.acquire(storage.DEFAULT_DB) if cfg.scheduler.enabled else nullcontext()
    with ownership:
        _run_polling(cfg, token)


def _run_polling(cfg: AppConfig, token: str) -> None:
    allowed_ids = _parse_allowed_user_ids()

    request = HTTPXRequest(
        http_version="1.1",
        connect_timeout=10.0,
        read_timeout=30.0,
        write_timeout=30.0,
        proxy=os.getenv("TELEGRAM_PROXY"),  # e.g. http://user:pass@host:3128
        connection_pool_size=32,
        pool_timeout=10.0,
    )

    app = (
        Application.builder()
        .token(token)
        .get_updates_proxy(os.getenv("TELEGRAM_PROXY"))
        .request(request)
        # ConversationHandler requires ordered updates.
        .concurrent_updates(False)
        .build()
    )
    app.bot_data["cfg"] = cfg

    # Busy-guard registry (init once to avoid races)
    app.bot_data[BUSY_USERS_KEY] = {}
    app.bot_data[BUSY_USERS_LOCK_KEY] = asyncio.Lock()

    # Access control
    if allowed_ids:
        log.info(
            "bot.access.restricted",
            extra={"event": "bot.access.restricted", "count": len(allowed_ids)},
        )
    else:
        log.warning(
            "bot.access.open",
            extra={"event": "bot.access.open", "hint": "set TELEGRAM_ALLOWED_USER_IDS"},
        )
    app.bot_data["allowed_user_ids"] = allowed_ids

    # Alerts deduper instance in bot_data (no globals)
    cooldown = cfg.alerts.effective_cooldown
    app.bot_data["alert_deduper"] = AlertDeduper(cooldown_sec=cooldown)

    # Handlers & jobs
    register_handlers(app)
    register_jobs(app, cooldown=cooldown)

    # Only the scheduler owner runs maintenance; command-only polling can coexist with a worker.
    if cfg.scheduler.enabled:
        # ---- Maintenance: daily history cleanup ----
        from ..maintenance import cleanup_history, cleanup_time

        async def _job_cleanup_history(context):
            await cleanup_history(cfg)

        scheduled_cleanup = cleanup_time(cfg)
        try:
            app.job_queue.run_daily(
                _job_cleanup_history,
                time=scheduled_cleanup,
                name="maintenance.cleanup_history",
            )
            log.info("maintenance.cleanup_history.scheduled", extra={"event": "maintenance.cleanup_history.scheduled", "time": str(scheduled_cleanup)})
        except Exception as e:
            log.warning("maintenance.cleanup_history.schedule_failed", extra={"event": "maintenance.cleanup_history.schedule_failed", "etype": e.__class__.__name__})

    log.info(
        "bot.start",
        extra={
            "event": "bot.start",
            "cooldown_sec": cooldown,
            "proxy_set": bool(os.getenv("TELEGRAM_PROXY")),
        },
    )

    # Start polling; drop pending updates to avoid backlog after restarts
    app.run_polling(drop_pending_updates=True)
