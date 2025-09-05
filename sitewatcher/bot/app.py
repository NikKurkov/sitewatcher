# /bot/app.py
from __future__ import annotations

import logging
import os
import asyncio

from telegram.ext import Application
from telegram.request import HTTPXRequest

from ..config import AppConfig, get_bot_token_from_env
from .alerts import AlertDeduper
from .router import register_handlers
from .jobs import register_jobs
from .utils import _parse_allowed_user_ids, BUSY_USERS_KEY, BUSY_USERS_LOCK_KEY, on_error

# Use module-level logger; global logging is configured in main.setup_logging(...)
log = logging.getLogger(__name__)


def run_bot(cfg: AppConfig) -> None:
    token = get_bot_token_from_env()
    if not token:
        raise RuntimeError("TELEGRAM_TOKEN is not set in environment (.env)")

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
        .request(request)
        .concurrent_updates(True)
        .build()
    )
    app.bot_data["cfg"] = cfg

    # Busy-guard registry (init once to avoid races)
    app.bot_data[BUSY_USERS_KEY] = {}
    app.bot_data[BUSY_USERS_LOCK_KEY] = asyncio.Lock()

    # Access control
    allowed_ids = _parse_allowed_user_ids()
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
    cooldown = int((getattr(cfg.alerts, "cooldown_sec", None)
                        or getattr(cfg.alerts, "debounce_sec", None)
                        or 0))
    app.bot_data["alert_deduper"] = AlertDeduper(cooldown_sec=cooldown)

    # Handlers & jobs
    register_handlers(app)
    register_jobs(app, cooldown=cooldown)

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

