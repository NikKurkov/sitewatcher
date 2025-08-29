# /bot/app.py
from __future__ import annotations

import logging
import os

from telegram.ext import Application
from telegram.request import HTTPXRequest

from ..config import AppConfig, get_bot_token_from_env
from .alerts import AlertDeduper
from .router import register_handlers
from .jobs import register_jobs
from .utils import _parse_allowed_user_ids

# Basic logging (centralized here)
logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logger = logging.getLogger("sitewatcher.bot")


def run_bot(cfg: AppConfig) -> None:
    token = get_bot_token_from_env()
    if not token:
        raise RuntimeError("TELEGRAM_TOKEN is not set in environment (.env)")

    request = HTTPXRequest(
        http_version="1.1",      # force HTTP/1.1 for stability
        connect_timeout=10.0,
        read_timeout=30.0,
        write_timeout=30.0,
        proxy=os.getenv("TELEGRAM_PROXY"),  # e.g. http://user:pass@host:3128
    )

    app = Application.builder().token(token).request(request).build()
    app.bot_data["cfg"] = cfg

    # Access control
    allowed_ids = _parse_allowed_user_ids()
    if allowed_ids:
        logger.info("Access limited to %d user(s)", len(allowed_ids))
    else:
        logger.warning("Access is open to all users; set TELEGRAM_ALLOWED_USER_IDS to restrict.")
    app.bot_data["allowed_user_ids"] = allowed_ids

    # Alerts deduper instance in bot_data (no globals)
    cooldown = int(getattr(cfg.alerts, "cooldown_sec", getattr(cfg.alerts, "debounce_sec", 300)) or 300)
    app.bot_data["alert_deduper"] = AlertDeduper(cooldown_sec=cooldown)

    # Handlers & jobs
    register_handlers(app)
    register_jobs(app, cooldown=cooldown)

    # Start polling
    app.run_polling()
