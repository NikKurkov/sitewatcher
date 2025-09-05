# sitewatcher/bot/handlers/user_prefs.py
from __future__ import annotations

import logging

from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes

from ... import storage
from ..utils import requires_auth, safe_reply_html

log = logging.getLogger(__name__)


@requires_auth(allow_while_busy=True)
async def cmd_stop_alerts(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Disable alerts for the current user (idempotent).
    - Persists the preference in storage.
    - Uses safe HTML replies and structured logging.
    """
    owner_id = update.effective_user.id
    msg = update.effective_message

    try:
        was_enabled = storage.is_user_alerts_enabled(owner_id)
    except Exception:
        # If we can't read state, proceed to attempt disabling anyway.
        was_enabled = None

    try:
        storage.set_user_alerts_enabled(owner_id, False)
        log.info("alerts.stop", extra={"event": "alerts.stop", "owner_id": owner_id})
    except Exception as e:
        log.exception("alerts.stop.error", extra={"event": "alerts.stop.error", "owner_id": owner_id})
        await safe_reply_html(msg, f"❌ Failed to disable alerts: <code>{e}</code>")
        return

    text = (
        "Alerts have been disabled for your account. Use /start_alerts to re-enable."
        if was_enabled is not False
        else "Alerts are already disabled for your account."
    )
    await safe_reply_html(msg, text)


@requires_auth(allow_while_busy=True)
async def cmd_start_alerts(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Enable alerts for the current user and bind them to the current chat.
    - Writes both the 'enabled' flag and the destination chat_id.
    - Uses safe HTML replies and structured logging.
    """
    owner_id = update.effective_user.id
    chat_id = update.effective_chat.id
    msg = update.effective_message

    try:
        storage.set_user_alerts_enabled(owner_id, True)
        storage.set_user_alert_chat_id(owner_id, chat_id)
        log.info(
            "alerts.start",
            extra={"event": "alerts.start", "owner_id": owner_id, "chat_id": chat_id},
        )
    except Exception as e:
        log.exception("alerts.start.error", extra={"event": "alerts.start.error", "owner_id": owner_id})
        await safe_reply_html(msg, f"❌ Failed to enable alerts: <code>{e}</code>")
        return

    await safe_reply_html(msg, "Alerts have been enabled. You will receive notifications here.")


def register_handlers(app: Application) -> None:
    """Register user-preferences commands on the application/router."""
    app.add_handler(CommandHandler("start_alerts", cmd_start_alerts, block=False), group=0)
    app.add_handler(CommandHandler("stop_alerts", cmd_stop_alerts, block=False), group=0)


def register_user_prefs_handlers(app: Application) -> None:
    """Backward-compatible alias expected by some routers."""
    register_handlers(app)
