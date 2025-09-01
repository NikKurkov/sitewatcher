# sitewatcher/bot/handlers/user_prefs.py
from __future__ import annotations

from telegram import Update
from telegram.ext import ContextTypes

from ... import storage
from ..utils import requires_auth

@requires_auth
async def cmd_stop_alerts(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    owner_id = update.effective_user.id
    storage.set_user_alerts_enabled(owner_id, False)
    await update.effective_message.reply_text(
        "Alerts have been disabled for your account. Use /start_alerts to re-enable."
    )

@requires_auth
async def cmd_start_alerts(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    owner_id = update.effective_user.id
    storage.set_user_alerts_enabled(owner_id, True)
    # Keep destination chat up-to-date for future alerts
    try:
        storage.set_user_alert_chat_id(owner_id, update.effective_chat.id)
    except Exception:
        pass
    await update.effective_message.reply_text(
        "Alerts have been enabled. You will receive notifications here."
    )
