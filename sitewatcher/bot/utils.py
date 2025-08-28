# /bot/utils.py
from __future__ import annotations

import asyncio
import functools
import html
import logging
import os
import re
from typing import Optional

from telegram import Update
from telegram.error import NetworkError
from telegram.ext import ContextTypes

logger = logging.getLogger("sitewatcher.bot")


def _parse_allowed_user_ids() -> set[int] | None:
    raw = os.getenv("TELEGRAM_ALLOWED_USER_IDS") or os.getenv("ALLOWED_USER_IDS")
    if not raw:
        return None
    ids: set[int] = set()
    for token in re.split(r"[,\s;]+", raw.strip()):
        if not token:
            continue
        try:
            ids.add(int(token))
        except ValueError:
            pass
    return ids or None


def requires_auth(func):
    """Gate each command by allow-list of Telegram user IDs (if configured)."""
    @functools.wraps(func)
    async def wrapper(update, context, *args, **kwargs):
        allowed: set[int] | None = context.application.bot_data.get("allowed_user_ids")
        if allowed is not None:
            uid = update.effective_user.id if update and update.effective_user else None
            if uid is None or uid not in allowed:
                msg = getattr(update, "effective_message", None)
                if msg is not None:
                    await msg.reply_text("⛔️ Access denied.")
                else:
                    cq = getattr(update, "callback_query", None)
                    if cq is not None:
                        await cq.answer("Access denied", show_alert=True)
                return
        return await func(update, context, *args, **kwargs)
    return wrapper


async def on_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger.exception("Unhandled error", exc_info=context.error)
    if isinstance(update, Update) and update.effective_message:
        await update.effective_message.reply_text("Oops, something went wrong. Please try again.")


async def safe_reply_html(message, text: str, retries: int = 3) -> None:
    """Send HTML message with simple exponential backoff on network errors."""
    delay = 1.0
    for attempt in range(1, retries + 1):
        try:
            await message.reply_html(text)
            return
        except NetworkError as e:
            if attempt == retries:
                raise
            logger.warning("Telegram send failed (attempt %d/%d): %s", attempt, retries, e)
            await asyncio.sleep(delay)
            delay *= 2


def _strip_cached_suffix(msg: str) -> str:
    """Remove tail like [cached Xm] to store clean messages in history."""
    import re as _re
    return _re.sub(r"(?:\s*\[cached\s+\d+m\])+$", "", msg or "", flags=_re.I)


def _parse_bool(val: str) -> bool | None:
    v = (val or "").strip().lower()
    if v in ("1", "true", "yes", "on", "enable", "+"):
        return True
    if v in ("0", "false", "no", "off", "disable", "-"):
        return False
    return None


def _parse_scalar_or_list(val: str) -> list[str] | str | None:
    s = (val or "").strip()
    if not s:
        return None
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        s = s[1:-1]
    if "," in s:
        items = [x.strip() for x in s.split(",") if x.strip()]
        return items
    return s


def _format_preview_dict(d: dict, indent: int = 0) -> str:
    pad = " " * indent
    lines = []
    for k, v in (d or {}).items():
        if isinstance(v, dict):
            lines.append(f"{pad}{k}:")
            lines.append(_format_preview_dict(v, indent + 2))
        else:
            lines.append(f"{pad}{k}: {v}")
    return "\n".join(lines) if lines else (pad + "-")


def _resolve_alert_chat_id(context: ContextTypes.DEFAULT_TYPE, update: Update | None = None, cfg=None) -> Optional[int]:
    cfg = cfg or context.application.bot_data.get("cfg")
    chat_id = (
        (getattr(cfg.alerts, "chat_id", None) if cfg else None)
        or (int(os.getenv("TELEGRAM_ALERT_CHAT_ID")) if os.getenv("TELEGRAM_ALERT_CHAT_ID") else None)
        or (update.effective_chat.id if update and update.effective_chat else None)
    )
    return chat_id
