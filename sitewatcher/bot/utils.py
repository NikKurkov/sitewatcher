# /bot/utils.py
from __future__ import annotations

import asyncio
import time
from functools import wraps
import logging
import os
import re
from datetime import datetime, timezone

from telegram import Update
from telegram.error import NetworkError, RetryAfter, TimedOut
from telegram.ext import ContextTypes

from .. import storage
from ..config import AppConfig

log = logging.getLogger(__name__)

# Keys for per-user busy registry stored in app.bot_data
BUSY_USERS_KEY = "busy_users"
BUSY_USERS_LOCK_KEY = "busy_users_lock"


def _parse_command_from_update(update) -> str:
    """Extract '/command' (without @bot) from message text."""
    msg = getattr(update, "effective_message", None)
    txt = (getattr(msg, "text", None) or "").strip()
    if not txt:
        return ""
    first = txt.split()[0]
    if first.startswith("/"):
        return first.split("@", 1)[0]
    return ""


def _parse_allowed_user_ids() -> set[int] | None:
    """Read allowed user ids from env and return as a set, or None if unrestricted."""
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


def requires_auth(func=None, *, allow_while_busy: bool = False):
    """
    Access control + per-user anti-overlap guard.

    Guard logic:
      1) If there's a running task for the user -> reject.
      2) Else, if this message was SENT while the previous command was running
         (msg.date ∈ [last_busy_start, last_busy_end]) -> reject.
      3) Else -> accept and mark this handler as running; on finish, record busy window.
    """
    def _decorator(handler_fn):
        @wraps(handler_fn)
        async def _wrapper(update, context, *args, **kwargs):
            # ---- access control ----
            allowed: set[int] | None = context.application.bot_data.get("allowed_user_ids")
            if allowed is not None:
                uid = update.effective_user.id if update.effective_user else None
                if uid is None or uid not in allowed:
                    # Log access denial for observability
                    log.warning(
                        "auth.denied",
                        extra={"event": "auth.denied", "user_id": uid, "command": _parse_command_from_update(update)},
                    )
                    if getattr(update, "message", None):
                        await update.message.reply_text("⛔️ Access denied.")
                    elif getattr(update, "callback_query", None):
                        await update.callback_query.answer("Access denied", show_alert=True)
                    return
            # ---- persist user + last chat for alerts ----
            try:
                u = update.effective_user
                chat_id = update.effective_chat.id if update.effective_chat else None
                storage.ensure_user(
                    telegram_id=u.id if u else None,
                    username=getattr(u, "username", None),
                    first_name=getattr(u, "first_name", None),
                    last_name=getattr(u, "last_name", None),
                    alert_chat_id=chat_id,
                )
                # Trace successful user persistence
                log.debug(
                    "user.ensure",
                    extra={"event": "user.ensure", "user_id": getattr(u, "id", None), "chat_id": chat_id},
                )
            except Exception:
                pass

            # ---- per-user busy guard (task + busy-window) ----
            uid = update.effective_user.id if update.effective_user else None
            marked_busy = False
            msg = getattr(update, "effective_message", None)
            # Telegram gives UTC-aware datetime for message.date
            msg_dt: datetime | None = getattr(msg, "date", None)
            if isinstance(msg_dt, datetime):
                if msg_dt.tzinfo is None:
                    msg_dt = msg_dt.replace(tzinfo=timezone.utc)
                else:
                    msg_dt = msg_dt.astimezone(timezone.utc)

            if not allow_while_busy and uid is not None:
                app = context.application

                # Ensure registry lock exists
                reg_lock = app.bot_data.get(BUSY_USERS_LOCK_KEY)
                if not isinstance(reg_lock, asyncio.Lock):
                    reg_lock = asyncio.Lock()
                    app.bot_data[BUSY_USERS_LOCK_KEY] = reg_lock

                async with reg_lock:
                    reg: dict = app.bot_data.setdefault(BUSY_USERS_KEY, {})
                    entry = reg.get(uid)
                    if entry is None:
                        entry = {
                            "task": None,
                            "cmd": "",
                            "since": 0.0,
                            # last busy window in wall time (UTC)
                            "last_start_dt": None,
                            "last_end_dt": None,
                            # current active window start (UTC)
                            "active_start_dt": None,
                        }
                        reg[uid] = entry

                    # 1) Already running? Reject immediately.
                    t: asyncio.Task | None = entry.get("task")
                    if t is not None and not t.done():
                        prev_cmd = (entry.get("cmd") or "previous command")
                        since = float(entry.get("since") or 0.0)
                        elapsed = int(max(0, time.monotonic() - since)) if since else 0
                        # Log busy rejection with timing
                        log.info(
                            "busy.reject.active",
                            extra={"event": "busy.reject.active", "user_id": uid, "prev_cmd": prev_cmd, "elapsed_s": elapsed},
                        )
                        if msg:
                            await msg.reply_text(
                                f"Please wait — I’m still processing your previous command "
                                f"({prev_cmd}, {elapsed}s elapsed)."
                            )
                        return

                    # 2) If message was sent while previous command was running, reject.
                    last_start: datetime | None = entry.get("last_start_dt")
                    last_end: datetime | None = entry.get("last_end_dt")
                    if msg_dt and last_start and last_end:
                        if last_start <= msg_dt <= last_end:
                            prev_cmd = (entry.get("cmd") or "previous command")
                            log.info(
                                "busy.reject.window",
                                extra={
                                    "event": "busy.reject.window",
                                    "user_id": uid,
                                    "prev_cmd": prev_cmd,
                                    "msg_dt": msg_dt.isoformat(),
                                    "win_start": last_start.isoformat() if last_start else None,
                                    "win_end": last_end.isoformat() if last_end else None,
                                },
                            )
                            if msg:
                                await msg.reply_text(
                                    "Please wait — your message was sent while the previous command "
                                    "was still running. Try again now."
                                )
                            return

                    # 3) Mark this handler as the running task for the user
                    entry["task"] = asyncio.current_task()
                    entry["cmd"] = _parse_command_from_update(update) or f"/{handler_fn.__name__}"
                    entry["since"] = time.monotonic()
                    # Record start of the active busy window in wall time
                    entry["active_start_dt"] = msg_dt or datetime.now(timezone.utc)
                    marked_busy = True
                    # Trace we marked this user as busy
                    log.debug(
                        "busy.mark",
                        extra={"event": "busy.mark", "user_id": uid, "cmd": entry["cmd"]},
                    )

            try:
                return await handler_fn(update, context, *args, **kwargs)
            finally:
                # Clear busy state and seal busy window
                if not allow_while_busy and uid is not None and marked_busy:
                    try:
                        reg_lock = context.application.bot_data.get(BUSY_USERS_LOCK_KEY)
                        if isinstance(reg_lock, asyncio.Lock):
                            async with reg_lock:
                                reg: dict = context.application.bot_data.get(BUSY_USERS_KEY, {})
                                entry = reg.get(uid)
                                if entry:
                                    # Seal last busy window [start,end]
                                    start_dt: datetime | None = entry.get("active_start_dt")
                                    entry["last_start_dt"] = start_dt
                                    entry["last_end_dt"] = datetime.now(timezone.utc)
                                    # Reset active
                                    elapsed_s = 0
                                    try:
                                        since = float(entry.get("since") or 0.0)
                                        elapsed_s = int(max(0, time.monotonic() - since)) if since else 0
                                    except Exception:
                                        pass
                                    entry["active_start_dt"] = None
                                    entry["task"] = None
                                    entry["since"] = 0.0
                                    entry["cmd"] = ""
                                    # Trace clearing with elapsed seconds
                                    log.debug(
                                        "busy.clear",
                                        extra={"event": "busy.clear", "user_id": uid, "elapsed_s": elapsed_s},
                                    )
                    except Exception:
                        pass

        return _wrapper
    return _decorator if func is None else _decorator(func)


async def on_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    # Always capture exception with context
    log.exception(
        "bot.unhandled_error",
        extra={"event": "bot.unhandled_error", "update_type": type(update).__name__ if update else None},
        exc_info=context.error,
    )
    if isinstance(update, Update) and update.effective_message:
        await update.effective_message.reply_text("Oops, something went wrong. Please try again.")


async def safe_reply_html(message, text: str, retries: int = 3) -> None:
    """Send HTML message with small retry policy (handles RetryAfter/TimedOut/NetworkError)."""
    delay = 1.0
    for attempt in range(1, retries + 1):
        try:
            await message.reply_html(text)
            return
        except RetryAfter as e:
            # Honor server-advised retry interval
            if attempt == retries:
                raise
            retry_after = getattr(e, "retry_after", None)
            sleep_s = float(retry_after) if retry_after else delay
            log.warning(
                "telegram.retry_after",
                extra={"event": "telegram.retry_after", "attempt": attempt, "retries": retries, "retry_after_s": sleep_s},
            )
            await asyncio.sleep(sleep_s)
            delay = max(delay, sleep_s) * 1.5
        except (TimedOut, NetworkError) as e:
            if attempt == retries:
                raise
            log.warning(
                "telegram.network_retry",
                extra={"event": "telegram.network_retry", "attempt": attempt, "retries": retries, "error": e.__class__.__name__},
            )
            await asyncio.sleep(delay)
            delay *= 2


def _strip_cached_suffix(msg: str) -> str:
    """Remove tail like [cached Xm] to store clean messages in history."""
    import re as _re
    return _re.sub(r"(?:\s*\[cached\s+\d+m\])+$", "", msg or "", flags=_re.I)


def _parse_bool(val: str) -> bool | None:
    """Parse yes/true/on/1 and no/false/off/0 into bool; return None if unknown."""
    v = (val or "").strip().lower()
    if v in ("1", "true", "yes", "on", "enable", "+"):
        return True
    if v in ("0", "false", "no", "off", "disable", "-"):
        return False
    return None


def _parse_scalar_or_list(val: str) -> list[str] | str | None:
    """Parse comma-separated list or return scalar; preserve quotes stripping."""
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
    """Pretty-print nested dict for previews."""
    pad = " " * indent
    lines = []
    for k, v in (d or {}).items():
        if isinstance(v, dict):
            lines.append(f"{pad}{k}:")
            lines.append(_format_preview_dict(v, indent + 2))
        else:
            lines.append(f"{pad}{k}: {v}")
    return "\n".join(lines) if lines else (pad + "-")


def _resolve_alert_chat_id(
    context,
    update: Update | None,
    cfg: AppConfig | None,
    owner_id: int | None = None,
) -> int | None:
    """
    Resolve alert destination chat id by priority:
      1) cfg.alerts.chat_id (explicit in config)
      2) per-user preference (users.alert_chat_id), if owner_id provided
      3) env TELEGRAM_ALERT_CHAT_ID
      4) chat from update (if present)
    """
    source = None
    result: int | None = None
    if cfg and getattr(cfg.alerts, "chat_id", None):
        try:
            result = int(cfg.alerts.chat_id)
            source = "config"
        except Exception:
            result = None
    if result is None and owner_id is not None:
        pref = storage.get_user_alert_chat_id(owner_id)
        if pref:
            result = pref
            source = "user"
    if result is None:
        env = os.getenv("TELEGRAM_ALERT_CHAT_ID")
        if env:
            try:
                result = int(env)
                source = "env"
            except Exception:
                result = None
    if result is None and update and update.effective_chat:
        result = update.effective_chat.id
        source = "update"

    # Trace resolution path for debugging
    log.debug(
        "alert.chat.resolve",
        extra={"event": "alert.chat.resolve", "owner_id": owner_id, "source": source, "chat_id": result},
    )
    return result
