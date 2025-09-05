# sitewatcher/bot/utils.py
from __future__ import annotations

import asyncio
import functools
import html
import json
import logging
import os
import re
import time
from typing import Any, Awaitable, Callable, Iterable, Optional, Set, TypeVar

from telegram.error import NetworkError, RetryAfter, TimedOut
from telegram.ext import ContextTypes

log = logging.getLogger(__name__)

# Keys used in application.bot_data
BUSY_USERS_KEY = "busy_users"
BUSY_USERS_LOCK_KEY = "busy_users_lock"

T = TypeVar("T")

# -----------------------------------------------------------------------------
# Small value parsers / format helpers
# -----------------------------------------------------------------------------

def _parse_bool(s: str | None) -> Optional[bool]:
    """Parse a boolean-ish string; return True/False or None if not recognized."""
    if s is None:
        return None
    v = str(s).strip().lower()
    if v in {"1", "true", "yes", "on", "y"}:
        return True
    if v in {"0", "false", "no", "off", "n"}:
        return False
    return None


def _parse_scalar_or_list(val: str | None) -> Optional[list[str] | str]:
    """
    Parse a value that can be either a scalar or a list of scalars.

    - Accepts comma- or whitespace-separated lists.
    - Returns None for empty input.
    - Returns a single string if only one token found (for backward compatibility).
    """
    if val is None:
        return None
    s = str(val).strip()
    if not s:
        return None
    # Split by commas or any whitespace
    tokens = [t.strip() for t in re.split(r"[,\s]+", s) if t.strip()]
    if not tokens:
        return None
    if len(tokens) == 1:
        return tokens[0]
    return tokens


def _format_preview_dict(d: Any) -> str:
    """Stable pretty rendering for dict-like objects for HTML <pre> blocks."""
    try:
        return json.dumps(d, ensure_ascii=False, sort_keys=True, indent=2)
    except Exception:
        # Fallback to repr if the object is not JSON-serializable
        return repr(d)


def _strip_cached_suffix(msg: str) -> str:
    """
    Remove trailing '[cached Xm]' markers from a message.
    Used before persisting to storage to keep messages clean.
    """
    return re.sub(r"(?:\s*\[cached\s+\d+m\])+$", "", msg or "", flags=re.I)


# -----------------------------------------------------------------------------
# Access control and busy-guard
# -----------------------------------------------------------------------------

def _parse_allowed_user_ids() -> Set[int]:
    """
    Read TELEGRAM_ALLOWED_USER_IDS=123,456 from env.
    Returns an empty set if not set (meaning "open for all").
    """
    raw = os.getenv("TELEGRAM_ALLOWED_USER_IDS", "").strip()
    if not raw:
        return set()
    out: Set[int] = set()
    for part in re.split(r"[,\s]+", raw):
        if not part:
            continue
        try:
            out.add(int(part))
        except Exception:
            continue
    return out


def _parse_command_from_update(update) -> str:
    """Extract '/command' (without @bot) from message text/caption."""
    msg = getattr(update, "effective_message", None)
    txt = (getattr(msg, "text", None) or getattr(msg, "caption", None) or "").strip()
    if not txt:
        return ""
    if not txt.startswith("/"):
        return ""
    # Strip bot mention if present: /cmd@MyBot -> /cmd
    space = txt.find(" ")
    cmd = txt[: space if space > 0 else len(txt)]
    at = cmd.find("@")
    return cmd[:at] if at > 0 else cmd


def requires_auth(
    _func: Optional[Callable[..., Awaitable[Any]]] = None,
    *,
    allow_while_busy: bool = False,
) -> (
    Callable[..., Awaitable[Any]]
    | Callable[[Callable[..., Awaitable[Any]]], Callable[..., Awaitable[Any]]]
):
    """
    PTB async handler decorator (supports all styles):
      - @requires_auth
      - @requires_auth(allow_while_busy=True)
      - requires_auth(handler, allow_while_busy=True)

    Behavior:
      - Checks allowed user ids if configured.
      - Adds a per-user busy-guard (unless allow_while_busy=True).
      - Emits structured logs for denials and busy rejections.
    """
    def _decorator(func: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
        @functools.wraps(func)
        async def wrapper(update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
            user = getattr(update, "effective_user", None)
            user_id = getattr(user, "id", None)
            if user_id is None:
                # System or channel updates: just drop
                return

            # Access control (if a list is configured)
            allowed: Set[int] = context.application.bot_data.get("allowed_user_ids") or set()
            if allowed and user_id not in allowed:
                log.warning(
                    "auth.denied",
                    extra={"event": "auth.denied", "user_id": user_id, "command": _parse_command_from_update(update)},
                )
                msg = getattr(update, "effective_message", None)
                if msg:
                    await safe_reply_html(msg, "You are not allowed to use this bot.")
                return

            # Busy-guard
            if not allow_while_busy:
                lock: asyncio.Lock = context.application.bot_data.get(BUSY_USERS_LOCK_KEY)  # type: ignore[assignment]
                if lock is None:
                    # Initialize lazily if app didn't set it up (defensive)
                    lock = asyncio.Lock()
                    context.application.bot_data[BUSY_USERS_LOCK_KEY] = lock
                async with lock:
                    busy: dict[int, dict[str, Any]] = context.application.bot_data.setdefault(BUSY_USERS_KEY, {})
                    entry = busy.get(user_id)
                    if entry:
                        elapsed = max(0, int(time.time() - float(entry.get("started_at", 0))))
                        prev_cmd = entry.get("cmd") or ""
                        log.info(
                            "busy.reject.active",
                            extra={"event": "busy.reject.active", "user_id": user_id, "prev_cmd": prev_cmd, "elapsed_s": elapsed},
                        )
                        msg = getattr(update, "effective_message", None)
                        if msg:
                            await safe_reply_html(
                                msg,
                                f"Please wait — I’m still processing your previous command ({html.escape(prev_cmd)}, {elapsed}s elapsed).",
                            )
                        return
                    # Mark as busy for this user
                    busy[user_id] = {"started_at": time.time(), "cmd": _parse_command_from_update(update) or "<unknown>"}

            try:
                return await func(update, context, *args, **kwargs)
            finally:
                # Release busy flag unless this step opted out
                if not allow_while_busy:
                    try:
                        lock: asyncio.Lock = context.application.bot_data.get(BUSY_USERS_LOCK_KEY)  # type: ignore[assignment]
                        if lock is None:
                            lock = asyncio.Lock()
                            context.application.bot_data[BUSY_USERS_LOCK_KEY] = lock
                        async with lock:
                            busy: dict[int, dict[str, Any]] = context.application.bot_data.setdefault(BUSY_USERS_KEY, {})
                            busy.pop(user_id, None)
                    except Exception:
                        # Do not fail the handler because of cleanup
                        pass

        return wrapper

    # Support:
    # - @requires_auth -> _func is the target function
    # - @requires_auth(...) -> _func is None, return real decorator
    # - requires_auth(func, ...) -> _func is the target function, return wrapper
    return _decorator if _func is None else _decorator(_func)


# -----------------------------------------------------------------------------
# Telegram send helpers
# -----------------------------------------------------------------------------

async def safe_reply_html(
    message,
    text: str,
    *,
    disable_web_page_preview: bool = True,
    retries: int = 3,
) -> None:
    """Send HTML message with a small retry policy (handles RetryAfter/TimedOut/NetworkError)."""
    delay = 1.0
    for attempt in range(1, retries + 1):
        try:
            # By default we suppress URL previews to keep messages compact and consistent.
            await message.reply_html(text, disable_web_page_preview=disable_web_page_preview)
            return
        except RetryAfter as e:
            # Respect Telegram backoff
            delay = max(delay, float(getattr(e, "retry_after", delay)))
        except (TimedOut, NetworkError):
            # Transient network failures
            delay = max(delay, float(attempt))
        try:
            await asyncio.sleep(delay)
        except Exception:
            pass


# -----------------------------------------------------------------------------
# Error handler
# -----------------------------------------------------------------------------

async def on_error(update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Global error handler for PTB.
    Logs exception details with minimal dependency on update structure.
    """
    err = getattr(context, "error", None)
    user_id = getattr(getattr(update, "effective_user", None), "id", None)
    chat_id = getattr(getattr(update, "effective_chat", None), "id", None)
    cmd = _parse_command_from_update(update)

    log.exception(
        "bot.unhandled_error",
        extra={
            "event": "bot.unhandled_error",
            "user_id": user_id,
            "chat_id": chat_id,
            "command": cmd,
            "error_type": err.__class__.__name__ if err else None,
        },
    )
    # Optional: do NOT spam the user with tech details.
    # You can enable a polite message here if desired.


# -----------------------------------------------------------------------------
# Alerts chat resolver
# -----------------------------------------------------------------------------

def _resolve_alert_chat_id(context: ContextTypes.DEFAULT_TYPE, update, cfg, owner_id: Optional[int]) -> Optional[int]:
    """
    Resolve alert destination chat id by priority:
      1) cfg.alerts.chat_id (explicit in config)
      2) per-user preference (users.alert_chat_id), if owner_id provided
      3) env TELEGRAM_ALERT_CHAT_ID
      4) chat from update (if present)
    Note: returns int | None and logs the chosen source for traceability.
    """
    # 1) Config value
    try:
        chat_id = getattr(getattr(cfg, "alerts", None), "chat_id", None)
        if isinstance(chat_id, int) and chat_id != 0:
            return chat_id
    except Exception:
        pass

    # 2) Per-user preference in storage (optional function)
    if owner_id is not None:
        try:
            from .. import storage  # local import to avoid circular imports
            getter = getattr(storage, "get_user_alert_chat_id", None)
            if callable(getter):
                val = getter(owner_id)
                if isinstance(val, int) and val != 0:
                    return val
        except Exception:
            pass

    # 3) Environment fallback
    env_val = os.getenv("TELEGRAM_ALERT_CHAT_ID", "").strip()
    if env_val:
        try:
            return int(env_val)
        except Exception:
            pass

    # 4) Use chat from the update if available
    try:
        chat = getattr(update, "effective_chat", None)
        if chat and getattr(chat, "id", None) is not None:
            return int(chat.id)
    except Exception:
        pass

    return None
