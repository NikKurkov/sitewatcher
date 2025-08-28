# sitewatcher/bot.py
from __future__ import annotations

import random
from datetime import datetime, timezone, timedelta
import os
import re
import functools
import sqlite3
from pathlib import Path
import asyncio
from telegram.error import NetworkError
from telegram.request import HTTPXRequest
from typing import List, NamedTuple, Optional
import html
import logging
import time
from dataclasses import dataclass

from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    ConversationHandler,
    MessageHandler,
    filters,
)

# Basic logging (you can centralize it elsewhere if you prefer)
logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(name)s:%(message)s')
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logger = logging.getLogger('sitewatcher.bot')

from .config import AppConfig, get_bot_token_from_env
from .dispatcher import Dispatcher
from . import storage

HELP_TEXT = (
    "/add <domain1> [domain2 ...] — add domains via quick wizard (keywords + interval)\n"
    "/add_domain <name> — add a domain (legacy, no wizard)\n"
    "/remove_domain <name> — remove a domain\n"
    "/list_domain — list domains\n"
    "/check_domain <name> [--force] — run checks for a domain (use cache unless --force)\n"
    "/check_all [--force] — run checks for all domains\n"
    "/cfg <name> — show effective config and DB override for a domain\n"
    "/cfg_set <name> <key> <value> — set override (e.g. checks.http_basic true, keywords \"a,b\")\n"
    "/cfg_unset <name> [key] — remove override key or whole override\n"
    "/clear_cache — clear RKN/WHOIS caches\n"
)

# ================= Anti-storm / cooldown deduper =================
class _AlertKey(NamedTuple):
    domain: str
    level: str   # overall level: "CRIT" | "WARN" | "OK" | "UNKNOWN"

@dataclass
class _AlertRecord:
    last_sent_at: float = 0.0
    suppressed: int = 0
    last_text: str = ""

class AlertDeduper:
    """
    In-memory per-process deduper with cooldown window.
    Suppresses repeated (domain, level) alerts within cooldown_sec.
    """
    def __init__(self, cooldown_sec: int) -> None:
        self.cooldown = max(0, int(cooldown_sec))
        self._state: dict[_AlertKey, _AlertRecord] = {}

    def should_send_now(self, key: _AlertKey, text: str, now: Optional[float] = None) -> tuple[bool, Optional[str]]:
        now = now or time.time()
        rec = self._state.get(key)
        if rec is None:
            rec = _AlertRecord()
            self._state[key] = rec
        # May send now?
        if rec.last_sent_at == 0 or (now - rec.last_sent_at) >= self.cooldown:
            prefix = f"(+{rec.suppressed} similar events in last {self.cooldown}s)\n" if rec.suppressed > 0 else ""
            rec.last_sent_at = now
            rec.last_text = text
            rec.suppressed = 0
            return True, (prefix + text)
        # Suppress and count
        rec.suppressed += 1
        rec.last_text = text
        return False, None

    def flush_summaries(self, max_batch: int = 20) -> list[tuple[_AlertKey, str]]:
        out: list[tuple[_AlertKey, str]] = []
        now = time.time()
        for key, rec in list(self._state.items()):
            if rec.suppressed > 0 and (now - rec.last_sent_at) >= self.cooldown:
                msg = f"{rec.suppressed} repetition(s) in last {self.cooldown}s for {key.domain} [{key.level}]"
                rec.suppressed = 0
                rec.last_sent_at = now
                out.append((key, msg))
                if len(out) >= max_batch:
                    break
        return out

_ALERT_DEDUPER: AlertDeduper | None = None

async def _flush_alert_summaries_job(context: ContextTypes.DEFAULT_TYPE) -> None:
    """Periodic job to flush suppression summaries to the alert chat."""
    global _ALERT_DEDUPER
    if _ALERT_DEDUPER is None:
        return
    summaries = _ALERT_DEDUPER.flush_summaries()
    if not summaries:
        return
    cfg: AppConfig = context.application.bot_data["cfg"]
    chat_id = _resolve_alert_chat_id(context, update=None, cfg=cfg)
    if not chat_id:
        return
    for _, summary in summaries:
        try:
            await context.bot.send_message(chat_id=chat_id, text=summary, disable_web_page_preview=True)
        except Exception as e:
            logger.warning("failed to send summary: %s", e)

# ================= Status helpers =================
def _status_weight(s: str) -> int:
    s = (s or "").upper()
    if s == "CRIT":
        return 2
    if s in ("WARN", "UNKNOWN"):
        return 1
    return 0  # OK / other

def _status_emoji(s: str) -> str:
    s = (s or "").upper()
    return {"CRIT": "🔴", "WARN": "🟡", "OK": "🟢", "UNKNOWN": "⚪"}.get(s, "⚪")

def _status_bullet(s: str) -> str:
    s = (s or "").upper()
    if s == "CRIT":
        return "🔺"
    if s == "WARN":
        return "🔸"
    return "•"  # for OK/UNKNOWN keep a calm marker

def _overall_from_results(results) -> str:
    worst = 0
    for r in results:
        st = getattr(r.status, "value", str(r.status))
        worst = max(worst, _status_weight(st))
    return {2: "CRIT", 1: "WARN", 0: "OK"}[worst]

# ================= Auth =================
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
    """Gate every command by a simple allow-list of Telegram user IDs (if configured)."""
    @functools.wraps(func)
    async def wrapper(update, context, *args, **kwargs):
        allowed: set[int] | None = context.application.bot_data.get("allowed_user_ids")
        if allowed is not None:
            uid = update.effective_user.id if update.effective_user else None
            if uid is None or uid not in allowed:
                # безопасный ответ: effective_message -> effective_chat
                msg = getattr(update, "effective_message", None)
                if msg is not None:
                    try:
                        await msg.reply_text("⛔️ Access denied.")
                    except Exception:
                        pass
                elif getattr(update, "callback_query", None):
                    try:
                        await update.callback_query.answer("Access denied", show_alert=True)
                    except Exception:
                        pass
                else:
                    chat = getattr(update, "effective_chat", None)
                    if chat is not None:
                        try:
                            await context.bot.send_message(chat_id=chat.id, text="⛔️ Access denied.")
                        except Exception:
                            pass
                return
        return await func(update, context, *args, **kwargs)
    return wrapper

# ================= General utils =================
async def on_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger.exception("Unhandled error", exc_info=context.error)
    if isinstance(update, Update):
        try:
            await reply_text_safe(update, context, "Oops, something went wrong. Please try again.")
        except Exception:
            pass

async def safe_reply_html(message, text: str, retries: int = 3) -> None:
    """Send HTML message to Telegram with simple exponential backoff on network errors."""
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

async def reply_html_safe(update: Update, context: ContextTypes.DEFAULT_TYPE, text: str, retries: int = 3) -> None:
    """Safe HTML reply: prefer effective_message; fallback to bot.send_message(effective_chat)."""
    msg = getattr(update, "effective_message", None)
    if msg is not None:
        return await safe_reply_html(msg, text, retries=retries)
    chat = getattr(update, "effective_chat", None)
    if chat is None:
        logger.warning("reply_html_safe: nowhere to reply (no effective_message/effective_chat)")
        return
    delay = 1.0
    for attempt in range(1, retries + 1):
        try:
            await context.bot.send_message(chat_id=chat.id, text=text, parse_mode="HTML", disable_web_page_preview=True)
            return
        except NetworkError as e:
            if attempt == retries:
                raise
            logger.warning("Telegram send failed (attempt %d/%d): %s", attempt, retries, e)
            await asyncio.sleep(delay)
            delay *= 2

async def reply_text_safe(update: Update, context: ContextTypes.DEFAULT_TYPE, text: str, retries: int = 3) -> None:
    """Safe TEXT reply: prefer effective_message; fallback to bot.send_message(effective_chat)."""
    msg = getattr(update, "effective_message", None)
    delay = 1.0
    if msg is not None:
        for attempt in range(1, retries + 1):
            try:
                await msg.reply_text(text)
                return
            except NetworkError as e:
                if attempt == retries:
                    raise
                logger.warning("Telegram send failed (attempt %d/%d): %s", attempt, retries, e)
                await asyncio.sleep(delay)
                delay *= 2
        return
    chat = getattr(update, "effective_chat", None)
    if chat is None:
        logger.warning("reply_text_safe: nowhere to reply (no effective_message/effective_chat)")
        return
    for attempt in range(1, retries + 1):
        try:
            await context.bot.send_message(chat_id=chat.id, text=text)
            return
        except NetworkError as e:
            if attempt == retries:
                raise
            logger.warning("Telegram send failed (attempt %d/%d): %s", attempt, retries, e)
            await asyncio.sleep(delay)
            delay *= 2

def _strip_cached_suffix(msg: str) -> str:
    """Remove tail like [cached Xm] to store clean messages in history."""
    return re.sub(r"(?:\s*\[cached\s+\d+m\])+$", "", msg or "", flags=re.I)

def _resolve_alert_chat_id(context: ContextTypes.DEFAULT_TYPE, update: Update | None = None, cfg: AppConfig | None = None) -> int | None:
    cfg = cfg or context.application.bot_data.get("cfg")
    chat_id = (
        (getattr(cfg.alerts, "chat_id", None) if cfg else None)
        or (int(os.getenv("TELEGRAM_ALERT_CHAT_ID")) if os.getenv("TELEGRAM_ALERT_CHAT_ID") else None)
        or (update.effective_chat.id if update and update.effective_chat else None)
    )
    return chat_id

# ================= Commands: simple ones =================
@requires_auth
async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await reply_text_safe(update, context, HELP_TEXT)

@requires_auth
async def cmd_add_domain(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Legacy add: just insert a domain, no wizard, no overrides."""
    if not context.args:
        await reply_text_safe(update, context, "Usage: /add_domain example.com")
        return
    name = context.args[0].strip().lower()
    storage.add_domain(name)
    await reply_text_safe(update, context, f"Added: {name}")

@requires_auth
async def cmd_remove_domain(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args:
        await reply_text_safe(update, context, "Usage: /remove_domain example.com")
        return
    name = context.args[0].strip().lower()
    ok = storage.remove_domain(name)
    await reply_text_safe(update, context, "Removed" if ok else "Not found")

@requires_auth
async def cmd_list_domain(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    items: List[str] = storage.list_domains()
    await reply_text_safe(update, context, "No domains yet" if not items else "\n".join(items))

async def _format_results(domain: str, results) -> str:
    """Store clean history and format a compact result text with emojis."""
    for r in results:
        storage.save_history(domain, r.check, r.status, _strip_cached_suffix(r.message), r.metrics)

    overall = _overall_from_results(results)
    head = f"{_status_emoji(overall)} <b>{html.escape(domain)}</b> — {overall}"

    lines = [head]
    for r in results:
        st = getattr(r.status, "value", str(r.status))
        bullet = _status_bullet(st)
        lines.append(
            "{bullet} <code>{check}</code> — <b>{status}</b> — {msg}".format(
                bullet=bullet,
                check=html.escape(str(r.check)),
                status=html.escape(st),
                msg=html.escape(str(r.message)),
            )
        )

    return "\n".join(lines)

def _due_checks_for_domain(cfg: AppConfig, domain: str) -> List[str]:
    """
    Decide which checks are due for the domain.

    If domain override contains 'interval_minutes':
      - <=0   → no scheduled checks for this domain (auto-check disabled)
      - >0    → use this single interval for ALL checks of the domain

    Otherwise: fall back to per-check intervals from cfg.schedules.
    """
    # Domain-level override
    override = {}
    try:
        override = storage.get_domain_override(domain) or {}
    except Exception:
        override = {}

    if isinstance(override.get("interval_minutes"), int):
        iv = int(override["interval_minutes"])
        if iv <= 0:
            return []  # disabled for this domain
        due: List[str] = []
        sched_names = list(cfg.schedules.model_dump().keys())
        for check_name in sched_names:
            mins = storage.minutes_since_last(domain, check_name)
            if mins is None or mins >= iv:
                due.append(check_name)
        return due

    # Default per-check schedule
    sched = cfg.schedules.model_dump()
    due: List[str] = []
    for check_name, sc in sched.items():
        interval_min = int(sc.get("interval_minutes") or 0)
        if interval_min <= 0:
            continue
        mins = storage.minutes_since_last(domain, check_name)
        if mins is None or mins >= interval_min:
            due.append(check_name)
    return due

async def _run_checks_for_all_domains(context, warmup: bool) -> None:
    """Background scheduler loop."""
    cfg: AppConfig = context.application.bot_data["cfg"]
    domains = storage.list_domains()
    if not domains:
        return

    async with Dispatcher(cfg) as d:
        for name in domains:
            try:
                due = _due_checks_for_domain(cfg, name)
                if not due:
                    continue
                results = await d.run_for(name, only_checks=due, use_cache=False)  # cache not needed in background
                for r in results:
                    storage.save_history(name, r.check, r.status, _strip_cached_suffix(r.message), r.metrics)
                await maybe_send_alert(None, context, name, results)
            except Exception as e:
                logger.exception("scheduler: %s failed: %s", name, e)

async def job_warmup(context: ContextTypes.DEFAULT_TYPE) -> None:
    """One-time warmup run: establish baseline without spamming alerts."""
    await _run_checks_for_all_domains(context, warmup=True)

async def job_periodic(context: ContextTypes.DEFAULT_TYPE) -> None:
    """Periodic scheduled checks."""
    await _run_checks_for_all_domains(context, warmup=False)

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
    for k, v in d.items():
        if isinstance(v, dict):
            lines.append(f"{pad}{k}:")
            lines.append(_format_preview_dict(v, indent + 2))
        else:
            lines.append(f"{pad}{k}: {v}")
    return "\n".join(lines) if lines else (pad + "-")

# ================= Alerting =================
async def maybe_send_alert(update, context, domain: str, results) -> None:
    """Decide whether to send an alert and deliver it (respect policy + cooldown)."""
    cfg: AppConfig = context.application.bot_data["cfg"]
    if not getattr(cfg.alerts, "enabled", True):
        return

    now = datetime.now(timezone.utc)
    overall = _overall_from_results(results)

    # previous state
    row = storage.get_alert_state(domain)
    prev_overall = row["last_overall"] if row else None
    policy = getattr(cfg.alerts, "policy", "overall_change")

    # last_sent_at from DB (iso)
    last_sent_at = None
    if row:
        raw_last = row["last_sent_at"]
        if raw_last:
            try:
                last_sent_at = datetime.fromisoformat(raw_last)
            except Exception:
                last_sent_at = None

    # baseline: first time — just store baseline
    if prev_overall is None:
        storage.upsert_alert_state(domain, overall, None)
        return

    # policy
    if policy == "worsen_only":
        if _status_weight(overall) <= _status_weight(prev_overall):
            storage.upsert_alert_state(domain, overall, row["last_sent_at"] if row else None)
            return
    elif policy == "overall_change":
        if overall == prev_overall:
            return
    elif policy == "all":
        pass  # always send (will still pass through cooldown)
    else:
        if overall == prev_overall:
            return

    # cooldown (supports new cooldown_sec, falls back to legacy debounce_sec)
    cooldown = int(getattr(cfg.alerts, "cooldown_sec", getattr(cfg.alerts, "debounce_sec", 0)) or 0)
    if last_sent_at is not None and (now - last_sent_at) < timedelta(seconds=cooldown):
        storage.upsert_alert_state(domain, overall, row["last_sent_at"])
        return

    # message
    head = f"{_status_emoji(overall)} <b>{html.escape(domain)}</b> — {overall} (was {prev_overall})"
    lines = [head]
    for r in results:
        st = getattr(r.status, "value", str(r.status))
        bullet = _status_bullet(st)
        lines.append(
            "{bullet} <code>{check}</code> — <b>{status}</b> — {msg}".format(
                bullet=bullet,
                check=html.escape(str(r.check)),
                status=html.escape(st),
                msg=html.escape(str(r.message)),
            )
        )
    text = "\n".join(lines)

    # where to send
    alert_chat_id = _resolve_alert_chat_id(context, update=update, cfg=cfg)
    if not alert_chat_id:
        storage.upsert_alert_state(domain, overall, None)
        return

    # de-dup per (domain, overall) with a cooldown burst summary
    key = _AlertKey(domain=domain, level=overall)
    global _ALERT_DEDUPER
    if _ALERT_DEDUPER is not None:
        send_now, maybe_text = _ALERT_DEDUPER.should_send_now(key, text)
        if not send_now:
            storage.upsert_alert_state(domain, overall, row["last_sent_at"] if row else None)
            return
        if maybe_text:
            text = maybe_text

    try:
        await context.bot.send_message(chat_id=alert_chat_id, text=text, parse_mode="HTML", disable_web_page_preview=True)
        storage.upsert_alert_state(domain, overall, now.isoformat())
    except Exception as e:
        logger.exception("alert send failed for %s: %s", domain, e)
        storage.upsert_alert_state(domain, overall, last_sent_at.isoformat() if last_sent_at else None)

# ================= Config commands =================
@requires_auth
async def cmd_cfg(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args:
        await reply_text_safe(update, context, "Usage: /cfg <domain>")
        return
    domain = context.args[0].strip().lower()
    cfg: AppConfig = context.application.bot_data["cfg"]

    # Get effective settings via Dispatcher.resolve
    async with Dispatcher(cfg) as d:
        settings = d._resolve(domain)  # private, but our codebase

    effective = {
        "checks": {k: getattr(settings.checks, k) for k in dir(settings.checks) if not k.startswith("_") and isinstance(getattr(settings.checks, k), (bool,))},
        "http_timeout_s": getattr(settings, "http_timeout_s", None),
        "latency_warn_ms": getattr(settings, "latency_warn_ms", None),
        "latency_crit_ms": getattr(settings, "latency_crit_ms", None),
        "tls_warn_days": getattr(settings, "tls_warn_days", None),
        "proxy": getattr(settings, "proxy", None),
        "keywords": getattr(settings, "keywords", None),
        "ports": getattr(settings, "ports", None),
    }

    from . import storage as _st
    override = _st.get_domain_override(domain)

    text = (
        f"<b>{html.escape(domain)}</b>\n\n"
        "<b>Effective:</b>\n"
        f"<pre>{html.escape(_format_preview_dict(effective))}</pre>\n\n"
        "<b>Override (DB):</b>\n"
        f"{('<pre>' + html.escape(_format_preview_dict(override)) + '</pre>') if override else '— none —'}"
    )

    await reply_html_safe(update, context, text)

@requires_auth
async def cmd_cfg_set(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if len(context.args) < 3:
        await reply_text_safe(
            update,
            context,
            "Usage: /cfg_set <domain> <key> <value>\n"
            "Examples:\n"
            "  /cfg_set example.com checks.http_basic true\n"
            "  /cfg_set example.com http_timeout_s 7\n"
            "  /cfg_set example.com keywords \"foo,bar,baz\"\n"
            "  /cfg_set example.com ports \"80,443,22\""
        )
        return
    domain = context.args[0].strip().lower()
    key = context.args[1].strip()
    val = " ".join(context.args[2:]).strip()

    # Supported: checks.<name>, http_timeout_s, latency_warn_ms, latency_crit_ms, tls_warn_days,
    # keywords (comma), ports (comma), proxy (string or 'none' to reset)
    patch: dict = {}

    if key.startswith("checks."):
        check_name = key.split(".", 1)[1]
        b = _parse_bool(val)
        if b is None:
            await reply_text_safe(update, context, "For checks.* use true/false")
            return
        patch = {"checks": {check_name: b}}
    elif key in ("http_timeout_s", "latency_warn_ms", "latency_crit_ms", "tls_warn_days"):
        try:
            iv = int(val)
        except ValueError:
            await reply_text_safe(update, context, f"{key} must be an integer")
            return
        patch = {key: iv}
    elif key in ("keywords", "ports"):
        v = _parse_scalar_or_list(val)
        if v is None:
            await reply_text_safe(update, context, f"{key}: empty value")
            return
        if isinstance(v, str):
            v = [v]
        patch = {key: v}
    elif key == "proxy":
        v = val.strip()
        if v.lower() in ("none", "-", "null", "off"):
            patch = {"proxy": None}
        else:
            patch = {"proxy": v}
    elif key == "interval_minutes":
        try:
            iv = int(val)
        except ValueError:
            await reply_text_safe(update, context, "interval_minutes must be integer (0 disables auto checks)")
            return
        patch = {"interval_minutes": iv}
    else:
        await reply_text_safe(
            update,
            context,
            "Unknown key. Use: checks.<name>, http_timeout_s, latency_warn_ms, latency_crit_ms, tls_warn_days, keywords, ports, proxy, interval_minutes"
        )
        return

    from . import storage as _st
    merged = _st.set_domain_override(domain, patch)
    await reply_html_safe(
        update,
        context,
        "✅ Saved.\nCurrent override:\n<pre>{}</pre>".format(html.escape(_format_preview_dict(merged))),
    )

@requires_auth
async def cmd_cfg_unset(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args:
        await reply_text_safe(update, context, "Usage: /cfg_unset <domain> [key]")
        return
    domain = context.args[0].strip().lower()
    key = context.args[1].strip() if len(context.args) > 1 else None

    from . import storage as _st
    _st.unset_domain_override(domain, key)

    if key:
        txt = f"🗑 Removed key <code>{html.escape(key)}</code> for <b>{html.escape(domain)}</b>."
    else:
        txt = f"🗑 Removed entire override for <b>{html.escape(domain)}</b>."
    await reply_html_safe(update, context, txt)

# ================= Run checks commands =================
@requires_auth
async def cmd_check_domain(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args:
        await reply_text_safe(update, context, "Usage: /check_domain example.com")
        return

    raw = context.args[0].strip().lower()
    force = raw in ("--force", "-f", "force")
    name = (context.args[1] if force and len(context.args) > 1 else raw).strip().lower()

    cfg: AppConfig = context.application.bot_data["cfg"]
    async with Dispatcher(cfg) as d:
        results = await d.run_for(name, use_cache=not force)
        text = await _format_results(name, results)

    await reply_html_safe(update, context, text)
    await maybe_send_alert(update, context, name, results)

@requires_auth
async def cmd_check_all(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    cfg: AppConfig = context.application.bot_data["cfg"]
    names = storage.list_domains()
    if not names:
        await reply_text_safe(update, context, "No domains in DB")
        return

    force = False
    if context.args:
        arg0 = (context.args[0] or "").lower()
        if arg0 in ("--force", "-f", "force"):
            force = True

    parts = []
    async with Dispatcher(cfg) as d:
        for name in names:
            results = await d.run_for(name, use_cache=not force)
            parts.append(await _format_results(name, results))
            await maybe_send_alert(update, context, name, results)

    await reply_html_safe(update, context, "\n\n".join(parts))

# ================= Cache cleanup =================
@requires_auth
async def cmd_clear_cache(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    cfg: AppConfig = context.application.bot_data["cfg"]

    # 1) WHOIS cache (table whois_state in main DB)
    try:
        whois_deleted = storage.clear_whois_cache()
    except Exception as e:
        whois_deleted = -1
        logger.exception("clear_whois_cache failed: %s", e)

    # 2) RKN index (SQLite file) + legacy artifacts
    base_dir = Path(__file__).resolve().parent
    data_dir = base_dir / "data"
    rkn_db_path = Path(cfg.rkn.index_db_path) if getattr(cfg.rkn, "index_db_path", None) else (data_dir / "z_i_index.db")

    rkn_removed = False
    rkn_fallback_clear = False
    rkn_error: str | None = None

    if rkn_db_path.exists():
        try:
            rkn_db_path.unlink()
            rkn_removed = True
        except Exception as e:
            rkn_error = f"unlink failed: {e}"
            try:
                conn = sqlite3.connect(rkn_db_path)
                with conn:
                    conn.execute("DELETE FROM domains")
                    conn.execute("DELETE FROM ips")
                    conn.execute("DELETE FROM meta")
                conn.close()
                rkn_fallback_clear = True
            except Exception as e2:
                rkn_error += f"; fallback failed: {e2}"

    removed_extra: list[str] = []
    for extra in (data_dir / "z_i_dump.csv.gz", data_dir / "z_i_index.json.gz"):
        try:
            if extra.exists():
                extra.unlink()
                removed_extra.append(extra.name)
        except Exception:
            pass

    parts = []
    parts.append(f"WHOIS: {'cleared ' + str(whois_deleted) + ' rows' if whois_deleted >= 0 else 'error'}")
    if rkn_removed:
        parts.append(f"RKN: removed file {rkn_db_path.name}")
    elif rkn_fallback_clear:
        parts.append("RKN: file busy, tables cleared")
    else:
        parts.append("RKN: nothing to remove" if not rkn_error else f"RKN: error ({rkn_error})")
    if removed_extra:
        parts.append(f"extra: removed {', '.join(removed_extra)}")

    await reply_text_safe(update, context, "✅ Cache cleared: " + "; ".join(parts))

# ================= /add quick wizard =================

# Conversation states
ADD_WAIT_KEYWORDS = 1001
ADD_WAIT_INTERVAL = 1002

# Permissive domain validator
_DOMAIN_RE = re.compile(r"^[a-z0-9.-]+\.[a-z]{2,}$", re.IGNORECASE)

def _parse_domains(args: List[str]) -> List[str]:
    """Extract domains from args and ignore any flags (not implemented yet for advanced mode)."""
    out = []
    for a in args:
        if a.startswith("--"):
            continue
        d = a.strip().lower()
        if d and _DOMAIN_RE.match(d):
            out.append(d)
    # de-duplicate while preserving order
    seen = set()
    uniq = []
    for d in out:
        if d not in seen:
            uniq.append(d)
            seen.add(d)
    return uniq

def _default_checks(keywords_enabled: bool) -> dict:
    """Default checks for quick mode (as requested)."""
    return {
        "http_basic": True,
        "tls_cert": True,
        "ping": True,
        "rkn_block": True,
        "whois": True,
        "ip_blacklist": True,
        "ip_change": True,
        "keywords": bool(keywords_enabled),
    }

@requires_auth
async def cmd_add_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    /add <domain1> [domain2 ...]
    Quick wizard:
      1) Ask for keywords (space-separated) or /none to disable keyword check.
      2) Ask for interval in minutes (1, 5, 10, 30, 60, 120, 1440) or /none to disable auto checks.
    """
    if not context.args:
        await reply_text_safe(
            update,
            context,
            "Usage: /add <domain1> [domain2 ...]\n\n"
            "Quick wizard steps:\n"
            "  • Step 1 — enter keywords (space-separated), or send /none to skip keyword check.\n"
            "  • Step 2 — enter interval in minutes (one of: 1, 5, 10, 30, 60, 120, 1440), "
            "or send /none to disable auto checks for this domain."
        )
        return ConversationHandler.END

    # Advanced flags are not yet implemented in this step
    if any(a.startswith("--") for a in context.args):
        await reply_text_safe(
            update,
            context,
            "Advanced flags mode is not implemented yet. "
            "Run /add with just domain names to use the quick wizard."
        )
        return ConversationHandler.END

    domains = _parse_domains(context.args)
    if not domains:
        await reply_text_safe(update, context, "No valid domains found. Example: /add example.com")
        return ConversationHandler.END

    # Initialize wizard state
    context.user_data["add_state"] = {
        "domains": domains,
        "keywords": None,          # list[str] or []
        "keywords_enabled": None,  # bool
        "interval_minutes": None,  # int or 0
    }

    await reply_text_safe(
        update,
        context,
        "Step 1/2 — Keywords\n"
        "Enter keywords to require on the home page (space-separated), e.g.:  gtag metrika analytics\n"
        "Or send /none if keyword check is not required."
    )
    return ADD_WAIT_KEYWORDS

@requires_auth
async def cmd_add_keywords_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    st = context.user_data.get("add_state")
    if not st:
        await reply_text_safe(update, context, "Session expired. Please run /add again.")
        return ConversationHandler.END

    txt = (update.effective_message.text or "").strip()
    if not txt:
        await reply_text_safe(
            update,
            context,
            "Please enter keywords (space-separated), or send /none to skip keyword check."
        )
        return ADD_WAIT_KEYWORDS

    kws_raw = txt.split()
    seen = set()
    kws: List[str] = []
    for k in kws_raw:
        kk = k.strip()
        if kk and kk not in seen:
            kws.append(kk)
            seen.add(kk)

    st["keywords"] = kws
    st["keywords_enabled"] = True

    await reply_text_safe(
        update,
        context,
        "Step 2/2 — Interval\n"
        "Enter check interval in minutes (one of: 1, 5, 10, 30, 60, 120, 1440), "
        "or send /none to disable auto checks for this domain."
    )
    return ADD_WAIT_INTERVAL

@requires_auth
async def cmd_add_keywords_none(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """User sent /none at the keywords step."""
    st = context.user_data.get("add_state")
    if not st:
        await reply_text_safe(update, context, "Session expired. Please run /add again.")
        return ConversationHandler.END

    st["keywords"] = []
    st["keywords_enabled"] = False

    await reply_text_safe(
        update,
        context,
        "Step 2/2 — Interval\n"
        "Enter check interval in minutes (one of: 1, 5, 10, 30, 60, 120, 1440), "
        "or send /none to disable auto checks for this domain."
    )
    return ADD_WAIT_INTERVAL

_ALLOWED_INTERVALS = {1, 5, 10, 30, 60, 120, 1440}

@requires_auth
async def cmd_add_interval_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    st = context.user_data.get("add_state")
    if not st:
        await reply_text_safe(update, context, "Session expired. Please run /add again.")
        return ConversationHandler.END

    raw = (update.effective_message.text or "").strip()
    try:
        val = int(raw)
        if val not in _ALLOWED_INTERVALS:
            raise ValueError
    except Exception:
        await reply_text_safe(
            update,
            context,
            "Please enter one of: 1, 5, 10, 30, 60, 120, 1440 — or send /none to disable auto checks."
        )
        return ADD_WAIT_INTERVAL

    st["interval_minutes"] = val
    return await _finalize_add(update, context, st)

@requires_auth
async def cmd_add_interval_none(update: Update, context: ContextTypes.DEFAULT_TYPE):
    st = context.user_data.get("add_state")
    if not st:
        await reply_text_safe(update, context, "Session expired. Please run /add again.")
        return ConversationHandler.END

    st["interval_minutes"] = 0  # disable auto checks
    return await _finalize_add(update, context, st)

async def _finalize_add(update: Update, context: ContextTypes.DEFAULT_TYPE, st: dict):
    domains: List[str] = st["domains"]
    keywords: List[str] = st["keywords"] or []
    kw_enabled: bool = bool(st["keywords_enabled"])
    interval: int = int(st["interval_minutes"])

    checks_map = _default_checks(keywords_enabled=kw_enabled)

    added = []
    for d in domains:
        storage.add_domain(d)
        patch = {
            "checks": checks_map,
            "interval_minutes": interval,  # 0 disables auto-checks for this domain
        }
        if kw_enabled:
            patch["keywords"] = keywords
        storage.set_domain_override(d, patch)
        added.append(d)

    # Cleanup state
    context.user_data.pop("add_state", None)

    kw_str = "(disabled)" if not kw_enabled else (" ".join(keywords) or "(none)")
    interval_str = "disabled" if interval <= 0 else f"{interval} min"

    await reply_text_safe(
        update,
        context,
        "✅ Added domain(s): {doms}\n"
        "Checks: http_basic, tls_cert, ping, rkn_block, whois, ip_blacklist, ip_change{kw}\n"
        "Keywords: {kw_str}\n"
        "Auto-check interval: {interval_str}\n\n"
        "Use /check_domain <name> to run a manual check now."
        .format(
            doms=", ".join(added),
            kw=", keywords" if kw_enabled else "",
            kw_str=kw_str,
            interval_str=interval_str,
        )
    )
    return ConversationHandler.END

@requires_auth
async def cmd_add_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data.pop("add_state", None)
    await reply_text_safe(update, context, "Cancelled.")
    return ConversationHandler.END

# ================= Launch bot =================
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

    allowed_ids = _parse_allowed_user_ids()
    if allowed_ids:
        logger.info("Access limited to %d user(s)", len(allowed_ids))
    else:
        logger.warning("Access is open to all users; set TELEGRAM_ALLOWED_USER_IDS to restrict.")
    app.bot_data["allowed_user_ids"] = allowed_ids

    # Conversation for /add (quick wizard)
    add_conv = ConversationHandler(
        entry_points=[CommandHandler("add", requires_auth(cmd_add_start))],
        states={
            ADD_WAIT_KEYWORDS: [
                CommandHandler("none", requires_auth(cmd_add_keywords_none)),
                MessageHandler(filters.TEXT & ~filters.COMMAND, requires_auth(cmd_add_keywords_text)),
            ],
            ADD_WAIT_INTERVAL: [
                CommandHandler("none", requires_auth(cmd_add_interval_none)),
                MessageHandler(filters.TEXT & ~filters.COMMAND, requires_auth(cmd_add_interval_text)),
            ],
        },
        fallbacks=[CommandHandler("cancel", requires_auth(cmd_add_cancel))],
        name="sitewatcher:add_wizard",
        persistent=False,
    )
    app.add_handler(add_conv)

    # Other handlers
    app.add_handler(CommandHandler(["start", "help"], requires_auth(cmd_help)))
    app.add_handler(CommandHandler("add_domain", requires_auth(cmd_add_domain)))
    app.add_handler(CommandHandler("remove_domain", requires_auth(cmd_remove_domain)))
    app.add_handler(CommandHandler("list_domain", requires_auth(cmd_list_domain)))
    app.add_handler(CommandHandler("check_domain", requires_auth(cmd_check_domain)))
    app.add_handler(CommandHandler("check_all", requires_auth(cmd_check_all)))
    app.add_handler(CommandHandler("clear_cache", requires_auth(cmd_clear_cache)))
    app.add_handler(CommandHandler("cfg", requires_auth(cmd_cfg)))
    app.add_handler(CommandHandler("cfg_set", requires_auth(cmd_cfg_set)))
    app.add_handler(CommandHandler("cfg_unset", requires_auth(cmd_cfg_unset)))
    app.add_error_handler(on_error)

    # Scheduler jobs
    jq = app.job_queue
    sch = cfg.scheduler

    # Initialize alert deduper (use alerts.cooldown_sec, fallback to debounce_sec)
    global _ALERT_DEDUPER
    cooldown = int(getattr(cfg.alerts, "cooldown_sec", getattr(cfg.alerts, "debounce_sec", 300)) or 300)
    _ALERT_DEDUPER = AlertDeduper(cooldown_sec=cooldown)

    if getattr(sch, "enabled", True):
        # Warmup run
        if getattr(sch, "run_on_startup", True):
            jq.run_once(job_warmup, when=5)

        interval = max(60, int(sch.interval_minutes) * 60)
        jitter = max(0, int(getattr(sch, "jitter_seconds", 0)))
        first = random.randint(1, max(1, jitter)) if jitter > 0 else interval

        jq.run_repeating(
            job_periodic,
            interval=interval,
            first=first,
            name="sitewatcher:periodic_checks",
        )

        # Periodic flush of deduper summaries
        jq.run_repeating(
            _flush_alert_summaries_job,
            interval=max(60, cooldown),
            first=cooldown + random.randint(0, 5),
            name="sitewatcher:alerts_flush",
        )

        logger.info(
            "Scheduler enabled: every %s min (first in ~%s s); alerts policy=%s; alerts cooldown=%ss",
            sch.interval_minutes,
            first,
            getattr(cfg.alerts, "policy", "overall_change"),
            cooldown,
        )
    else:
        logger.info("Scheduler disabled by config")

    # Start polling
    app.run_polling()
