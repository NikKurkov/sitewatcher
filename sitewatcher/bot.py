# sitewatcher/bot.py
from __future__ import annotations

import asyncio
import functools
import html
import logging
import os
import random
import re
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, List, NamedTuple, Optional

from telegram import Update
from telegram.error import NetworkError
from telegram.ext import Application, CommandHandler, ContextTypes
from telegram.request import HTTPXRequest

from . import storage
from .config import AppConfig, get_bot_token_from_env
from .dispatcher import Dispatcher

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
# If you have a centralized logging setup, remove basicConfig and configure there.
logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logger = logging.getLogger("sitewatcher.bot")

# -----------------------------------------------------------------------------
# Constants / Help
# -----------------------------------------------------------------------------
HELP_TEXT = (
    "/add_domain <name.tld> — add a domain\n"
    "/remove_domain <name.tld> — remove a domain\n"
    "/list_domain — list domains\n"
    "/check_domain <name.tld> — check one domain\n"
    "/check_all — check all domains\n"
    "/clear_cache — clear RKN/WHOIS caches\n"
    "/cfg <name.tld> — show effective config and DB override\n"
    "/cfg_set <name.tld> <key> <value> — set per-domain override\n"
    "/cfg_unset <name.tld> [key] — remove per-domain override or a specific key\n"
)

STATUS_TO_WEIGHT = {"CRIT": 2, "WARN": 1, "UNKNOWN": 1, "OK": 0}
STATUS_TO_EMOJI = {"CRIT": "🔴", "WARN": "🟡", "OK": "🟢", "UNKNOWN": "⚪"}

# -----------------------------------------------------------------------------
# Anti-storm / cooldown deduper
# -----------------------------------------------------------------------------
class _AlertKey(NamedTuple):
    """Unique dedupe key for the alert stream."""
    domain: str
    level: str  # "CRIT" | "WARN" | "OK" | "UNKNOWN"


@dataclass
class _AlertRecord:
    """Internal deduper record."""
    last_sent_at: float = 0.0
    suppressed: int = 0
    last_text: str = ""


class AlertDeduper:
    """Suppress repeated alerts for (domain, overall) during a cooldown window."""

    def __init__(self, cooldown_sec: int) -> None:
        self.cooldown = max(0, int(cooldown_sec))
        self._state: dict[_AlertKey, _AlertRecord] = {}

    def should_send_now(
        self, key: _AlertKey, text: str, now: Optional[float] = None
    ) -> tuple[bool, Optional[str]]:
        now = now or time.time()
        rec = self._state.get(key)
        if rec is None:
            rec = _AlertRecord()
            self._state[key] = rec

        # allowed to send
        if rec.last_sent_at == 0 or (now - rec.last_sent_at) >= self.cooldown:
            prefix = (
                f"(suppressed {rec.suppressed} similar event(s) in the last {self.cooldown}s)\n"
                if rec.suppressed > 0
                else ""
            )
            rec.last_sent_at = now
            rec.last_text = text
            rec.suppressed = 0
            return True, (prefix + text)

        # suppress this one
        rec.suppressed += 1
        rec.last_text = text
        return False, None

    def flush_summaries(self, max_batch: int = 20) -> list[tuple[_AlertKey, str]]:
        """Return summary messages for keys that crossed cooldown since last send."""
        out: list[tuple[_AlertKey, str]] = []
        now = time.time()
        for key, rec in list(self._state.items()):
            if rec.suppressed > 0 and (now - rec.last_sent_at) >= self.cooldown:
                msg = f"{rec.suppressed} repeated event(s) in {self.cooldown}s for {key.domain} [{key.level}]"
                rec.suppressed = 0
                rec.last_sent_at = now
                out.append((key, msg))
                if len(out) >= max_batch:
                    break
        return out


_ALERT_DEDUPER: AlertDeduper | None = None


async def _flush_alert_summaries_job(context: ContextTypes.DEFAULT_TYPE) -> None:
    """Periodic job to emit deduper summaries."""
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
            await context.bot.send_message(
                chat_id=chat_id, text=summary, disable_web_page_preview=True
            )
        except Exception as e:
            logger.warning("failed to send summary: %s", e)

# -----------------------------------------------------------------------------
# Status helpers
# -----------------------------------------------------------------------------
def _status_weight(s: str) -> int:
    return STATUS_TO_WEIGHT.get((s or "").upper(), 0)


def _status_emoji(s: str) -> str:
    return STATUS_TO_EMOJI.get((s or "").upper(), "⚪")


def _status_bullet(s: str) -> str:
    s = (s or "").upper()
    if s == "CRIT":
        return "🔺"
    if s == "WARN":
        return "🔸"
    return "•"


def _overall_from_results(results) -> str:
    """Compute overall domain status from individual check results."""
    worst = 0
    for r in results:
        st = getattr(r.status, "value", str(r.status))
        worst = max(worst, _status_weight(st))
    return {2: "CRIT", 1: "WARN", 0: "OK"}[worst]

# -----------------------------------------------------------------------------
# Auth
# -----------------------------------------------------------------------------
def _parse_allowed_user_ids() -> set[int] | None:
    """Read allowed Telegram user IDs from env."""
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
    """Decorator: block handler unless user ID is allowed (if allowlist is set)."""

    @functools.wraps(func)
    async def wrapper(update, context, *args, **kwargs):
        allowed: set[int] | None = context.application.bot_data.get("allowed_user_ids")
        if allowed is not None:
            uid = update.effective_user.id if update.effective_user else None
            if uid is None or uid not in allowed:
                if getattr(update, "message", None):
                    await update.message.reply_text("⛔️ Access denied.")
                elif getattr(update, "callback_query", None):
                    await update.callback_query.answer("Access denied", show_alert=True)
                return
        return await func(update, context, *args, **kwargs)

    return wrapper

# -----------------------------------------------------------------------------
# Common utils
# -----------------------------------------------------------------------------
async def on_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Global error handler to avoid hard crashes on handler exceptions."""
    logger.exception("Unhandled error", exc_info=context.error)
    if isinstance(update, Update) and update.effective_message:
        await update.effective_message.reply_text(
            "Oops, something went wrong. Please try again."
        )


async def safe_reply_html(message, text: str, retries: int = 3) -> None:
    """Reply with HTML and retry on transient Telegram network errors."""
    delay = 1.0
    for attempt in range(1, retries + 1):
        try:
            await message.reply_html(text)
            return
        except NetworkError as e:
            if attempt == retries:
                raise
            logger.warning(
                "Telegram send failed (attempt %d/%d): %s", attempt, retries, e
            )
            await asyncio.sleep(delay)
            delay *= 2


def _strip_cached_suffix(msg: str) -> str:
    """Remove repeated trailing '[cached Xm]' chunks from a message."""
    return re.sub(r"(?:\s*\[cached\s+\d+m\])+$", "", msg or "", flags=re.I)


def _resolve_alert_chat_id(
    context: ContextTypes.DEFAULT_TYPE, update: Update | None = None, cfg: AppConfig | None = None
) -> int | None:
    """Resolve alert chat target in priority: cfg.alerts.chat_id -> env -> current chat."""
    cfg = cfg or context.application.bot_data.get("cfg")
    chat_id = (
        (getattr(cfg.alerts, "chat_id", None) if cfg else None)
        or (int(os.getenv("TELEGRAM_ALERT_CHAT_ID")) if os.getenv("TELEGRAM_ALERT_CHAT_ID") else None)
        or (update.effective_chat.id if update and update.effective_chat else None)
    )
    return chat_id


def _parse_bool(val: str) -> bool | None:
    """Parse loose boolean user input."""
    v = (val or "").strip().lower()
    if v in ("1", "true", "yes", "on", "enable", "+"):
        return True
    if v in ("0", "false", "no", "off", "disable", "-"):
        return False
    return None


def _parse_scalar_or_list(val: str) -> list[str] | str | None:
    """Parse string-or-comma-list from input value."""
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
    """Pretty-print nested dict as indented YAML-like structure (plain text)."""
    pad = " " * indent
    lines: list[str] = []
    for k, v in d.items():
        if isinstance(v, dict):
            lines.append(f"{pad}{k}:")
            lines.append(_format_preview_dict(v, indent + 2))
        else:
            lines.append(f"{pad}{k}: {v}")
    return "\n".join(lines) if lines else (pad + "-")

# -----------------------------------------------------------------------------
# Commands: basic CRUD
# -----------------------------------------------------------------------------
async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(HELP_TEXT)


async def cmd_add_domain(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args:
        await update.message.reply_text("Usage: /add_domain example.com")
        return
    name = context.args[0].strip().lower()
    storage.add_domain(name)
    await update.message.reply_text(f"Added: {name}")


async def cmd_remove_domain(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args:
        await update.message.reply_text("Usage: /remove_domain example.com")
        return
    name = context.args[0].strip().lower()
    ok = storage.remove_domain(name)
    await update.message.reply_text("Removed" if ok else "Not found")


async def cmd_list_domain(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    items: List[str] = storage.list_domains()
    await update.message.reply_text("No domains" if not items else "\n".join(items))

# -----------------------------------------------------------------------------
# Result formatting
# -----------------------------------------------------------------------------
async def _format_results(domain: str, results) -> str:
    """Format domain results for Telegram and persist clean history messages."""
    for r in results:
        storage.save_history(
            domain, r.check, r.status, _strip_cached_suffix(r.message), r.metrics
        )

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
    """Return check names that are due now by schedules vs. last history timestamps."""
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

# -----------------------------------------------------------------------------
# Scheduler jobs
# -----------------------------------------------------------------------------
async def _run_checks_for_all_domains(context, warmup: bool) -> None:
    """Run due checks for all domains and maybe send alerts."""
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
                results = await d.run_for(name, only_checks=due, use_cache=False)
                for r in results:
                    storage.save_history(
                        name, r.check, r.status, _strip_cached_suffix(r.message), r.metrics
                    )
                await maybe_send_alert(None, context, name, results)
            except Exception as e:
                logger.exception("scheduler: %s failed: %s", name, e)


async def job_warmup(context: ContextTypes.DEFAULT_TYPE) -> None:
    """First run after startup to establish baseline alert states without spamming."""
    await _run_checks_for_all_domains(context, warmup=True)


async def job_periodic(context: ContextTypes.DEFAULT_TYPE) -> None:
    """Periodic run that respects per-check schedules."""
    await _run_checks_for_all_domains(context, warmup=False)

# -----------------------------------------------------------------------------
# Alerting
# -----------------------------------------------------------------------------
async def maybe_send_alert(update, context, domain: str, results) -> None:
    """Decide if an alert should be sent and send it if required."""
    cfg: AppConfig = context.application.bot_data["cfg"]
    if not getattr(cfg.alerts, "enabled", True):
        return

    now = datetime.now(timezone.utc)
    overall = _overall_from_results(results)

    row = storage.get_alert_state(domain)
    prev_overall = row["last_overall"] if row else None
    policy = getattr(cfg.alerts, "policy", "overall_change")

    # restore last_sent_at (iso -> datetime) for debounce/cooldown
    last_sent_at: datetime | None = None
    if row and row["last_sent_at"]:
        try:
            last_sent_at = datetime.fromisoformat(row["last_sent_at"])
        except Exception:
            last_sent_at = None

    # baseline: first observation only sets the state
    if prev_overall is None:
        storage.upsert_alert_state(domain, overall, None)
        return

    # policy gate
    if policy == "worsen_only":
        if _status_weight(overall) <= _status_weight(prev_overall):
            storage.upsert_alert_state(domain, overall, row["last_sent_at"] if row else None)
            return
    elif policy == "overall_change":
        if overall == prev_overall:
            return
    elif policy == "all":
        pass  # always send (subject to cooldown below)
    else:
        # unknown value: fall back to "overall_change"
        if overall == prev_overall:
            return

    # cooldown (prefer alerts.cooldown_sec, fall back to alerts.debounce_sec)
    cooldown = int(getattr(cfg.alerts, "cooldown_sec", getattr(cfg.alerts, "debounce_sec", 0)) or 0)
    if last_sent_at is not None and (now - last_sent_at) < timedelta(seconds=cooldown):
        storage.upsert_alert_state(domain, overall, row["last_sent_at"])
        return

    # build alert body
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

    # resolve target
    alert_chat_id = _resolve_alert_chat_id(context, update=update, cfg=cfg)
    if not alert_chat_id:
        storage.upsert_alert_state(domain, overall, None)
        return

    # extra cooldown: dedupe same (domain, overall)
    key = _AlertKey(domain=domain, level=overall)
    global _ALERT_DEDUPER
    if _ALERT_DEDUPER is not None:
        send_now, maybe_text = _ALERT_DEDUPER.should_send_now(key, text)
        if not send_now:
            storage.upsert_alert_state(domain, overall, row["last_sent_at"] if row else None)
            return
        if maybe_text:
            text = maybe_text

    # send
    try:
        await context.bot.send_message(
            chat_id=alert_chat_id, text=text, parse_mode="HTML", disable_web_page_preview=True
        )
        storage.upsert_alert_state(domain, overall, now.isoformat())
    except Exception as e:
        logger.exception("alert send failed for %s: %s", domain, e)
        storage.upsert_alert_state(domain, overall, last_sent_at.isoformat() if last_sent_at else None)

# -----------------------------------------------------------------------------
# Per-domain config commands
# -----------------------------------------------------------------------------
@requires_auth
async def cmd_cfg(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Show effective settings (defaults + domain + DB override) and current DB override blob."""
    if not context.args:
        await update.message.reply_text("Usage: /cfg <domain>")
        return
    domain = context.args[0].strip().lower()
    cfg: AppConfig = context.application.bot_data["cfg"]

    # Resolve effective settings via Dispatcher (uses DB overrides inside)
    async with Dispatcher(cfg) as d:
        settings = d._resolve(domain)  # internal but OK in our codebase

    effective = {
        "checks": {
            k: getattr(settings.checks, k)
            for k in dir(settings.checks)
            if not k.startswith("_") and isinstance(getattr(settings.checks, k), (bool,))
        },
        "http_timeout_s": getattr(settings, "http_timeout_s", None),
        "latency_warn_ms": getattr(settings, "latency_warn_ms", None),
        "latency_crit_ms": getattr(settings, "latency_crit_ms", None),
        "tls_warn_days": getattr(settings, "tls_warn_days", None),
        "proxy": getattr(settings, "proxy", None),
        "keywords": getattr(settings, "keywords", None),
        "ports": getattr(settings, "ports", None),
    }

    override = storage.get_domain_override(domain)

    text = (
        f"<b>{html.escape(domain)}</b>\n\n"
        "<b>Effective settings:</b>\n"
        f"<pre>{html.escape(_format_preview_dict(effective))}</pre>\n\n"
        "<b>DB override:</b>\n"
        f"{('<pre>' + html.escape(_format_preview_dict(override)) + '</pre>') if override else '— none —'}"
    )
    await update.message.reply_html(text, disable_web_page_preview=True)


@requires_auth
async def cmd_cfg_set(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Set a per-domain override key."""
    if len(context.args) < 3:
        await update.message.reply_text(
            "Usage: /cfg_set <domain> <key> <value>\n"
            "Examples:\n"
            "  /cfg_set example.com checks.http_basic true\n"
            "  /cfg_set example.com http_timeout_s 7\n"
            "  /cfg_set example.com keywords \"foo,bar,baz\"\n"
            "  /cfg_set example.com ports \"80,443,22\"\n"
        )
        return

    domain = context.args[0].strip().lower()
    key = context.args[1].strip()
    val = " ".join(context.args[2:]).strip()

    patch: dict = {}

    if key.startswith("checks."):
        check_name = key.split(".", 1)[1]
        b = _parse_bool(val)
        if b is None:
            await update.message.reply_text("Value for checks.* must be true/false.")
            return
        patch = {"checks": {check_name: b}}

    elif key in ("http_timeout_s", "latency_warn_ms", "latency_crit_ms", "tls_warn_days"):
        try:
            iv = int(val)
        except ValueError:
            await update.message.reply_text(f"{key} must be an integer.")
            return
        patch = {key: iv}

    elif key in ("keywords", "ports"):
        v = _parse_scalar_or_list(val)
        if v is None:
            await update.message.reply_text(f"{key}: empty value.")
            return
        if isinstance(v, str):
            v = [v]
        patch = {key: v}

    elif key == "proxy":
        v = val.strip()
        patch = {"proxy": None} if v.lower() in ("none", "-", "null", "off") else {"proxy": v}

    else:
        await update.message.reply_text(
            "Unknown key. Supported: checks.<name>, http_timeout_s, latency_warn_ms, "
            "latency_crit_ms, tls_warn_days, keywords, ports, proxy"
        )
        return

    merged = storage.set_domain_override(domain, patch)
    await update.message.reply_text(
        "✅ Saved.\nCurrent override:\n<pre>{}</pre>".format(
            html.escape(_format_preview_dict(merged))
        ),
        parse_mode="HTML",
        disable_web_page_preview=True,
    )


@requires_auth
async def cmd_cfg_unset(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Unset a per-domain override key or the whole override."""
    if not context.args:
        await update.message.reply_text("Usage: /cfg_unset <domain> [key]")
        return

    domain = context.args[0].strip().lower()
    key = context.args[1].strip() if len(context.args) > 1 else None

    storage.unset_domain_override(domain, key)

    if key:
        txt = f"🗑 Removed key <code>{html.escape(key)}</code> for <b>{html.escape(domain)}</b>."
    else:
        txt = f"🗑 Removed full override for <b>{html.escape(domain)}</b>."
    await update.message.reply_html(txt)

# -----------------------------------------------------------------------------
# Check commands
# -----------------------------------------------------------------------------
async def cmd_check_domain(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args:
        await update.message.reply_text("Usage: /check_domain example.com")
        return

    # support flag --force/-f to bypass cache
    raw = context.args[0].strip().lower()
    force = raw in ("--force", "-f", "force")
    name = (context.args[1] if force and len(context.args) > 1 else raw).strip().lower()

    cfg: AppConfig = context.application.bot_data["cfg"]
    async with Dispatcher(cfg) as d:
        results = await d.run_for(name, use_cache=not force)
        text = await _format_results(name, results)

    await safe_reply_html(update.message, text)
    await maybe_send_alert(update, context, name, results)


async def cmd_check_all(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    cfg: AppConfig = context.application.bot_data["cfg"]
    names = storage.list_domains()
    if not names:
        await update.message.reply_text("No domains in DB.")
        return

    force = False
    if context.args:
        arg0 = (context.args[0] or "").lower()
        if arg0 in ("--force", "-f", "force"):
            force = True

    parts: list[str] = []
    async with Dispatcher(cfg) as d:
        for name in names:
            results = await d.run_for(name, use_cache=not force)
            parts.append(await _format_results(name, results))
            await maybe_send_alert(update, context, name, results)

    await safe_reply_html(update.message, "\n\n".join(parts))

# -----------------------------------------------------------------------------
# Cache maintenance
# -----------------------------------------------------------------------------
async def cmd_clear_cache(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Clear WHOIS cache (DB table) and RKN index (SQLite file)."""
    cfg: AppConfig = context.application.bot_data["cfg"]

    # 1) WHOIS cache (table whois_state in main DB)
    try:
        whois_deleted = storage.clear_whois_cache()
    except Exception as e:
        whois_deleted = -1
        logger.exception("clear_whois_cache failed: %s", e)

    # 2) RKN SQLite index (file) + old artifacts
    base_dir = Path(__file__).resolve().parent
    data_dir = base_dir / "data"
    rkn_db_path = (
        Path(cfg.rkn.index_db_path)
        if getattr(cfg.rkn, "index_db_path", None)
        else (data_dir / "z_i_index.db")
    )

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
    parts.append(
        f"WHOIS: {'cleared ' + str(whois_deleted) + ' rows' if whois_deleted >= 0 else 'error'}"
    )
    if rkn_removed:
        parts.append(f"RKN: removed file {rkn_db_path.name}")
    elif rkn_fallback_clear:
        parts.append("RKN: file busy, tables cleared")
    else:
        parts.append("RKN: nothing to remove" if not rkn_error else f"RKN: error ({rkn_error})")
    if removed_extra:
        parts.append(f"extra: removed {', '.join(removed_extra)}")

    await update.message.reply_text("✅ The cache is cleared: " + "; ".join(parts))

# -----------------------------------------------------------------------------
# Bot entrypoint
# -----------------------------------------------------------------------------
def run_bot(cfg: AppConfig) -> None:
    """Build and start Telegram bot with scheduler jobs."""
    token = get_bot_token_from_env()
    if not token:
        raise RuntimeError("TELEGRAM_TOKEN is not set")

    request = HTTPXRequest(
        http_version="1.1",          # stick to HTTP/1.1 for stability
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

    # Handlers
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

    # Scheduler
    jq = app.job_queue
    sch = cfg.scheduler

    # Anti-storm deduper (prefer alerts.cooldown_sec, fallback to alerts.debounce_sec)
    global _ALERT_DEDUPER
    cooldown = int(getattr(cfg.alerts, "cooldown_sec", getattr(cfg.alerts, "debounce_sec", 300)) or 300)
    _ALERT_DEDUPER = AlertDeduper(cooldown_sec=cooldown)

    if getattr(sch, "enabled", True):
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

    # Start bot
    app.run_polling()
