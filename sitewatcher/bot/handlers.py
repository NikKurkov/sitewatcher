# /bot/handlers.py
from __future__ import annotations

import asyncio
import html
import logging
import re
import sqlite3
from pathlib import Path
from typing import List

from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    ConversationHandler,
    MessageHandler,
    filters,
)

from .. import storage
from ..config import AppConfig, resolve_settings
from ..dispatcher import Dispatcher
from .alerts import _status_bullet, _status_emoji, _overall_from_results, maybe_send_alert
from .utils import (
    requires_auth,
    safe_reply_html,
    _strip_cached_suffix,
    _parse_bool,
    _parse_scalar_or_list,
    _format_preview_dict,
    on_error,
)

logger = logging.getLogger("sitewatcher.bot")


HELP_TEXT = (
    "/add <domain1> [domain2 ...] — add domains via quick wizard (keywords + interval)\n"
    "/add_domain <name> — add a domain (legacy, no wizard)\n"
    "/remove <name> — remove a domain\n"
    "/list — list domains\n"
    "/check <name> [--force] — run checks for a domain (use cache unless --force)\n"
    "/check_all [--force] — run checks for all domains\n"
    "/cfg <name> — show effective config and DB override for a domain\n"
    "/cfg_set <name> <key> <value> — set override (e.g. checks.http_basic true, keywords \"a,b\")\n"
    "/cfg_unset <name> [key] — remove override key or whole override\n"
    "/clear_cache — clear RKN/WHOIS caches\n"
)

# Conversation states for /add
ADD_WAIT_KEYWORDS = 1001
ADD_WAIT_INTERVAL = 1002

# Permissive domain validator
_DOMAIN_RE = re.compile(r"^[a-z0-9.-]+\.[a-z]{2,}$", re.IGNORECASE)
DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$")

@requires_auth
async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    msg = getattr(update, "effective_message", None)
    if msg is not None:
        await msg.reply_text(HELP_TEXT)


@requires_auth
async def cmd_add_domain(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Add domain quickly; basic validation is applied."""
    msg = getattr(update, "effective_message", None)
    if not context.args:
        if msg:
            await msg.reply_text("Usage: /add_domain example.com")
        return

    owner_id = update.effective_user.id
    name = context.args[0].strip().lower()

    # Basic domain validation to prevent garbage input.
    if not DOMAIN_RE.match(name):
        if msg:
            await msg.reply_text("Invalid domain format. Expect like: example.com")
        return

    storage.add_domain(owner_id, name)
    if msg:
        await msg.reply_text(f"Added: <b>{html.escape(name)}</b>", parse_mode="HTML")


@requires_auth
async def cmd_remove_domain(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    msg = getattr(update, "effective_message", None)
    if not context.args:
        if msg:
            await msg.reply_text("Usage: /remove_domain example.com")
        return
    name = context.args[0].strip().lower()
    owner_id = update.effective_user.id
    ok = storage.remove_domain(owner_id, name)
    if msg:
        await msg.reply_text("Removed" if ok else "Not found")


@requires_auth
async def cmd_list_domain(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    owner_id = update.effective_user.id
    items: List[str] = storage.list_domains(owner_id)
    msg = getattr(update, "effective_message", None)
    if msg:
        await msg.reply_text("No domains yet" if not items else "\n".join(items))


async def _format_results(owner_id: int, domain: str, results, persist: bool = True) -> str:
    """Store clean history (optionally) and format a compact result text with emojis."""
    if persist:
        for r in results:
            storage.save_history(owner_id, domain, r.check, r.status, _strip_cached_suffix(r.message), r.metrics)

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
    """Default checks for quick mode."""
    return {
        "http_basic": True,
        "tls_cert": True,
        "ping": True,
        "rkn_block": True,
        "whois": True,
        "ip_blacklist": True,
        "ip_change": True,
        "keywords": bool(keywords_enabled),
        # отключаем ports в автосборке для новых доменов
        "ports": False,
    }


@requires_auth
async def cmd_add_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    /add <domain1> [domain2 ...]
    Quick wizard:
      1) Ask for keywords (space-separated) or /none to disable keyword check.
      2) Ask for interval in minutes (1, 5, 10, 30, 60, 120, 1440) or /none to disable auto checks.
    """
    msg = getattr(update, "effective_message", None)
    if not context.args:
        if msg:
            await msg.reply_text(
                "Usage: /add <domain1> [domain2 ...]\n\n"
                "Quick wizard steps:\n"
                "  • Step 1 — enter keywords (space-separated), or send /none to skip keyword check.\n"
                "  • Step 2 — enter interval in minutes (one of: 1, 5, 10, 30, 60, 120, 1440), "
                "or send /none to disable auto checks for this domain."
            )
        return ConversationHandler.END

    if any(a.startswith("--") for a in context.args):
        if msg:
            await msg.reply_text(
                "Advanced flags mode is not implemented yet. "
                "Run /add with just domain names to use the quick wizard."
            )
        return ConversationHandler.END

    domains = _parse_domains(context.args)
    if not domains:
        if msg:
            await msg.reply_text("No valid domains found. Example: /add example.com")
        return ConversationHandler.END

    context.user_data["add_state"] = {
        "domains": domains,
        "keywords": None,          # list[str] or []
        "keywords_enabled": None,  # bool
        "interval_minutes": None,  # int or 0
    }

    if msg:
        await msg.reply_text(
            "Step 1/2 — Keywords\n"
            "Enter keywords to require on the home page (space-separated), e.g.:  gtag metrika analytics\n"
            "Or send /none if keyword check is not required."
        )
    return ADD_WAIT_KEYWORDS


@requires_auth
async def cmd_add_keywords_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    st = context.user_data.get("add_state")
    msg = getattr(update, "effective_message", None)
    if not st:
        if msg:
            await msg.reply_text("Session expired. Please run /add again.")
        return ConversationHandler.END

    txt = (msg.text or "").strip() if msg else ""
    if not txt:
        if msg:
            await msg.reply_text(
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

    if msg:
        await msg.reply_text(
            "Step 2/2 — Interval\n"
            "Enter check interval in minutes (one of: 1, 5, 10, 30, 60, 120, 1440), "
            "or send /none to disable auto checks for this domain."
        )
    return ADD_WAIT_INTERVAL


@requires_auth
async def cmd_add_keywords_none(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """User sent /none at the keywords step."""
    st = context.user_data.get("add_state")
    msg = getattr(update, "effective_message", None)
    if not st:
        if msg:
            await msg.reply_text("Session expired. Please run /add again.")
        return ConversationHandler.END

    st["keywords"] = []
    st["keywords_enabled"] = False

    if msg:
        await msg.reply_text(
            "Step 2/2 — Interval\n"
            "Enter check interval in minutes (one of: 1, 5, 10, 30, 60, 120, 1440), "
            "or send /none to disable auto checks for this domain."
        )
    return ADD_WAIT_INTERVAL


_ALLOWED_INTERVALS = {1, 5, 10, 30, 60, 120, 1440}


@requires_auth
async def cmd_add_interval_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    st = context.user_data.get("add_state")
    msg = getattr(update, "effective_message", None)
    if not st:
        if msg:
            await msg.reply_text("Session expired. Please run /add again.")
        return ConversationHandler.END

    raw = (msg.text or "").strip() if msg else ""
    try:
        val = int(raw)
        if val not in _ALLOWED_INTERVALS:
            raise ValueError
    except Exception:
        if msg:
            await msg.reply_text(
                "Please enter one of: 1, 5, 10, 30, 60, 120, 1440 — or send /none to disable auto checks."
            )
        return ADD_WAIT_INTERVAL

    st["interval_minutes"] = val
    return await _finalize_add(update, context, st)


@requires_auth
async def cmd_add_interval_none(update: Update, context: ContextTypes.DEFAULT_TYPE):
    st = context.user_data.get("add_state")
    msg = getattr(update, "effective_message", None)
    if not st:
        if msg:
            await msg.reply_text("Session expired. Please run /add again.")
        return ConversationHandler.END

    st["interval_minutes"] = 0  # disable auto checks
    return await _finalize_add(update, context, st)


async def _finalize_add(update: Update, context: ContextTypes.DEFAULT_TYPE, st: dict):
    msg = getattr(update, "effective_message", None)

    domains: List[str] = st["domains"]
    keywords: List[str] = st["keywords"] or []
    kw_enabled: bool = bool(st["keywords_enabled"])
    interval: int = int(st["interval_minutes"])
    owner_id = update.effective_user.id
    checks_map = _default_checks(keywords_enabled=kw_enabled)

    added = []
    for d in domains:
        storage.add_domain(owner_id, d)
        patch = {
            "checks": checks_map,
            "interval_minutes": interval,
        }
        if kw_enabled:
            patch["keywords"] = keywords
        storage.set_domain_override(owner_id, d, patch)
        added.append(d)

    # Cleanup state
    context.user_data.pop("add_state", None)

    kw_str = "(disabled)" if not kw_enabled else (" ".join(keywords) or "(none)")
    interval_str = "disabled" if interval <= 0 else f"{interval} min"

    if msg:
        await msg.reply_text(
            "✅ Added domain(s): {doms}\n"
            "Checks: http_basic, tls_cert, ping, rkn_block, whois, ip_blacklist, ip_change{kw}\n"
            "Keywords: {kw_str}\n"
            "Auto-check interval: {interval_str}\n\n"
            "Use /check <name> to run a manual check now."
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
    msg = getattr(update, "effective_message", None)
    if msg:
        await msg.reply_text("Cancelled.")
    return ConversationHandler.END


@requires_auth
async def cmd_cfg(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args:
        msg = getattr(update, "effective_message", None)
        if msg:
            await msg.reply_text("Usage: /cfg <domain>")
        return

    domain = context.args[0].strip().lower()
    owner_id = update.effective_user.id
    cfg: AppConfig = context.application.bot_data["cfg"]

    # Get effective settings via Dispatcher.resolve (owner-aware)
    async with Dispatcher(cfg) as d:
        settings = d._resolve(owner_id, domain)  # ожидается owner-aware реализация

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

    override = storage.get_domain_override(owner_id, domain)

    text = (
        f"<b>{html.escape(domain)}</b>\n\n"
        "<b>Effective:</b>\n"
        f"<pre>{html.escape(_format_preview_dict(effective))}</pre>\n\n"
        "<b>Override (DB):</b>\n"
        f"{('<pre>' + html.escape(_format_preview_dict(override)) + '</pre>') if override else '— none —'}"
    )

    msg = getattr(update, "effective_message", None)
    if msg is not None:
        await msg.reply_html(text, disable_web_page_preview=True)
    else:
        chat = getattr(update, "effective_chat", None)
        if chat is not None:
            await context.bot.send_message(
                chat_id=chat.id,
                text=text,
                parse_mode="HTML",
                disable_web_page_preview=True,
            )
        else:
            logger.warning("cmd_cfg: nowhere to reply (no effective_message/effective_chat)")


@requires_auth
async def cmd_cfg_set(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    msg = getattr(update, "effective_message", None)
    if len(context.args) < 3:
        if msg:
            await msg.reply_text(
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
    owner_id = update.effective_user.id

    patch: dict = {}

    if key.startswith("checks."):
        check_name = key.split(".", 1)[1]
        b = _parse_bool(val)
        if b is None:
            if msg:
                await msg.reply_text("For checks.* use true/false")
            return
        patch = {"checks": {check_name: b}}
    elif key in ("http_timeout_s", "latency_warn_ms", "latency_crit_ms", "tls_warn_days"):
        try:
            iv = int(val)
        except ValueError:
            if msg:
                await msg.reply_text(f"{key} must be an integer")
            return
        patch = {key: iv}
    elif key in ("keywords", "ports"):
        v = _parse_scalar_or_list(val)
        if v is None:
            if msg:
                await msg.reply_text(f"{key}: empty value")
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
            if msg:
                await msg.reply_text("interval_minutes must be integer (0 disables auto checks)")
            return
        patch = {"interval_minutes": iv}
    else:
        if msg:
            await msg.reply_text("Unknown key. Use: checks.<name>, http_timeout_s, latency_warn_ms, latency_crit_ms, tls_warn_days, keywords, ports, proxy, interval_minutes")
        return

    merged = storage.set_domain_override(owner_id, domain, patch)
    if msg:
        await msg.reply_text(
            "✅ Saved.\nCurrent override:\n<pre>{}</pre>".format(html.escape(_format_preview_dict(merged))),
            parse_mode="HTML",
            disable_web_page_preview=True,
        )


@requires_auth
async def cmd_cfg_unset(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    msg = getattr(update, "effective_message", None)
    if not context.args:
        if msg:
            await msg.reply_text("Usage: /cfg_unset <domain> [key]")
        return
    domain = context.args[0].strip().lower()
    key = context.args[1].strip() if len(context.args) > 1 else None
    owner_id = update.effective_user.id

    storage.unset_domain_override(owner_id, domain, key)

    if msg:
        if key:
            txt = f"🗑 Removed key <code>{html.escape(key)}</code> for <b>{html.escape(domain)}</b>."
        else:
            txt = f"🗑 Removed entire override for <b>{html.escape(domain)}</b>."
        await msg.reply_html(txt)


@requires_auth
async def cmd_check_domain(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args:
        await update.message.reply_text("Usage: /check example.com")
        return

    owner_id = update.effective_user.id
    raw = context.args[0].strip().lower()
    force = raw in ("--force", "-f", "force")
    name = (context.args[1] if force and len(context.args) > 1 else raw).strip().lower()

    cfg: AppConfig = context.application.bot_data["cfg"]

    # Если домен принадлежит пользователю — обычный режим (пишем историю, алерты и т.д.)
    if storage.domain_exists(owner_id, name):
        async with Dispatcher(cfg) as d:
            results = await d.run_for(owner_id, name, use_cache=not force)
            text = await _format_results(owner_id, name, results, persist=True)
        await safe_reply_html(update.message, text)
        await maybe_send_alert(update, context, owner_id, name, results)
        return

    # Эпизодический режим: домена нет у пользователя → без сохранения и без алертов.
    async with Dispatcher(cfg) as d:
        # Базовые настройки из конфигурации
        settings = resolve_settings(cfg, name)
        # Принудительно выключаем keywords для таких разовых проверок
        try:
            settings.checks.keywords = False
        except Exception:
            pass
        # Собираем проверки и запускаем их параллельно
        checks = d._build_checks(settings)
        results = await asyncio.gather(*(chk.run() for chk in checks))

    text = await _format_results(owner_id, name, results, persist=False)
    await safe_reply_html(update.message, text)
    # Никаких maybe_send_alert в эпизодическом режиме


@requires_auth
async def cmd_check_all(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    msg = getattr(update, "effective_message", None)
    cfg: AppConfig = context.application.bot_data["cfg"]
    owner_id = update.effective_user.id
    names = storage.list_domains(owner_id)
    if not names:
        if msg:
            await msg.reply_text("No domains in DB")
        return

    force = False
    if context.args:
        arg0 = (context.args[0] or "").lower()
        if arg0 in ("--force", "-f", "force"):
            force = True

    parts = []
    async with Dispatcher(cfg) as d:
        for name in names:
            results = await d.run_for(owner_id, name, use_cache=not force)
            parts.append(await _format_results(owner_id, name, results, persist=True))
            await maybe_send_alert(update, context, owner_id, name, results)

    if msg:
        await safe_reply_html(msg, "\n\n".join(parts))


@requires_auth
async def cmd_clear_cache(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    cfg: AppConfig = context.application.bot_data["cfg"]
    msg = getattr(update, "effective_message", None)

    # 1) WHOIS cache (table whois_state in main DB)
    try:
        whois_deleted = storage.clear_whois_cache()
    except Exception as e:
        whois_deleted = -1
        logger.exception("clear_whois_cache failed: %s", e)

    # 2) RKN index (SQLite file) + legacy artifacts
    # base_dir -> корень пакета (на уровень выше /bot)
    base_dir = Path(__file__).resolve().parents[1]
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

    if msg:
        await msg.reply_text("✅ Cache cleared: " + "; ".join(parts))


def register_handlers(app: Application) -> None:
    """Wire up all handlers on the given Application."""
    # Conversation for /add (quick wizard)
    add_conv = ConversationHandler(
        entry_points=[CommandHandler("add", cmd_add_start)],
        states={
            ADD_WAIT_KEYWORDS: [
                CommandHandler("none", cmd_add_keywords_none),
                MessageHandler(filters.TEXT & ~filters.COMMAND, cmd_add_keywords_text),
            ],
            ADD_WAIT_INTERVAL: [
                CommandHandler("none", cmd_add_interval_none),
                MessageHandler(filters.TEXT & ~filters.COMMAND, cmd_add_interval_text),
            ],
        },
        fallbacks=[CommandHandler("cancel", cmd_add_cancel)],
        name="sitewatcher:add_wizard",
        persistent=False,
    )
    app.add_handler(add_conv)

    # Other handlers
    app.add_handler(CommandHandler(["start", "help"], cmd_help))
    app.add_handler(CommandHandler("add_domain", cmd_add_domain))
    app.add_handler(CommandHandler("remove", cmd_remove_domain))
    app.add_handler(CommandHandler("list", cmd_list_domain))
    app.add_handler(CommandHandler("check", cmd_check_domain))
    app.add_handler(CommandHandler("check_all", cmd_check_all))
    app.add_handler(CommandHandler("clear_cache", cmd_clear_cache))
    app.add_handler(CommandHandler("cfg", cmd_cfg))
    app.add_handler(CommandHandler("cfg_set", cmd_cfg_set))
    app.add_handler(CommandHandler("cfg_unset", cmd_cfg_unset))

    # Global error handler
    app.add_error_handler(on_error)
