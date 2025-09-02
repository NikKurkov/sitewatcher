# sitewatcher/bot/handlers/cfg.py
from __future__ import annotations

import html

from telegram import Update
from telegram.ext import ContextTypes

from ... import storage
from ...config import AppConfig
from ...dispatcher import Dispatcher
from ..utils import requires_auth, _parse_bool, _parse_scalar_or_list, _format_preview_dict


@requires_auth(allow_while_busy=True)
async def cmd_cfg(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Show effective settings and DB override for a domain."""
    if not context.args:
        msg = getattr(update, "effective_message", None)
        if msg:
            await msg.reply_text("Usage: /cfg <domain>")
        return

    domain = context.args[0].strip().lower()
    owner_id = update.effective_user.id
    cfg: AppConfig = context.application.bot_data["cfg"]

    # Resolve effective settings via Dispatcher (owner-aware)
    async with Dispatcher(cfg) as d:
        settings = d._resolve(owner_id, domain)

    effective = {
        "checks": {k: getattr(settings.checks, k) for k in dir(settings.checks) if not k.startswith("_") and isinstance(getattr(settings.checks, k), (bool,))},
        "http_timeout_s": getattr(settings, "http_timeout_s", None),
        "latency_warn_ms": getattr(settings, "latency_crit_ms", None) and getattr(settings, "latency_warn_ms", None),
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


@requires_auth(allow_while_busy=True)
async def cmd_cfg_set(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Set a config override (typed) for a domain."""
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


@requires_auth(allow_while_busy=True)
async def cmd_cfg_unset(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Unset one key or the whole override for a domain."""
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
