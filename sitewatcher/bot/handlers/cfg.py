from __future__ import annotations

import html
import logging
from copy import deepcopy

from telegram import Update
from telegram.ext import ContextTypes

from ... import storage
from ...config import AppConfig, ChecksModel, resolve_settings, validate_domain_override, validation_message
from ...utils.domains import normalize_domain
from ...utils.secrets import redact_configuration
from ..utils import _parse_bool, _parse_list, _format_preview_dict, safe_reply_html

log = logging.getLogger(__name__)


async def cmd_cfg(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Show effective config for a domain (defaults + per-domain overrides applied)."""
    msg = getattr(update, "effective_message", None)
    if not context.args:
        if msg:
            await msg.reply_text("Usage: /cfg example.com")
        return

    domain = normalize_domain(context.args[0])
    if domain is None:
        await msg.reply_text("Invalid domain")
        return
    owner_id = update.effective_user.id
    cfg: AppConfig = context.application.bot_data["cfg"]

    try:
        override = storage.get_domain_override(owner_id, domain) or {}
        settings = resolve_settings(cfg, domain, override)
    except storage.InvalidDomainOverride as error:
        await msg.reply_text(str(error))
        return
    except ValueError as error:
        await msg.reply_text(validation_message(error))
        return
    effective = {
        "checks": settings.checks.model_dump(),
        "http_timeout_s": getattr(settings, "http_timeout_s", None),
        # bugfix: return actual warn value (no accidental boolean 'and')
        "latency_warn_ms": getattr(settings, "latency_warn_ms", None),
        "latency_crit_ms": getattr(settings, "latency_crit_ms", None),
        "tls_warn_days": getattr(settings, "tls_warn_days", None),
        "proxy": getattr(settings, "proxy", None),
        "keywords": getattr(settings, "keywords", None),
        "ports": [port.model_dump(exclude_none=True) for port in settings.ports] if settings.ports is not None else None,
        "interval_minutes": settings.interval_minutes,
    }

    text = (
        f"<b>{html.escape(domain)}</b>\n\n"
        f"<b>Effective settings</b>:\n<pre>{html.escape(_format_preview_dict(redact_configuration(effective)))}</pre>\n\n"
        f"<b>Domain override</b>:\n<pre>{html.escape(_format_preview_dict(redact_configuration(override)))}</pre>"
    )

    log.info("cfg.show", extra={"event": "cfg.show", "owner_id": owner_id, "domain": domain})

    if msg is not None:
        await safe_reply_html(msg, text)
    else:
        chat = getattr(update, "effective_chat", None)
        if chat is not None:
            await context.bot.send_message(
                chat_id=chat.id,
                text=text,
                parse_mode="HTML",
                disable_web_page_preview=True,
            )


async def cmd_cfg_set(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Set per-domain override: checks.<name>=bool, ints, lists, proxy, interval_minutes."""
    msg = getattr(update, "effective_message", None)
    if len(context.args) < 3:
        if msg:
            await msg.reply_text(
                "Usage:\n"
                "/cfg_set <domain> <key> <value>\n\n"
                "Keys: checks.<name> (true/false), http_timeout_s, latency_warn_ms, latency_crit_ms,\n"
                "tls_warn_days, keywords, ports, proxy, interval_minutes\n\n"
                "Examples:\n"
                "  /cfg_set example.com checks.malware true\n"
                "  /cfg_set example.com keywords \"gtag,metrika\"\n"
            )
        return

    domain = context.args[0].strip().lower()
    key = context.args[1].strip()
    val = " ".join(context.args[2:]).strip()
    owner_id = update.effective_user.id

    log.info(
        "cfg.set.start",
        extra={"event": "cfg.set.start", "owner_id": owner_id, "domain": domain, "key": key},
    )

    # Build patch based on key type
    if key.startswith("checks."):
        check_name = key.split(".", 1)[1]
        if check_name not in ChecksModel.model_fields and check_name != 'rkn_block':
            if msg:
                await msg.reply_text(f"Unknown check: {check_name}")
            return
        b = _parse_bool(val)
        if b is None:
            if msg:
                await msg.reply_text("For checks.* use true/false")
            log.warning("cfg.set.invalid_bool", extra={"event": "cfg.set.invalid_bool", "key": key})
            return
        patch = {"checks": ChecksModel.model_validate({check_name: b}).model_dump(exclude_unset=True)}

    elif key in ("http_timeout_s", "latency_warn_ms", "latency_crit_ms", "tls_warn_days"):
        try:
            iv = int(val)
        except ValueError:
            if msg:
                await msg.reply_text(f"{key} must be an integer")
            log.warning("cfg.set.invalid_int", extra={"event": "cfg.set.invalid_int", "key": key})
            return
        patch = {key: iv}

    elif key in ("keywords", "ports"):
        v = _parse_list(val)
        if not v:
            if msg:
                await msg.reply_text(f"{key}: empty value")
            log.warning("cfg.set.empty", extra={"event": "cfg.set.empty", "key": key})
            return
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
            log.warning("cfg.set.invalid_int", extra={"event": "cfg.set.invalid_int", "key": key})
            return
        patch = {"interval_minutes": iv}

    else:
        if msg:
            await msg.reply_text(
                "Unknown key. Use: checks.<name>, http_timeout_s, latency_warn_ms, "
                "latency_crit_ms, tls_warn_days, keywords, ports, proxy, interval_minutes"
            )
        log.warning("cfg.set.unknown_key", extra={"event": "cfg.set.unknown_key", "key": key})
        return

    domain = normalize_domain(domain)
    if domain is None:
        await msg.reply_text("Invalid domain")
        return
    if not storage.domain_exists(owner_id, domain):
        await msg.reply_text("Domain not found. Add it with /add_domain first.")
        return
    cfg = context.application.bot_data["cfg"]
    try:
        validate_domain_override(cfg, domain, patch, storage.get_domain_override(owner_id, domain))
    except ValueError as error:
        await msg.reply_text(validation_message(error))
        return
    merged = storage.set_domain_override(owner_id, domain, patch)
    if msg:
        await safe_reply_html(
            msg,
            "✅ Saved.\nCurrent override:\n<pre>{}</pre>".format(html.escape(_format_preview_dict(redact_configuration(merged)))),
        )
    log.info("cfg.set.done", extra={"event": "cfg.set.done", "owner_id": owner_id, "domain": domain, "key": key})


async def cmd_cfg_unset(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Unset a single override key or clear the entire override."""
    msg = getattr(update, "effective_message", None)
    if not context.args:
        if msg:
            await msg.reply_text("Usage: /cfg_unset <domain> [key]")
        return

    domain = normalize_domain(context.args[0])
    if domain is None:
        await msg.reply_text("Invalid domain")
        return
    key = context.args[1].strip() if len(context.args) > 1 else None
    owner_id = update.effective_user.id
    try:
        candidate = {} if key is None else deepcopy(storage.get_domain_override(owner_id, domain) or {})
        if key is not None:
            ref = candidate
            parts = key.split(".")
            for part in parts[:-1]:
                ref = ref.get(part, {}) if isinstance(ref, dict) else {}
            if isinstance(ref, dict):
                ref.pop(parts[-1], None)
        validate_domain_override(context.application.bot_data["cfg"], domain, candidate)
        storage.unset_domain_override(owner_id, domain, key)
    except storage.InvalidDomainOverride as error:
        await msg.reply_text(str(error))
        return
    except ValueError as error:
        await msg.reply_text(validation_message(error))
        return

    if msg:
        if key:
            txt = f"🗑 Removed key <code>{html.escape(key)}</code> for <b>{html.escape(domain)}</b>."
        else:
            txt = f"🗑 Removed entire override for <b>{html.escape(domain)}</b>."
        await safe_reply_html(msg, txt)

    log.info(
        "cfg.unset",
        extra={"event": "cfg.unset", "owner_id": owner_id, "domain": domain, "key": key if key else "*"},
    )
