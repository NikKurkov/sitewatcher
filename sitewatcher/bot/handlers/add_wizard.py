# sitewatcher/bot/handlers/add_wizard.py
from __future__ import annotations

from typing import List

from telegram import Update
from telegram.ext import ContextTypes, ConversationHandler

from ... import storage
from ..constants import ADD_WAIT_INTERVAL, ADD_WAIT_KEYWORDS, ALLOWED_INTERVALS
from ..utils import requires_auth
from ..validators import parse_domains


def _default_checks(keywords_enabled: bool) -> dict:
    """Default checks map for quick add wizard."""
    return {
        "http_basic": True,
        "tls_cert": True,
        "ping": True,
        "rkn_block": True,
        "whois": True,
        "ip_blacklist": True,
        "ip_change": True,
        "keywords": bool(keywords_enabled),
        "deface": True,
        # Disable ports by default in quick wizard
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

    domains = parse_domains(context.args)
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
    """Handle free-text keywords input for the wizard."""
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
    """Handle /none during the keywords step."""
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


@requires_auth
async def cmd_add_interval_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle interval minutes input for the wizard."""
    st = context.user_data.get("add_state")
    msg = getattr(update, "effective_message", None)
    if not st:
        if msg:
            await msg.reply_text("Session expired. Please run /add again.")
        return ConversationHandler.END

    raw = (msg.text or "").strip() if msg else ""
    try:
        val = int(raw)
        if val not in ALLOWED_INTERVALS:
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
    """Handle /none during the interval step (disables auto checks)."""
    st = context.user_data.get("add_state")
    msg = getattr(update, "effective_message", None)
    if not st:
        if msg:
            await msg.reply_text("Session expired. Please run /add again.")
        return ConversationHandler.END

    st["interval_minutes"] = 0  # disable auto checks
    return await _finalize_add(update, context, st)


async def _finalize_add(update: Update, context: ContextTypes.DEFAULT_TYPE, st: dict):
    """Persist all domains with prepared overrides and finish the wizard."""
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
    """Cancel the wizard and cleanup state."""
    context.user_data.pop("add_state", None)
    msg = getattr(update, "effective_message", None)
    if msg:
        await msg.reply_text("Cancelled.")
    return ConversationHandler.END
