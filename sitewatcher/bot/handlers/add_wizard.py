# sitewatcher/bot/handlers/add_wizard.py
from __future__ import annotations

import html
import logging
from typing import List, Optional

from telegram import Update
from telegram.ext import ContextTypes, ConversationHandler

from ... import storage
from ..constants import ADD_WAIT_INTERVAL, ADD_WAIT_KEYWORDS, ALLOWED_INTERVALS
from ..utils import requires_auth, safe_reply_html
from ..validators import parse_domains

log = logging.getLogger(__name__)


def _default_checks(keywords_enabled: bool) -> dict:
    """Default checks map for quick add wizard."""
    return {
        "http_basic": True,
        "tls_cert": True,
        "ping": True,
        "rkn_block": True,
        "whois": True,
        "ip_blacklist": False,
        "ip_change": False,
        "keywords": bool(keywords_enabled),
        "malware": False,
        "ports": False,
        "deface": True,
    }


@requires_auth(allow_while_busy=True)
async def cmd_add_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    /add <domain1> [domain2 ...]
    Quick wizard:
      1) Ask for keywords (space-separated) or /none to disable keyword check.
      2) Ask for interval in minutes (from ALLOWED_INTERVALS) or /none to disable auto checks.
    """
    msg = getattr(update, "effective_message", None)

    if not context.args:
        if msg:
            opts = ", ".join(str(x) for x in sorted(ALLOWED_INTERVALS))
            await safe_reply_html(
                msg,
                "Usage: <code>/add &lt;domain1&gt; [domain2 ...]</code>\n\n"
                "<b>Quick wizard:</b>\n"
                "• Step 1 — enter keywords (space-separated), or send <code>/none</code> to skip keyword check.\n"
                f"• Step 2 — enter interval in minutes (one of: <code>{opts}</code>), "
                "or send <code>/none</code> to disable auto checks for this domain."
            )
        return ConversationHandler.END

    if any(a.startswith("--") for a in context.args):
        if msg:
            await safe_reply_html(
                msg,
                "Advanced flags mode is not implemented yet. "
                "Run <code>/add</code> with just domain names to use the quick wizard."
            )
        return ConversationHandler.END

    domains = parse_domains(context.args)
    if not domains:
        if msg:
            await safe_reply_html(msg, "No valid domains found. Example: <code>/add example.com</code>")
        return ConversationHandler.END

    context.user_data["add_state"] = {
        "domains": domains,         # List[str]
        "keywords": None,           # list[str] or []
        "keywords_enabled": None,   # bool
        "interval_minutes": None,   # int or 0
    }

    log.info(
        "add_wizard.start",
        extra={"event": "add_wizard.start", "owner_id": update.effective_user.id, "domains": len(domains)},
    )

    if msg:
        await safe_reply_html(
            msg,
            "Step 1/2 — <b>Keywords</b>\n"
            "Enter keywords to require on the home page (space-separated), e.g.:  <code>gtag metrika analytics</code>\n"
            "Or send <code>/none</code> if keyword check is not required."
        )
    return ADD_WAIT_KEYWORDS


@requires_auth(allow_while_busy=True)
async def cmd_add_keywords_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle free-text keywords input for the wizard."""
    st = context.user_data.get("add_state")
    msg = getattr(update, "effective_message", None)
    if not st:
        if msg:
            await safe_reply_html(msg, "Session expired. Please run <code>/add</code> again.")
        return ConversationHandler.END

    txt = (msg.text or "").strip() if msg else ""
    if not txt:
        if msg:
            await safe_reply_html(
                msg,
                "Please enter keywords (space-separated), or send <code>/none</code> to skip keyword check."
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

    log.info(
        "add_wizard.keywords.set",
        extra={"event": "add_wizard.keywords.set", "owner_id": update.effective_user.id, "count": len(kws)},
    )

    if msg:
        opts = ", ".join(str(x) for x in sorted(ALLOWED_INTERVALS))
        await safe_reply_html(
            msg,
            "Step 2/2 — <b>Interval</b>\n"
            f"Enter check interval in minutes (one of: <code>{opts}</code>), "
            "or send <code>/none</code> to disable auto checks for this domain."
        )
    return ADD_WAIT_INTERVAL


@requires_auth(allow_while_busy=True)
async def cmd_add_keywords_none(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /none during the keywords step."""
    st = context.user_data.get("add_state")
    msg = getattr(update, "effective_message", None)
    if not st:
        if msg:
            await safe_reply_html(msg, "Session expired. Please run <code>/add</code> again.")
        return ConversationHandler.END

    st["keywords"] = []
    st["keywords_enabled"] = False

    log.info(
        "add_wizard.keywords.skip",
        extra={"event": "add_wizard.keywords.skip", "owner_id": update.effective_user.id},
    )

    if msg:
        opts = ", ".join(str(x) for x in sorted(ALLOWED_INTERVALS))
        await safe_reply_html(
            msg,
            "Step 2/2 — <b>Interval</b>\n"
            f"Enter check interval in minutes (one of: <code>{opts}</code>), "
            "or send <code>/none</code> to disable auto checks for this domain."
        )
    return ADD_WAIT_INTERVAL


@requires_auth(allow_while_busy=True)
async def cmd_add_interval_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle interval minutes input for the wizard."""
    st = context.user_data.get("add_state")
    msg = getattr(update, "effective_message", None)
    if not st:
        if msg:
            await safe_reply_html(msg, "Session expired. Please run <code>/add</code> again.")
        return ConversationHandler.END

    raw = (msg.text or "").strip() if msg else ""
    try:
        val = int(raw)
        if val not in ALLOWED_INTERVALS:
            raise ValueError
    except Exception:
        if msg:
            opts = ", ".join(str(x) for x in sorted(ALLOWED_INTERVALS))
            await safe_reply_html(
                msg,
                f"Please enter one of: <code>{opts}</code> — or send <code>/none</code> to disable auto checks."
            )
        return ADD_WAIT_INTERVAL

    st["interval_minutes"] = val
    return await _finalize_add(update, context, st)


@requires_auth(allow_while_busy=True)
async def cmd_add_interval_none(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /none during the interval step (disables auto checks)."""
    st = context.user_data.get("add_state")
    msg = getattr(update, "effective_message", None)
    if not st:
        if msg:
            await safe_reply_html(msg, "Session expired. Please run <code>/add</code> again.")
        return ConversationHandler.END

    st["interval_minutes"] = 0  # disable auto checks
    return await _finalize_add(update, context, st)


async def _finalize_add(update: Update, context: ContextTypes.DEFAULT_TYPE, st: dict):
    """Persist all domains with prepared overrides and finish the wizard."""
    msg = getattr(update, "effective_message", None)

    domains: List[str] = st["domains"]
    keywords: List[str] = st["keywords"] or []
    kw_enabled: bool = bool(st["keywords_enabled"])
    interval: int = int(st["interval_minutes"]) if st["interval_minutes"] is not None else 0
    owner_id = update.effective_user.id
    checks_map = _default_checks(keywords_enabled=kw_enabled)

    added: List[str] = []
    for d in domains:
        try:
            storage.add_domain(owner_id, d)
        except Exception as e:
            log.exception(
                "add_wizard.add_domain.failed",
                extra={"event": "add_wizard.add_domain.failed", "owner_id": owner_id, "domain": d},
            )
            if msg:
                await safe_reply_html(msg, f"❌ Failed to add <b>{html.escape(d)}</b>: <code>{html.escape(str(e))}</code>")
            # Continue to next domain
            continue

        patch = {
            "checks": checks_map,
            "interval_minutes": interval,
        }
        if kw_enabled:
            patch["keywords"] = keywords

        try:
            storage.set_domain_override(owner_id, d, patch)
        except Exception as e:
            log.exception(
                "add_wizard.override.failed",
                extra={"event": "add_wizard.override.failed", "owner_id": owner_id, "domain": d},
            )
            if msg:
                await safe_reply_html(
                    msg,
                    f"⚠️ Domain <b>{html.escape(d)}</b> added, but failed to save overrides: "
                    f"<code>{html.escape(str(e))}</code>"
                )
        added.append(d)

    # Cleanup state
    context.user_data.pop("add_state", None)

    if not added:
        if msg:
            await safe_reply_html(msg, "No domains were added.")
        return ConversationHandler.END

    kw_str = "(disabled)" if not kw_enabled else (" ".join(keywords) or "(none)")
    interval_str = "disabled" if interval <= 0 else f"{interval} min"

    log.info(
        "add_wizard.commit",
        extra={
            "event": "add_wizard.commit",
            "owner_id": owner_id,
            "domains": len(added),
            "keywords": len(keywords) if kw_enabled else 0,
            "interval": interval,
        },
    )

    if msg:
        checks_txt = (
            "<code>http_basic</code>, <code>tls_cert</code>, <code>ping</code>, "
            "<code>rkn_block</code>, <code>whois</code>, <code>ip_blacklist</code>, <code>ip_change</code>"
            f"{', <code>keywords</code>' if kw_enabled else ''}"
        )
        await safe_reply_html(
            msg,
            (
                "✅ Added domain(s): <b>{doms}</b>\n"
                "Checks: {checks}\n"
                "Keywords: {kw_str}\n"
                "Auto-check interval: <b>{interval_str}</b>\n\n"
                "Use <code>/check &lt;name&gt;</code> to run a manual check now."
            ).format(
                doms=", ".join(html.escape(d) for d in added),
                checks=checks_txt,
                kw_str=html.escape(kw_str),
                interval_str=html.escape(interval_str),
            ),
        )
    return ConversationHandler.END


@requires_auth(allow_while_busy=True)
async def cmd_add_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Cancel the wizard and cleanup state."""
    context.user_data.pop("add_state", None)
    msg = getattr(update, "effective_message", None)
    if msg:
        await safe_reply_html(msg, "Cancelled.")
    return ConversationHandler.END
