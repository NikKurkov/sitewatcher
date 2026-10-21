# sitewatcher/bot/handlers/checks.py
from __future__ import annotations

import logging
from typing import Iterable

from telegram import Update
from telegram.ext import ContextTypes

from ... import storage
from ...config import AppConfig
from ...dispatcher import Dispatcher
from ..formatting import _format_results, _format_results_summary
from ..utils import safe_reply_html
from ..alerts import maybe_send_alert
from ..validators import DOMAIN_RE, normalize_domain

log = logging.getLogger(__name__)

# --- internal helpers ---------------------------------------------------------

def _parse_force(args: Iterable[str]) -> bool:
    """Return True if args contain any force flag."""
    tokens = {str(a).strip().lower() for a in (args or [])}
    return bool({"--force", "-f", "force"} & tokens)


# --- commands ----------------------------------------------------------------

async def cmd_check_domain(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Run checks for a single domain (ephemeral if not owned)."""
    if not context.args:
        await update.message.reply_text("Usage: /check example.com")
        return

    cfg: AppConfig = context.application.bot_data["cfg"]
    owner_id = update.effective_user.id

    raw = context.args[0].strip().lower()
    force = raw in ("--force", "-f", "force")
    name = normalize_domain(context.args[1] if force and len(context.args) > 1 else raw)
    if not name or not DOMAIN_RE.fullmatch(name):
        await update.message.reply_text("Enter a valid domain, for example /check example.com")
        return

    log.info(
        "cmd.check.start",
        extra={"event": "cmd.check.start", "owner_id": owner_id, "domain": name, "force": bool(force)},
    )

    # Owned domain: normal mode (persist history + alerts)
    if storage.domain_exists(owner_id, name):
        log.info(
            "cmd.check.mode",
            extra={"event": "cmd.check.mode", "owner_id": owner_id, "domain": name, "mode": "owned"},
        )
        async with Dispatcher(cfg) as d:
            results = await d.run_for(owner_id, name, use_cache=not force)
            text = await _format_results(owner_id, name, results, persist=True)
        await safe_reply_html(update.message, text)
        await maybe_send_alert(update, context, owner_id, name, results)
        log.info(
            "cmd.check.done",
            extra={"event": "cmd.check.done", "owner_id": owner_id, "domain": name, "mode": "owned"},
        )
        return

    # Ephemeral mode: not owned -> no persistence, no alerts, force-disable keywords
    log.info(
        "cmd.check.mode",
        extra={"event": "cmd.check.mode", "owner_id": owner_id, "domain": name, "mode": "ephemeral"},
    )
    async with Dispatcher(cfg) as d:
        allowed = [check for check in type(cfg.defaults.checks).model_fields if check != "keywords"]
        results = await d.run_for(owner_id, name, only_checks=allowed, use_cache=False, ephemeral=True)

    text = await _format_results(owner_id, name, results, persist=False)
    await safe_reply_html(update.message, text)
    log.info(
        "cmd.check.done",
        extra={"event": "cmd.check.done", "owner_id": owner_id, "domain": name, "mode": "ephemeral"},
    )


async def cmd_check_all_detail(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Detailed check for all owned domains (per-check lines for every domain)."""
    await _check_all(update, context, _format_results, "\n\n", "check_all_detail")


async def cmd_check_all(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Summary check for all owned domains (overall line; details only for non-OK)."""
    await _check_all(update, context, _format_results_summary, "\n", "check_all")


async def _check_all(update, context, format_results, separator: str, command: str) -> None:
    msg = getattr(update, "effective_message", None)
    cfg: AppConfig = context.application.bot_data["cfg"]
    owner_id = update.effective_user.id
    names = storage.list_domains(owner_id)

    if not names:
        if msg:
            await msg.reply_text("No domains in DB")
        return

    force = _parse_force(context.args)
    log.info(
        f"cmd.{command}.start",
        extra={"event": f"cmd.{command}.start", "owner_id": owner_id, "count": len(names), "force": bool(force)},
    )

    parts: list[str] = []
    async with Dispatcher(cfg) as d:
        for name in names:
            try:
                results = await d.run_for(owner_id, name, use_cache=not force)
            except Exception:
                # Keep going even if one domain fails
                log.exception(
                    f"cmd.{command}.domain_error",
                    extra={"event": f"cmd.{command}.domain_error", "owner_id": owner_id, "domain": name},
                )
                continue
            parts.append(await format_results(owner_id, name, results, persist=True))
            await maybe_send_alert(update, context, owner_id, name, results)

    text = separator.join(parts) if parts else "No results."
    await safe_reply_html(msg, text)

    log.info(
        f"cmd.{command}.done",
        extra={"event": f"cmd.{command}.done", "owner_id": owner_id, "count": len(names)},
    )
