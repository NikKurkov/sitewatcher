# sitewatcher/bot/handlers/checks.py
from __future__ import annotations

import asyncio
import logging
from typing import Iterable, List

from telegram import Update
from telegram.ext import ContextTypes

from ... import storage
from ...config import AppConfig, resolve_settings
from ...dispatcher import Dispatcher
from ..formatting import _format_results, _format_results_summary
from ..utils import safe_reply_html
from ..alerts import maybe_send_alert

log = logging.getLogger(__name__)

# --- internal helpers ---------------------------------------------------------

def _parse_force(args: Iterable[str]) -> bool:
    """Return True if args contain any force flag."""
    tokens = {str(a).strip().lower() for a in (args or [])}
    return bool({"--force", "-f", "force"} & tokens)


def _chunk_text(text: str, limit: int = 4000) -> List[str]:
    """Split long HTML into Telegram-friendly chunks."""
    if len(text) <= limit:
        return [text]
    parts: List[str] = []
    buf: List[str] = []
    size = 0
    for line in text.splitlines(keepends=True):
        if size + len(line) > limit and buf:
            parts.append("".join(buf))
            buf = []
            size = 0
        buf.append(line)
        size += len(line)
    if buf:
        parts.append("".join(buf))
    return parts


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
    name = (context.args[1] if force and len(context.args) > 1 else raw).strip().lower()

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
        settings = resolve_settings(cfg, name)
        try:
            settings.checks.keywords = False
        except Exception:
            pass
        checks = d._build_checks(settings)
        results = await asyncio.gather(*(chk.run() for chk in checks))

    text = await _format_results(owner_id, name, results, persist=False)
    await safe_reply_html(update.message, text)
    log.info(
        "cmd.check.done",
        extra={"event": "cmd.check.done", "owner_id": owner_id, "domain": name, "mode": "ephemeral"},
    )


async def cmd_check_all_detail(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Detailed check for all owned domains (per-check lines for every domain)."""
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
        "cmd.check_all_detail.start",
        extra={"event": "cmd.check_all_detail.start", "owner_id": owner_id, "count": len(names), "force": bool(force)},
    )

    parts: list[str] = []
    async with Dispatcher(cfg) as d:
        for name in names:
            try:
                results = await d.run_for(owner_id, name, use_cache=not force)
            except Exception:
                # Keep going even if one domain fails
                log.exception(
                    "cmd.check_all_detail.domain_error",
                    extra={"event": "cmd.check_all_detail.domain_error", "owner_id": owner_id, "domain": name},
                )
                continue
            parts.append(await _format_results(owner_id, name, results, persist=True))
            await maybe_send_alert(update, context, owner_id, name, results)

    text = "\n\n".join(parts) if parts else "No results."
    for chunk in _chunk_text(text):
        await safe_reply_html(msg, chunk)

    log.info(
        "cmd.check_all_detail.done",
        extra={"event": "cmd.check_all_detail.done", "owner_id": owner_id, "count": len(names)},
    )


async def cmd_check_all(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Summary check for all owned domains (overall line; details only for non-OK)."""
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
        "cmd.check_all.start",
        extra={"event": "cmd.check_all.start", "owner_id": owner_id, "count": len(names), "force": bool(force)},
    )

    parts: list[str] = []
    async with Dispatcher(cfg) as d:
        for name in names:
            try:
                results = await d.run_for(owner_id, name, use_cache=not force)
            except Exception:
                log.exception(
                    "cmd.check_all.domain_error",
                    extra={"event": "cmd.check_all.domain_error", "owner_id": owner_id, "domain": name},
                )
                continue
            parts.append(await _format_results_summary(owner_id, name, results, persist=True))
            await maybe_send_alert(update, context, owner_id, name, results)

    text = "\n".join(parts) if parts else "No results."
    for chunk in _chunk_text(text):
        await safe_reply_html(msg, chunk)

    log.info(
        "cmd.check_all.done",
        extra={"event": "cmd.check_all.done", "owner_id": owner_id, "count": len(names)},
    )
