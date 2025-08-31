# sitewatcher/bot/handlers/checks.py
from __future__ import annotations

import asyncio
from telegram import Update
from telegram.ext import ContextTypes

from ... import storage
from ...config import AppConfig, resolve_settings
from ...dispatcher import Dispatcher
from ..formatting import _format_results, _format_results_summary
from ..utils import requires_auth, safe_reply_html
from ..alerts import maybe_send_alert


@requires_auth
async def cmd_check_domain(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Run checks for a single domain (ephemeral if not owned)."""
    if not context.args:
        await update.message.reply_text("Usage: /check example.com")
        return

    owner_id = update.effective_user.id
    raw = context.args[0].strip().lower()
    force = raw in ("--force", "-f", "force")
    name = (context.args[1] if force and len(context.args) > 1 else raw).strip().lower()

    cfg: AppConfig = context.application.bot_data["cfg"]

    # Owned domain: normal mode (persist history + alerts)
    if storage.domain_exists(owner_id, name):
        async with Dispatcher(cfg) as d:
            results = await d.run_for(owner_id, name, use_cache=not force)
            text = await _format_results(owner_id, name, results, persist=True)
        await safe_reply_html(update.message, text)
        await maybe_send_alert(update, context, owner_id, name, results)
        return

    # Ephemeral mode: not owned -> no persistence, no alerts, force-disable keywords
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


@requires_auth
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

    force = False
    if context.args:
        arg0 = (context.args[0] or "").lower()
        if arg0 in ("--force", "-f", "force"):
            force = True

    parts: list[str] = []
    async with Dispatcher(cfg) as d:
        for name in names:
            results = await d.run_for(owner_id, name, use_cache=not force)
            parts.append(await _format_results(owner_id, name, results, persist=True))
            await maybe_send_alert(update, context, owner_id, name, results)

    # Split long output into multiple Telegram-safe messages
    if msg:
        MAX_LEN = 3800
        blocks: list[str] = []
        cur: list[str] = []
        cur_len = 0
        for p in parts:
            add_len = (2 if cur else 0) + len(p)
            if cur_len + add_len > MAX_LEN and cur:
                blocks.append("\n\n".join(cur))
                cur = [p]
                cur_len = len(p)
            else:
                cur.append(p)
                cur_len += add_len
        if cur:
            blocks.append("\n\n".join(cur))
        for b in blocks:
            await safe_reply_html(msg, b)

@requires_auth
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

    force = False
    if context.args:
        arg0 = (context.args[0] or "").lower()
        if arg0 in ("--force", "-f", "force"):
            force = True

    parts: list[str] = []
    async with Dispatcher(cfg) as d:
        for name in names:
            results = await d.run_for(owner_id, name, use_cache=not force)
            parts.append(await _format_results_summary(owner_id, name, results, persist=True))
            await maybe_send_alert(update, context, owner_id, name, results)

    # Split long output into multiple Telegram-safe messages
    if msg:
        MAX_LEN = 3800
        blocks: list[str] = []
        cur: list[str] = []
        cur_len = 0
        for p in parts:
            add_len = (2 if cur else 0) + len(p)
            if cur_len + add_len > MAX_LEN and cur:
                blocks.append("\n\n".join(cur))
                cur = [p]
                cur_len = len(p)
            else:
                cur.append(p)
                cur_len += add_len
        if cur:
            blocks.append("\n\n".join(cur))
        for b in blocks:
            await safe_reply_html(msg, b)
