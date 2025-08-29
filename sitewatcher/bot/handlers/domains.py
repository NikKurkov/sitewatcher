# sitewatcher/bot/handlers/domains.py
from __future__ import annotations

import html
from typing import List

from telegram import Update
from telegram.ext import ContextTypes

from ... import storage
from ..utils import requires_auth
from ..validators import DOMAIN_RE


@requires_auth
async def cmd_add_domain(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Add a single domain; strict validation is applied."""
    msg = getattr(update, "effective_message", None)
    if not context.args:
        if msg:
            await msg.reply_text("Usage: /add_domain example.com")
        return

    owner_id = update.effective_user.id
    name = context.args[0].strip().lower()

    if not DOMAIN_RE.match(name):
        if msg:
            await msg.reply_text("Invalid domain format. Expect like: example.com")
        return

    storage.add_domain(owner_id, name)
    if msg:
        await msg.reply_text(f"Added: <b>{html.escape(name)}</b>", parse_mode="HTML")


@requires_auth
async def cmd_remove_domain(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Remove a domain from owner's list."""
    msg = getattr(update, "effective_message", None)
    if not context.args:
        if msg:
            await msg.reply_text("Usage: /remove example.com")
        return
    name = context.args[0].strip().lower()
    owner_id = update.effective_user.id
    ok = storage.remove_domain(owner_id, name)
    if msg:
        await msg.reply_text("Removed" if ok else "Not found")


@requires_auth
async def cmd_list_domain(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """List domains owned by the user."""
    owner_id = update.effective_user.id
    items: List[str] = storage.list_domains(owner_id)
    msg = getattr(update, "effective_message", None)
    if msg:
        await msg.reply_text("No domains yet" if not items else "\n".join(items))
