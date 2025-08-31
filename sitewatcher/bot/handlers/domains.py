# sitewatcher/bot/handlers/domains.py
from __future__ import annotations

import html
from typing import List

from telegram import Update
from telegram.ext import ContextTypes, ConversationHandler, MessageHandler, CommandHandler, filters

from ... import storage
from ..utils import requires_auth
from ..validators import DOMAIN_RE


# Confirmation state for /remove_all
REMOVE_ALL_CONFIRM = 1201

@requires_auth
async def cmd_remove_all_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Ask the user to confirm bulk deletion of all domains."""
    msg = getattr(update, "effective_message", None)
    if msg:
        # Text as requested:
        await msg.reply_text("Are you sure? Type delete if you want to delete, or /none if you changed your mind.")
    return REMOVE_ALL_CONFIRM

@requires_auth
async def cmd_remove_all_confirm(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Handle confirmation input for /remove_all."""
    text = (update.effective_message.text or "").strip()
    low = text.lower()

    # Cancel on /none or 'none'
    if low in {"/none", "none"}:
        await update.effective_message.reply_text("Cancelled.")
        return ConversationHandler.END

    # Proceed only if user types 'delete'
    if low == "delete":
        owner_id = update.effective_user.id
        names = storage.list_domains(owner_id)
        removed = 0
        for name in names:
            try:
                if storage.remove_domain(owner_id, name):
                    removed += 1
            except Exception:
                # Keep going even if a single removal fails
                pass
        await update.effective_message.reply_text(f"✅ Deleted {removed} domain(s).")
        return ConversationHandler.END

    # Any other input -> re-prompt
    await update.effective_message.reply_text("Are you sure? Type delete if you want to delete, or /none if you changed your mind.")
    return REMOVE_ALL_CONFIRM

@requires_auth
async def cmd_remove_all_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Explicit cancel handler for conversation fallbacks."""
    await update.effective_message.reply_text("Cancelled.")
    return ConversationHandler.END


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
    """List domains owned by the user (alphabetically sorted)."""
    owner_id = update.effective_user.id
    items: List[str] = storage.list_domains(owner_id)
    # Sort domains alphabetically before printing
    items_sorted: List[str] = sorted(items)
    msg = getattr(update, "effective_message", None)
    if msg:
        await msg.reply_text("No domains yet" if not items_sorted else "\n".join(items_sorted))
