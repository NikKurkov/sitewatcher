# sitewatcher/bot/handlers/help.py
from __future__ import annotations

from telegram import Update
from telegram.ext import ContextTypes

from ..utils import requires_auth

HELP_TEXT = (
    "/add <domain1> [domain2 ...] — add domains via quick wizard (keywords + interval)\n"
    "/add_domain <name> — add a domain (legacy, no wizard)\n"
    "/remove <name> — remove a domain\n"
    "/remove_all — remove all your domains (confirmation required)\n"
    "/list — list domains\n"
    "/check <name> [--force] — run checks for a domain (use cache unless --force)\n"
    "/check_all [--force] — run checks for all domains\n"
    "/cfg <name> — show effective config and DB override for a domain\n"
    "/cfg_set <name> <key> <value> — set override (e.g. checks.http_basic true, keywords \"a,b\")\n"
    "/cfg_unset <name> [key] — remove override key or whole override\n"
    "/clear_cache — clear RKN/WHOIS caches\n"
    "/export_csv — export domains and overrides to CSV (semicolon-separated)\n"
    "/import_csv [replace] — import domains from CSV (default: merge; use 'replace' to overwrite)\n"
)



@requires_auth
async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Reply with help text and available commands."""
    msg = getattr(update, "effective_message", None)
    if msg is not None:
        await msg.reply_text(HELP_TEXT)
