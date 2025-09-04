# sitewatcher/bot/handlers/help.py
from __future__ import annotations

import logging
from telegram import Update
from telegram.ext import ContextTypes

from ..utils import safe_reply_html

log = logging.getLogger(__name__)

# Keep help as HTML to match the rest of the bot outputs.
HELP_TEXT = (
    "<b>SiteWatcher — commands</b>\n\n"
    "<b>Domain management</b>\n"
    "• <code>/add &lt;domain1&gt; [domain2 ...]</code> — add domains via quick wizard (keywords + interval)\n"
    "• <code>/add_domain &lt;name&gt;</code> — add a domain (legacy, no wizard)\n"
    "• <code>/remove &lt;name&gt;</code> — remove a domain\n"
    "• <code>/remove_all</code> — remove all your domains (confirmation required)\n"
    "• <code>/list</code> — list domains\n\n"
    "<b>Monitoring (run checks)</b>\n"
    "• <code>/check &lt;name&gt; [--force]</code> — run checks for a domain (use cache unless --force)\n"
    "• <code>/check_all [--force]</code> — run checks for all domains (summary)\n"
    "• <code>/check_all_detail [--force]</code> — run checks for all domains (detailed)\n\n"
    "<b>Status &amp; history (no new checks)</b>\n"
    "• <code>/status [crit|warn|ok|unknown|problems]</code> — show last known status for all your domains\n"
    "• <code>/status &lt;domain&gt; [crit|warn|ok|unknown|problems]</code> — detailed last results for one domain\n"
    "• <code>/history</code> "
    "[&lt;domain&gt;] [<code>check.&lt;name&gt;</code>] "
    "[crit|warn|ok|unknown|problems] [<code>limit=N</code>] "
    "[<code>since=YYYY-MM-DD|7d|24h|90m</code>] [<code>changes</code>] "
    "— show recent saved results without running new checks.\n\n"
    "<b>Per-domain config</b>\n"
    "• <code>/cfg &lt;name&gt;</code> — show effective config and DB override for a domain\n"
    "• <code>/cfg_set &lt;name&gt; &lt;key&gt; &lt;value&gt;</code> — set override "
    "(e.g. <code>checks.http_basic true</code>, <code>keywords \"a,b\"</code>)\n"
    "• <code>/cfg_unset &lt;name&gt; [key]</code> — remove override key or whole override\n\n"
    "<b>Data import/export &amp; caches</b>\n"
    "• <code>/export_csv</code> — export domains and overrides to CSV (semicolon-separated)\n"
    "• <code>/import_csv [replace]</code> — import domains from CSV (default: merge; use 'replace' to overwrite)\n"
    "• <code>/clear_cache</code> — clear RKN/WHOIS caches\n\n"
    "<b>Alerts</b>\n"
    "• <code>/stop_alerts</code> — disable alerts for your account\n"
    "• <code>/start_alerts</code> — enable alerts for your account\n\n"
    "<b>Notes</b>\n"
    "• Use <code>--force</code> with /check* to bypass cache.\n"
    "• Unicode (IDN) domains are accepted and converted to punycode internally.\n"
    "• URL input like <code>https://example.com/path</code> is normalized to its host.\n"
)


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Reply with help text and available commands."""
    log.info("help.show", extra={"event": "help.show", "owner_id": update.effective_user.id})
    msg = getattr(update, "effective_message", None)
    if msg is not None:
        # Use common helper: HTML + retries + no URL previews by default
        await safe_reply_html(msg, HELP_TEXT)
