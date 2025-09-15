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
    "<code>/add &lt;domain1&gt; [domain2 ...]</code> — add domains via quick wizard (keywords + interval)\n"
    "<code>/add_domain &lt;name&gt;</code> — add a domain (legacy, no wizard)\n"
    "/remove &lt;name&gt; — remove a domain\n"
    "/remove_all — remove all your domains (confirmation required)\n"
    "/list — list domains\n\n"
    "<b>Monitoring (run checks)</b>\n"
    "/check &lt;name&gt; [--force] — run checks for a domain (use cache unless --force)\n"
    "/check_all [--force] — run checks for all domains (summary)\n"
    "/check_all_detail [--force] — run checks for all domains (detailed)\n\n"
    "<b>Status &amp; history (no new checks)</b>\n"
    "/status [crit|warn|ok|unknown|problems] — show last known status for all your domains\n"
    "/status &lt;domain&gt; [crit|warn|ok|unknown|problems] — detailed last results for one domain\n"
    "/history"
    " [&lt;domain&gt;] [<code>check.&lt;name&gt;</code>] "
    "[crit|warn|ok|unknown|problems] [<code>limit=N</code>] "
    "[<code>since=YYYY-MM-DD|7d|24h|90m</code>] [<code>changes</code>] "
    "— show recent saved results without running new checks.\n\n"
    "<b>Per-domain config</b>\n"
    "<code>/cfg &lt;name&gt;</code> — show effective config and DB override for a domain\n"
    "<code>/cfg_set &lt;name&gt; &lt;key&gt; &lt;value&gt;</code> — set override "
    "(e.g. <code>checks.http_basic true</code>, <code>keywords \"a,b\"</code>)\n"
    "<code>/cfg_unset &lt;name&gt; [key]</code> — remove override key or whole override\n\n"
    "<b>Data import/export &amp; caches</b>\n"
    "/export_csv — export domains and overrides to CSV (semicolon-separated)\n"
    "/import_csv [replace] — import domains from CSV (default: merge; use 'replace' to overwrite)\n"
    "/clear_cache — clear RKN/WHOIS caches\n\n"
    "<b>Alerts</b>\n"
    "/stop_alerts — disable alerts for your account\n"
    "/start_alerts — enable alerts for your account\n\n"
    "<b>Notes</b>\n"
    "• Use <code>--force</code> with /check* to bypass cache.\n"
    "• Unicode (IDN) domains are accepted and converted to punycode internally.\n"
    "• URL input like <code>https://example.com/path</code> is normalized to its host.\n"
<<<<<<< HEAD
    "• <b>Malware check</b>: VirusTotal passive reputation; requires API key in server config; no active URL submission.\n"
    "• VT Free limits are enforced: 4/min, 500/day, 15.5k/month; if quota is hit you'll see "
    "<code>UNKNOWN: VT rate limited</code>. Limits are configurable in <code>malware.vt_limits</code>.\n"
    "• Enable per-domain via <code>/cfg_set &lt;name&gt; checks.malware true</code> or via CSV column <code>checks.malware</code>.\n"
=======
>>>>>>> fbb85f0e808f8e62eb1ab2a505f698bb82d7d2ca
)


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Reply with help text and available commands."""
    log.info("help.show", extra={"event": "help.show", "owner_id": update.effective_user.id})
    msg = getattr(update, "effective_message", None)
    if msg is not None:
        # Use common helper: HTML + retries + no URL previews by default
        await safe_reply_html(msg, HELP_TEXT)
