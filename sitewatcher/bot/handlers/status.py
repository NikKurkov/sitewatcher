# sitewatcher/bot/handlers/status.py
from __future__ import annotations

import html
import json
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional, Sequence

from telegram import Update
from telegram.ext import ContextTypes

from ... import storage
from ..utils import requires_auth, safe_reply_html, _strip_cached_suffix
from ..alerts import _status_bullet, _status_emoji, _status_weight, _enabled_checks_for
from ..validators import DOMAIN_RE

FILTER_TOKENS = {"ok", "warn", "crit", "unknown", "problems"}

def _parse_iso(ts: Optional[str]) -> Optional[datetime]:
    """Parse ISO timestamp to aware UTC datetime; return None on failure."""
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts)
    except Exception:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _fmt_utc(dt: Optional[datetime]) -> str:
    """Format datetime as 'DD.MM HH:MM UTC'; return dash if missing."""
    if not dt:
        return "–"
    return dt.strftime("%d.%m %H:%M UTC")


def _last_row(owner_id: int, domain: str, check: str) -> Optional[Dict]:
    """Load last stored result for a given (owner, domain, check) and decode metrics."""
    row = storage.last_history_for_check(owner_id, domain, check)
    if not row:
        return None
    # Convert sqlite3.Row → plain dict
    d = {k: row[k] for k in row.keys()}
    # Decode metrics JSON if present
    try:
        d["metrics"] = json.loads(d.get("metrics_json") or "{}")
    except Exception:
        d["metrics"] = {}
    return d


def _short_msg(msg: str, limit: int = 120) -> str:
    """Compact message: strip cached suffix, collapse whitespace, clip to limit."""
    if not msg:
        return ""
    msg = _strip_cached_suffix(msg)
    msg = re.sub(r"\s+", " ", msg).strip()
    if len(msg) > limit:
        msg = msg[: limit - 1] + "…"
    return msg


def _overall_from_rows(rows: Sequence[Dict]) -> str:
    """Compute overall status (OK/WARN/CRIT/UNKNOWN) from individual last rows."""
    worst = 0
    for r in rows:
        st = str(r.get("status", "")).upper()
        worst = max(worst, _status_weight(st))
    return {2: "CRIT", 1: "WARN", 0: "OK"}[worst] if rows else "UNKNOWN"


@requires_auth
async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Show last known status for all user's domains (no new checks).

    Filters (optional args): crit|warn|ok|unknown|problems
      - "problems" == {CRIT, WARN}
      - default: all statuses

    Output per domain (single line):
      <emoji> <domain> — <OVERALL> (DD.MM HH:MM UTC — <latency>, exp <days>)
      If OVERALL in {WARN, CRIT}: append up to 3 problem reasons inside the same parentheses.
    """
    args = [a.lower() for a in (context.args or [])]
    if args and (args[0] not in FILTER_TOKENS) and DOMAIN_RE.match(args[0]):
        domain = args[0]
        filters = set(args[1:]) & FILTER_TOKENS
        return await cmd_status_one(update, context, domain=domain, filters=filters)
        
    owner_id = update.effective_user.id
    names = sorted(storage.list_domains(owner_id))

    # ---- parse filters
    want: set[str] = set()
    aliases = {
        "crit": "CRIT",
        "warn": "WARN",
        "ok": "OK",
        "unknown": "UNKNOWN",
        "problems": None,  # will expand to {"CRIT","WARN"}
    }
    for a in (context.args or []):
        key = a.strip().lower()
        if key in aliases:
            if key == "problems":
                want.update({"CRIT", "WARN"})
            else:
                want.add(aliases[key])
    if not want:
        want = {"CRIT", "WARN", "OK", "UNKNOWN"}

    # ---- accumulate lines grouped by severity (ordering: CRIT, WARN, OK, UNKNOWN)
    lines_crit: List[str] = []
    lines_warn: List[str] = []
    lines_ok: List[str] = []
    lines_unk: List[str] = []

    for domain in names:
        enabled = _enabled_checks_for(context.application.bot_data["cfg"], owner_id, domain)

        last_rows: List[Dict] = []
        latest_dt: Optional[datetime] = None

        # aggregated display fields
        latency_txt = "–"
        exp_txt = "–"
        problems: List[str] = []

        for chk in enabled:
            row = _last_row(owner_id, domain, chk)
            if not row:
                continue
            last_rows.append(row)

            # newest timestamp (created_at/ts/updated_at)
            dt = _parse_iso(row.get("created_at")) or _parse_iso(row.get("ts")) or _parse_iso(row.get("updated_at"))
            if dt and (latest_dt is None or dt > latest_dt):
                latest_dt = dt

            # latency from http_basic metrics or from message fallback
            if chk == "http_basic":
                m = row.get("metrics") or {}
                if "latency_ms" in m and isinstance(m["latency_ms"], (int, float)):
                    latency_txt = f"{int(m['latency_ms'])} ms"
                else:
                    mm = re.search(r"latency\s+(\d+)\s*ms", str(row.get("message", "")), re.I)
                    if mm:
                        latency_txt = f"{mm.group(1)} ms"

            # expiry days from whois metrics
            if chk == "whois":
                m = row.get("metrics") or {}
                dl = m.get("days_left")
                if isinstance(dl, (int, float)):
                    exp_txt = f"{int(dl)}d"

            # collect problem reasons (WARN/CRIT/UNKNOWN)
            st = str(row.get("status", "")).upper()
            if st in {"WARN", "CRIT", "UNKNOWN"}:
                problems.append(f"{chk} {st}: {_short_msg(str(row.get('message','')))}")

        overall = _overall_from_rows(last_rows)
        if overall not in want:
            continue

        emoji = _status_emoji(overall)
        when = _fmt_utc(latest_dt)
        head = f"{when} — {latency_txt}" if latency_txt != "–" else when
        base = f"{emoji} {html.escape(domain)} — {overall} ({head}, exp {exp_txt}"

        # append concise problem list only for WARN/CRIT
        if overall in {"WARN", "CRIT"} and problems:
            problems = problems[:3] + ([f"+{len(problems)-3} more"] if len(problems) > 3 else [])
            tail = "; " + "; ".join(html.escape(p) for p in problems)
        else:
            tail = ""

        line = f"{base}{tail})"

        if overall == "CRIT":
            lines_crit.append(line)
        elif overall == "WARN":
            lines_warn.append(line)
        elif overall == "OK":
            lines_ok.append(line)
        else:
            lines_unk.append(line)

    # Build final output (keep group order)
    out_lines = []
    if "CRIT" in want:
        out_lines += lines_crit
    if "WARN" in want:
        out_lines += lines_warn
    if "OK" in want:
        out_lines += lines_ok
    if "UNKNOWN" in want:
        out_lines += lines_unk

    text = "\n".join(out_lines) if out_lines else "No data yet"

    # Telegram safety: chunk if too long
    MAX = 3500
    if len(text) <= MAX:
        await safe_reply_html(update.effective_message, text)
        return

    start = 0
    while start < len(text):
        end = text.rfind("\n", start, start + MAX)
        if end == -1 or end <= start:
            end = min(len(text), start + MAX)
        await safe_reply_html(update.effective_message, text[start:end])
        start = end + 1


def _allow_status(st: str, filters: Optional[set[str]]) -> bool:
    if not filters:
        return True
    f = {x.upper() for x in filters}
    if "PROBLEMS" in f:
        return st in {"WARN", "CRIT", "UNKNOWN"}
    return st in f  # OK/WARN/CRIT/UNKNOWN


@requires_auth
async def cmd_status_one(update: Update, context: ContextTypes.DEFAULT_TYPE, *, domain: str | None = None, filters: set[str] | None = None) -> None:
    msg = getattr(update, "effective_message", None)
    if domain is None:
        if not context.args:
            if msg:
                await msg.reply_text("Usage: /status <domain>")
            return
        domain = context.args[0].strip().lower()
    owner_id = update.effective_user.id
    name = domain

    if not storage.domain_exists(owner_id, name):
        if msg:
            await msg.reply_text("Domain not found or no data yet.")
        return

    cfg = context.application.bot_data["cfg"]
    # Walk through known checks (by schedules) and pick the latest saved row for each
    checks = list(cfg.schedules.model_dump().keys())
    rows: list[tuple[str, dict]] = []
    for chk in checks:
        row = storage.last_history_for_check(owner_id, name, chk)
        if row:
            rows.append((chk, row))

    if not rows:
        if msg:
            await msg.reply_text("No data for this domain yet.")
        return

    # Overall = worst of last saved statuses
    worst = 0
    for _, row in rows:
        st = str(row["status"]).upper()
        worst = max(worst, _status_weight(st))
    overall = {2: "CRIT", 1: "WARN", 0: "OK"}[worst]

    lines = [f"{_status_emoji(overall)} <b>{html.escape(name)}</b> — {overall}"]

    # Show CRIT/WARN first, then OK; alphabetical inside same severity
    rows_sorted = sorted(
        rows,
        key=lambda p: (-_status_weight(str(p[1]["status"]).upper()), p[0])
    )

    for chk, row in rows_sorted:
        st = str(row["status"]).upper()
        if not _allow_status(st, filters):
            continue
        bullet = _status_bullet(st)
        msg_txt = _strip_cached_suffix(row["message"] or "")
        lines.append(
            "{bullet} <code>{check}</code> — <b>{status}</b> — {msg}".format(
                bullet=bullet,
                check=html.escape(chk),
                status=html.escape(st),
                msg=html.escape(msg_txt),
            )
        )

    if msg:
        await safe_reply_html(msg, "\n".join(lines))

