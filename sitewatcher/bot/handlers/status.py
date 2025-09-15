# sitewatcher/bot/handlers/status.py
from __future__ import annotations

import html
import logging
import re
from datetime import datetime, timezone
from typing import Any, Iterable, List, Optional, Set, Tuple

from telegram import Update
from telegram.ext import ContextTypes

from ... import storage
from ..utils import safe_reply_html, _strip_cached_suffix
from ..alerts import _status_bullet, _status_emoji, _status_weight, _enabled_checks_for
from ..validators import DOMAIN_RE

log = logging.getLogger(__name__)

# Accepted filter tokens for statuses
FILTER_TOKENS = {"crit", "warn", "ok", "unknown", "problems"}


# ---------------------------- small helpers ----------------------------

def _parse_iso(ts: Optional[str]) -> Optional[datetime]:
    """Parse ISO timestamp (supports '...Z') or SQLite 'YYYY-MM-DD HH:MM:SS' to aware UTC datetime."""
    if not ts:
        return None
    s = str(ts)
    try:
        if s.endswith("Z"):
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        else:
            dt = datetime.fromisoformat(s)
    except Exception:
        # SQLite DATETIME('now') style
        try:
            dt = datetime.strptime(s, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except Exception:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _fmt_ts(ts: Optional[str]) -> str:
    """Format timestamp to '[DD.MM HH:MM UTC]' or placeholder if missing."""
    dt = _parse_iso(ts)
    if not dt:
        return "[--.-- --:-- UTC]"
    return "[" + dt.strftime("%d.%m %H:%M UTC") + "]"


def _get(row: Any, key: str, default: Any = None) -> Any:
    """Duck-typed access for dict/sqlite3.Row/objects."""
    try:
        if hasattr(row, "keys") and key in row.keys():  # sqlite3.Row supports keys() and __getitem__
            return row[key]
    except Exception:
        pass
    if isinstance(row, dict):
        return row.get(key, default)
    return getattr(row, key, default)


def _row_status(row: Any) -> str:
    val = _get(row, "status", "UNKNOWN")
    return str(getattr(val, "value", val)).upper()


def _row_check(row: Any) -> str:
    val = _get(row, "check_name", None)
    if not val:
        val = _get(row, "check", "")
    return str(val or "")


def _row_message(row: Any) -> str:
    return str(_get(row, "message", "") or "")


def _row_created_at(row: Any) -> Optional[str]:
    return _get(row, "created_at", None)


def _overall_from_rows(rows: Iterable[Any]) -> str:
    worst = 0
    for r in rows:
        worst = max(worst, _status_weight(_row_status(r)))
    return {2: "CRIT", 1: "WARN", 0: "OK"}[worst]


def _parse_filters(args: Iterable[str], *, default_problems: bool) -> Set[str]:
    """Return desired status set: {'CRIT','WARN','OK','UNKNOWN'}."""
    mapping = {
        "crit": "CRIT",
        "warn": "WARN",
        "ok": "OK",
        "unknown": "UNKNOWN",
        "problems": "PROBLEMS",
    }
    out: Set[str] = set()
    for a in args:
        key = a.strip().lower()
        if key in mapping:
            v = mapping[key]
            if v == "PROBLEMS":
                out.update({"CRIT", "WARN", "UNKNOWN"})
            else:
                out.add(v)
    if not out:
        return {"CRIT", "WARN", "UNKNOWN"} if default_problems else {"CRIT", "WARN", "OK", "UNKNOWN"}
    return out


# ------------------------------ commands -------------------------------

async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    /status [crit|warn|ok|unknown|problems] — overall per domain (no new checks)
    /status <domain> [crit|warn|ok|unknown|problems] — detailed last results for one domain
    """
    args = [a.lower() for a in (context.args or [])]
    # If first arg looks like a domain, delegate to detailed mode
    if args and (args[0] not in FILTER_TOKENS) and DOMAIN_RE.match(args[0]):
        domain = args[0]
        filters = _parse_filters(args[1:], default_problems=False)
        return await cmd_status_one(update, context, domain=domain, filters=filters)

    owner_id = update.effective_user.id
    names = sorted(storage.list_domains(owner_id))

    log.info(
        "status.start",
        extra={"event": "status.start", "owner_id": owner_id, "domains": len(names), "cmd_args": args},
    )

    if not names:
        await safe_reply_html(update.effective_message, "No domains yet.")
        log.info("status.done", extra={"event": "status.done", "owner_id": owner_id, "lines": 0})
        return

    # Default to problems-only for overall view
    wanted = _parse_filters(args, default_problems=False)

    cfg = context.application.bot_data["cfg"]

    lines: List[str] = []
    pairs: List[Tuple[int, str, str]] = []  # (neg_severity, domain, line)

    for name in names:
        checks = _enabled_checks_for(cfg, owner_id, name)
        rows: List[Any] = []
        for chk in checks:
            row = storage.last_history_for_check(owner_id, name, chk)
            if row:
                rows.append(row)

        if not rows:
            overall = "UNKNOWN"
            if "UNKNOWN" not in wanted:
                continue
            line = f"{_status_emoji(overall)} <b>{html.escape(name)}</b> — {overall} (no data)"
            pairs.append((-_status_weight(overall), name, line))
            continue

        # Compute overall from latest rows
        overall = _overall_from_rows(rows)
        if overall not in wanted:
            continue

        # Take the newest timestamp among rows for display
        newest_ts = None
        try:
            newest_ts = max((_row_created_at(r) or "" for r in rows))
        except Exception:
            newest_ts = None

        ts = _fmt_ts(newest_ts)
        
        # Build short reason for CRIT/WARN based on the most recent worst check
        reason = ""
        if overall in {"CRIT", "WARN"}:
            try:
                worst_weight = max(_status_weight(_row_status(r)) for r in rows)
                candidates = [r for r in rows if _status_weight(_row_status(r)) == worst_weight]
                best = max(candidates, key=lambda r: _row_created_at(r) or "") if candidates else None
            except Exception:
                best = None
            if best is not None:
                chk = html.escape(_row_check(best))
                msg = html.escape(_strip_cached_suffix(_row_message(best)))
                if len(msg) > 100:
                    msg = msg[:97] + "…"
                reason = f" ({chk}: {msg})"

        line = f"{_status_emoji(overall)} {ts} <b>{html.escape(name)}</b> — {overall}{reason}"
        pairs.append((-_status_weight(overall), name, line))


    if not pairs:
        await safe_reply_html(update.effective_message, "No data yet")
        log.info("status.done", extra={"event": "status.done", "owner_id": owner_id, "lines": 0})
        return

    pairs.sort()
    lines = [p[2] for p in pairs]

    text = "\n".join(lines)
    await safe_reply_html(update.effective_message, text)
    log.info("status.done", extra={"event": "status.done", "owner_id": owner_id, "lines": len(lines)})


async def cmd_status_one(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    *,
    domain: str | None = None,
    filters: Set[str] | None = None,
) -> None:
    """
    Detailed last known results for a single domain (no new checks).
    Shows each enabled check's latest stored status and message.
    """
    msg = getattr(update, "effective_message", None)
    if domain is None:
        # If invoked directly, parse from args
        args = [a.lower() for a in (context.args or [])]
        if not args:
            if msg:
                await msg.reply_text("Usage: /status <domain> [crit|warn|ok|unknown|problems]")
            return
        domain = args[0]
        filters = _parse_filters(args[1:], default_problems=False)
    name = domain

    owner_id = update.effective_user.id
    cfg = context.application.bot_data["cfg"]

    checks = _enabled_checks_for(cfg, owner_id, name)
    rows: List[Tuple[str, Any]] = []
    for chk in checks:
        row = storage.last_history_for_check(owner_id, name, chk)
        if row:
            rows.append((chk, row))

    if not rows:
        await safe_reply_html(update.effective_message, f"No data yet for <b>{html.escape(name)}</b>.")
        return

    # Header: overall
    overall = _overall_from_rows((r for _, r in rows))
    head = f"{_status_emoji(overall)} <b>{html.escape(name)}</b> — {overall}"

    # Default: show all for single-domain detailed view, unless filters were provided
    wanted = filters or {"CRIT", "WARN", "OK", "UNKNOWN"}

    # Sort checks by severity DESC then by check name
    items: List[Tuple[int, str, str]] = []  # (neg_sev, check, line)
    for chk, row in rows:
        st = _row_status(row)
        if st not in wanted and not (("CRIT" in wanted or "WARN" in wanted or "UNKNOWN" in wanted) and st in {"CRIT", "WARN", "UNKNOWN"}):
            # simple membership check; above condition is redundant but explicit for clarity
            continue
        ts = _fmt_ts(_row_created_at(row))
        bullet = _status_bullet(st)
        msg_text = html.escape(_strip_cached_suffix(_row_message(row)))
        line = f"{bullet} {ts} <code>{html.escape(chk)}</code> — <b>{st}</b> — {msg_text}"
        items.append((-_status_weight(st), chk, line))

    if not items:
        await safe_reply_html(update.effective_message, head + "\n(no checks matched filters)")
        return

    items.sort()
    lines = [head] + [it[2] for it in items]
    await safe_reply_html(update.effective_message, "\n".join(lines))
