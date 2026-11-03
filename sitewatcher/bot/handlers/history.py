# sitewatcher/bot/handlers/history.py
from __future__ import annotations

import html
import logging
import re
from datetime import datetime, timedelta, timezone
from sqlite3 import Row
from typing import Iterable, List, Optional, Set, Tuple

from telegram import Update
from telegram.ext import ContextTypes

from ... import storage
from ..utils import safe_reply_html
from ..formatting import _fmt_ts
from ...utils.results import status_emoji as _status_emoji, strip_cached_suffix as _strip_cached_suffix
from ..validators import DOMAIN_RE

log = logging.getLogger(__name__)

# ---------------------------- small helpers ----------------------------

def _parse_check(tokens: Iterable[str]) -> Optional[str]:
    """Extract check name from tokens like 'check.http_basic'."""
    for t in tokens:
        if t.startswith("check.") and len(t) > 6:
            return t.split(".", 1)[1].strip()
    return None


def _parse_statuses(tokens: Iterable[str]) -> Set[str]:
    """Parse status filters. Default: problems (CRIT/WARN/UNKNOWN)."""
    mapping = {
        "crit": "CRIT",
        "critical": "CRIT",
        "warn": "WARN",
        "warning": "WARN",
        "ok": "OK",
        "unknown": "UNKNOWN",
        "problems": "PROBLEMS",
    }
    wanted: Set[str] = set()
    for t in tokens:
        key = t.strip().lower()
        if key in mapping:
            m = mapping[key]
            if m == "PROBLEMS":
                wanted.update({"CRIT", "WARN", "UNKNOWN"})
            else:
                wanted.add(m)
    if not wanted:
        wanted.update({"CRIT", "WARN", "UNKNOWN"})
    return wanted


def _parse_limit(tokens: Iterable[str], *, default: int, max_lim: int) -> int:
    """Parse 'limit=NN' (or 'limit:NN'). Clamp to [1, max_lim]."""
    lim = None
    for t in tokens:
        m = re.match(r"^limit\s*[:=]\s*(\d{1,5})$", t.strip(), flags=re.I)
        if m:
            try:
                lim = int(m.group(1))
            except Exception:
                pass
            break
    if lim is None:
        return default
    return max(1, min(max_lim, lim))


def _parse_since(tokens: Iterable[str]) -> Optional[datetime]:
    """Parse since=YYYY-MM-DD | since=7d | since=24h | since=90m (UTC)."""
    for t in tokens:
        m = re.match(r"^since\s*[:=]\s*(.+)$", t.strip(), flags=re.I)
        if not m:
            continue
        val = m.group(1).strip()
        now = datetime.now(timezone.utc)
        # Relative forms
        rm = re.match(r"^(\d+)\s*([dhm])$", val, flags=re.I)
        if rm:
            num = int(rm.group(1))
            unit = rm.group(2).lower()
            if unit == "d":
                return now - timedelta(days=num)
            if unit == "h":
                return now - timedelta(hours=num)
            if unit == "m":
                return now - timedelta(minutes=num)
            return None
        # Absolute date
        try:
            dt = datetime.fromisoformat(val)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            # YYYY-MM-DD
            try:
                dt = datetime.strptime(val, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                return dt
            except Exception:
                return None
    return None


def _parse_changes_flag(tokens: Iterable[str]) -> bool:
    """Return True if 'changes' token is present."""
    return any(t.strip().lower() == "changes" for t in tokens)


# ------------------------------ command --------------------------------

async def cmd_history(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    /history [<domain>] [check.<name>] [crit|warn|ok|unknown|problems] [limit=N] [since=YYYY-MM-DD|7d|24h|90m] [changes]

    Shows last history rows without running new checks.
    Default filters: problems (CRIT/WARN/UNKNOWN), limit=20, no since, no 'changes' mode.
    """
    owner_id = update.effective_user.id
    tokens = [t.strip() for t in (context.args or [])]

    # Extract parts
    domain = next((t for t in tokens if DOMAIN_RE.match(t)), None)
    check = _parse_check(tokens)
    statuses = _parse_statuses(tokens)
    limit = _parse_limit(tokens, default=20, max_lim=200)
    since = _parse_since(tokens)
    only_changes = _parse_changes_flag(tokens)

    log.info(
        "history.start",
        extra={
            "event": "history.start",
            "owner_id": owner_id,
            "domain": domain,
            "check": check,
            "statuses": sorted(list(statuses)),
            "limit": limit,
            "since": since.isoformat() if since else None,
            "changes": bool(only_changes),
        },
    )

    # Fetch all statuses when detecting transitions, including intervening recoveries.
    rows = list(
        storage.iter_history(
            owner_id=owner_id,
            domain=domain,
            check=check,
            statuses=None if only_changes else statuses,
            since=since,
            limit=max(limit * 5, limit + 50) if only_changes else limit,  # wider window for 'changes'
        )
    )

    log.debug(
        "history.fetched",
        extra={"event": "history.fetched", "owner_id": owner_id, "raw_count": len(rows)},
    )

    # Post-process for 'changes' mode (keep only status transitions)
    if only_changes and rows:
        # Group by (domain, check) and scan ASC to detect changes
        by_pair: dict[Tuple[str, str], List[Row]] = {}
        for r in rows:
            by_pair.setdefault((r["domain"], r["check"]), []).append(r)

        selected: List[Row] = []
        for grp in by_pair.values():
            prev: Optional[str] = None
            for r in sorted(grp, key=lambda r: (r["created_at"] or "", r["id"])):
                st = r["status"].upper()
                if prev is not None and st != prev:
                    selected.append(r)
                prev = st

        rows = sorted(
            (r for r in selected if r["status"].upper() in statuses),
            key=lambda r: (r["created_at"] or "", r["id"]), reverse=True,
        )[:limit]

        log.debug(
            "history.changes.selected",
            extra={"event": "history.changes.selected", "owner_id": owner_id, "selected": len(rows)},
        )

    if not rows:
        await safe_reply_html(update.effective_message, "No history rows.")
        log.info("history.done", extra={"event": "history.done", "owner_id": owner_id, "rows": 0})
        return

    # Render lines
    lines: List[str] = []
    for r in rows[:limit]:
        st = r["status"].upper()
        ts = _fmt_ts(r["created_at"])
        dom = html.escape((r["domain"] or ""))
        chk = html.escape((r["check"] or ""))
        msg = html.escape(_strip_cached_suffix((r["message"] or "")))
        lines.append(f"{_status_emoji(st)} {ts} <b>{dom}</b> — <code>{chk}</code> — <b>{st}</b> — {msg}")

    text = "\n".join(lines)

    await safe_reply_html(update.effective_message, text)
    log.info("history.done", extra={"event": "history.done", "owner_id": owner_id, "rows": len(rows[:limit])})
