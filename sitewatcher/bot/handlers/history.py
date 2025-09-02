# sitewatcher/bot/handlers/history.py
from __future__ import annotations

import html
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Iterable, List, Optional, Sequence, Tuple

from telegram import Update
from telegram.ext import ContextTypes

from ... import storage
from ..utils import requires_auth, safe_reply_html, _strip_cached_suffix
from ..alerts import _status_emoji, _status_weight
from ..validators import DOMAIN_RE

# Allowed status filters; "problems" expands to CRIT|WARN|UNKNOWN
_STATUS_ALIASES = {
    "ok": "OK",
    "warn": "WARN",
    "crit": "CRIT",
    "unknown": "UNKNOWN",
    "problems": None,  # expands to {"CRIT","WARN","UNKNOWN"}
}

# Message size guard for Telegram
_MAX_CHARS = 3500


def _parse_limit(tokens: Sequence[str], default: int = 20, max_lim: int = 200) -> int:
    """Parse limit=N token; clamp to [1, max_lim]."""
    lim = default
    for t in tokens:
        m = re.fullmatch(r"limit=(\d{1,5})", t)
        if m:
            try:
                lim = max(1, min(int(m.group(1)), max_lim))
            except Exception:
                pass
    return lim


def _parse_since(tokens: Sequence[str]) -> Optional[datetime]:
    """Parse since=YYYY-MM-DD | since=<Nd|Nh|Nm>. Returns aware UTC dt or None."""
    for t in tokens:
        if not t.startswith("since="):
            continue
        val = t.split("=", 1)[1]
        # Absolute date
        m_date = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})", val)
        if m_date:
            try:
                dt = datetime(int(m_date.group(1)), int(m_date.group(2)), int(m_date.group(3)), tzinfo=timezone.utc)
                return dt
            except Exception:
                return None
        # Relative window
        m_rel = re.fullmatch(r"(\d{1,5})([dhm])", val, flags=re.I)
        if m_rel:
            n = int(m_rel.group(1))
            unit = m_rel.group(2).lower()
            if unit == "d":
                delta = timedelta(days=n)
            elif unit == "h":
                delta = timedelta(hours=n)
            else:
                delta = timedelta(minutes=n)
            return datetime.now(timezone.utc) - delta
    return None


def _parse_check(tokens: Sequence[str]) -> Optional[str]:
    """Parse check.<name> or <name> (safe subset). Returns normalized check name or None."""
    for t in tokens:
        # Prefer explicit prefix
        m = re.fullmatch(r"check\.([a-z_]{2,32})", t)
        if m:
            return m.group(1)
    # Accept bare name if clearly a check token and not a known keyword like 'ok'
    for t in tokens:
        m = re.fullmatch(r"([a-z_]{2,32})", t)
        if m and t not in _STATUS_ALIASES and not t.startswith(("limit=", "since=")) and not DOMAIN_RE.match(t):
            return m.group(1)
    return None


def _parse_statuses(tokens: Sequence[str]) -> set[str]:
    """Return desired set of statuses; default = problems (CRIT,WARN,UNKNOWN)."""
    want: set[str] = set()
    for t in tokens:
        key = t.lower()
        if key in _STATUS_ALIASES:
            if key == "problems":
                want.update({"CRIT", "WARN", "UNKNOWN"})
            else:
                want.add(_STATUS_ALIASES[key])  # type: ignore[arg-type]
    if not want:
        want.update({"CRIT", "WARN", "UNKNOWN"})  # default
    return want


def _short_msg(s: str, limit: int = 120) -> str:
    """Collapse whitespace, strip cache suffix, clip."""
    s = _strip_cached_suffix(s or "")
    s = re.sub(r"\s+", " ", s).strip()
    if len(s) > limit:
        s = s[: limit - 1] + "…"
    return s


def _fmt_ts(ts: str | None) -> str:
    """Format ISO → [DD.MM HH:MM UTC]."""
    if not ts:
        return "[--.-- --:-- UTC]"
    try:
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt = dt.astimezone(timezone.utc)
        return "[" + dt.strftime("%d.%m %H:%M UTC") + "]"
    except Exception:
        return "[--.-- --:-- UTC]"


def _row_status(row) -> str:
    return str(row["status"]).upper()


def _row_key(row) -> tuple[str, str]:
    return (row["domain"], row["check"])


def _parse_changes_flag(tokens: Sequence[str]) -> bool:
    return any(t.lower() == "changes" for t in tokens)


@requires_auth(allow_while_busy=True)
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

    # Fetch raw rows (DESC by created_at)
    rows = list(storage.iter_history(
        owner_id=owner_id,
        domain=domain,
        check=check,
        statuses=statuses,
        since=since,
        limit= max(limit * 5, limit + 50) if only_changes else limit,  # wider window for 'changes'
    ))

    if only_changes and rows:
        # Build map domain+check -> last seen status while walking ASC to detect transitions
        by_pair: dict[tuple[str, str], List] = {}
        for r in rows:
            by_pair.setdefault(_row_key(r), []).append(r)
        # sort each group by created_at ASC to detect changes
        selected: List = []
        for _, grp in by_pair.items():
            try:
                grp_sorted = sorted(grp, key=lambda r: r["created_at"])
            except Exception:
                grp_sorted = grp  # fallback
            prev: Optional[str] = None
            for r in grp_sorted:
                st = _row_status(r)
                if prev is not None and st != prev:
                    selected.append(r)
                prev = st
        # Sort selected DESC by created_at and cut to limit
        try:
            rows = sorted(selected, key=lambda r: r["created_at"], reverse=True)[:limit]
        except Exception:
            rows = selected[:limit]

    # Format output
    if not rows:
        await safe_reply_html(update.effective_message, "No history rows found.")
        return

    # Display oldest → newest
    try:
        rows = sorted(rows, key=lambda r: r["created_at"])
    except Exception:
        # fallback if something is odd with types
        rows = list(rows)[::-1]

    lines: List[str] = []
    for r in rows[:limit]:
        emoji = _status_emoji(_row_status(r))
        when = _fmt_ts(r["created_at"])
        dom = html.escape(r["domain"])
        chk = html.escape(r["check"])
        st = html.escape(_row_status(r))
        msg = _short_msg(r["message"] or "")
        lines.append(f"{when} {emoji} {dom} · <code>{chk}</code> — <b>{st}</b> — {html.escape(msg)}")

    text = "\n".join(lines)

    # Chunked send if necessary
    if len(text) <= _MAX_CHARS:
        await safe_reply_html(update.effective_message, text)
        return

    start = 0
    while start < len(text):
        end = text.rfind("\n", start, start + _MAX_CHARS)
        if end == -1 or end <= start:
            end = min(len(text), start + _MAX_CHARS)
        await safe_reply_html(update.effective_message, text[start:end])
        start = end + 1
