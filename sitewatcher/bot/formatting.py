# sitewatcher/bot/formatting.py
from __future__ import annotations

import html
import logging
import re
from typing import Iterable, List, Any

from .. import storage

log = logging.getLogger(__name__)


# ----------------------------- small helpers -----------------------------

def _strip_cached_suffix(msg: str) -> str:
    """
    Remove trailing '[cached Xm]' markers from a message.
    We keep the original message for user output but strip it before persisting.
    """
    return re.sub(r"(?:\s*\[cached\s+\d+m\])+$", "", msg or "", flags=re.I)


def _status_text(s: Any) -> str:
    """Normalize status (enum or str) to UPPER string."""
    return getattr(s, "value", str(s)).upper()


def _status_weight(s: str) -> int:
    """Numeric weight for severity comparisons."""
    s = s.upper()
    if s == "CRIT":
        return 2
    if s in ("WARN", "UNKNOWN"):
        return 1
    return 0


def _status_emoji(s: str) -> str:
    """Traffic light emoji for overall header."""
    s = (s or "").upper()
    return {"CRIT": "🔴", "WARN": "🟡", "OK": "🟢", "UNKNOWN": "⚪"}.get(s, "⚪")


def _status_bullet(s: str) -> str:
    """Compact bullet for per-check lines."""
    s = (s or "").upper()
    if s == "CRIT":
        return "🔺"
    if s == "WARN":
        return "🔸"
    return "•"


def _overall_from_results(results: Iterable) -> str:
    """Compute overall status from individual check results."""
    worst = 0
    for r in results:
        st = _status_text(getattr(r, "status", "UNKNOWN"))
        worst = max(worst, _status_weight(st))
    return {2: "CRIT", 1: "WARN", 0: "OK"}[worst]


def _persist_results(owner_id: int, domain: str, results: Iterable, persist: bool) -> None:
    """Persist results to storage if requested; strip '[cached Xm]' before saving."""
    if not persist:
        return
    for r in results:
        try:
            storage.save_history(
                owner_id,
                domain,
                getattr(r, "check", ""),
                getattr(r, "status", "UNKNOWN"),
                _strip_cached_suffix(getattr(r, "message", "")),
                getattr(r, "metrics", {}) or {},
            )
        except Exception as e:  # defensive: never break formatting on persistence errors
            log.warning(
                "format.persist_failed",
                extra={
                    "event": "format.persist_failed",
                    "owner_id": owner_id,
                    "domain": domain,
                    "check": getattr(r, "check", ""),
                    "error": e.__class__.__name__,
                },
            )


# ------------------------------- public API -------------------------------

async def _format_results(owner_id: int, domain: str, results: Iterable, persist: bool = True) -> str:
    """
    Store clean history (optionally) and format a compact result text with emojis.

    Output shape:
      🟢 example.com — OK
      • <check> — <STATUS> — message
      ...
    """
    _persist_results(owner_id, domain, results, persist)

    overall = _overall_from_results(results)
    head = f"{_status_emoji(overall)} <b>{html.escape(domain)}</b> — {overall}"

    lines = [head]
    for r in results:
        st = _status_text(getattr(r, "status", "UNKNOWN"))
        bullet = _status_bullet(st)
        lines.append(
            "{bullet} <code>{check}</code> — <b>{status}</b> — {msg}".format(
                bullet=bullet,
                check=html.escape(str(getattr(r, "check", ""))),
                status=html.escape(st),
                msg=html.escape(str(getattr(r, "message", "") or "")),
            )
        )
    return "\n".join(lines)


async def _format_results_summary(owner_id: int, domain: str, results: Iterable, persist: bool = True) -> str:
    """
    Compact per-domain summary: overall line; details only for non-OK checks.

    For WARN/CRIT overall status, prints only problematic checks (CRIT/WARN/UNKNOWN),
    sorted by severity (CRIT first) and then by check name for a stable output.
    """
    _persist_results(owner_id, domain, results, persist)

    overall = _overall_from_results(results)
    head = f"{_status_emoji(overall)} <b>{html.escape(domain)}</b> — {overall}"

    lines: List[str] = [head]
    if overall in ("WARN", "CRIT"):
        # Collect problematic checks
        bad: List[tuple[int, str, str, Any]] = []
        for r in results:
            st = _status_text(getattr(r, "status", "UNKNOWN"))
            if st in ("WARN", "CRIT", "UNKNOWN"):
                bad.append((-_status_weight(st), str(getattr(r, "check", "")), st, r))
        bad.sort()

        for _, _, st, r in bad:
            bullet = _status_bullet(st)
            lines.append(
                "{bullet} <code>{check}</code> — <b>{status}</b> — {msg}".format(
                    bullet=bullet,
                    check=html.escape(str(getattr(r, "check", ""))),
                    status=html.escape(st),
                    msg=html.escape(str(getattr(r, "message", "") or "")),
                )
            )

    return "\n".join(lines)
