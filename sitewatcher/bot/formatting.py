from __future__ import annotations

import html
import logging
from datetime import datetime, timezone
from typing import Iterable

from .. import storage
from ..checks.base import CheckOutcome
from ..utils.results import (
    is_missing_malware_report,
    overall_from_results as _overall_from_results,
    status_text as _status_text,
    status_weight as _status_weight,
    status_emoji as _status_emoji,
    status_bullet as _status_bullet,
    strip_cached_suffix as _strip_cached_suffix,
)

log = logging.getLogger(__name__)


# ----------------------------- small helpers -----------------------------

def _fmt_ts(timestamp: str | None) -> str:
    """Render stored ISO/SQLite timestamps in UTC, or a placeholder if invalid."""
    if not timestamp:
        return "[--.-- --:-- UTC]"
    try:
        dt = datetime.fromisoformat(timestamp)
    except ValueError:
        return "[--.-- --:-- UTC]"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("[%d.%m %H:%M UTC]")


def _format_check(result: CheckOutcome) -> str:
    status = _status_text(result.status)
    return (
        f"{_status_bullet(status)} <code>{html.escape(str(result.check))}</code>"
        f" — <b>{html.escape(status)}</b> — {html.escape(result.message)}"
    )


def _persist_results(owner_id: int, domain: str, results: Iterable, persist: bool) -> None:
    """Persist results to storage if requested; strip '[cached Xm]' before saving."""
    if not persist:
        return
    cleaned = [
        CheckOutcome(r.check, r.status, _strip_cached_suffix(r.message), r.metrics, r.cached,
                     getattr(r, "assessment_changed", False))
        for r in results
    ]
    storage.save_histories(owner_id, domain, cleaned, create_missing=False, source="manual")


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

    return "\n".join([head] + [_format_check(result) for result in results])


async def _format_results_summary(owner_id: int, domain: str, results: Iterable, persist: bool = True) -> str:
    """
    Compact per-domain summary: overall line; details only for non-OK checks.

    For WARN/CRIT overall status, prints only problematic checks (CRIT/WARN/UNKNOWN),
    sorted by severity (CRIT first) and then by check name for a stable output.
    """
    _persist_results(owner_id, domain, results, persist)

    overall = _overall_from_results(results)
    head = f"{_status_emoji(overall)} <b>{html.escape(domain)}</b> — {overall}"

    bad = sorted(
        (result for result in results
         if _status_text(result.status) in {"CRIT", "WARN", "UNKNOWN"}
         and not is_missing_malware_report(result.check, result.status, result.message)),
        key=lambda result: (-_status_weight(result.status), result.check),
    )
    return "\n".join([head] + [_format_check(result) for result in bad])
