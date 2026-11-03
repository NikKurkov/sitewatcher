"""Shared severity and cached-message handling for CLI, checks, and the bot."""
from __future__ import annotations

import re
import json
from datetime import datetime, timedelta, timezone
from typing import Iterable


def current_rkn_result(check_name: str, metrics, max_age_hours: int = 168, *, status=None) -> bool:
    """Frozen-source results remain history, never evidence for a current RKN result."""
    if check_name not in {'rkn_domain', 'rkn_ip'}:
        return True
    try:
        data = json.loads(metrics) if isinstance(metrics, str) else metrics
        if not isinstance(data, dict):
            return False
        if status_text(status) == 'UNKNOWN' and data.get('registry_version') == '3':
            return True  # A failed current attempt still has a valid scheduling timestamp.
        if data.get('source') not in {'antifilter', 'bol-van'}:
            return False
        updated = datetime.fromisoformat(data['source_updated_at'].replace('Z', '+00:00'))
        age = datetime.now(timezone.utc) - updated
        return -timedelta(minutes=5) <= age <= timedelta(hours=max_age_hours)
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        return False


def status_text(status: object) -> str:
    return str(getattr(status, "value", status)).upper()


def status_weight(status: object) -> int:
    return {"CRIT": 2, "WARN": 1, "UNKNOWN": 1}.get(status_text(status), 0)


def status_emoji(status: object) -> str:
    return {"CRIT": "🔴", "WARN": "🟡", "OK": "🟢", "UNKNOWN": "⚪"}.get(status_text(status), "⚪")


def status_bullet(status: object) -> str:
    return {"CRIT": "🔺", "WARN": "🔸"}.get(status_text(status), "•")


def overall_from_statuses(statuses: Iterable, *, empty: str = "UNKNOWN") -> str:
    worst = max((status_weight(status) for status in statuses), default=-1)
    return {2: "CRIT", 1: "WARN", 0: "OK", -1: empty}[worst]


def overall_from_results(results: Iterable) -> str:
    return overall_from_statuses(getattr(result, "status", "UNKNOWN") for result in results)


def strip_cached_suffix(message: str) -> str:
    return re.sub(r"(?:\s*\[cached\s+\d+m\])+$", "", message or "", flags=re.I)
