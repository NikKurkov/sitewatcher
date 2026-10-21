"""Shared severity and cached-message handling for CLI, checks, and the bot."""
from __future__ import annotations

import re
from typing import Iterable


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
