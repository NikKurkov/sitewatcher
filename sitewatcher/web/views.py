"""Read models and small, dependency-free charts for the web panel."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any

from markupsafe import Markup

from .. import storage
from ..config import AppConfig, resolve_settings


STATUS_ORDER = {"CRIT": 0, "WARN": 1, "UNKNOWN": 2, "OK": 3}
STATUS_COLOR = {"CRIT": "#e45f64", "WARN": "#e8a241", "UNKNOWN": "#91a0ae", "OK": "#3dbb91"}


def overall_status(rows: Sequence[str]) -> str:
    return min(rows, key=lambda status: STATUS_ORDER.get(status, 2), default="UNKNOWN")


def domain_cards(owner_id: int, cfg: AppConfig) -> tuple[list[dict[str, Any]], dict[str, int]]:
    latest = storage.latest_results_for_owner(owner_id)
    cards = []
    for name in storage.list_domains(owner_id):
        settings = resolve_settings(cfg, name, storage.get_domain_override(owner_id, name) or {})
        enabled = [key for key, value in settings.checks.model_dump().items() if value]
        rows = latest.get(name, {})
        statuses = [str(rows[key]["status"]).upper() if key in rows else "UNKNOWN" for key in enabled]
        status = overall_status(statuses)
        observed = [rows[key] for key in enabled if key in rows]
        newest = max(observed, key=lambda row: row["id"], default=None)
        worst = next((rows[key] for key in enabled if key in rows and rows[key]["status"] == status), None)
        cards.append({
            "name": name,
            "status": status,
            "checked_at": newest["created_at"] if newest else None,
            "message": worst["message"] if worst else "Awaiting first check",
        })
    cards.sort(key=lambda card: (STATUS_ORDER.get(card["status"], 2), card["name"]))
    counts = Counter(card["status"] for card in cards)
    return cards, {
        "total": len(cards), "ok": counts["OK"], "warn": counts["WARN"],
        "crit": counts["CRIT"], "unknown": counts["UNKNOWN"],
    }


def domain_checks(owner_id: int, domain: str, cfg: AppConfig) -> list[dict[str, str | None]]:
    settings = resolve_settings(cfg, domain, storage.get_domain_override(owner_id, domain) or {})
    rows = storage.latest_check_results(owner_id, domain)
    checks = []
    for name, enabled in settings.checks.model_dump().items():
        if not enabled:
            continue
        row = rows.get(name)
        checks.append({
            "check": name,
            "status": str(row["status"]).upper() if row else "UNKNOWN",
            "message": row["message"] if row else "No result yet",
            "created_at": row["created_at"] if row else None,
        })
    return checks


def history_dicts(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [dict(row) for row in rows]


def status_chart(rows: Sequence[Mapping[str, Any]]) -> Markup:
    """Return an accessible status-sample strip; values never enter HTML unescaped."""
    if not rows:
        return Markup('<p class="empty-chart">No samples in this period.</p>')
    samples = list(reversed(rows))[-120:]
    step = 720 / len(samples)
    bars = "".join(
        f'<rect x="{index * step:.1f}" y="12" width="{max(step - 2, 1):.1f}" height="68" '
        f'fill="{STATUS_COLOR.get(str(row["status"]).upper(), STATUS_COLOR["UNKNOWN"])}" />'
        for index, row in enumerate(samples)
    )
    return Markup(
        '<svg class="status-chart" viewBox="0 0 720 92" role="img" '
        'aria-label="Recent check results, oldest to newest">' + bars + '</svg>'
    )


def latency_chart(rows: Sequence[Mapping[str, Any]]) -> Markup:
    """Return a small SVG of numeric HTTP response-time samples."""
    values = []
    for row in reversed(rows):
        if row.get("check") != "http_basic" and row.get("check_name") != "http_basic":
            continue
        try:
            metrics = json.loads(row.get("metrics_json") or "{}")
            value = float(metrics.get("latency_ms_total", metrics.get("latency_ms_initial")))
            if 0 <= value < 1_000_000:
                values.append(value)
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
    values = values[-120:]
    if not values:
        return Markup('<p class="empty-chart">No HTTP latency samples in this period.</p>')
    high = max(max(values), 1)
    points = " ".join(
        f"{index * 720 / max(len(values) - 1, 1):.1f},{78 - value * 66 / high:.1f}"
        for index, value in enumerate(values)
    )
    return Markup(
        '<svg class="latency-chart" viewBox="0 0 720 92" role="img" '
        'aria-label="HTTP response time trend in milliseconds">'
        f'<title>HTTP latency: {values[-1]:.0f} ms latest, {high:.0f} ms peak</title>'
        f'<polyline points="{points}" fill="none" stroke="currentColor" stroke-width="3" '
        'stroke-linecap="round" stroke-linejoin="round" /></svg>'
    )
