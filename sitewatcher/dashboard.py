"""Server-rendered monitoring view; usable without JavaScript."""
from __future__ import annotations

import html
from datetime import datetime, timezone
from importlib.resources import files
from string import Template


FILTERS = {
    "all": "All domains", "problems": "Problems", "ok": "Healthy", "warn": "Warnings",
    "crit": "Critical", "unknown": "No data", "paused": "Paused", "stale": "Overdue",
}
_LABELS = {"OK": "Healthy", "WARN": "Warning", "CRIT": "Critical", "UNKNOWN": "No data"}


def _badge(status: str) -> str:
    label = _LABELS.get(status, "No data")
    css = status.lower() if status in _LABELS else "unknown"
    return f'<span class="badge {css}"><span class="dot" aria-hidden="true"></span>{label}</span>'


def _time(value: str | None) -> str:
    if not value:
        return '<span class="muted">Not yet</span>'
    try:
        timestamp = datetime.fromisoformat(value)
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        label = timestamp.astimezone(timezone.utc).strftime("%d %b, %H:%M UTC")
    except ValueError:
        return '<span class="muted">Unknown</span>'
    return f'<time datetime="{html.escape(value, quote=True)}">{label}</time>'


def _domain_card(domain: dict) -> str:
    checks = []
    for check in domain["checks"]:
        freshness = '<span class="tag overdue">Overdue</span>' if check["stale"] else ""
        checks.append(
            f'<tr><th scope="row"><code>{html.escape(check["name"])}</code>{freshness}</th>'
            f'<td>{_badge(check["status"])}</td>'
            f'<td class="check-message">{html.escape(check["message"])}</td>'
            f'<td class="check-time">{_time(check["checked_at"])}</td></tr>'
        )
    tags = ""
    if domain["paused"]:
        tags += '<span class="tag">Paused</span>'
    elif domain["stale"]:
        tags += '<span class="tag overdue">Overdue</span>'
    error = f'<p class="domain-error">{html.escape(domain["error"])}</p>' if domain["error"] else ""
    check_table = (
        '<table><caption class="sr-only">Latest saved check results</caption>'
        '<thead><tr><th scope="col">Check</th><th scope="col">State</th>'
        '<th scope="col">Result</th><th scope="col">Checked</th></tr></thead>'
        f'<tbody>{"".join(checks)}</tbody></table>'
    ) if checks else '<p class="empty-checks">No enabled checks with results.</p>'
    next_due = 'Paused' if domain["paused"] else _time(domain["next_due_at"])
    return f'''<details class="domain-card">
      <summary>
        <div class="domain-state">{_badge(domain["overall"])}</div>
        <div class="domain-name"><h2>{html.escape(domain["name"])}</h2><div class="tags">{tags}</div></div>
        <div class="domain-time"><span>Last checked</span>{_time(domain["last_checked_at"])}</div>
        <span class="expand-label">View checks <span aria-hidden="true">⌄</span></span>
      </summary>
      <div class="domain-details">
        <div class="detail-heading"><h3>Latest checks</h3><p>Next due: {next_due}</p></div>
        {error}<div class="table-scroll">{check_table}</div>
      </div>
    </details>'''


def render_dashboard(snapshot: dict, query: str = "", status: str = "all", *,
                     auto_refresh: bool = True) -> str:
    """Render one owner-scoped snapshot with server-side search and filters."""
    if status not in FILTERS:
        raise ValueError("Unknown status filter")
    selected = []
    for domain in snapshot["domains"]:
        matches = (
            status == "all"
            or status == "problems" and domain["overall"] in {"CRIT", "WARN"}
            or status in {"paused", "stale"} and domain[status]
            or domain["overall"].lower() == status
        )
        if matches and query.casefold() in domain["name"].casefold():
            selected.append(domain)
    selected.sort(key=lambda domain: (
        {"CRIT": 0, "WARN": 1, "UNKNOWN": 2, "OK": 3}.get(domain["overall"], 2), domain["name"],
    ))
    content = "\n".join(_domain_card(domain) for domain in selected)
    if not content:
        message = "No domains match your filters." if snapshot["summary"]["total"] else "No domains yet."
        content = f'''<div class="empty-state"><span class="empty-icon" aria-hidden="true">◎</span>
          <h2>{message}</h2><p>Manage domains in your Telegram bot. Try <code>/add example.com</code>.</p>
          <a href="/">Reset filters</a></div>'''
    options = "".join(
        f'<option value="{key}"{" selected" if key == status else ""}>{label}</option>'
        for key, label in FILTERS.items()
    )
    summary = snapshot["summary"]
    template = Template(files("sitewatcher").joinpath("data/dashboard.html").read_text(encoding="utf-8"))
    return template.substitute(
        query=html.escape(query, quote=True), status_options=options, domains=content,
        total=summary["total"], healthy=summary["ok"], problems=summary["crit"] + summary["warn"],
        paused=summary["paused"], overdue=summary["stale"], shown=len(selected),
        generated=_time(snapshot["generated_at"]),
        refresh_meta='<meta http-equiv="refresh" content="30">' if auto_refresh else '',
        refresh_checked='' if auto_refresh else ' checked',
        refresh_label='Refreshes every 30 seconds' if auto_refresh else 'Auto refresh paused',
    )
