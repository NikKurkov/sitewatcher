"""Server-rendered monitoring view; usable without JavaScript."""
from __future__ import annotations

import html
from datetime import datetime, timezone
from importlib.resources import files
from string import Template
from urllib.parse import urlencode


FILTERS = {
    "all": "All domains", "problems": "Problems", "ok": "Healthy", "warn": "Warnings",
    "crit": "Critical", "unknown": "No data", "paused": "Paused", "stale": "Overdue",
}
_LABELS = {"OK": "Healthy", "WARN": "Warning", "CRIT": "Critical", "UNKNOWN": "No data"}


def _theme(value: str) -> str:
    return value if value in {"light", "dark", "system"} else "system"


def theme_controls(theme: str, next_path: str = "/") -> str:
    links = []
    for mode, label in (("light", "Day"), ("dark", "Night"), ("system", "System")):
        query = html.escape(urlencode({"mode": mode, "next": next_path}), quote=True)
        current = ' aria-current="true"' if mode == _theme(theme) else ''
        links.append(f'<a href="/theme?{query}" data-theme-choice="{mode}"{current}>{label}</a>')
    return '<nav class="theme-controls" aria-label="Color theme">' + ''.join(links) + '</nav>'


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


def _domain_card(domain: dict, csrf_token: str | None = None) -> str:
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
    controls = ""
    if csrf_token is not None:
        from .management import domain_action
        query = html.escape(urlencode({"domain": domain["name"]}), quote=True)
        controls = ('<nav class="domain-actions" aria-label="Manage domain">'
                    f'<a href="/domains/edit?{query}">Edit settings</a>'
                    f'<a href="/domains/history?{query}">History</a>' +
                    domain_action('check', domain['name'], 'Run checks', csrf_token) +
                    domain_action('resume' if domain['paused'] else 'pause', domain['name'],
                                  'Resume' if domain['paused'] else 'Pause', csrf_token) +
                    f'<a href="/domains/delete?{query}">Remove</a></nav>'
                    '<details class="reset-confirm"><summary>Reset settings to inherited values'
                    '</summary><p>This removes all per-domain overrides, including the proxy.</p>' +
                    domain_action('reset', domain['name'], 'Reset all overrides', csrf_token) +
                    '</details>')
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
        {error}<div class="table-scroll">{check_table}</div>{controls}
      </div>
    </details>'''


def render_dashboard(snapshot: dict, query: str = "", status: str = "all", *,
                     auto_refresh: bool = True, csrf_token: str | None = None,
                     notice: str = "", theme: str = "system") -> str:
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
    content = "\n".join(_domain_card(domain, csrf_token) for domain in selected)
    if not content:
        message = "No domains match your filters." if snapshot["summary"]["total"] else "No domains yet."
        guidance = ('<a href="/domains/new">Add your first domain</a> to start monitoring.'
                    if csrf_token is not None else
                    'Manage domains in your Telegram bot. Try <code>/add example.com</code>.')
        content = f'''<div class="empty-state"><span class="empty-icon" aria-hidden="true">◎</span>
          <h2>{message}</h2><p>{guidance}</p>
          <a href="/">Reset filters</a></div>'''
    options = "".join(
        f'<option value="{key}"{" selected" if key == status else ""}>{label}</option>'
        for key, label in FILTERS.items()
    )
    management = ""
    if csrf_token is not None:
        from .management import domain_action
        management = ('<nav class="management-toolbar" aria-label="Manage workspace">'
                      '<a class="button-link" href="/domains/new">Add domain</a>'
                      '<a href="/import">Import CSV</a><a href="/export.csv">Export CSV</a>'
                      '<a href="/workspace">Workspace settings</a>' +
                      domain_action('check', '*', 'Run all checks', csrf_token) + '</nav>')
    summary = snapshot["summary"]
    template = Template(files("sitewatcher").joinpath("data/dashboard.html").read_text(encoding="utf-8"))
    return template.substitute(
        theme=_theme(theme), theme_controls=theme_controls(theme), management=management,
        notice=f'<p class="notice" role="status">{html.escape(notice)}</p>' if notice else '',
        footer=('Read-only view · Monitoring continues in your Telegram bot.'
                if csrf_token is None else 'Scheduled monitoring continues in your Telegram bot.'),
        query=html.escape(query, quote=True), status_options=options, domains=content,
        total=summary["total"], healthy=summary["ok"], problems=summary["crit"] + summary["warn"],
        paused=summary["paused"], overdue=summary["stale"], shown=len(selected),
        generated=_time(snapshot["generated_at"]),
        refresh_meta='<meta http-equiv="refresh" content="30">' if auto_refresh else '',
        refresh_checked='' if auto_refresh else ' checked',
        refresh_label='Refreshes every 30 seconds' if auto_refresh else 'Auto refresh paused',
    )
