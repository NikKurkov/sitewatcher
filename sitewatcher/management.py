"""Native browser forms for the fixed monitoring workspace."""
from __future__ import annotations

import html
import json
from urllib.parse import urlencode

from .dashboard import _badge, _theme, _time, theme_controls


_CHECK_LABELS = {
    'http_basic': 'HTTP availability', 'tls_cert': 'TLS certificate',
    'keywords': 'Required keywords', 'deface': 'Defacement markers',
    'ping': 'Ping reachability', 'rkn_block': 'RKN blocking', 'ports': 'TCP ports',
    'whois': 'Domain registration', 'ip_blacklist': 'IP blocklists',
    'ip_change': 'IP address changes', 'malware': 'Malware detection',
}


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def csrf_input(token: str) -> str:
    return f'<input type="hidden" name="csrf_token" value="{_escape(token)}">'


def domain_action(action: str, domain: str, label: str, token: str) -> str:
    return (f'<form method="post" action="/domains/{action}" class="inline-form">'
            f'{csrf_input(token)}<input type="hidden" name="domain" value="{_escape(domain)}">'
            f'<button type="submit">{_escape(label)}</button></form>')


def _select(name: str, value: str, choices: tuple[tuple[str, str], ...]) -> str:
    options = ''.join(f'<option value="{_escape(key)}"'
                      f'{" selected" if key == value else ""}>{_escape(label)}</option>'
                      for key, label in choices)
    return f'<select id="{_escape(name)}" name="{_escape(name)}">{options}</select>'


def _settings(view: str, context: dict, token: str) -> str:
    values = context['values']
    domain = values.get('domain', context['domain'])
    editing = view == 'edit'
    action = 'save' if editing else 'add'
    result = [f'<form method="post" action="/domains/{action}" class="management-form">',
              csrf_input(token), '<input type="hidden" name="revision" '
              f'value="{_escape(context.get("revision", values.get("revision", "")))}">',
              '<label for="domain">Domain</label>',
              f'<input id="domain" name="domain" value="{_escape(domain)}" required '
              f'autocomplete="off"{" readonly" if editing else ""}>',
              '<p class="field-help">Enter a hostname such as example.com.</p>',
              '<fieldset><legend>Checks</legend>',
              '<p class="field-help">Inherit follows the workspace configuration.</p>',
              '<div class="form-grid">']
    for name in context['check_names']:
        key = f'check.{name}'
        result.append(f'<div><label for="{_escape(key)}">{_escape(_CHECK_LABELS.get(name, name))}</label>' +
                      _select(key, values.get(key, ''),
                              (('', 'Inherit'), ('on', 'On'), ('off', 'Off'))) + '</div>')
    result.extend(['</div></fieldset>', '<fieldset><legend>Per-domain settings</legend>',
                   '<p class="field-help">Leave a field blank to inherit its workspace value.</p>',
                   '<div class="form-grid">'])
    fields = (
        ('interval_minutes', 'Check interval (minutes; 0 pauses)', '0', '1'),
        ('http_timeout_s', 'HTTP timeout (seconds)', '1', '1'),
        ('latency_warn_ms', 'Latency warning (milliseconds)', '0', '1'),
        ('latency_crit_ms', 'Latency critical (milliseconds)', '0', '1'),
        ('tls_warn_days', 'TLS warning (days before expiry)', '0', '1'),
    )
    for key, label, minimum, step in fields:
        result.append(f'<div><label for="{key}">{label}</label><input type="number" '
                      f'id="{key}" name="{key}" value="{_escape(values.get(key, ""))}" '
                      f'min="{minimum}" step="{step}"></div>')
    result.append('</div>')
    for key, label, example in [('keywords', 'Required keywords (JSON array)', '["Welcome", "Shop"]'),
                                ('ports', 'TCP ports (JSON array)', '[80, 443]')]:
        result.append(f'<label for="{key}">{label}</label><textarea id="{key}" name="{key}" '
                      f'rows="3" aria-describedby="{key}-help">'
                      f'{_escape(values.get(key, ""))}</textarea><p class="field-help" '
                      f'id="{key}-help">Example: <code>{_escape(example)}</code>. '
                      'Use [] for an empty list; blank inherits.</p>')
    proxy_state = 'A proxy is configured.' if context['proxy_present'] else 'No proxy configured.'
    result.extend(['</fieldset><fieldset><legend>Proxy</legend>',
                   f'<p class="field-help">{proxy_state} Credentials are never displayed.</p>',
                   '<label for="proxy_mode">Proxy action</label>',
                   _select('proxy_mode', values.get('proxy_mode', 'keep'),
                           (('keep', 'Keep existing override'), ('inherit', 'Inherit workspace proxy'),
                            ('clear', 'Clear domain override (use common client)'), ('set', 'Set a new proxy'))),
                   '<label for="proxy">New proxy URL</label>',
                   '<input type="password" id="proxy" name="proxy" value="" '
                   'autocomplete="new-password" aria-describedby="proxy-help">',
                   '<p class="field-help" id="proxy-help">Choose “Set a new proxy” to apply this '
                   'value. Re-enter it after a validation error.</p></fieldset>',
                   '<div class="form-actions"><button type="submit">',
                   'Save settings' if editing else 'Add domain',
                   '</button><a href="/">Cancel</a></div></form>'])
    if editing:
        effective = {key: value for key, value in context.get('effective', {}).items()
                     if key != 'proxy'}
        result.append('<details class="effective-settings"><summary>Effective settings</summary>'
                      f'<pre>{_escape(json.dumps(effective, indent=2, ensure_ascii=False))}</pre>'
                      '</details><section class="danger-zone"><h2>Reset overrides</h2>'
                      '<p>Reset removes every per-domain override, including the proxy. '
                      'All settings will inherit workspace values.</p>' +
                      domain_action('reset', context['domain'], 'Reset all overrides', token) +
                      '</section>')
    return ''.join(result)


def render_management(view: str, context: dict, csrf_token: str, *, error: str = '',
                      theme: str = 'light') -> str:
    """Render escaped settings, confirmation, history, import or workspace forms."""
    titles = {'add': 'Add domain', 'edit': 'Edit domain', 'delete': 'Remove domain',
              'history': 'Recent check history', 'import': 'Import domain CSV',
              'workspace': 'Workspace settings'}
    title = titles[view]
    if view in {'add', 'edit'}:
        body = _settings(view, context, csrf_token)
    elif view == 'delete':
        domain = _escape(context['domain'])
        body = (f'<p>Remove <strong>{domain}</strong> and its saved check history? '
                'This cannot be undone.</p><form method="post" action="/domains/delete" '
                f'class="management-form">{csrf_input(csrf_token)}'
                f'<input type="hidden" name="domain" value="{domain}">'
                f'<label for="confirm">Type {domain} to confirm removal</label>'
                '<input id="confirm" name="confirm" required autocomplete="off">'
                '<div class="form-actions"><button type="submit" class="danger-button">'
                'Remove domain and history</button><a href="/">Cancel</a></div></form>')
    elif view == 'history':
        rows = ''.join(f'<tr><td>{_time(row.get("created_at"))}</td>'
                       f'<th scope="row">{_escape(row["check_name"])}</th>'
                       f'<td>{_badge(row["status"])}</td>'
                       f'<td class="check-message">{_escape(row["message"])}</td></tr>'
                       for row in context['rows'])
        body = (f'<p>{_escape(context["domain"])}</p><div class="table-scroll"><table>'
                '<caption class="sr-only">Recent saved check results</caption><thead><tr>'
                '<th scope="col">Checked (UTC)</th><th scope="col">Check</th>'
                '<th scope="col">State</th><th scope="col">Result</th></tr></thead>'
                f'<tbody>{rows}</tbody></table></div>' if rows else
                f'<p>No saved check history for {_escape(context["domain"])}.</p>')
    elif view == 'import':
        body = (f'<form method="post" action="/import" enctype="multipart/form-data" '
                f'class="management-form">{csrf_input(csrf_token)}'
                '<p>Choose a CSV backup or paste CSV text. Use only one source. '
                'Validate the selected mode before importing.</p>'
                '<label for="csv_file">CSV file</label>'
                '<input type="file" id="csv_file" name="csv_file" accept=".csv,text/csv">'
                '<label for="csv_text">Or paste CSV text</label>'
                f'<textarea id="csv_text" name="csv_text" rows="8">'
                f'{_escape(context.get("csv_text", ""))}</textarea>'
                '<label for="mode">Import mode</label>' +
                _select('mode', context.get('mode', 'merge'),
                        (('merge', 'Merge into existing overrides'),
                         ('replace', 'Replace overrides for listed domains'))) +
                '<p class="field-help">Domains absent from the CSV remain unchanged. '
                'Replace removes omitted overrides for each listed domain.</p>'
                '<div class="form-actions"><button type="submit">Import CSV</button>'
                '<a href="/">Cancel</a></div></form>')
    else:
        body = (f'<form method="post" action="/alerts" class="management-form">'
                f'{csrf_input(csrf_token)}<label for="enabled">Telegram notifications</label>' +
                _select('enabled', 'on' if context['alerts_enabled'] else 'off',
                        (('on', 'Enabled'), ('off', 'Disabled'))) +
                '<p class="field-help">The Telegram bot sends notifications when running. '
                'Scheduled monitoring also requires the bot process.</p>'
                '<button type="submit">Save notification setting</button></form>'
                '<p><a href="/export.csv">Download domain CSV backup</a> · '
                '<a href="/import">Import domain CSV</a></p>'
                '<p>Global configuration, credentials and scheduling are configured '
                'in your deployment.</p>')
    next_path = {'add': '/domains/new', 'edit': '/domains/edit',
                 'delete': '/domains/delete', 'history': '/domains/history',
                 'import': '/import', 'workspace': '/workspace'}[view]
    if view in {'edit', 'delete', 'history'}:
        next_path += '?' + urlencode({'domain': context['domain']})
    alert = f'<p class="notice error-notice" role="alert">{_escape(error)}</p>' if error else ''
    if error and view == 'edit':
        alert += f'<p><a href="{_escape(next_path)}">Reload saved settings</a></p>'
    if error and view == 'import':
        alert += '<p>Re-select the file or paste the CSV again. Private CSV content is not redisplayed.</p>'
    return f'''<!doctype html>
<html lang="en" data-theme="{_theme(theme)}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark"><script src="/theme.js" defer></script><title>SiteWatcher — {title}</title>
<link rel="stylesheet" href="/style.css"></head><body>
<a class="skip-link" href="#content">Skip to content</a>
<header class="topbar"><div class="topbar-inner"><a class="brand" href="/">
<span class="brand-mark" aria-hidden="true">◉</span>SiteWatcher</a>
<span class="workspace">Monitoring workspace</span>{theme_controls(theme, next_path)}</div></header>
<main class="management-page" id="content"><p><a href="/">← Back to domains</a></p>
<h1>{title}</h1>{alert}<section class="management-panel">{body}</section>
<footer><span>Scheduled monitoring continues in your Telegram bot.</span>
<span>SiteWatcher</span></footer></main></body></html>'''
