from html.parser import HTMLParser

import pytest

from sitewatcher.dashboard import render_dashboard


class Forms(HTMLParser):
    def __init__(self, page):
        super().__init__()
        self.forms = []
        self.current = None
        self.feed(page)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'form':
            self.current = {**attrs, 'inputs': []}
            self.forms.append(self.current)
        elif tag == 'input' and self.current is not None:
            self.current['inputs'].append(attrs)

    def handle_endtag(self, tag):
        if tag == 'form':
            self.current = None


def settings():
    return {'domain': 'example.com', 'check_names': ['http_basic', 'ping'],
            'values': {'domain': 'example.com', 'check.ping': 'off',
                       'interval_minutes': '12', 'keywords': '["<script>"]',
                       'proxy': 'must-never-appear', 'proxy_mode': 'keep'},
            'proxy_present': True, 'effective': {'interval_minutes': 12, 'proxy': 'configured'}}


@pytest.mark.parametrize('view', ['add', 'edit', 'delete', 'history', 'import', 'workspace'])
def test_management_views_use_native_forms_without_refresh_or_inline_scripts(view):
    from sitewatcher.management import render_management
    context = settings() if view in {'add', 'edit'} else {
        'domain': 'example.com', 'rows': [], 'alerts_enabled': True}
    page = render_management(view, context, 'test-token')
    assert '<script>' not in page and 'http-equiv="refresh"' not in page
    assert '<script src="/theme.js" defer></script>' in page
    assert '/style.css' in page
    assert ('<label' in page) if view != 'history' else ('No saved' in page)
    for form in Forms(page).forms:
        assert form['method'] == 'post'
        assert {'type': 'hidden', 'name': 'csrf_token', 'value': 'test-token'} in form['inputs']


def test_settings_form_retains_inheritance_values_without_proxy_credentials():
    from sitewatcher.management import render_management
    page = render_management('edit', settings(), 'token', error='<unsafe>')
    assert 'must-never-appear' not in page
    assert 'type="password"' in page and 'name="proxy" value=""' in page
    assert 'name="check.ping"' in page and 'value="off" selected' in page
    assert 'name="interval_minutes" value="12"' in page
    assert '[&quot;&lt;script&gt;&quot;]' in page
    assert '&lt;unsafe&gt;' in page and '<unsafe>' not in page
    assert '/domains/reset' in page and 'inherit' in page.lower()
    for key in ['http_timeout_s', 'latency_warn_ms', 'latency_crit_ms', 'tls_warn_days', 'ports']:
        assert f'name="{key}"' in page


def test_delete_requires_typed_domain_and_import_offers_upload_and_text():
    from sitewatcher.management import render_management
    page = render_management('delete', {'domain': '<bad>'}, 'token')
    assert 'name="confirm"' in page and '&lt;bad&gt;' in page and '<bad>' not in page
    page = render_management('import', {}, 'token')
    assert 'enctype="multipart/form-data"' in page
    assert 'type="file"' in page and 'name="csv_text"' in page
    assert 'value="merge"' in page and 'value="replace"' in page


def test_dashboard_management_is_opt_in_and_every_mutation_uses_post():
    snapshot = {'generated_at': None,
                'summary': {'total': 1, 'ok': 0, 'warn': 0, 'crit': 0, 'paused': 0, 'stale': 0},
                'domains': [{'name': 'example.com', 'overall': 'UNKNOWN', 'paused': False,
                             'stale': False, 'last_checked_at': None, 'next_due_at': None,
                             'checks': [], 'error': None}]}
    page = render_dashboard(snapshot)
    assert 'csrf_token' not in page and '/domains/add' not in page
    assert 'Read-only view' in page
    page = render_dashboard(snapshot, csrf_token='token', notice='<unsafe>')
    for action in ['/domains/edit?', '/domains/history?', '/domains/delete?', '/domains/new',
                   '/import', '/export.csv', '/workspace']:
        assert action in page
    assert '&lt;unsafe&gt;' in page and '<unsafe>' not in page
    posts = [form for form in Forms(page).forms if form['method'] == 'post']
    assert {form['action'] for form in posts} == {'/domains/check', '/domains/pause', '/domains/reset'}
    for form in posts:
        assert any(inp.get('name') == 'csrf_token' for inp in form['inputs'])
    assert 'Read-only view' not in page


def test_all_management_pages_offer_safe_theme_switching():
    from sitewatcher.management import render_management
    page = render_management('edit', settings(), 'token', theme='dark')
    assert 'data-theme="dark"' in page
    assert '/theme?mode=light' in page and '/theme?mode=system' in page
    page = render_management('edit', settings(), 'token', theme='"><unsafe>')
    assert 'data-theme="system"' in page and '<unsafe>' not in page


def test_edit_form_includes_revision_for_stale_update_protection():
    from sitewatcher.management import render_management
    context = settings()
    context['revision'] = 'revision-1'
    page = render_management('edit', context, 'token')
    assert 'name="revision" value="revision-1"' in page


def test_check_selectors_have_readable_english_labels():
    from sitewatcher.management import render_management
    page = render_management('edit', settings(), 'token')
    assert '<label for="check.http_basic">HTTP availability</label>' in page
    assert '<label for="check.ping">Ping reachability</label>' in page
