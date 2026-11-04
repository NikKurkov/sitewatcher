"""The owner UI presents saved observations honestly and preserves native forms."""
import pytest
from django.contrib.auth import get_user_model

from sitewatcher import storage


@pytest.fixture
def owner(web_database, client):
    from sitewatcher.webapp.models import Workspace
    user = get_user_model().objects.create_user(username='presentation-owner')
    workspace = Workspace.objects.create(user=user, owner_id=41)
    storage.ensure_user(41)
    client.force_login(user)
    return workspace


def get(client, path):
    return client.get(path, HTTP_HOST='localhost')


def test_overview_problem_first_and_real_measurement(owner, client):
    for name, ok in [('a-healthy.example', True), ('z-failing.example', False)]:
        storage.add_domain(41, name)
        from sitewatcher.config import ChecksModel
        storage.set_domain_override(41, name, {'checks': {
            key: key == 'http_basic' for key in ChecksModel.model_fields}})
        storage.save_history(41, name, 'http_basic', 'OK' if ok else 'CRIT',
                              'saved', {'availability': 'available' if ok else 'unavailable', 'final_code': 200 if ok else 503,
                                        'latency_ms_total': 125 if ok else None}, source='scheduled')
    body = get(client, '/').content.decode()
    assert 'Successful checks' in body
    assert body.index('z-failing.example') < body.index('a-healthy.example')
    assert 'Last checked' in body and '<time datetime=' in body
    assert 'Europe/Moscow' in body
    assert 'data-label="Successful checks"' in body
    assert 'data-label="Last checked"' in body
    assert '/domains/new' in body and '1 domain needs attention' in body
    header, main = body.split('</header>', 1)
    assert header.index('class="brand"') < header.index('1 domain needs attention')
    assert header.index('1 domain needs attention') < header.index('class="topbar-actions"')
    assert 'Updated just now' in header and '<time datetime=' in header
    assert 'Latest saved check result' in header
    assert header.count('class="toolbar-group"') == 3
    assert 'class="overview-history-toolbar"' not in main
    table_header = main.split('<thead>', 1)[1].split('</thead>', 1)[0]
    assert table_header.index('Last checked') < table_header.index('class="periods"')
    assert 'class="status-overview' not in main
    assert 'data-domain-key="z-failing.example"' in main
    assert 'data-domain-summary' in main and 'data-domain-toggle' in main
    assert 'class="domain-detail-row" hidden' in main
    assert 'class="domain-detail-layout"' in main
    assert 'Latest monitoring checks' in main and 'Response time' in main


def test_empty_and_no_observation_states(owner, client):
    empty = get(client, '/').content.decode()
    assert 'Add your first domain' in empty
    assert 'header-monitoring-summary' not in empty
    storage.add_domain(41, 'new.example')
    body = get(client, '/domains/history?domain=new.example').content.decode()
    assert 'No HTTP observations in this period' in body
    assert '24h' in body and '7d' in body and '30d' in body
    assert 'Successful checks' in body and 'Response time' in body
    assert 'No data' in body and '100%' not in body


@pytest.mark.parametrize('state,label', [
    ('healthy', 'No active warnings'), ('paused', 'Monitoring is paused'),
    ('waiting', 'Waiting for first results'),
])
def test_header_summary_preserves_monitoring_states(owner, client, state, label):
    from sitewatcher.config import ChecksModel

    storage.add_domain(41, 'one.example')
    storage.set_domain_override(41, 'one.example', {
        'checks': {key: key == 'http_basic' for key in ChecksModel.model_fields},
        **({'interval_minutes': 0} if state == 'paused' else {}),
    })
    if state != 'waiting':
        storage.save_history(41, 'one.example', 'http_basic', 'OK', 'up', {'final_code': 200})
    header = get(client, '/').content.decode().split('</header>', 1)[0]
    assert label in header
    assert ('is-neutral' in header) == (state != 'healthy')
    assert 'header-monitoring-summary' not in get(client, '/workspace').content.decode()


def test_detail_percent_sources_timezone_and_bounded_chart(owner, client):
    storage.add_domain(41, 'one.example')
    for ok in [True, False, True]:
        storage.save_history(41, 'one.example', 'http_basic', 'OK',
                             'private diagnostic', {'availability': 'available' if ok else 'unavailable', 'final_code': 200 if ok else 503,
                                                    'latency_ms_total': 120}, source='manual')
    body = get(client, '/domains/history?domain=one.example&days=7').content.decode()
    assert '66.7%' in body and '120 ms' in body
    assert '3 manual' in body and '0 scheduled' in body and '0 legacy' in body
    assert 'View chart data' in body and '<svg' in body
    assert 'Successful checks' in body and 'continuous uptime' not in body
    assert 'private diagnostic' not in body.split('Latest monitoring checks')[0]
    assert 'Europe/Moscow' in body
    for invalid in ['0', '365', 'nope']:
        assert get(client, '/domains/history?domain=one.example&days=' + invalid).status_code == 400


def test_chart_gaps_break_paths_and_unknown_latency():
    from sitewatcher.webapp.presentation import chart_context
    points = [{'index': i, 'latency_ms': value} for i, value in
              [(0, 100), (1, 110), (3, 120), (4, None), (5, 130), (6, 120)]]
    chart = chart_context(points, 'latency_ms')
    assert len(chart['segments']) == 3
    assert len(chart['dots']) == 5
    assert chart['dots'][2]['x'] == pytest.approx(3 * 1000 / 120)
    assert chart_context([], 'latency_ms')['segments'] == []


@pytest.mark.parametrize('age,label', [
    (0, 'Обновлено только что'), (60, 'Обновлено 1 минуту назад'),
    (120, 'Обновлено 2 минуты назад'), (300, 'Обновлено 5 минут назад'),
    (1260, 'Обновлено 21 минуту назад'), (3600, 'Обновлено 1 час назад'),
    (86400, 'Обновлено 1 день назад'), (-1, 'Дата и время находятся в будущем'),
])
def test_relative_summary_time_uses_russian_plural_forms(age, label):
    from django.utils import translation
    from sitewatcher.webapp.presentation import _updated_label

    with translation.override('ru'):
        assert str(_updated_label(age)) == label


def test_theme_native_fallback_and_forms(owner, client):
    client.cookies['sitewatcher_theme'] = 'dark'
    response = get(client, '/domains/new')
    body = response.content.decode()
    assert 'data-theme="dark"' in body and 'role="switch"' in body
    assert 'aria-checked="true"' in body and 'name="next"' in body
    assert '<details' in body and 'Advanced checks and settings' in body
    assert body.index('Website availability') < body.index('Advanced checks and settings')
    assert body.index('Check interval') < body.index('Advanced checks and settings')
    theme = get(client, '/theme?mode=light&next=/domains/new')
    assert theme.status_code == 303 and theme['Location'] == '/domains/new'
    assert theme.cookies['sitewatcher_theme'].value == 'light'
    assert 'max-age' in str(theme.cookies).lower()


def test_concurrent_deletion_during_edit_error_is_404(owner, client, monkeypatch):
    from sitewatcher.webapp import domains
    storage.add_domain(41, 'deleted.example')
    def delete_then_fail(*args, **kwargs):
        storage.remove_domain(41, 'deleted.example')
        raise ValueError('Domain not found')
    monkeypatch.setattr(domains, 'save_domain', delete_then_fail)
    response = client.post('/domains/edit', {'domain': 'deleted.example', 'revision': 'old'},
                           HTTP_HOST='localhost')
    assert response.status_code == 404
    assert not storage.domain_exists(41, 'deleted.example')


def test_anonymous_theme_only_changes_cosmetic_cookie(web_database, client):
    response = get(client, '/theme?mode=dark&next=/login/')
    assert response.status_code == 303 and response['Location'] == '/login/'
    assert response.cookies['sitewatcher_theme'].value == 'dark'
    assert get(client, '/').status_code == 302
    assert get(client, '/theme?mode=dark&next=https://evil.example/').status_code == 400


def test_new_domain_form_selects_workspace_defaults(owner, client):
    from html.parser import HTMLParser
    class SelectedOptions(HTMLParser):
        def __init__(self):
            super().__init__()
            self.name = None
            self.values = {}
        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            if tag == 'select':
                self.name = attrs.get('name')
            if tag == 'option' and 'selected' in attrs:
                self.values[self.name] = attrs['value']
    parser = SelectedOptions()
    parser.feed(get(client, '/domains/new').content.decode())
    from sitewatcher.config import ChecksModel
    assert {key: parser.values['check.' + key] for key in ChecksModel.model_fields} == {
        key: ''
        for key in ChecksModel.model_fields}
    parser.values.update(domain='basic.example')
    response = client.post('/domains/add', parser.values, HTTP_HOST='localhost')
    assert response.status_code == 303
    assert 'checks' not in storage.get_domain_override(41, 'basic.example')


def test_new_domain_interval_is_filled_from_configured_schedule(owner, client, settings):
    from sitewatcher.config import AppConfig
    settings.SITEWATCHER_CONFIG = AppConfig.model_validate({
        'schedules': {'http_basic': {'interval_minutes': 17}},
        'defaults': {'checks': {'ping': True}},
    })
    body = get(client, '/domains/new').content.decode()
    assert 'name="interval_minutes" value="17"' in body
    assert '<option value="" selected>Default (On)</option>' in body
    assert 'placeholder="Default (10)"' in body
    assert 'JSON list' not in body


def test_rkn_controls_and_history_distinguish_domain_critical_from_ip_warning(owner, client,
                                                                            settings):
    from sitewatcher.config import AppConfig, ChecksModel
    settings.SITEWATCHER_CONFIG = AppConfig.model_validate({'defaults': {'checks': {
        **dict.fromkeys(ChecksModel.model_fields, False), 'rkn_domain': True, 'rkn_ip': True,
    }}})
    body = get(client, '/domains/new').content.decode()
    assert 'name="check.rkn_domain"' in body and 'RKN domain blocking' in body
    assert 'name="check.rkn_ip"' in body and 'RKN IP listing' in body
    assert 'name="check.rkn_block"' not in body
    storage.add_domain(41, 'shared.example')
    storage.save_history(41, 'shared.example', 'rkn_block', 'CRIT', 'Legacy IP result', {})
    from datetime import datetime, timezone
    metrics = {'source': 'antifilter', 'source_updated_at': datetime.now(timezone.utc).isoformat()}
    storage.save_history(41, 'shared.example', 'rkn_domain', 'OK', 'Domain not listed', metrics)
    storage.save_history(41, 'shared.example', 'rkn_ip', 'WARN', 'Shared IP listed', metrics)
    body = get(client, '/domains/history?domain=shared.example').content.decode()
    assert 'badge warn' in body and 'Warning' in body and 'Critical' not in body
    assert body.count('RKN domain blocking') == body.count('RKN IP listing') == 3
    assert 'Legacy RKN blocking' in body


def test_history_tolerates_unparseable_legacy_time():
    from sitewatcher.webapp.presentation import local_time
    assert local_time('invalid legacy timestamp', 'Europe/Moscow') is None


def test_overview_summary_does_not_count_paused_domain_as_healthy(owner, client):
    from sitewatcher.config import ChecksModel
    storage.add_domain(41, 'paused.example')
    storage.set_domain_override(41, 'paused.example', {'interval_minutes': 0, 'checks': {
        key: key == 'http_basic' for key in ChecksModel.model_fields}})
    storage.save_history(41, 'paused.example', 'http_basic', 'OK', 'saved',
                         {'final_code': 200}, source='scheduled')
    body = get(client, '/').content.decode()
    assert '0 healthy' in body and '1 paused' in body


def test_observation_labels_include_local_timezone():
    from sitewatcher.webapp.presentation import local_time
    stamp = local_time('2026-10-22T12:00:00Z', 'Europe/Moscow')
    assert stamp['iso'] == '2026-10-22T12:00:00+00:00'
    assert stamp['label'] == '22 Oct 2026, 15:00 MSK'


@pytest.mark.parametrize('days', [1, 7, 30])
def test_latency_bucket_starts_align_with_the_true_window(days):
    from datetime import datetime, timedelta, timezone
    from sitewatcher.webapp.presentation import chart_context
    start = datetime(2026, 10, 1, tzinfo=timezone.utc)
    duration = timedelta(days=days)
    points = [{'index': index, 'start_at': start + index * duration / 120, 'latency_ms': 100}
              for index in [0, 60, 119]]
    chart = chart_context(points, 'latency_ms')
    for point, dot in zip(points, chart['dots'], strict=True):
        assert dot['x'] / 1000 == pytest.approx((point['start_at'] - start) / duration)
    assert chart['dots'][-1]['x'] < 1000


@pytest.mark.parametrize(('field', 'value', 'extra'), [
    ('domain', 'not a hostname', {}),
    ('domain', 'duplicate.example', {}),
    ('keywords', '[', {}),
    ('ports', '{"unsafe-input-name": 1}', {}),
    ('ports', '[70000]', {}),
    ('proxy', '', {'proxy_mode': 'set'}),
    ('proxy', 'bad://user:private-password@example.com', {'proxy_mode': 'set'}),
    ('proxy_mode', 'unsafe-input-name', {}),
    ('interval_minutes', 'no-number', {}),
])
def test_native_form_errors_identify_fields_without_exposing_proxy(owner, client, field, value, extra):
    from html.parser import HTMLParser
    storage.add_domain(41, 'duplicate.example')
    response = client.post('/domains/add', {
        'domain': 'draft.example', field: value, **extra}, HTTP_HOST='localhost')
    assert response.status_code == 400
    body = response.content.decode()
    class FormTags(HTMLParser):
        def __init__(self):
            super().__init__()
            self.tags = {}
        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            if 'id' in attrs:
                self.tags[attrs['id']] = attrs
    parsed = FormTags()
    parsed.feed(body)
    assert parsed.tags[field].get('aria-invalid') == 'true'
    assert field + '-error' in parsed.tags[field].get('aria-describedby', '').split()
    assert field + '-error' in parsed.tags
    assert parsed.tags['proxy']['value'] == ''
    assert 'private-password' not in body
    # Draft content stays in its input, never in generated validation messages.
    error_summary = body.split('role="alert">')[1].split('</div>')[0]
    assert 'unsafe-input-name' not in error_summary
    assert not storage.domain_exists(41, 'draft.example')


def test_stopped_monitoring_shows_measurement_age_and_overdue_state(owner, client):
    from datetime import datetime, timedelta, timezone
    from sitewatcher.config import ChecksModel

    storage.add_domain(41, 'stopped.example')
    storage.set_domain_override(41, 'stopped.example', {'checks': {
        key: key == 'http_basic' for key in ChecksModel.model_fields}})
    storage.save_history(41, 'stopped.example', 'http_basic', 'OK', 'saved',
                         {'final_code': 200, 'latency_ms_total': 50}, source='scheduled')
    old = (datetime.now(timezone.utc) - timedelta(hours=2, minutes=5)).isoformat()
    with storage._write_connection() as connection:
        connection.execute('UPDATE history SET created_at=?', (old,))
    body = get(client, '/').content.decode()
    from html import unescape
    assert '2 hours' in unescape(body).replace('\xa0', ' ') and 'ago' in body
    assert 'Some checks are overdue' in body
    assert 'Last checked' in body and 'Worker running' not in body


def test_measurement_age_handles_future_and_corrupt_timestamps():
    from datetime import datetime, timedelta, timezone
    from django.template.loader import render_to_string
    from sitewatcher.webapp.presentation import local_time

    future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    body = render_to_string('sitewatcher/partials/time.html',
                            {'stamp': local_time(future, 'Europe/Moscow')})
    assert 'Timestamp is in the future' in body and 'ago' not in body
    for invalid in ['invalid timestamp', '9999-12-31T23:59:59+00:00']:
        body = render_to_string('sitewatcher/partials/time.html',
                                {'stamp': local_time(invalid, 'Europe/Moscow')})
        assert 'Not checked yet' in body and 'ago' not in body


def test_overview_latency_refresh_and_native_timezone_choices(owner, client):
    storage.add_domain(41, 'one.example')
    storage.save_history(41, 'one.example', 'http_basic', 'OK', '',
                         {'final_code': 200, 'response_latency_ms': 125})
    body = get(client, '/').content.decode()
    assert 'Average response' in body and '125 ms' in body
    assert 'data-auto-refresh' in body and 'Refresh now' in body
    body = get(client, '/settings').content.decode()
    assert '<select name="timezone"' in body
    assert 'Moscow' in body and 'Dates and times use your selected timezone.' in body
    assert 'data-auto-refresh' not in body and 'IANA' not in body


def test_legacy_guarantees_native_forms_escape_and_readonly(owner, client, settings):
    storage.add_domain(41, 'one.example')
    response = get(client, '/?q=%22%3E%3Cscript%3E')
    assert b'<script>' not in response.content and b'&lt;script&gt;' in response.content
    assert get(client, '/?status=bad').status_code == 400
    for route in ('/domains/new', '/domains/edit?domain=one.example',
                  '/domains/delete?domain=one.example', '/import', '/settings'):
        body = get(client, route).content.decode()
        assert 'csrfmiddlewaretoken' in body
        assert 'http-equiv="refresh"' not in body and '<script>' not in body
        assert 'data-auto-refresh' not in body
    settings.SITEWATCHER_READ_ONLY = True
    assert b'/domains/new' not in get(client, '/').content
    assert client.post('/domains/pause', {'domain': 'one.example'},
                       HTTP_HOST='localhost').status_code == 405


def test_overview_shows_per_domain_latency_and_reading_order(owner, client):
    storage.add_domain(41, 'fast.example')
    storage.add_domain(41, 'empty.example')
    storage.save_history(41, 'fast.example', 'http_basic', 'OK', '',
                         {'final_code': 200, 'response_latency_ms': 125})
    body = get(client, '/').content.decode()
    assert body.index('data-auto-refresh') < body.index('<h1 class="sr-only">Overview')
    table = body[body.index('<tbody data-domain-key='):body.rindex('</tbody>')]
    assert 'Average response: 125 ms' in table
    assert 'No latency data' in table
    assert 'Just now' in table and '0 minutes ago' not in table


@pytest.mark.parametrize('route', ['/', '/api/status', '/healthz', '/assets/workspace.css'])
def test_get_head_parity_retains_private_security_headers(owner, client, route):
    response = get(client, route)
    head = client.head(route, HTTP_HOST='localhost')
    assert response.status_code == head.status_code == 200
    assert head.content == b''
    assert head['Content-Type'] == response['Content-Type']
    assert head['Cache-Control'] == 'no-store'
    assert head['X-Frame-Options'] == 'DENY'
    assert 'Access-Control-Allow-Origin' not in head


def test_chart_hover_values_stay_with_their_bucket_across_gaps():
    from sitewatcher.webapp.presentation import chart_context
    chart = chart_context([
        {'index': 0, 'latency_ms': 125.5, 'label': '2026-11-03 10:00 MSK'},
        {'index': 1, 'latency_ms': None, 'label': '2026-11-03 10:12 MSK'},
        {'index': 2, 'latency_ms': 0, 'label': '2026-11-03 10:24 MSK'},
    ], 'latency_ms')
    assert [(dot['label'], dot['value']) for dot in chart['dots']] == [
        ('2026-11-03 10:00 MSK', 125.5), ('2026-11-03 10:24 MSK', 0),
    ]


def test_dashboard_problem_tooltip_uses_each_check_time_and_only_owner_results(owner, client,
                                                                              settings):
    from sitewatcher.config import AppConfig, ChecksModel
    settings.SITEWATCHER_CONFIG = AppConfig.model_validate({'defaults': {'checks': {
        **dict.fromkeys(ChecksModel.model_fields, False), 'http_basic': True, 'tls_cert': True,
    }}})
    for owner_id in (41, 99):
        storage.add_domain(owner_id, 'problem.example')
    storage.save_history(41, 'problem.example', 'http_basic', 'CRIT', '<HTTP failed>', {})
    storage.save_history(41, 'problem.example', 'tls_cert', 'WARN', 'Certificate expires soon', {})
    storage.save_history(99, 'problem.example', 'http_basic', 'CRIT', 'OTHER OWNER DETAIL', {})
    with storage._write_connection() as conn:
        conn.execute("UPDATE history SET created_at='2026-11-03 10:00:00' "
                     "WHERE owner_id=41 AND check_name='http_basic'")
        conn.execute("UPDATE history SET created_at='2026-11-03 10:30:00' "
                     "WHERE owner_id=41 AND check_name='tls_cert'")
    response = get(client, '/')
    row = next(row for row in response.context['rows'] if row['name'] == 'problem.example')
    assert [check['name'] for check in row['problems']] == ['http_basic', 'tls_cert']
    html = response.content.decode()
    assert 'data-status-preview' in html and 'role="tooltip" tabindex="0"' in html
    assert '&lt;HTTP failed&gt;' in html and 'Certificate expires soon' in html
    assert '2026-11-03T10:00:00+00:00' in html and '2026-11-03T10:30:00+00:00' in html
    assert 'OTHER OWNER DETAIL' not in html


def test_dashboard_tooltip_explains_overdue_success_as_warning():
    from sitewatcher.webapp.domains import _row_context
    row = {'overall': 'WARN', 'paused': False, 'error': None, 'last_checked_at': None,
           'checks': [{'name': 'http_basic', 'status': 'OK', 'stale': True, 'missing': False,
                       'checked_at': '2026-11-03T10:00:00+00:00', 'message': 'HTTP 200'}]}
    _row_context(row, 'Europe/Moscow')
    assert row['state'] == 'warn'
    assert row['problems'][0]['stale'] is True
    assert row['problems'][0]['observed']['label'] == '03 Nov 2026, 13:00 MSK'


def test_overview_actions_are_accessible_header_icons_without_intro(owner, client, settings):
    storage.add_domain(41, 'one.example')
    body = get(client, '/').content.decode()
    header = body.split('<header class="topbar">', 1)[1].split('</header>', 1)[0]
    assert 'class="topbar-actions"' in header
    assert 'data-activity-toggle hidden' in header and 'aria-controls="live-checks"' in header
    assert 'data-live-activity hidden' in body
    assert '/assets/activity.js' in body
    assert '/assets/activity.css' in body
    assert 'href="/domains/new"' in header and 'action="/domains/check"' in header
    assert 'aria-label="Refresh now"' in header
    assert 'data-refresh-enabled' in header and 'aria-pressed="true"' in header
    assert 'Your workspace' not in body and 'Keep an eye on the sites that matter.' not in body
    assert '<h1>Overview</h1>' not in body
    assert 'class="refresh-controls"' not in body
    settings.SITEWATCHER_READ_ONLY = True
    header = get(client, '/').content.decode().split('</header>', 1)[0]
    assert 'href="/domains/new"' not in header and 'action="/domains/check"' not in header
    assert 'data-refresh-enabled' in header and 'aria-label="Refresh now"' in header


def test_settings_navigation_is_a_header_icon_and_marks_current_page(owner, client):
    body = get(client, '/settings').content.decode()
    header = body.split('<header class="topbar">', 1)[1].split('</header>', 1)[0]
    assert '<nav' not in header
    assert '<a class="brand" href="/" aria-label="SiteWatcher">' in header
    import re
    button = re.search(r'<a class="button icon-button settings-button"[^>]*>', header).group()
    assert 'title="Settings"' in button and 'aria-label="Settings"' in button
    assert 'aria-current="page"' in button
    assert '<svg ' in header


@pytest.mark.parametrize('route', ['/', '/settings', '/domains/new', '/password/',
                                  '/domains/edit?domain=one.example',
                                  '/domains/history?domain=one.example'])
def test_owner_toolbar_keeps_order_and_limits_refresh_to_overview(owner, client, route):
    storage.add_domain(41, 'one.example')
    response = get(client, route)
    assert response.status_code == 200
    body = response.content.decode()
    header = body.split('<header class="topbar">', 1)[1].split('</header>', 1)[0]
    labels = ['Add domain', 'Check all domains now', 'Live checks', 'Refresh now',
              'Refresh every minute', 'Settings', 'Dark theme']
    positions = [header.index(f'aria-label="{label}"') for label in labels]
    assert positions == sorted(positions)
    assert 'method="post" action="/domains/check"' in header
    assert 'csrfmiddlewaretoken' in header and 'name="domain" value="*"' in header
    if route == '/':
        assert 'data-auto-refresh' in header and 'data-activity-toggle' in header
    else:
        assert 'data-auto-refresh' not in body and 'data-refresh-option' not in body
        assert 'data-activity-navigation hidden' in header
        assert 'Automatic refresh is available on the overview' in header
        assert '/assets/activity.js' not in body and 'data-live-activity' not in body


def test_toolbar_domain_presence_is_owner_scoped_and_readonly(owner, client, settings):
    storage.ensure_user(42)
    storage.add_domain(42, 'other.example')
    header = get(client, '/settings').content.decode().split('</header>', 1)[0]
    assert 'Check all domains now' in header and 'Live checks' in header
    assert 'action="/domains/check"' not in header
    assert 'data-activity-navigation' not in header
    storage.add_domain(41, 'own.example')
    settings.SITEWATCHER_READ_ONLY = True
    for route in ['/', '/settings', '/domains/new', '/password/']:
        header = get(client, route).content.decode().split('</header>', 1)[0]
        assert 'href="/domains/new"' not in header
        assert 'action="/domains/check"' not in header


def test_toolbar_context_skips_public_anonymous_and_unbound_requests(web_database, monkeypatch):
    from types import SimpleNamespace
    from sitewatcher.webapp import context_processors

    def private_query_forbidden(*args, **kwargs):
        raise AssertionError('Private toolbar queries must not run')

    with monkeypatch.context() as patch:
        patch.setattr(context_processors.connection, 'cursor', private_query_forbidden)
        for request in [
            SimpleNamespace(path='/status/[redacted]/'),
            SimpleNamespace(path='/login/', user=SimpleNamespace(is_authenticated=False)),
            SimpleNamespace(path='/login/', user=SimpleNamespace(is_authenticated=True)),
        ]:
            assert context_processors.owner_toolbar(request) == {}


def test_toolbar_check_all_retains_native_csrf_protection(owner):
    from django.test import Client

    storage.add_domain(41, 'one.example')
    protected = Client(enforce_csrf_checks=True)
    protected.force_login(owner.user)
    header = get(protected, '/settings').content.decode().split('</header>', 1)[0]
    assert 'csrfmiddlewaretoken' in header
    assert protected.post('/domains/check', {'domain': '*'},
                          HTTP_HOST='localhost').status_code == 403


def test_login_has_no_private_toolbar(owner, client):
    header = get(client, '/login/').content.decode().split('</header>', 1)[0]
    assert 'topbar-actions' not in header and 'settings-button' not in header


@pytest.mark.parametrize(('zone', 'expected'), [
    ('Europe/Moscow', '2026-11-03 15:46'), ('UTC', '2026-11-03 12:46'),
])
def test_compact_observation_timestamp_uses_workspace_timezone(zone, expected):
    from django.template.loader import render_to_string
    from sitewatcher.webapp.presentation import local_time
    stamp = local_time('2026-11-03T12:46:00Z', zone)
    body = render_to_string('sitewatcher/partials/time.html', {'stamp': stamp, 'compact': True})
    assert f'>{expected}</time>' in body
    assert 'MSK' not in body and 'UTC</time>' not in body
    assert 'datetime="2026-11-03T12:46:00+00:00"' in body
    assert ' · ' not in body
