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


def test_empty_and_no_observation_states(owner, client):
    assert 'Add your first domain' in get(client, '/').content.decode()
    storage.add_domain(41, 'new.example')
    body = get(client, '/domains/history?domain=new.example').content.decode()
    assert 'No HTTP observations in this period' in body
    assert '24h' in body and '7d' in body and '30d' in body
    assert 'Successful checks' in body and 'Response time' in body
    assert 'No data' in body and '100%' not in body


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
    assert 'Successful checks' in body and 'continuous uptime' in body
    assert 'private diagnostic' not in body.split('Recent check history')[0]
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
    assert chart['dots'][2]['x'] == pytest.approx(3 * 1000 / 119)
    assert chart_context([], 'latency_ms')['segments'] == []


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


def test_new_domain_form_defaults_to_http_tls_only(owner, client):
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
        key: 'on' if key in {'http_basic', 'tls_cert'} else 'off'
        for key in ChecksModel.model_fields}
    parser.values.update(domain='basic.example')
    response = client.post('/domains/add', parser.values, HTTP_HOST='localhost')
    assert response.status_code == 303
    assert storage.get_domain_override(41, 'basic.example')['checks']['ping'] is False


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
    assert stamp == {'iso': '2026-10-22T12:00:00+00:00', 'label': '22 Oct 2026, 15:00 MSK'}
