"""A public bearer link grants only selected aggregate observations, never owner authority."""
import hashlib
import json
import re

import pytest
from django.contrib.auth import get_user_model
from django.test import Client

from sitewatcher import storage


@pytest.fixture
def owner(web_database, client):
    from sitewatcher.webapp.models import Workspace
    user = get_user_model().objects.create_user(username='public-owner')
    workspace = Workspace.objects.create(user=user, owner_id=731)
    other = get_user_model().objects.create_user(username='other-public-owner')
    Workspace.objects.create(user=other, owner_id=973)
    for identity in (731, 973):
        storage.ensure_user(identity)
    for identity, name, success in [(731, 'shared.example', True),
                                     (731, 'hidden-sentinel.example', False),
                                     (973, 'shared.example', False),
                                     (973, 'foreign.example', False)]:
        storage.add_domain(identity, name)
        storage.save_history(identity, name, 'http_basic', 'OK' if success else 'CRIT',
                             'private-message-sentinel chat=-100888 proxy=password',
                             {'final_code': 200 if success else 503, 'latency_ms_total': 120,
                              'secret': 'private-metrics-sentinel',
                              'proxy': 'https://private:password@proxy.example'}, source='manual')
    client.force_login(user)
    return workspace


def publish(client, domains=('shared.example',), action='enable'):
    response = client.post('/settings/public', {'action': action, 'domains': '\n'.join(domains)},
                           HTTP_HOST='localhost')
    assert response.status_code == 200
    match = re.search(r'http://localhost(/status/([A-Za-z0-9_-]+)/)', response.content.decode())
    assert match is not None
    return match.group(1), match.group(2), response


def get(client, path):
    return client.get(path, HTTP_HOST='localhost')


def test_public_disabled_by_default_and_hash_only_one_time_link(owner, client):
    assert not owner.public_enabled and owner.public_token_hash == '' and owner.public_domains == []
    assert get(Client(), '/status/' + 'x' * 43 + '/').status_code == 404
    path, token, response = publish(client)
    owner.refresh_from_db()
    assert len(token) == 43 and owner.public_token_hash == hashlib.sha256(token.encode()).hexdigest()
    assert token not in json.dumps(owner.__dict__, default=str)
    assert owner.public_domains == ['shared.example']
    assert b'Copy public link' in response.content
    assert token.encode() not in get(client, '/settings').content
    assert b'Rotate link' in get(client, '/settings').content


def test_selected_only_aggregate_dto_guest_and_authenticated_owner(owner, client):
    path, token, _ = publish(client)
    for viewer in (Client(), client):
        response = get(viewer, path)
        assert response.status_code == 200
        body = response.content.decode()
        assert 'shared.example' in body and '100.0%' in body and '0.0%' in body
        assert 'Europe/Moscow' in body and 'Last checked' in body
        assert 'View chart data' in body and '24h' in body and '30d' in body
        for forbidden in ('hidden-sentinel', 'foreign.example', 'private-message', 'private-metrics',
                          'password', '-100888', 'owner_id', 'href="/settings', 'href="/workspace', '/domains/',
                          'Check now', 'Main navigation', token):
            assert forbidden not in body
        assert response['Referrer-Policy'] == 'no-referrer'
        assert response['X-Robots-Tag'] == 'noindex, nofollow, noarchive'
        assert response['Cache-Control'] == 'no-store'
    data = get(Client(), path + 'data?days=7').json()
    assert data['totals']['successful'] == 1 and data['totals']['failed'] == 0
    assert [row['domain'] for row in data['domains']] == ['shared.example']
    assert set(data['totals']) == {'successful', 'failed', 'unknown', 'sample_count',
                                  'success_percent', 'failure_percent'}
    encoded = json.dumps(data)
    assert 'sources' not in encoded and 'owner' not in encoded
    for secret in ('private-message-sentinel', 'private-metrics-sentinel', 'password',
                   '-100888', 'hidden-sentinel.example', 'foreign.example', token):
        assert secret not in encoded
    for suffix in ('?domain=hidden-sentinel.example', 'data?domain=foreign.example',
                   '?owner_id=973', '?days=1&days=7', '?days=2'):
        assert get(Client(), path + suffix).status_code == 404


def test_disable_rotation_and_selection_take_effect_despite_cached_reports(owner, client):
    path, _, _ = publish(client)
    assert get(Client(), path + 'data').status_code == 200
    next_path, _, _ = publish(client, action='rotate')
    assert next_path != path
    assert get(Client(), path).status_code == 404
    assert get(Client(), path + 'data').status_code == 404
    assert get(Client(), next_path).status_code == 200
    response = client.post('/settings/public', {'action': 'selection', 'domains': ''}, HTTP_HOST='localhost')
    assert response.status_code == 200
    assert get(Client(), next_path + 'data').json()['domains'] == []
    assert b'No domains published' in get(Client(), next_path).content
    assert client.post('/settings/public', {'action': 'disable'}, HTTP_HOST='localhost').status_code == 200
    assert get(Client(), next_path).status_code == 404
    owner.refresh_from_db()
    assert not owner.public_enabled and owner.public_token_hash == ''


def test_public_selection_owner_auth_csrf_validation_and_readonly(owner, client, settings):
    assert Client().post('/settings/public', {'action': 'enable'}, HTTP_HOST='localhost').status_code == 302
    secure = Client(enforce_csrf_checks=True)
    secure.force_login(owner.user)
    assert secure.post('/settings/public', {'action': 'enable'}, HTTP_HOST='localhost').status_code == 403
    for fields in ({'action': 'enable', 'domains': 'foreign.example'},
                   {'action': 'enable', 'domains': 'shared.example', 'owner_id': '973'},
                   {'action': 'rotate'}, {'action': 'unknown'}):
        assert client.post('/settings/public', fields, HTTP_HOST='localhost').status_code == 400
    owner.refresh_from_db()
    assert not owner.public_enabled
    settings.SITEWATCHER_READ_ONLY = True
    assert client.post('/settings/public', {'action': 'enable'}, HTTP_HOST='localhost').status_code == 405


def test_public_get_head_and_direct_mutations_never_dispatch_or_write(owner, client, monkeypatch):
    path, token, _ = publish(client)
    from django.db import connection
    from sitewatcher.webapp import domains
    def forbidden(*args, **kwargs):
        raise AssertionError('Public requests must not dispatch or write')
    monkeypatch.setattr(domains, 'run_manual_checks', forbidden)
    original_write = storage._write_connection
    monkeypatch.setattr(storage, '_write_connection', forbidden)
    writes = []
    def observe(execute, sql, params, many, context):
        if re.match(r'\s*(INSERT|UPDATE|DELETE|REPLACE|CREATE|ALTER)', sql, re.I):
            writes.append(sql)
        return execute(sql, params, many, context)
    guest = Client(enforce_csrf_checks=True)
    with connection.execute_wrapper(observe):
        assert get(guest, path).status_code == 200
        assert guest.head(path, HTTP_HOST='localhost').status_code == 200
        assert get(guest, path + 'data').status_code == 200
        assert guest.post(path, {'action': 'check', 'owner_id': '731'}, HTTP_HOST='localhost').status_code == 405
        assert guest.post(path + 'data', HTTP_HOST='localhost').status_code == 405
        assert get(guest, '/api/status?token=' + token).status_code == 401
        assert guest.post('/domains/check', {'domain': '*', 'token': token}, HTTP_HOST='localhost').status_code in (302, 403)
    assert writes == []
    monkeypatch.setattr(storage, '_write_connection', original_write)


def test_bearer_paths_never_enter_django_404_or_exception_logs(owner, client, caplog, monkeypatch):
    from sitewatcher.webapp import public
    path, token, _ = publish(client)
    caplog.set_level('DEBUG')
    guest = Client(raise_request_exception=False)
    for suffix in ('missing', '?unexpected=private-query-sentinel', 'data/missing'):
        assert get(guest, path + suffix).status_code == 404
    assert get(guest, '/status/invalid-token-sentinel/').status_code == 404
    monkeypatch.setattr(public, 'public_report', lambda *a, **kw: (_ for _ in ()).throw(RuntimeError(token)))
    assert get(guest, path).status_code == 503
    assert 'Public status unavailable (RuntimeError)' in caplog.text
    assert token not in caplog.text and 'invalid-token-sentinel' not in caplog.text
    assert 'private-query-sentinel' not in caplog.text
    for record in caplog.records:
        if hasattr(record, 'request'):
            assert token not in record.request.get_full_path()
            assert token not in str(record.request.META)


def test_public_native_theme_preserves_period_without_echoing_bearer(owner, client):
    path, token, _ = publish(client)
    guest = Client()
    body = get(guest, path + '?days=7').content.decode()
    assert 'name="days" value="7"' in body and 'name="next"' not in body
    assert 'href="?days=7"' in body and 'action=""' in body
    response = get(guest, path + '?mode=dark&days=7')
    assert response.status_code == 303 and response['Location'] == '?days=7'
    assert response.cookies['sitewatcher_theme'].value == 'dark'
    response = get(guest, path + '?days=7')
    assert b'data-theme="dark"' in response.content and token.encode() not in response.content
    assert get(guest, path + '?mode=invalid').status_code == 404
    assert get(guest, path + 'data?mode=dark').status_code == 404


def test_public_no_data_unknowns_and_gap_axes_are_honest(owner, client):
    storage.add_domain(731, 'empty.example')
    path, _, _ = publish(client, domains=('empty.example',))
    response = get(Client(), path)
    assert b'No data' in response.content and b'100.0%' not in response.content
    assert b'No HTTP observations in this period' in response.content
    storage.save_history(731, 'empty.example', 'http_basic', 'WARN', 'private unknown',
                         {'final_code': True, 'secret': 'unknown-private-sentinel'})
    data = get(Client(), path + 'data').json()
    assert data['totals']['unknown'] == 1 and data['totals']['success_percent'] is None
    assert data['totals']['failure_percent'] is None
    assert 'unknown-private-sentinel' not in json.dumps(data)
    # Public graphs use the shared absolute bucket axis and preserve missing intervals.
    from sitewatcher.webapp.presentation import report_context
    report = data['domains'][0]
    report['buckets'] = [{**report['buckets'][0], 'index': index, 'latency_ms': value}
                         for index, value in [(1, 100), (3, 200), (4, None), (5, 150)]]
    chart = report_context(report)['chart']
    assert len(chart['segments']) == 3
    assert chart['dots'][1]['x'] == pytest.approx(3 * 1000 / 120)


def test_deselected_deleted_and_guessed_links_never_reveal_previous_selection(owner, client):
    path, token, _ = publish(client)
    assert get(Client(), path + 'data').json()['totals']['successful'] == 1
    response = client.post('/settings/public', {'action': 'selection', 'domains': 'hidden-sentinel.example'},
                           HTTP_HOST='localhost')
    assert response.status_code == 200
    data = get(Client(), path + 'data').json()
    assert data['totals']['successful'] == 0 and data['totals']['failed'] == 1
    assert [row['domain'] for row in data['domains']] == ['hidden-sentinel.example']
    storage.remove_domain(731, 'hidden-sentinel.example')
    assert get(Client(), path + 'data').json()['domains'] == []
    guessed = ('A' if token[0] != 'A' else 'B') + token[1:]
    assert get(Client(), '/status/' + guessed + '/').status_code == 404


def test_revoked_and_malformed_public_logs_and_mutation_body_do_not_leak(owner, client, caplog):
    path, token, _ = publish(client)
    caplog.set_level('DEBUG')
    guest = Client(enforce_csrf_checks=True)
    assert guest.post(path, {'token': token, 'owner_id': 731}, HTTP_HOST='localhost').status_code == 405
    assert client.post('/settings/public', {'action': 'disable'}, HTTP_HOST='localhost').status_code == 200
    for suffix in ('', 'data', 'no-such-path'):
        assert get(guest, path + suffix).status_code == 404
    assert token not in caplog.text
    assert all(token not in record.request.get_full_path() for record in caplog.records
               if hasattr(record, 'request'))


def test_native_publication_checkboxes_select_owned_domains(owner, client):
    body = get(client, '/settings').content.decode()
    assert 'name="domain.shared.example"' in body and 'name="domain.hidden-sentinel.example"' in body
    response = client.post('/settings/public', {'action': 'enable', 'domain.shared.example': 'on'},
                           HTTP_HOST='localhost')
    assert response.status_code == 200
    owner.refresh_from_db()
    assert owner.public_domains == ['shared.example']
    for fields in ({'action': 'selection', 'domain.foreign.example': 'on'},
                   {'action': 'selection', 'domain.shared.example': 'unexpected'},
                   {'action': 'selection', 'domains': '', 'domain.shared.example': 'on'}):
        assert client.post('/settings/public', fields, HTTP_HOST='localhost').status_code == 400
    assert b'<details class="public-component-chart">' in get(Client(), re.search(
        r'http://localhost(/status/[A-Za-z0-9_-]+/)', response.content.decode())[1]).content


def test_public_early_boundary_keeps_host_and_security_checks(owner, client, caplog):
    path, token, _ = publish(client)
    guest = Client(raise_request_exception=False)
    response = guest.get(path, HTTP_HOST='untrusted.invalid')
    assert response.status_code == 400
    response = get(guest, path)
    assert response['Content-Security-Policy'].startswith("default-src 'self'")
    assert response['X-Content-Type-Options'] == 'nosniff'
    assert response['X-Frame-Options'] == 'DENY'
    caplog.set_level('DEBUG')
    response = get(guest, path + '?' + '&'.join(f'field{i}=1' for i in range(1100)))
    assert response.status_code == 404
    assert token not in caplog.text
    # Owner cookies cannot turn any public method into a scan or owner operation.
    for method in ('post', 'put', 'patch', 'delete'):
        assert getattr(client, method)(path, {'action': 'check', 'owner_id': 731},
                                       HTTP_HOST='localhost').status_code == 405


def test_stale_and_paused_current_state_do_not_misrepresent_historical_success(owner, client):
    from datetime import datetime, timedelta, timezone
    path, _, _ = publish(client)
    current = get(Client(), path + 'data').json()['domains'][0]
    assert current['current_state'] == 'available'
    # The reporting policy derives freshness from effective intervals; old HTTP200 is history only.
    old = (datetime.now(timezone.utc) - timedelta(days=2)).replace(tzinfo=None).isoformat(' ')
    with storage._write_connection() as conn:
        conn.execute('UPDATE history SET created_at=? WHERE owner_id=? AND domain=?',
                     (old, 731, 'shared.example'))
    data = get(Client(), path + 'data?days=7').json()
    assert data['domains'][0]['current_state'] == 'no_recent_data'
    assert data['totals']['success_percent'] == 100
    body = get(Client(), path + '?days=7').content.decode()
    assert 'No recent data' in body and 'All published services available' not in body
    assert '100.0%' in body
    storage.set_domain_override(731, 'shared.example', {'interval_minutes': 0})
    data = get(Client(), path + 'data?days=7').json()
    assert data['domains'][0]['current_state'] == 'paused'
    body = get(Client(), path + '?days=7').content.decode()
    assert 'Paused' in body and 'All published services available' not in body
    assert '100.0%' in body


def test_one_time_link_render_failure_never_logs_issued_bearer(owner, client, monkeypatch, caplog):
    from sitewatcher.webapp import preferences, public
    issued = 'render-failure-sentinel'.ljust(43, 'x')
    monkeypatch.setattr(public.secrets, 'token_urlsafe', lambda size: issued)
    def broken_render(request, **kwargs):
        raise RuntimeError(kwargs['public_link'])
    monkeypatch.setattr(preferences, '_render', broken_render)
    caplog.set_level('DEBUG')
    client.raise_request_exception = False
    response = client.post('/settings/public', {'action': 'enable', 'domains': 'shared.example'},
                           HTTP_HOST='localhost')
    assert response.status_code == 503
    assert issued not in caplog.text
    assert 'Public status settings unavailable (RuntimeError)' in caplog.text


@pytest.mark.parametrize('metrics,expected,label', [
    ({'final_code': 200}, 'available', 'Available'),
    ({'final_code': 503}, 'unavailable', 'Unavailable'),
    ({'availability': 'unknown'}, 'no_recent_data', 'No recent data'),
])
def test_current_http_state_is_independent_of_selected_history_period(owner, client, metrics,
                                                                    expected, label):
    from datetime import datetime, timedelta, timezone
    old = (datetime.now(timezone.utc) - timedelta(days=2)).replace(tzinfo=None).isoformat(' ')
    storage.set_domain_override(731, 'shared.example', {'interval_minutes': 3 * 24 * 60})
    with storage._write_connection() as conn:
        conn.execute("UPDATE history SET created_at=?,status='CRIT',metrics_json=? "
                     "WHERE owner_id=? AND domain=? AND check_name='http_basic'",
                     (old, json.dumps({**metrics, 'secret': 'latest-private-sentinel'}),
                      731, 'shared.example'))
    path, _, _ = publish(client)
    states = []
    for days in (1, 7, 30):
        data = get(Client(), path + 'data?days=' + str(days)).json()
        item = data['domains'][0]
        states.append(item['current_state'])
        assert item['current_state'] == expected
        # The chart still reports only its selected historical period.
        assert item['totals']['sample_count'] == (0 if days == 1 else 1)
        if days == 1:
            assert item['totals']['success_percent'] is None and item['buckets'] == []
        body = get(Client(), path + '?days=' + str(days)).content.decode()
        assert label + '</span>' in body
        assert 'latest-private-sentinel' not in body and 'latest-private-sentinel' not in json.dumps(data)
    assert states == [expected] * 3
