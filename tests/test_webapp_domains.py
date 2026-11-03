"""Authenticated management preserves owner isolation and existing storage semantics."""
import asyncio
import re
import threading

import pytest
from django.contrib.auth import get_user_model
from django.test import Client

from sitewatcher import storage
from sitewatcher.config import AppConfig, ChecksModel
from sitewatcher.utils.domains_csv import export_domains_csv
from sitewatcher.web_actions import settings_context


@pytest.fixture
def owner(web_database, client):
    from sitewatcher.webapp.models import Workspace
    user = get_user_model().objects.create_user(username='owner')
    workspace = Workspace.objects.create(user=user, owner_id=31)
    storage.ensure_user(31)
    storage.add_domain(31, 'one.example')
    storage.add_domain(99, 'private.example')
    client.force_login(user)
    return workspace


def post(client, path, fields):
    return client.post(path, fields, HTTP_HOST='localhost')


def test_authenticated_crud_history_and_owner_isolation(owner, client):
    response = post(client, '/domains/new', {'domain': 'new.example', 'interval_minutes': '12'})
    assert response.status_code == 303
    assert storage.get_domain_override(31, 'new.example')['interval_minutes'] == 12
    for path in ('/', '/api/status', '/domains/history?domain=new.example', '/export.csv'):
        response = client.get(path, HTTP_HOST='localhost')
        assert response.status_code == 200
        assert b'private.example' not in response.content
    for path in ('/domains/edit', '/domains/history', '/domains/delete'):
        assert client.get(path + '?domain=private.example', HTTP_HOST='localhost').status_code == 404
    for action in ('pause', 'resume', 'reset', 'delete', 'check'):
        fields = {'domain': 'private.example'}
        if action == 'delete':
            fields['confirm'] = 'private.example'
        assert post(client, '/domains/' + action, fields).status_code == 404
    assert storage.domain_exists(99, 'private.example')
    assert post(client, '/domains/new', {'domain': 'bad.example', 'owner_id': '99'}).status_code == 400
    assert not storage.domain_exists(99, 'bad.example')
    assert not storage.domain_exists(31, 'bad.example')
    revision = settings_context(AppConfig(), 31, 'new.example')['revision']
    assert post(client, '/domains/edit', {'domain': 'new.example', 'revision': revision,
                                        'interval_minutes': '13'}).status_code == 303
    assert post(client, '/domains/delete', {'domain': 'new.example'}).status_code == 400
    assert post(client, '/domains/delete', {'domain': 'new.example',
                                          'confirm': 'new.example'}).status_code == 303
    assert not storage.domain_exists(31, 'new.example')


def test_pause_resume_reset_notifications_and_csv(owner, client):
    for action in ('pause', 'resume', 'reset'):
        fields = {'domain': 'one.example'}
        if action == 'reset':
            fields['revision'] = storage.domain_reset_revision(31, 'one.example')
        assert post(client, '/domains/' + action, fields).status_code == 303
        override = storage.get_domain_override(31, 'one.example') or {}
        assert (override.get('interval_minutes') == 0) == (action == 'pause')
    assert post(client, '/workspace', {'enabled': 'off'}).status_code == 303
    assert not storage.is_user_alerts_enabled(31)
    data = export_domains_csv(31).decode().replace('one.example', 'imported.example')
    assert post(client, '/import', {'csv_text': data, 'mode': 'merge'}).status_code == 303
    assert storage.domain_exists(31, 'imported.example')
    response = client.get('/export.csv', HTTP_HOST='localhost')
    assert response['Content-Disposition'].startswith('attachment;')
    assert response['Cache-Control'] == 'no-store'
    assert b'imported.example' in response.content


def test_safe_methods_do_not_mutate_and_readonly_rejects_mutations(owner, client, settings):
    before = storage.get_domain_override(31, 'one.example')
    for method in ('get', 'head'):
        for action in ('pause', 'resume', 'reset', 'check'):
            assert getattr(client, method)('/domains/' + action + '?domain=one.example',
                                           HTTP_HOST='localhost').status_code == 405
    assert storage.get_domain_override(31, 'one.example') == before
    settings.SITEWATCHER_READ_ONLY = True
    for path, fields in [('/domains/new', {'domain': 'new.example'}),
                         ('/domains/edit', {'domain': 'one.example'}),
                         ('/domains/delete', {'domain': 'one.example', 'confirm': 'one.example'}),
                         ('/domains/pause', {'domain': 'one.example'}),
                         ('/domains/resume', {'domain': 'one.example'}),
                         ('/domains/reset', {'domain': 'one.example'}),
                         ('/domains/check', {'domain': '*'}),
                         ('/workspace', {'enabled': 'off'}),
                         ('/import', {'csv_text': 'domain\nnew.example'})]:
        assert post(client, path, fields).status_code == 405
    assert storage.list_domains(31) == ['one.example']
    assert storage.get_domain_override(31, 'one.example') == before
    assert b'/domains/new' not in client.get('/', HTTP_HOST='localhost').content


def test_csrf_duplicate_fields_body_limits_and_drafts(owner, client):
    secure = Client(enforce_csrf_checks=True)
    secure.force_login(owner.user)
    assert post(secure, '/domains/new', {'domain': 'new.example'}).status_code == 403
    response = secure.get('/domains/new', HTTP_HOST='localhost')
    token = re.search(rb'name="csrfmiddlewaretoken" value="([^"]+)"', response.content).group(1).decode()
    assert post(secure, '/domains/new', {'csrfmiddlewaretoken': token,
                                       'domain': 'new.example'}).status_code == 303
    assert client.post('/domains/new', 'domain=one.example&domain=other.example',
                       content_type='application/x-www-form-urlencoded',
                       HTTP_HOST='localhost').status_code == 400
    assert client.post('/import', b'x' * (1024 * 1024 + 1),
                       content_type='application/x-www-form-urlencoded',
                       HTTP_HOST='localhost').status_code == 413
    secret = 'http://private-user:private-password@proxy.example:8080'
    response = post(client, '/domains/new', {'domain': 'draft.example', 'interval_minutes': '-2',
                                           'proxy_mode': 'set', 'proxy': secret})
    assert response.status_code == 400
    assert b'draft.example' in response.content
    assert b'private-password' not in response.content
    assert b'value="-2"' in response.content
    assert not storage.domain_exists(31, 'draft.example')


def test_stale_edit_retains_atomic_revision_and_draft(owner, client):
    revision = settings_context(AppConfig(), 31, 'one.example')['revision']
    storage.set_domain_override(31, 'one.example', {'interval_minutes': 8})
    response = post(client, '/domains/edit', {'domain': 'one.example', 'revision': revision,
                                            'interval_minutes': '99'})
    assert response.status_code == 400
    assert b'Settings changed' in response.content
    assert b'value="99"' in response.content
    assert revision.encode() in response.content
    assert storage.get_domain_override(31, 'one.example')['interval_minutes'] == 8


def test_manual_check_lock_timeout_and_deleted_domain(owner, client, monkeypatch):
    from sitewatcher.webapp import domains
    from sitewatcher.checks.base import CheckOutcome, Status
    entered, release = threading.Event(), threading.Event()
    seen = []

    class Probe:
        def __init__(self, cfg):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            pass
        async def run_for(self, owner_id, name, **kwargs):
            seen.append((owner_id, name, kwargs))
            entered.set()
            await asyncio.to_thread(release.wait, 4)
            return [CheckOutcome('http_basic', Status.OK, 'saved probe', {})]

    monkeypatch.setattr(domains, 'Dispatcher', Probe)
    other = Client()
    other.force_login(owner.user)
    result = []
    thread = threading.Thread(target=lambda: result.append(post(other, '/domains/check',
                                                                {'domain': 'one.example'})))
    thread.start()
    try:
        assert entered.wait(3)
        assert post(client, '/domains/check', {'domain': 'one.example'}).status_code == 409
        assert post(client, '/domains/delete', {'domain': 'one.example',
                                              'confirm': 'one.example'}).status_code == 303
    finally:
        release.set()
        thread.join(5)
    assert not thread.is_alive()
    assert result[0].status_code == 303
    assert seen == [(31, 'one.example', {'use_cache': False})]
    assert not storage.domain_exists(31, 'one.example')
    assert storage.last_results(31, 'one.example') == []


def test_csv_concurrent_merge_does_not_overwrite_changed_settings(owner, client, monkeypatch):
    storage.set_domain_override(31, 'one.example', {'interval_minutes': 10})
    csv_text = export_domains_csv(31).decode().replace(';10', ';20')
    original = storage.set_domain_override

    def concurrent_change(owner_id, domain, patch, **kwargs):
        original(owner_id, domain, {'interval_minutes': 30})
        return original(owner_id, domain, patch, **kwargs)

    monkeypatch.setattr(storage, 'set_domain_override', concurrent_change)
    response = post(client, '/import', {'csv_text': csv_text, 'mode': 'merge'})
    assert response.status_code == 400
    assert b'1 skipped' in response.content
    assert storage.get_domain_override(31, 'one.example')['interval_minutes'] == 30


def test_manual_timeout_releases_lock_without_exposing_exception(owner, client, monkeypatch):
    from sitewatcher.webapp import domains

    def timeout(*args):
        raise TimeoutError('private probe diagnostic')

    monkeypatch.setattr(domains, 'run_manual_checks', timeout)
    response = post(client, '/domains/check', {'domain': 'one.example'})
    assert response.status_code == 504
    assert b'private probe diagnostic' not in response.content
    monkeypatch.setattr(domains, 'run_manual_checks', lambda *args: None)
    assert post(client, '/domains/check', {'domain': 'one.example'}).status_code == 303


@pytest.mark.parametrize('path', ['/domains/new', '/domains/edit', '/domains/history',
                                  '/domains/delete', '/domains/check', '/workspace',
                                  '/import', '/export.csv'])
def test_no_anonymous_management_access(web_database, client, path):
    response = client.get(path, HTTP_HOST='localhost')
    assert response.status_code == 302
    assert response.url.startswith('/login/?next=')


def test_mutations_reject_foreign_origin_and_get_queries(owner, client):
    secure = Client(enforce_csrf_checks=True)
    secure.force_login(owner.user)
    secure.get('/domains/new', HTTP_HOST='localhost')
    token = secure.cookies['csrftoken'].value
    response = secure.post('/domains/new', {'domain': 'forged.example',
                                            'csrfmiddlewaretoken': token},
                           HTTP_HOST='localhost', HTTP_ORIGIN='https://evil.example')
    assert response.status_code == 403
    assert post(client, '/domains/pause?owner=99', {'domain': 'one.example'}).status_code == 400
    assert not storage.domain_exists(31, 'forged.example')
    assert storage.get_domain_override(31, 'one.example') is None


def test_csv_download_rejects_ambiguous_query(owner, client):
    assert client.get('/export.csv?owner=31&owner=99', HTTP_HOST='localhost').status_code == 400


def test_csv_upload_size_and_duplicate_file_fields_are_rejected(owner, client):
    from django.core.files.uploadedfile import SimpleUploadedFile

    response = post(client, '/import', {'csv_file': SimpleUploadedFile('backup.csv',
                                                                      b'x' * (1024 * 1024))})
    assert response.status_code == 413
    response = post(client, '/import', {'csv_file': [SimpleUploadedFile('one.csv', b'domain'),
                                                    SimpleUploadedFile('two.csv', b'domain')]})
    assert response.status_code == 400
    assert storage.list_domains(31) == ['one.example']


def test_corrupt_settings_owner_recovery_is_explicit_scoped_and_preserves_history(
        owner, client, settings):
    raw = '{corrupt-private-canary'
    storage.save_history(31, 'one.example', 'http_basic', 'OK', 'old result', {})
    storage.set_domain_override(31, 'one.example', {})
    with storage._write_connection() as conn:
        conn.execute('UPDATE domain_overrides SET data_json=? WHERE owner_id=31', (raw,))

    def saved_raw():
        from contextlib import closing
        with closing(storage._connect()) as conn:
            return conn.execute('SELECT data_json FROM domain_overrides WHERE owner_id=31').fetchone()[0]

    for path in ('/', '/domains/history?domain=one.example', '/domains/edit?domain=one.example'):
        response = client.get(path, HTTP_HOST='localhost')
        assert response.status_code == 200
        assert b'Invalid domain settings' in response.content
        assert b'No checks enabled' not in response.content
        assert raw.encode() not in response.content
        assert saved_raw() == raw
    revision = re.search(rb'name="revision" value="([^"]+)"', response.content).group(1).decode()
    fields = {'domain': 'one.example', 'revision': revision}
    secure = Client(enforce_csrf_checks=True)
    secure.force_login(owner.user)
    assert post(secure, '/domains/reset', fields).status_code == 403
    assert post(client, '/domains/reset', {'domain': 'one.example'}).status_code == 400
    assert post(client, '/domains/reset', {**fields, 'domain': 'private.example'}).status_code == 404
    settings.SITEWATCHER_READ_ONLY = True
    assert b'/domains/reset' not in client.get('/domains/edit?domain=one.example',
                                              HTTP_HOST='localhost').content
    assert post(client, '/domains/reset', fields).status_code == 405
    settings.SITEWATCHER_READ_ONLY = False
    assert saved_raw() == raw
    # The separate public serializer must never acquire owner diagnostics or raw settings.
    response = post(client, '/settings/public', {'action': 'enable', 'domain.one.example': 'on'})
    link = re.search(rb'id="public-link"[^>]*value="([^"]+)"', response.content).group(1).decode()
    public = Client().get(link, HTTP_HOST='localhost')
    assert public.status_code == 200
    assert b'Invalid domain settings' not in public.content and raw.encode() not in public.content
    assert post(client, '/domains/reset', fields).status_code == 303
    assert storage.get_domain_override(31, 'one.example') is None
    assert len(list(storage.iter_history(31, domain='one.example'))) == 1
    assert storage.domain_exists(99, 'private.example')


def test_stale_corrupt_settings_recovery_does_not_erase_new_override(owner, client):
    storage.set_domain_override(31, 'one.example', {})
    with storage._write_connection() as conn:
        conn.execute("UPDATE domain_overrides SET data_json='{broken' WHERE owner_id=31")
    page = client.get('/domains/edit?domain=one.example', HTTP_HOST='localhost')
    assert page.status_code == 200
    revision = re.search(rb'name="revision" value="([^"]+)"', page.content).group(1).decode()
    storage.set_domain_override(31, 'one.example', {'interval_minutes': 19}, replace=True)
    response = post(client, '/domains/reset', {'domain': 'one.example', 'revision': revision})
    assert response.status_code == 409
    assert b'Settings changed' in response.content
    assert storage.get_domain_override(31, 'one.example') == {'interval_minutes': 19}


def test_current_warning_explanation_survives_recent_history_limit(owner, client):
    from sitewatcher.web_actions import history_context
    message = 'Certificate expires soon <private-current-detail>'
    storage.save_history(31, 'one.example', 'tls_cert', 'WARN', message, {})
    for _ in range(101):
        storage.save_history(31, 'one.example', 'http_basic', 'OK', 'HTTP OK', {})
    assert len(history_context(31, 'one.example')) == 100
    assert all(row['message'] != message for row in history_context(31, 'one.example'))
    response = client.get('/domains/history?domain=one.example', HTTP_HOST='localhost')
    assert response.status_code == 200
    assert b'Certificate expires soon &lt;private-current-detail&gt;' in response.content
    assert b'<private-current-detail>' not in response.content
    response = post(client, '/settings/public', {'action': 'enable', 'domain.one.example': 'on'})
    link = re.search(rb'id="public-link"[^>]*value="([^"]+)"', response.content).group(1).decode()
    assert b'private-current-detail' not in Client().get(link, HTTP_HOST='localhost').content


def test_add_multiple_domains_with_shared_settings(owner, client):
    response = post(client, '/domains/add', {
        'domain': 'BATCH.example, private.example, last.example',
        'interval_minutes': '17', 'keywords': 'welcome, shop', 'ports': '80, 443',
        'check.tls_cert': 'off',
    })
    assert response.status_code == 303
    overrides = [storage.get_domain_override(31, name) for name in
                 ('batch.example', 'private.example', 'last.example')]
    assert overrides[0] == overrides[1] == overrides[2]
    assert overrides[0]['interval_minutes'] == 17
    assert overrides[0]['keywords'] == ['welcome', 'shop']
    assert overrides[0]['checks']['tls_cert'] is False
    assert storage.get_domain_override(99, 'private.example') is None


@pytest.mark.parametrize('second', ['bad/path', 'one.example', 'FIRST.example'])
def test_bulk_add_failure_preserves_draft_and_creates_nothing(owner, client, second):
    response = post(client, '/domains/add', {
        'domain': f'first.example, {second}', 'interval_minutes': '19',
    })
    assert response.status_code == 400
    assert storage.list_domains(31) == ['one.example']
    assert f'first.example, {second}'.encode() in response.content
    assert second.encode() in response.content
    assert b'value="19"' in response.content


def test_bulk_add_storage_failure_rolls_back_whole_batch(owner, client, monkeypatch):
    original = storage._store_domain_override

    def fail_second(conn, owner_id, domain, data):
        if domain == 'second.example':
            raise ValueError('injected failure')
        return original(conn, owner_id, domain, data)

    monkeypatch.setattr(storage, '_store_domain_override', fail_second)
    response = post(client, '/domains/add', {
        'domain': 'first.example, second.example',
    })
    assert response.status_code in {400, 503}
    assert storage.list_domains(31) == ['one.example']


def test_old_extra_domain_fields_are_rejected_and_plus_button_is_removed(owner, client):
    assert post(client, '/domains/save', {
        'domain': 'one.example', 'domain.1': 'second.example',
    }).status_code == 400
    assert post(client, '/domains/add', {
        'domain': 'first.example', 'domain.10': 'second.example',
    }).status_code == 400
    response = client.get('/domains/new', HTTP_HOST='localhost')
    assert b'data-add-domain' not in response.content
    assert b'example.com, example.org' in response.content
    response = client.get('/domains/edit?domain=one.example', HTTP_HOST='localhost')
    assert b'data-add-domain' not in response.content


def test_bulk_add_fifty_domains_using_full_native_form(owner, client):
    from html import unescape
    response = client.get('/domains/new', HTTP_HOST='localhost')
    html = re.search(r'<form\b[^>]*class="panel domain-form"[^>]*>(.*?)</form>',
                     response.content.decode(), re.S).group(1)
    fields = {name: unescape(value) for name, value in re.findall(
        r'<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"', html)}
    fields.update({f'check.{name}': '' for name in ChecksModel.model_fields})
    fields.update(keywords='welcome', ports='80', proxy_mode='keep', proxy='')
    fields['domain'] = ', '.join(f'batch{i}.example' for i in range(50))
    assert post(client, '/domains/add', fields).status_code == 303
    assert len(storage.list_domains(31)) == 51


def test_bulk_add_ignores_empty_separators_but_requires_a_domain(owner, client):
    assert post(client, '/domains/add', {
        'domain': 'first.example,  ,last.example,',
    }).status_code == 303
    assert storage.list_domains(31) == ['first.example', 'last.example', 'one.example']
    assert post(client, '/domains/add', {
        'domain': ' , , ',
    }).status_code == 400
    assert not storage.domain_exists(31, 'second.example')


def test_bulk_add_invalid_shared_settings_redacts_proxy_and_creates_nothing(owner, client):
    response = post(client, '/domains/add', {
        'domain': 'first.example, second.example',
        'ports': '99999', 'proxy_mode': 'set', 'proxy': 'http://hidden:secret@example.com',
    })
    assert response.status_code == 400
    assert b'secret' not in response.content
    assert b'second.example' in response.content
    assert storage.list_domains(31) == ['one.example']


def test_bulk_add_marks_invalid_list_and_preserves_it(owner, client):
    response = post(client, '/domains/add', {'domain': 'first.example, one.example'})
    assert response.status_code == 400
    html = response.content.decode()
    field = re.search(r'<input id="domain"[^>]*>', html).group()
    assert 'aria-invalid="true"' in field
    assert 'value="first.example, one.example"' in field
    assert 'name="domain.1"' not in html


def test_comma_separated_domain_count_is_bounded(owner, client):
    response = post(client, '/domains/add', {
        'domain': ','.join(f'batch{i}.example' for i in range(51)),
    })
    assert response.status_code == 400
    assert storage.list_domains(31) == ['one.example']


def test_history_filters_apply_before_limit_and_use_workspace_dates(owner, client):
    storage.save_history(31, 'one.example', 'tls_cert', 'CRIT', 'matching older result', {})
    with storage._write_connection() as conn:
        conn.execute("UPDATE history SET created_at='2026-11-02 21:30:00'")
    for _ in range(105):
        storage.save_history(31, 'one.example', 'http_basic', 'OK', 'newer other result', {})
    response = client.get('/domains/history', {'domain': 'one.example', 'days': '7',
        'history_from': '2026-11-03', 'history_to': '2026-11-03',
        'history_check': 'tls_cert', 'history_status': 'CRIT'}, HTTP_HOST='localhost')
    assert response.status_code == 200
    rows = response.context['history']
    assert len(rows) == 1 and rows[0]['message'] == 'matching older result'
    assert response.context['report']['days'] == 7
    assert b'name="history_from"' in response.content
    assert b'name="history_check"' in response.content
    assert b'name="history_status"' in response.content
    response = client.get('/domains/history', {'domain': 'one.example',
        'history_to': '2026-11-02', 'history_check': 'tls_cert'}, HTTP_HOST='localhost')
    assert response.status_code == 200
    assert response.context['history'] == []


@pytest.mark.parametrize('filters', [
    {'history_from': 'bad'}, {'history_status': 'INVALID'}, {'history_check': 'injected'},
    {'history_from': '2026-11-04', 'history_to': '2026-11-03'},
])
def test_history_filters_reject_invalid_values(owner, client, filters):
    response = client.get('/domains/history', {'domain': 'one.example', **filters},
                          HTTP_HOST='localhost')
    assert response.status_code == 400
    assert response.context['history'] == []


def test_history_filter_midnight_boundaries_and_owner_domain_isolation(owner, client):
    storage.add_domain(99, 'one.example')
    storage.add_domain(31, 'other.example')
    with storage._write_connection() as conn:
        for owner_id, domain, stamp, check, state, message in [
            (31, 'one.example', '2026-11-02 20:59:59', 'tls_cert', 'CRIT', 'before'),
            (31, 'one.example', '2026-11-02 21:00:00', 'tls_cert', 'CRIT', 'start'),
            (31, 'one.example', '2026-11-03 20:59:59', 'tls_cert', 'CRIT', 'end'),
            (31, 'one.example', '2026-11-03 21:00:00', 'tls_cert', 'CRIT', 'after'),
            (31, 'one.example', '2026-11-03 12:00:00', 'tls_cert', 'OK', 'other state'),
            (31, 'one.example', '2026-11-03 12:00:00', 'ping', 'CRIT', 'other check'),
            (31, 'other.example', '2026-11-03 12:00:00', 'tls_cert', 'CRIT', 'other domain'),
            (99, 'one.example', '2026-11-03 12:00:00', 'tls_cert', 'CRIT', 'other owner'),
        ]:
            conn.execute('INSERT INTO history(owner_id,domain,created_at,check_name,status,message)'
                         ' VALUES(?,?,?,?,?,?)', (owner_id, domain, stamp, check, state, message))
    response = client.get('/domains/history', {'domain': 'one.example', 'days': '7',
        'history_from': '2026-11-03', 'history_to': '2026-11-03',
        'history_check': 'tls_cert', 'history_status': 'CRIT'}, HTTP_HOST='localhost')
    assert response.status_code == 200
    assert [item['message'] for item in response.context['history']] == ['end', 'start']
    from html import unescape
    from urllib.parse import parse_qs, urlsplit
    html = unescape(response.content.decode())
    nav = html.split('<nav class="periods"', 1)[1].split('</nav>', 1)[0]
    for href in re.findall('href="([^"]+)"', nav):
        query = parse_qs(urlsplit(href).query)
        assert query['domain'] == ['one.example']
        assert query['history_from'] == query['history_to'] == ['2026-11-03']
        assert query['history_check'] == ['tls_cert'] and query['history_status'] == ['CRIT']


@pytest.mark.parametrize(('day', 'hours'), [('2026-03-29', 23), ('2026-10-25', 25)])
def test_history_dates_follow_dst(day, hours):
    from sitewatcher.webapp.forms import HistoryFiltersForm
    form = HistoryFiltersForm({'history_from': day, 'history_to': day}, zone='Europe/Berlin')
    assert form.is_valid(), form.errors
    duration = form.cleaned_data['until'] - form.cleaned_data['since']
    assert duration.total_seconds() == hours * 3600


def test_favorites_persist_sort_first_and_toggle_without_changing_monitoring(owner, client):
    storage.add_domain(31, 'z-favorite.example')
    storage.save_history(31, 'one.example', 'http_basic', 'CRIT', 'down', {})
    before = storage.get_domain_override(31, 'z-favorite.example')
    fields = {'domain': 'z-favorite.example', 'favorite': 'on', 'q': '', 'status': 'all', 'days': '7'}
    response = post(client, '/domains/favorite', fields)
    assert response.status_code == 303
    assert 'days=7' in response['Location']
    response = client.get('/', HTTP_HOST='localhost')
    assert response.context['rows'][0]['name'] == 'z-favorite.example'
    assert response.context['rows'][0]['favorite'] is True
    assert b'aria-pressed="true"' in response.content
    assert storage.get_domain_override(31, 'z-favorite.example') == before
    # Explicit state is idempotent; a repeated submission must not toggle it off.
    assert post(client, '/domains/favorite', fields).status_code == 303
    assert client.get('/', HTTP_HOST='localhost').context['rows'][0]['favorite'] is True
    assert post(client, '/domains/favorite', {**fields, 'favorite': 'off'}).status_code == 303
    rows = client.get('/', HTTP_HOST='localhost').context['rows']
    assert rows[0]['name'] == 'one.example'
    assert not any(row['favorite'] for row in rows)


def test_favorites_obey_owner_isolation_csrf_readonly_and_validate_return_filters(owner, client,
                                                                               settings):
    secure = Client(enforce_csrf_checks=True)
    secure.force_login(owner.user)
    fields = {'domain': 'one.example', 'favorite': 'on'}
    assert post(secure, '/domains/favorite', fields).status_code == 403
    html = secure.get('/', HTTP_HOST='localhost').content
    token = re.search(rb'name="csrfmiddlewaretoken" value="([^"]+)"', html).group(1).decode()
    assert post(secure, '/domains/favorite', {**fields, 'csrfmiddlewaretoken': token}).status_code == 303
    assert client.get('/domains/favorite', HTTP_HOST='localhost').status_code == 405
    assert post(client, '/domains/favorite', {**fields, 'domain': 'private.example'}).status_code == 404
    for patch in ({'favorite': 'invalid'}, {'owner_id': '99'}, {'days': '0'}, {'status': 'invalid'}):
        assert post(client, '/domains/favorite', {**fields, **patch}).status_code == 400
    assert post(client, '/domains/favorite', {**fields, 'q': 'one', 'days': '30',
                                            'status': 'problems'}).status_code == 303
    settings.SITEWATCHER_READ_ONLY = True
    assert post(client, '/domains/favorite', {**fields, 'favorite': 'off'}).status_code == 405
    html = client.get('/', HTTP_HOST='localhost').content
    assert b'action="/domains/favorite"' not in html


def test_same_hostname_favorite_is_owner_scoped_and_delete_clears_it(owner, client):
    storage.add_domain(99, 'one.example')
    storage.set_domain_favorite(99, 'one.example', True)
    rows = client.get('/', HTTP_HOST='localhost').context['rows']
    assert rows[0]['favorite'] is False
    assert post(client, '/domains/favorite', {'domain': 'one.example', 'favorite': 'on'}).status_code == 303
    storage.remove_domain(31, 'one.example')
    storage.add_domain(31, 'one.example')
    assert client.get('/', HTTP_HOST='localhost').context['rows'][0]['favorite'] is False


def test_domain_reorder_persists_filters_favorites_and_owner_scope(owner, client):
    import json
    for name in ('two.example', 'three.example', 'z-favorite.example'):
        storage.add_domain(31, name)
    storage.set_domain_favorite(31, 'z-favorite.example', True)
    before = storage.get_domain_override(31, 'one.example')
    response = post(client, '/domains/reorder', {'order': json.dumps([
        'z-favorite.example', 'three.example', 'two.example', 'one.example'])})
    assert response.status_code == 200
    assert [r['name'] for r in client.get('/', HTTP_HOST='localhost').context['rows']] == [
        'z-favorite.example', 'three.example', 'two.example', 'one.example']
    # Reordering a filtered subset leaves hidden rows in their previous slots.
    assert post(client, '/domains/reorder', {'order': json.dumps([
        'one.example', 'three.example'])}).status_code == 200
    assert [r['name'] for r in client.get('/', HTTP_HOST='localhost').context['rows']] == [
        'z-favorite.example', 'one.example', 'two.example', 'three.example']
    assert storage.get_domain_override(31, 'one.example') == before
    storage.add_domain(31, 'new.example')
    assert client.get('/', HTTP_HOST='localhost').context['rows'][-1]['name'] == 'new.example'
    owner.refresh_from_db()
    assert 'private.example' not in owner.domain_order


@pytest.mark.parametrize('value', ['not json', '{}', '[]', '["one.example"]',
                                  '["one.example","one.example"]',
                                  '["one.example",42]', '["one.example", "private.example"]'])
def test_domain_reorder_rejects_invalid_or_foreign_names(owner, client, value):
    response = post(client, '/domains/reorder', {'order': value})
    assert response.status_code in {400, 404}
    owner.refresh_from_db()
    assert owner.domain_order == []


def test_domain_reorder_requires_csrf_post_and_writable_workspace(owner, client):
    import json
    from django.conf import settings
    storage.add_domain(31, 'two.example')
    fields = {'order': json.dumps(['two.example', 'one.example'])}
    secure = Client(enforce_csrf_checks=True)
    secure.force_login(owner.user)
    assert post(secure, '/domains/reorder', fields).status_code == 403
    secure.get('/', HTTP_HOST='localhost')
    token = secure.cookies['csrftoken'].value
    assert post(secure, '/domains/reorder', {**fields, 'csrfmiddlewaretoken': token}).status_code == 200
    assert client.get('/domains/reorder', HTTP_HOST='localhost').status_code == 405
    assert post(client, '/domains/reorder', {**fields, 'owner_id': '99'}).status_code == 400
    settings.SITEWATCHER_READ_ONLY = True
    assert post(client, '/domains/reorder', fields).status_code == 405
    assert b'data-domain-drag' not in client.get('/', HTTP_HOST='localhost').content


def test_reordering_cannot_move_favorites_below_regular_domains(owner, client):
    import json
    storage.add_domain(31, 'favorite.example')
    storage.set_domain_favorite(31, 'favorite.example', True)
    assert post(client, '/domains/reorder', {'order': json.dumps([
        'one.example', 'favorite.example'])}).status_code == 400
    owner.refresh_from_db()
    assert owner.domain_order == []


def test_domain_reorder_detects_another_tabs_saved_order(owner, client, monkeypatch):
    import json
    from sitewatcher.webapp import domains
    from sitewatcher.webapp.models import Workspace
    storage.add_domain(31, 'two.example')
    original = domains.build_snapshot

    def another_tab(*args, **kwargs):
        snapshot = original(*args, **kwargs)
        Workspace.objects.filter(pk=owner.pk).update(domain_order=['two.example', 'one.example'])
        return snapshot

    monkeypatch.setattr(domains, 'build_snapshot', another_tab)
    response = post(client, '/domains/reorder', {'order': json.dumps(['one.example', 'two.example'])})
    assert response.status_code == 409
    owner.refresh_from_db()
    assert owner.domain_order == ['two.example', 'one.example']


def test_row_actions_keep_list_filters_and_check_only_the_selected_domain(owner, client, monkeypatch):
    from urllib.parse import parse_qs, urlsplit
    from sitewatcher.webapp import domains
    calls = []
    monkeypatch.setattr(domains, 'run_manual_checks', lambda cfg, identity, names:
                        calls.append((identity, names)))
    fields = {'domain': 'one.example', 'q': 'one', 'status': 'all', 'days': '7'}
    for action in ('check', 'pause', 'resume'):
        response = post(client, '/domains/' + action, fields)
        assert response.status_code == 303
        query = parse_qs(urlsplit(response['Location']).query)
        assert query['q'] == ['one'] and query['status'] == ['all'] and query['days'] == ['7']
    assert calls == [(31, ['one.example'])]
    for action in ('check', 'pause', 'resume'):
        assert post(client, '/domains/' + action, {**fields, 'days': '0'}).status_code == 400
    assert calls == [(31, ['one.example'])]
