"""Authenticated management preserves owner isolation and existing storage semantics."""
import asyncio
import re
import threading

import pytest
from django.contrib.auth import get_user_model
from django.test import Client

from sitewatcher import storage
from sitewatcher.config import AppConfig
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
        assert post(client, '/domains/' + action, {'domain': 'one.example'}).status_code == 303
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
