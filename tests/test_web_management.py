import json
import re
import sqlite3
import threading
from contextlib import closing
from http.client import HTTPConnection
from urllib.parse import urlencode

import pytest

from sitewatcher import storage
from sitewatcher.config import AppConfig
from sitewatcher.web import create_server


@pytest.fixture
def management_server():
    storage.add_domain(1, 'one.example')
    storage.add_domain(2, 'private.example')
    httpd = create_server(AppConfig(), 1, port=0)
    thread = threading.Thread(target=httpd.serve_forever, kwargs={'poll_interval': 0.01})
    thread.start()
    yield httpd
    httpd.shutdown()
    thread.join(timeout=3)
    httpd.server_close()
    assert not thread.is_alive()


def request(server, path='/', *, method='GET', fields=None, headers=None, body=None):
    if fields is not None:
        body = urlencode(fields)
    all_headers = {'Content-Type': 'application/x-www-form-urlencoded',
                   'Origin': f'http://127.0.0.1:{server.server_port}'}
    all_headers.update(headers or {})
    client = HTTPConnection(*server.server_address, timeout=5)
    try:
        client.request(method, path, body=body, headers=all_headers)
        response = client.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        client.close()


def token(server):
    code, _, body = request(server, '/domains/new')
    assert code == 200
    return re.search(rb'name="csrf_token" value="([^"]+)"', body).group(1).decode()


def test_mutations_require_csrf_and_same_origin_before_writing(management_server):
    server = management_server
    before = storage.list_domains(1)
    for fields, headers in [({'domain': 'new.example'}, {}),
                            ({'domain': 'new.example', 'csrf_token': 'wrong'}, {}),
                            ({'domain': 'new.example', 'csrf_token': token(server)}, {'Origin': 'https://evil.example'})]:
        assert request(server, '/domains/add', method='POST', fields=fields, headers=headers)[0] == 403
    assert storage.list_domains(1) == before
    assert request(server, '/domains/add?domain=new.example')[0] in {404, 405}


def test_add_edit_delete_flow_and_owner_scope(management_server):
    server = management_server
    csrf = token(server)
    code, headers, _ = request(server, '/domains/add', method='POST', fields={
        'csrf_token': csrf, 'domain': 'HTTPS://NEW.EXAMPLE/path', 'interval_minutes': '15',
    })
    assert code == 303 and headers['Location'].startswith('/')
    assert storage.domain_exists(1, 'new.example')
    assert storage.get_domain_override(1, 'new.example')['interval_minutes'] == 15
    assert request(server, '/domains/edit?domain=private.example')[0] == 404
    for action in ['pause', 'resume', 'reset', 'delete', 'check']:
        code, _, _ = request(server, f'/domains/{action}', method='POST', fields={
            'csrf_token': csrf, 'domain': 'private.example', 'confirm': 'private.example',
        })
        assert code in {400, 404}
    assert storage.domain_exists(2, 'private.example')
    assert request(server, '/domains/delete', method='POST', fields={
        'csrf_token': csrf, 'domain': 'new.example',
    })[0] == 400
    assert storage.domain_exists(1, 'new.example')
    assert request(server, '/domains/delete', method='POST', fields={
        'csrf_token': csrf, 'domain': 'new.example', 'confirm': 'new.example',
    })[0] == 303
    assert not storage.domain_exists(1, 'new.example')


def test_invalid_form_preserves_database_and_never_redisplays_proxy(management_server):
    server = management_server
    code, _, body = request(server, '/domains/add', method='POST', fields={
        'csrf_token': token(server), 'domain': 'unsafe.example', 'interval_minutes': '-1',
        'proxy_mode': 'set', 'proxy': 'http://private:secret@proxy.example:8080',
    })
    assert code == 400
    assert b'secret' not in body and b'private:' not in body
    assert not storage.domain_exists(1, 'unsafe.example')


def test_parser_rejects_duplicate_fields_oversized_bodies_and_bad_encoding(management_server):
    server = management_server
    csrf = token(server)
    for body in [f'csrf_token={csrf}&domain=a.example&domain=b.example',
                 f'csrf_token={csrf}&domain=%FF']:
        assert request(server, '/domains/add', method='POST', body=body)[0] == 400
    assert request(server, '/domains/add', method='POST', body='x' * (1024 * 1024 + 1))[0] == 413
    assert storage.list_domains(1) == ['one.example']


def test_theme_cookie_persists_across_pages_without_data_writes(management_server):
    server = management_server
    before = storage.DEFAULT_DB.read_bytes()
    code, headers, _ = request(server, '/theme?mode=dark&next=%2Fdomains%2Fnew')
    assert code == 303 and headers['Location'] == '/domains/new'
    cookie = headers['Set-Cookie'].split(';')[0]
    for path in ['/', '/domains/new', '/workspace']:
        code, _, body = request(server, path, headers={'Cookie': cookie})
        assert code == 200 and b'data-theme="dark"' in body
    assert request(server, '/theme?mode=invalid')[0] == 400
    assert request(server, '/theme?mode=dark&next=https://evil.example')[0] == 400
    assert storage.DEFAULT_DB.read_bytes() == before


def test_csv_export_import_and_notification_toggle(management_server):
    server = management_server
    code, headers, body = request(server, '/export.csv')
    assert code == 200 and 'attachment' in headers['Content-Disposition']
    assert b'one.example' in body and b'private.example' not in body
    csrf = token(server)
    assert request(server, '/alerts', method='POST', fields={
        'csrf_token': csrf, 'enabled': 'off',
    })[0] == 303
    assert not storage.is_user_alerts_enabled(1)
    assert storage.is_user_alerts_enabled(2)
    content = body.decode('utf-8-sig').replace('one.example', 'imported.example')
    code, _, _ = request(server, '/import', method='POST', fields={
        'csrf_token': csrf, 'csv_text': content, 'mode': 'merge',
    })
    assert code == 303 and storage.domain_exists(1, 'imported.example')


def test_history_shows_only_fixed_owner(management_server):
    storage.save_history(1, 'one.example', 'ping', 'CRIT', 'visible incident', {})
    storage.save_history(2, 'private.example', 'ping', 'CRIT', 'hidden incident', {})
    code, _, body = request(management_server, '/domains/history?domain=one.example')
    assert code == 200 and b'visible incident' in body and b'hidden incident' not in body


def test_snapshot_json_remains_free_of_settings_and_management_token(management_server):
    storage.set_domain_override(1, 'one.example', {'proxy': 'http://private:secret@proxy.example'})
    code, headers, body = request(management_server, '/api/status')
    assert headers['Referrer-Policy'] == 'same-origin'
    assert code == 200 and json.loads(body)['summary']['total'] == 1
    assert b'secret' not in body and b'csrf_token' not in body
    with closing(sqlite3.connect(storage.DEFAULT_DB)) as db:
        assert db.execute('PRAGMA quick_check').fetchone() == ('ok',)


def test_unicode_csrf_and_missing_origin_are_rejected_without_mutation(management_server):
    server = management_server
    assert request(server, '/domains/add', method='POST', fields={
        'csrf_token': 'неверный-токен', 'domain': 'no.example',
    })[0] == 403
    client = HTTPConnection(*server.server_address, timeout=3)
    try:
        client.request('POST', '/domains/add', body=urlencode({
            'csrf_token': token(server), 'domain': 'no.example',
        }), headers={'Content-Type': 'application/x-www-form-urlencoded'})
        assert client.getresponse().status == 403
    finally:
        client.close()
    assert not storage.domain_exists(1, 'no.example')


def test_live_checks_save_results_bound_concurrency_and_allow_readers(management_server, monkeypatch):
    import concurrent.futures
    from sitewatcher import web
    from sitewatcher.checks.base import CheckOutcome, Status

    server = management_server
    started, release = threading.Event(), threading.Event()
    calls = []

    class Dispatcher:
        def __init__(self, cfg):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            pass

        async def run_for(self, owner, domain, **kwargs):
            calls.append((owner, domain, kwargs))
            started.set()
            assert release.wait(timeout=4)
            return [CheckOutcome('http_basic', Status.OK, 'synthetic web probe', {})]

    monkeypatch.setattr(web, 'Dispatcher', Dispatcher)
    fields = {'csrf_token': token(server), 'domain': 'one.example'}
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(request, server, '/domains/check', method='POST', fields=fields)
        try:
            assert started.wait(timeout=3)
            assert request(server, '/healthz')[0] == 200
            assert request(server, '/domains/check', method='POST', fields=fields)[0] == 409
        finally:
            release.set()
        assert future.result(timeout=3)[0] == 303
    assert calls == [(1, 'one.example', {'use_cache': False})]
    assert storage.last_results(1, 'one.example')[0]['message'] == 'synthetic web probe'
    assert not storage.last_results(2, 'private.example')


def test_deleted_domain_is_not_restored_by_finished_web_check(management_server, monkeypatch):
    from sitewatcher import web
    from sitewatcher.checks.base import CheckOutcome, Status

    class Dispatcher:
        def __init__(self, cfg):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            pass

        async def run_for(self, owner, domain, **kwargs):
            storage.remove_domain(owner, domain)
            return [CheckOutcome('ping', Status.OK, 'late response', {})]

    monkeypatch.setattr(web, 'Dispatcher', Dispatcher)
    server = management_server
    assert request(server, '/domains/check', method='POST', fields={
        'csrf_token': token(server), 'domain': 'one.example',
    })[0] == 303
    assert not storage.domain_exists(1, 'one.example')
    assert not storage.last_results(1, 'one.example')


def test_multipart_csv_upload_uses_existing_owner_scoped_importer(management_server):
    server = management_server
    csv_text = request(server, '/export.csv')[2].decode('utf-8-sig').replace('one.example', 'upload.example')
    boundary = 'sitewatcher-test-boundary'
    fields = {'csrf_token': token(server), 'mode': 'merge', 'csv_text': '', 'csv_file': csv_text}
    chunks = []
    for name, value in fields.items():
        filename = '; filename="backup.csv"' if name == 'csv_file' else ''
        chunks.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"{filename}\r\n\r\n{value}\r\n')
    body = (''.join(chunks) + f'--{boundary}--\r\n').encode('utf-8')
    assert request(server, '/import', method='POST', body=body,
                   headers={'Content-Type': f'multipart/form-data; boundary={boundary}'})[0] == 303
    assert storage.domain_exists(1, 'upload.example')


def test_readonly_mode_rejects_writes_and_hides_management_controls():
    storage.add_domain(1, 'one.example')
    server = create_server(AppConfig(), 1, port=0, read_only=True)
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01})
    thread.start()
    try:
        code, _, body = request(server)
        assert code == 200 and b'csrf_token' not in body and b'/domains/new' not in body
        assert request(server, '/domains/new')[0] == 404
        assert request(server, '/domains/add', method='POST', fields={'domain': 'no.example'})[0] == 405
        assert not storage.domain_exists(1, 'no.example')
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()


def test_rejected_stale_edit_cannot_overwrite_changes_by_resubmitting(management_server):
    server = management_server
    csrf = token(server)
    code, _, page = request(server, '/domains/edit?domain=one.example')
    assert code == 200
    revision = re.search(rb'name="revision"\s+value="([^"]+)"', page).group(1).decode()
    storage.set_domain_override(1, 'one.example', {'interval_minutes': 60})
    fields = {'csrf_token': csrf, 'domain': 'one.example', 'revision': revision,
              'interval_minutes': '15'}
    code, _, error_page = request(server, '/domains/save', method='POST', fields=fields)
    assert code == 400 and b'Settings changed' in error_page
    fields['revision'] = re.search(rb'name="revision"\s+value="([^"]+)"', error_page).group(1).decode()
    assert request(server, '/domains/save', method='POST', fields=fields)[0] == 400
    assert storage.get_domain_override(1, 'one.example')['interval_minutes'] == 60


def test_csv_error_preserves_selected_mode_without_redisplaying_private_content(management_server):
    server = management_server
    code, _, body = request(server, '/import', method='POST', fields={
        'csrf_token': token(server), 'mode': 'replace', 'csv_text': 'invalid;private:secret',
    })
    assert code == 400 and b'value="replace" selected' in body
    assert b'private:secret' not in body


def test_import_rejects_two_sources_and_forged_owner_fields(management_server):
    server = management_server
    csrf = token(server)
    code, _, _ = request(server, '/import', method='POST', fields={
        'csrf_token': csrf, 'csv_file': 'a', 'csv_text': 'b', 'mode': 'merge',
    })
    assert code == 400
    assert request(server, '/alerts', method='POST', fields={
        'csrf_token': csrf, 'enabled': 'off', 'owner_id': '2',
    })[0] == 400
    assert storage.is_user_alerts_enabled(1) and storage.is_user_alerts_enabled(2)
