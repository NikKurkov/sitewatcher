import json
import sqlite3
import threading
from contextlib import closing
from http.client import HTTPConnection

import pytest

from sitewatcher import storage
from sitewatcher.config import AppConfig


@pytest.fixture
def server(tmp_path, monkeypatch):
    from sitewatcher.web import create_server

    monkeypatch.setattr(storage, 'DEFAULT_DB', tmp_path / 'monitor.db')
    with closing(sqlite3.connect(storage.DEFAULT_DB)) as connection:
        connection.executescript(storage.SCHEMA_SQL)
        connection.executemany('INSERT INTO users(telegram_id) VALUES(?)', [(1,), (2,)])
        connection.executemany('INSERT INTO domains(owner_id,name) VALUES(?,?)',
                               [(1, 'owner-one.example'), (2, 'private-owner-two.example')])
        connection.commit()
    httpd = create_server(AppConfig(), 1, port=0, read_only=True)
    thread = threading.Thread(target=httpd.serve_forever, kwargs={'poll_interval': 0.01})
    thread.start()
    yield httpd
    httpd.shutdown()
    thread.join(timeout=2)
    httpd.server_close()
    assert not thread.is_alive()


def request(server, path='/', method='GET', headers=None):
    connection = HTTPConnection(*server.server_address, timeout=2)
    try:
        connection.request(method, path, headers=headers or {})
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def test_loopback_server_json_is_fixed_owner_and_readonly(server):
    assert server.server_address[0] == '127.0.0.1'
    before = storage.DEFAULT_DB.read_bytes()
    status, headers, body = request(server, '/api/status?owner=2')
    assert status == 200
    snapshot = json.loads(body)
    assert [item['name'] for item in snapshot['domains']] == ['owner-one.example']
    assert 'private-owner-two' not in body.decode()
    assert storage.DEFAULT_DB.read_bytes() == before
    assert headers['Cache-Control'] == 'no-store'
    assert headers['X-Content-Type-Options'] == 'nosniff'
    assert headers['X-Frame-Options'] == 'DENY'
    assert "default-src 'none'" in headers['Content-Security-Policy']
    assert "style-src 'self'" in headers['Content-Security-Policy']
    assert "frame-ancestors 'none'" in headers['Content-Security-Policy']
    assert 'Access-Control-Allow-Origin' not in headers


@pytest.mark.parametrize('path', ['/', '/style.css', '/api/status', '/healthz'])
def test_get_and_head_routes_have_correct_lengths_without_head_body(server, path):
    get_status, get_headers, body = request(server, path)
    head_status, head_headers, head_body = request(server, path, method='HEAD')
    assert get_status == head_status == 200
    assert int(get_headers['Content-Length']) == len(body)
    assert int(head_headers['Content-Length']) > 0
    assert head_headers['Content-Type'] == get_headers['Content-Type']
    assert head_body == b''


@pytest.mark.parametrize('host', ['evil.example', '127.0.0.1.evil.example', 'localhost.evil.example',
                                 '127.0.0.1:1', 'localhost:1'])
def test_host_rebinding_and_wrong_ports_rejected(server, host):
    assert request(server, headers={'Host': host})[0] == 403


def test_missing_or_duplicate_host_is_rejected(server):
    connection = HTTPConnection(*server.server_address, timeout=2)
    try:
        connection.putrequest('GET', '/', skip_host=True)
        connection.endheaders()
        assert connection.getresponse().status == 403
    finally:
        connection.close()
    connection = HTTPConnection(*server.server_address, timeout=2)
    try:
        connection.putrequest('GET', '/')
        connection.putheader('Host', f'localhost:{server.server_port}')
        connection.endheaders()
        assert connection.getresponse().status == 403
    finally:
        connection.close()


def test_same_origin_only_and_localhost_is_accepted(server):
    host = f'localhost:{server.server_port}'
    assert request(server, '/healthz', headers={'Host': host, 'Origin': f'http://{host}'})[0] == 200
    for origin in ('https://evil.example', 'null', f'http://127.0.0.1:{server.server_port}'):
        assert request(server, headers={'Host': host, 'Origin': origin})[0] == 403


@pytest.mark.parametrize('method', ['POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'TRACE',
                                   'CONNECT', 'CUSTOM'])
def test_write_and_unsupported_methods_are_rejected(server, method):
    status, headers, body = request(server, method=method)
    assert status == 405
    assert headers['Allow'] == 'GET, HEAD'


def test_unknown_paths_and_invalid_view_filters(server):
    assert request(server, '/missing')[0] == 404
    assert request(server, '/?status=private-unknown-status')[0] == 400
    assert request(server, 'http://evil.example/',
                   headers={'Host': f'127.0.0.1:{server.server_port}'})[0] == 400


def test_snapshot_failure_is_sanitized_and_health_fails(server, capsys):
    storage.DEFAULT_DB.write_bytes(b'corrupt private monitoring data')
    for path in ('/', '/api/status', '/healthz'):
        status, headers, body = request(server, path + '?q=private-query-value')
        assert status == 503
        assert b'private' not in body
        assert headers['Cache-Control'] == 'no-store'
    output = capsys.readouterr()
    assert 'private-query-value' not in output.out + output.err


@pytest.mark.parametrize('owner', [0, -1, True, '1'])
def test_explicit_positive_integer_owner_required(owner):
    from sitewatcher.web import create_server

    with pytest.raises(ValueError):
        create_server(AppConfig(), owner, port=0)


def test_http_parser_errors_keep_security_headers_and_sanitized_body(server):
    status, headers, body = request(server, '/' + 'private-query-value' * 4000)
    assert status == 414
    assert headers['Cache-Control'] == 'no-store'
    assert headers['X-Content-Type-Options'] == 'nosniff'
    assert b'private-query-value' not in body


def test_run_web_prints_actual_url_and_closes_on_interrupt(monkeypatch, capsys):
    from sitewatcher import web

    class InterruptedServer:
        server_port = 12345
        closed = False

        def serve_forever(self):
            raise KeyboardInterrupt

        def server_close(self):
            self.closed = True

    server = InterruptedServer()
    monkeypatch.setattr(web, 'create_server', lambda *args, **kwargs: server)
    web.run_web(AppConfig(), 1)
    assert server.closed
    assert capsys.readouterr().out.strip() == 'http://127.0.0.1:12345'


@pytest.mark.parametrize('host', ['localhost', '127.0.0.1'])
def test_default_http_port_accepts_browser_host_without_port(server, monkeypatch, host):
    # Browsers omit the default port from both Host and Origin.
    monkeypatch.setattr(server, 'server_port', 80)
    assert request(server, '/healthz', headers={'Host': host, 'Origin': f'http://{host}'})[0] == 200


def test_reader_can_pause_browser_refresh(server):
    status, headers, body = request(server, '/?refresh=off')
    assert status == 200
    assert b'http-equiv="refresh"' not in body
    assert b'name="refresh" value="off" checked' in body
