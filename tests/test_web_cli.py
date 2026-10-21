import os
import json
import secrets
import selectors
import signal
import subprocess
import sys
from contextlib import closing
from http.client import HTTPConnection
from urllib.parse import urlsplit

import pytest

from sitewatcher import storage


@pytest.mark.parametrize('stop_signal', [signal.SIGINT, signal.SIGTERM])
def test_web_cli_serves_saved_results_and_stops_cleanly(tmp_path, monkeypatch, stop_signal):
    path = tmp_path / "monitor.db"
    monkeypatch.setattr(storage, "DEFAULT_DB", path)
    storage.save_history(7, "example.com", "ping", "OK", "online", {})
    password = secrets.token_urlsafe(32)
    setup = """
import os
from sitewatcher.config import AppConfig
from sitewatcher.webapp.bootstrap import configure_web, migrate_web_database
configure_web(AppConfig())
migrate_web_database()
from django.contrib.auth import get_user_model
from sitewatcher.webapp.models import Workspace
user = get_user_model().objects.create_user(username='owner', password=os.environ['TEST_PASSWORD'])
Workspace.objects.create(user=user, owner_id=7)
"""
    env = os.environ.copy()
    env["DATABASE_PATH"] = str(path)
    env.pop("TELEGRAM_TOKEN", None)
    provision = subprocess.run([sys.executable, '-c', setup], cwd=tmp_path,
                               env={**env, 'TEST_PASSWORD': password}, capture_output=True, text=True)
    assert provision.returncode == 0, provision.stderr
    process = subprocess.Popen([
        sys.executable, "-m", "sitewatcher.main", "web", "--owner", "7", "--port", "0",
    ], cwd=tmp_path, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
    try:
        url = None
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            for _ in range(10):
                assert selector.select(timeout=5), "web command did not publish its local URL"
                line = process.stdout.readline()
                if line.startswith("http://127.0.0.1:"):
                    url = urlsplit(line.strip())
                    break
                if not line and process.poll() is not None:
                    break
        assert url is not None
        import http.cookiejar
        import urllib.request
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        base = f'http://{url.netloc}'
        with opener.open(base + '/') as response:
            assert response.url.endswith('/login/?next=/')
            page = response.read()
        import re
        from urllib.parse import urlencode
        token = re.search(rb'name="csrfmiddlewaretoken" value="([^"]+)"', page).group(1).decode()
        with opener.open(base + '/login/', urlencode({'csrfmiddlewaretoken': token,
                         'username': 'owner', 'password': password}).encode()) as response:
            assert response.status == 200
            assert b'example.com' in response.read()
        with opener.open(base + '/api/status') as response:
            assert json.load(response)['summary']['total'] == 1

    finally:
        if process.poll() is None:
            process.send_signal(stop_signal)
        output, error = process.communicate(timeout=5)
    assert process.returncode == 0, error


def test_web_cli_explicit_owner_requires_existing_mapping(tmp_path):
    env = {**os.environ, 'DATABASE_PATH': str(tmp_path / 'monitor.sqlite')}
    run = subprocess.run([sys.executable, '-m', 'sitewatcher.main', 'web', '--owner', '7'],
                         cwd=tmp_path, env=env, capture_output=True, text=True, timeout=10)
    assert run.returncode != 0 and 'owner does not match' in run.stderr


@pytest.mark.parametrize('read_only', [False, True])
def test_fresh_web_installation_and_readonly_fallback(tmp_path, read_only):
    path = tmp_path / 'fresh.sqlite'
    env = os.environ.copy()
    env['DATABASE_PATH'] = str(path)
    env.pop('TELEGRAM_TOKEN', None)
    args = [sys.executable, '-m', 'sitewatcher.main', 'web', '--port', '0']
    if read_only:
        args.append('--read-only')
    process = subprocess.Popen(args, cwd=tmp_path, env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            assert selector.select(timeout=5)
            url = urlsplit(process.stdout.readline().strip())
        with closing(HTTPConnection(url.hostname, url.port, timeout=3)) as client:
            client.request('GET', '/')
            response = client.getresponse()
            body = response.read()
            assert response.status == 302
            assert b'/domains/new' not in body
        assert path.exists()
    finally:
        process.send_signal(signal.SIGTERM)
        _, error = process.communicate(timeout=5)
    assert process.returncode == 0, error


def test_web_startup_database_error_is_sanitized(tmp_path):
    path = tmp_path / 'private-database.sqlite'
    path.write_bytes(b'private corrupted data')
    env = os.environ.copy()
    env['DATABASE_PATH'] = str(path)
    run = subprocess.run([sys.executable, '-m', 'sitewatcher.main', 'web', '--port', '0'],
                         cwd=tmp_path, env=env, capture_output=True, text=True, timeout=5)
    assert run.returncode != 0 and 'Cannot start local dashboard' in run.stderr
    assert 'Traceback' not in run.stderr and 'private corrupted data' not in run.stderr
    assert path.read_bytes() == b'private corrupted data'
