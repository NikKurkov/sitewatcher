import os
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
    env = os.environ.copy()
    env["DATABASE_PATH"] = str(path)
    env.pop("TELEGRAM_TOKEN", None)
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
        with closing(HTTPConnection(url.hostname, url.port, timeout=5)) as client:
            client.request("GET", "/")
            response = client.getresponse()
            assert response.status == 200
            assert b"example.com" in response.read()
    finally:
        if process.poll() is None:
            process.send_signal(stop_signal)
        output, error = process.communicate(timeout=5)
    assert process.returncode == 0, error


def test_web_cli_requires_explicit_owner(tmp_path):
    run = subprocess.run([sys.executable, "-m", "sitewatcher.main", "web"], cwd=tmp_path,
                         capture_output=True, text=True)
    assert run.returncode != 0 and "web requires --owner" in run.stderr
