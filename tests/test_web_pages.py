from __future__ import annotations

import re

from fastapi.testclient import TestClient

from sitewatcher import storage
from sitewatcher.web.app import create_app
from sitewatcher.web.auth import WebSettings, hash_password


def _login(client: TestClient) -> str:
    login = client.get("/login")
    token = re.search(r'name="csrf" value="([^"]+)"', login.text).group(1)
    response = client.post("/login", data={"csrf": token, "password": "a sufficiently long password"})
    assert response.status_code == 200
    return re.search(r'name="csrf" value="([^"]+)"', response.text).group(1)


def test_all_pages_render_and_escape_check_messages(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DEFAULT_DB", tmp_path / "pages.db")
    storage._INITIALIZED_PATHS.clear()
    settings = WebSettings(11, hash_password("a sufficiently long password"), "x" * 64)
    with TestClient(create_app(settings)) as client:
        token = _login(client)
        storage.add_domain(11, "example.com")
        storage.save_history(11, "example.com", "http_basic", "CRIT", '<script>alert(1)</script>',
                             {"latency_ms_total": 42})
        for path, heading in [("/", "Overview"), ("/domains", "Domains"),
                              ("/domains/example.com", "Domain detail"),
                              ("/history", "Check history"), ("/settings", "Settings"),
                              ("/import", "Import domains")]:
            response = client.get(path)
            assert response.status_code == 200, path
            assert heading in response.text
        detail = client.get("/domains/example.com?period=1d").text
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in detail
        assert '<script>alert(1)</script>' not in detail
        assert "HTTP latency" in detail
        assert "42 ms" in detail
        assert client.post("/domains/example.com/settings/reset", data={"csrf": token}).status_code == 200


def test_global_settings_validate_before_writing(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DEFAULT_DB", tmp_path / "config.db")
    monkeypatch.setenv("SITEWATCHER_CONFIG", str(tmp_path / "config.yaml"))
    settings = WebSettings(11, hash_password("a sufficiently long password"), "x" * 64)
    with TestClient(create_app(settings)) as client:
        token = _login(client)
        path = tmp_path / "config.yaml"
        response = client.post("/settings/config", data={"csrf": token, "yaml_text": "scheduler:\n  interval_minutes: 2\n"})
        assert response.status_code == 200
        assert path.exists()
        before = path.read_text()
        bad = client.post("/settings/config", data={"csrf": token, "yaml_text": "scheduler: ["})
        assert bad.status_code == 400
        assert path.read_text() == before


def test_global_settings_without_explicit_config_path_apply_to_web(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("SITEWATCHER_CONFIG", raising=False)
    monkeypatch.setattr(storage, "DEFAULT_DB", tmp_path / "default-config.db")
    settings = WebSettings(11, hash_password("a sufficiently long password"), "x" * 64)
    with TestClient(create_app(settings)) as client:
        token = _login(client)
        response = client.post("/settings/config", data={"csrf": token, "yaml_text": "scheduler:\n  interval_minutes: 2\n"})
        assert response.status_code == 200
        assert (tmp_path / "config.yaml").exists()
        assert "every 2 min" in client.get("/settings").text
