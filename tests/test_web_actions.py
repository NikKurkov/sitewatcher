from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from sitewatcher import storage
from sitewatcher.checks.base import CheckOutcome, Status
from sitewatcher.web.auth import WebSettings, hash_password
from sitewatcher.web.app import create_app


@pytest.fixture
def panel(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DEFAULT_DB", tmp_path / "sitewatcher.db")
    storage._INITIALIZED_PATHS.clear()
    settings = WebSettings(101, hash_password("correct horse battery staple"), "s" * 64)
    with TestClient(create_app(settings)) as client:
        yield client, settings


def csrf(html: str) -> str:
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


def login(client: TestClient) -> str:
    token = csrf(client.get("/login").text)
    response = client.post("/login", data={"password": "correct horse battery staple", "csrf": token})
    assert response.status_code == 200
    return csrf(response.text)


def test_private_pages_and_owner_isolation(panel):
    client, _ = panel
    storage.add_domain(101, "mine.example")
    storage.add_domain(202, "secret.example")
    assert client.get("/domains", follow_redirects=False).status_code == 303
    login(client)
    page = client.get("/domains").text
    assert "mine.example" in page
    assert "secret.example" not in page
    assert client.get("/domains/secret.example").status_code == 404


def test_csrf_and_domain_actions(panel):
    client, _ = panel
    token = login(client)
    assert client.post("/domains", data={"name": "example.com"}).status_code == 403
    assert client.post("/domains", data={"name": "bad host", "csrf": token}).status_code == 400
    assert client.post("/domains", data={"name": "example.com", "csrf": token}).status_code == 200
    assert storage.domain_exists(101, "example.com")
    assert client.post("/domains/example.com/delete", data={"csrf": "bad"}).status_code == 403
    assert client.post("/domains/example.com/delete", data={"csrf": token}).status_code == 200
    assert not storage.domain_exists(101, "example.com")


def test_manual_run_persists_only_owned_domain(panel, monkeypatch):
    client, _ = panel
    token = login(client)
    storage.add_domain(101, "example.com")

    class FakeDispatcher:
        def __init__(self, config):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def run_for(self, owner_id, domain, **kwargs):
            assert (owner_id, domain) == (101, "example.com")
            return [CheckOutcome("http_basic", Status.OK, "reachable", {"latency_ms": 18})]

    monkeypatch.setattr("sitewatcher.web.app.Dispatcher", FakeDispatcher)
    assert client.post("/domains/other.example/check", data={"csrf": token}).status_code == 404
    response = client.post("/domains/example.com/check", data={"csrf": token})
    assert response.status_code == 200
    assert storage.last_results(101, "example.com")[0]["check_name"] == "http_basic"


def test_settings_and_export(panel):
    client, _ = panel
    token = login(client)
    storage.add_domain(101, "example.com")
    response = client.post(
        "/domains/example.com/settings",
        data={"csrf": token, "checks.http_basic": "on", "interval_minutes": "15", "keywords": "hello, world"},
    )
    assert response.status_code == 200
    override = storage.get_domain_override(101, "example.com")
    assert override["interval_minutes"] == 15
    assert override["keywords"] == ["hello", "world"]
    assert client.get("/export").headers["content-type"].startswith("text/csv")
    assert "example.com" in client.get("/export").text


def test_settings_preserve_inherited_values_and_rich_port_targets(panel):
    client, _ = panel
    token = login(client)
    storage.add_domain(101, "example.com")
    storage.set_domain_override(101, "example.com", {
        "ports": [{"port": 443, "host": "special.example", "tls": True}],
    })
    response = client.post("/domains/example.com/settings", data={
        "csrf": token, "checks.http_basic": "on", "latency_warn_ms": "500",
        "ports": "443", "keywords": "", "proxy": "",
    })
    assert response.status_code == 200
    override = storage.get_domain_override(101, "example.com")
    assert override["ports"] == [{"port": 443, "host": "special.example", "tls": True}]
    assert "keywords" not in override
    assert "proxy" not in override

    detail = client.get("/domains/example.com").text
    assert "special.example" in detail
    response = client.post("/domains/example.com/settings", data={
        "csrf": token, "checks.http_basic": "on",
        "ports": '[{"port":443,"tls":true,"host":"other.example"}]',
    })
    assert response.status_code == 200
    assert storage.get_domain_override(101, "example.com")["ports"] == [
        {"port": 443, "host": "other.example", "tls": True}
    ]


def test_history_can_reach_results_after_page_twenty(panel):
    client, _ = panel
    login(client)
    storage.add_domain(101, "example.com")
    for number in range(1001):
        storage.save_history(101, "example.com", "http_basic", "OK", f"sample-{number}", {})
    page = client.get("/history?page=21&period=30d")
    assert page.status_code == 200
    assert "Page 21" in page.text
    assert "sample-0" in page.text


def test_alert_toggle_and_logout(panel):
    client, _ = panel
    token = login(client)
    assert client.post("/settings/alerts", data={"csrf": token, "enabled": "false"}).status_code == 200
    assert not storage.is_user_alerts_enabled(101)
    assert client.post("/logout", data={"csrf": token}).status_code == 200
    assert client.get("/", follow_redirects=False).status_code == 303


def test_export_import_roundtrip_stays_with_owner(panel):
    client, _ = panel
    token = login(client)
    storage.add_domain(101, "example.com")
    storage.set_domain_override(101, "example.com", {"latency_warn_ms": 350})
    payload = client.get("/export").content
    storage.remove_domain(101, "example.com")
    result = client.post("/import", data={"csrf": token, "mode": "replace"},
                         files={"file": ("domains.csv", payload, "text/csv")})
    assert result.status_code == 200
    assert "1 added" in result.text
    assert storage.domain_exists(101, "example.com")
    assert storage.get_domain_override(101, "example.com")["latency_warn_ms"] == 350
    assert not storage.domain_exists(202, "example.com")


def test_scan_untracked_domain_does_not_persist(panel, monkeypatch):
    client, _ = panel
    token = login(client)

    class FakeDispatcher:
        def __init__(self, config):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def run_for(self, owner_id, domain, **kwargs):
            assert kwargs["ephemeral"] is True
            return [CheckOutcome("http_basic", Status.OK, "reachable", {})]

    monkeypatch.setattr("sitewatcher.web.app.Dispatcher", FakeDispatcher)
    result = client.post("/scan", data={"csrf": token, "name": "untracked.example"})
    assert result.status_code == 200
    assert "reachable" in result.text
    assert not storage.domain_exists(101, "untracked.example")


def test_delete_all_requires_explicit_phrase(panel):
    client, _ = panel
    token = login(client)
    storage.add_domain(101, "one.example")
    assert client.post("/domains/delete-all", data={"csrf": token, "confirm": "no"}).status_code == 400
    assert storage.domain_exists(101, "one.example")
    assert client.post("/domains/delete-all", data={"csrf": token, "confirm": "DELETE ALL"}).status_code == 200
    assert storage.list_domains(101) == []
