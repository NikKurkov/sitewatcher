import pytest

from sitewatcher.dashboard import render_dashboard


@pytest.fixture
def snapshot():
    return {
        "generated_at": "2026-10-21T17:00:00+00:00",
        "summary": {"total": 2, "ok": 1, "warn": 0, "crit": 1, "unknown": 0, "paused": 0, "stale": 0},
        "domains": [
            {"name": "offline.example", "overall": "CRIT", "paused": False, "stale": False,
             "last_checked_at": "2026-10-21T16:59:00+00:00", "next_due_at": "2026-10-21T17:04:00+00:00",
             "checks": [{"name": "http_basic", "status": "CRIT", "message": "HTTP 503 <unavailable>",
                         "checked_at": "2026-10-21T16:59:00+00:00", "missing": False, "stale": False}], "error": None},
            {"name": "healthy.example", "overall": "OK", "paused": False, "stale": False,
             "last_checked_at": "2026-10-21T16:59:00+00:00", "next_due_at": "2026-10-21T17:04:00+00:00",
             "checks": [{"name": "ping", "status": "OK", "message": "online",
                         "checked_at": "2026-10-21T16:59:00+00:00", "missing": False, "stale": False}], "error": None},
        ],
    }


def test_dashboard_renders_accessible_saved_results_without_javascript(snapshot):
    page = render_dashboard(snapshot)
    assert "offline.example" in page and "healthy.example" in page
    assert "HTTP 503 &lt;unavailable&gt;" in page
    assert "<details" in page and "<summary" in page
    assert '<form method="get"' in page and '<script src="/theme.js" defer></script>' in page
    assert 'content="30"' in page and '/style.css' in page


def test_dashboard_filters_domains_and_escapes_search_value(snapshot):
    page = render_dashboard(snapshot, query="offline", status="problems")
    assert "offline.example" in page and "healthy.example" not in page
    page = render_dashboard(snapshot, query='\"><script>alert(1)</script>')
    assert '<script>' not in page and '&lt;script&gt;' in page
    assert "No domains match" in page


def test_dashboard_escapes_stored_names_and_check_messages(snapshot):
    snapshot["domains"][0]["name"] = '<img src=x onerror="alert(1)">'
    snapshot["domains"][0]["checks"][0]["message"] = '<script>alert(2)</script>'
    page = render_dashboard(snapshot)
    assert "<img" not in page and "<script>" not in page
    assert page.count("<script") == 1
    assert "&lt;img" in page and "&lt;script&gt;" in page


def test_dashboard_rejects_unknown_status_filters(snapshot):
    with pytest.raises(ValueError):
        render_dashboard(snapshot, status="typo")


def test_auto_refresh_can_be_paused_while_reading_expanded_results(snapshot):
    page = render_dashboard(snapshot, auto_refresh=False)
    assert 'http-equiv="refresh"' not in page
    assert 'name="refresh" value="off" checked' in page
    assert 'Auto refresh paused' in page
