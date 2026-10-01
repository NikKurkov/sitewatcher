from sitewatcher import storage
from sitewatcher.config import AppConfig
from sitewatcher.web.views import domain_cards, latency_chart, status_chart


def test_domain_cards_rank_problems_and_ignore_other_owners(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DEFAULT_DB", tmp_path / "cards.db")
    storage.add_domain(1, "healthy.example")
    storage.add_domain(1, "down.example")
    storage.add_domain(2, "private.example")
    storage.save_history(1, "healthy.example", "http_basic", "OK", "up", {})
    storage.save_history(1, "down.example", "http_basic", "CRIT", "down", {})
    storage.save_history(2, "private.example", "http_basic", "CRIT", "secret", {})
    cards, summary = domain_cards(1, AppConfig())
    assert [card["name"] for card in cards] == ["down.example", "healthy.example"]
    assert summary["crit"] == 1
    assert summary["total"] == 2


def test_charts_use_only_numeric_values():
    rows = [
        {"check": "http_basic", "status": "OK", "metrics_json": '{"latency_ms_total": 42}'},
        {"check": "http_basic", "status": "CRIT", "metrics_json": '{"latency_ms_total": 100}'},
    ]
    assert "<svg" in str(status_chart(rows))
    assert "<svg" in str(latency_chart(rows))
    assert "42" in str(latency_chart(rows))
