from sitewatcher import storage
from sitewatcher.bot.alerts import _complete_results, _overall_from_results
from sitewatcher.checks.base import CheckOutcome, Status
from sitewatcher.config import AppConfig


def test_partial_scheduled_result_keeps_previous_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DEFAULT_DB", tmp_path / "alerts.db")
    storage.save_history(1, "example.com", "ping", Status.CRIT, "down", {})
    storage.save_history(1, "example.com", "http_basic", Status.OK, "fine", {})
    cfg = AppConfig()
    cfg.defaults.checks.tls_cert = False
    cfg.defaults.checks.whois = False
    cfg.defaults.checks.ip_change = False

    current = [CheckOutcome("http_basic", Status.OK, "fine", {})]
    combined = _complete_results(cfg, 1, "example.com", current)
    assert _overall_from_results(combined) == "CRIT"
    assert {result.check for result in combined} == {"http_basic", "ping"}


def test_no_results_cannot_mean_healthy():
    assert _overall_from_results([]) == "UNKNOWN"


def test_enabled_check_without_any_result_is_unknown(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DEFAULT_DB", tmp_path / "missing.db")
    cfg = AppConfig()
    cfg.defaults.checks.http_basic = False
    cfg.defaults.checks.tls_cert = False
    cfg.defaults.checks.whois = False
    cfg.defaults.checks.ip_change = False

    combined = _complete_results(cfg, 1, "example.com", [])
    assert {result.check: result.status for result in combined} == {"ping": Status.UNKNOWN}
