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


def test_missing_virustotal_report_is_neutral_but_errors_and_detections_are_not():
    import asyncio
    from sitewatcher.bot.formatting import _format_results_summary

    for message in ('VirusTotal has no report for this URL', 'VT: not_found [cached 2m]',
                    'VirusTotal analysis is pending'):
        result = CheckOutcome('malware', Status.UNKNOWN, message)
        assert _overall_from_results([result]) == 'OK'
        assert result.status == Status.UNKNOWN
        summary = asyncio.run(_format_results_summary(1, 'example.com', [result], persist=False))
        assert 'malware' not in summary
        assert _overall_from_results([result, CheckOutcome('ping', Status.CRIT, 'down')]) == 'CRIT'
    for status, message, expected in (
        (Status.UNKNOWN, 'VirusTotal rejected the API key. Check your API key.', 'WARN'),
        (Status.UNKNOWN, 'VirusTotal connection timed out.', 'WARN'),
        (Status.WARN, 'VT: suspicious=1', 'WARN'),
        (Status.CRIT, 'VT: malicious=1', 'CRIT'),
    ):
        assert _overall_from_results([CheckOutcome('malware', status, message)]) == expected
    assert _overall_from_results([
        CheckOutcome('ping', Status.UNKNOWN, 'VirusTotal has no report for this URL')]) == 'WARN'


def test_enabled_check_without_any_result_is_unknown(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DEFAULT_DB", tmp_path / "missing.db")
    cfg = AppConfig()
    cfg.defaults.checks.http_basic = False
    cfg.defaults.checks.tls_cert = False
    cfg.defaults.checks.whois = False
    cfg.defaults.checks.ip_change = False

    combined = _complete_results(cfg, 1, "example.com", [])
    assert {result.check: result.status for result in combined} == {"ping": Status.UNKNOWN}
