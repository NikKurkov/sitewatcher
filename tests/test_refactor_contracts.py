import asyncio
import csv
import io
import json
import subprocess
import sys
from types import SimpleNamespace

import pytest

from sitewatcher import storage
from sitewatcher.bot import formatting
from sitewatcher.bot.alerts import _compose_message, _overall_from_results
from sitewatcher.bot.handlers import checks, history, status
from sitewatcher.checks.base import CheckOutcome, Status
from sitewatcher.checks.ports import PortsCheck
from sitewatcher.config import AppConfig, PortSpec
from sitewatcher.main import _overall_from
from sitewatcher.utils.domains_csv import HEADERS, import_domains_csv


@pytest.fixture
def bot(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DEFAULT_DB", tmp_path / "monitor.db")
    replies = []

    class Message:
        async def reply_html(self, text, **kwargs):
            replies.append(text)

        async def reply_text(self, text, **kwargs):
            replies.append(text)

    cfg = AppConfig()
    cfg.alerts.enabled = False
    cfg.defaults.checks.http_basic = False
    cfg.defaults.checks.tls_cert = False
    cfg.defaults.checks.whois = False
    cfg.defaults.checks.ip_change = False
    message = Message()
    update = SimpleNamespace(effective_message=message, effective_user=SimpleNamespace(id=1))
    context = SimpleNamespace(args=[], application=SimpleNamespace(bot_data={"cfg": cfg}))
    return update, context, replies


def test_result_rendering_preserves_severity_escaping_and_cached_messages():
    results = [
        CheckOutcome("ping", Status.OK, "up", {}),
        CheckOutcome("tls_cert", Status.CRIT, "expired <today>", {}),
        CheckOutcome("whois", Status.UNKNOWN, "waiting [cached 2m]", {}, cached=True),
    ]
    detailed = asyncio.run(formatting._format_results(1, "example.com", results, persist=False))
    summary = asyncio.run(formatting._format_results_summary(1, "example.com", results, persist=False))
    assert "🔴 <b>example.com</b> — CRIT" in detailed
    assert "expired &lt;today&gt;" in detailed
    assert "waiting [cached 2m]" in summary
    assert "<code>ping</code>" in detailed and "<code>ping</code>" not in summary
    assert summary.index("tls_cert") < summary.index("whois")
    assert _compose_message("example.com", "CRIT", "OK", results).endswith(
        "• <code>whois</code> — <b>UNKNOWN</b> — waiting [cached 2m]"
    )
    for overall in (_overall_from, _overall_from_results, formatting._overall_from_results):
        assert overall([]) == "UNKNOWN"
        assert overall([CheckOutcome("ping", Status.UNKNOWN, "waiting", {})]) == "WARN"


def test_status_and_history_render_real_owner_scoped_sqlite_rows(bot):
    update, context, replies = bot
    storage.save_history(1, "example.com", "ping", "CRIT", "down <now> [cached 2m]", {})
    storage.save_history(2, "private.example", "ping", "CRIT", "private", {})
    asyncio.run(status.cmd_status(update, context))
    context.args = ["example.com"]
    asyncio.run(status.cmd_status(update, context))
    asyncio.run(history.cmd_history(update, context))
    assert all("example.com" in reply and "down &lt;now&gt;" in reply for reply in replies)
    assert all("private" not in reply and "cached" not in reply for reply in replies)
    assert "<code>ping</code>" in replies[1] and "<code>ping</code>" in replies[2]


@pytest.mark.parametrize("command", [checks.cmd_check_all, checks.cmd_check_all_detail])
def test_bulk_checks_keep_owner_persistence_and_continue_after_failure(bot, monkeypatch, command):
    update, context, replies = bot
    for name in ("a.example", "b.example", "c.example"):
        storage.add_domain(1, name)
    storage.add_domain(2, "private.example")
    context.args = ["--force"]

    class Dispatcher:
        def __init__(self, cfg):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            pass

        async def run_for(self, owner, domain, *, use_cache):
            assert owner == 1 and use_cache is False
            if domain == "b.example":
                raise RuntimeError("offline")
            return [CheckOutcome("ping", Status.OK, "up", {})]

    monkeypatch.setattr(checks, "Dispatcher", Dispatcher)
    asyncio.run(command(update, context))
    text = "\n".join(replies)
    assert "a.example" in text and "c.example" in text
    assert "b.example" not in text and "private.example" not in text
    assert len(storage.last_results(1, "c.example")) == 1
    assert storage.last_results(2, "private.example") == []
    assert ("<code>ping</code>" in text) is (command is checks.cmd_check_all_detail)
    assert ("\n\n" in text) is (command is checks.cmd_check_all_detail)


@pytest.mark.parametrize("mode", ["merge", "replace"])
def test_csv_modes_preserve_zero_numeric_values_and_distinct_empty_list_behavior(bot, mode):
    storage.add_domain(1, "example.com")
    storage.set_domain_override(1, "example.com", {"keywords": ["keep"], "ports": [443]})
    stream = io.StringIO()
    writer = csv.DictWriter(stream, fieldnames=HEADERS, delimiter=";")
    writer.writeheader()
    writer.writerow({
        "domain": "example.com", "http_timeout_s": "3", "latency_warn_ms": "0",
        "latency_crit_ms": "100", "tls_warn_days": "0", "interval_minutes": "0", "proxy": "off",
    })
    report = import_domains_csv(1, stream.getvalue().encode("utf-8-sig"), mode=mode)
    assert report.updated == 1 and report.errors == []
    override = storage.get_domain_override(1, "example.com")
    assert override == {
        "keywords": ["keep"] if mode == "merge" else [],
        "ports": [443] if mode == "merge" else [],
        "http_timeout_s": 3, "latency_warn_ms": 0, "latency_crit_ms": 100,
        "tls_warn_days": 0, "interval_minutes": 0, "proxy": None,
    }
    assert storage.get_domain_override(2, "example.com") is None


def test_ports_accept_config_models_and_legacy_override_shapes():
    targets = [80, "443", {"port": "22", "host": "ssh.example", "tls": False}, PortSpec(port=25)]
    check = PortsCheck("example.com", targets=targets, defaults=AppConfig().ports)
    assert [(target.port, target.host, target.tls) for target in check.targets] == [
        (80, None, False), (443, None, False), (22, "ssh.example", False), (25, None, False),
    ]


@pytest.mark.parametrize("timestamp", [
    "2026-10-21 12:30:00", "2026-10-21T12:30:00Z", "2026-10-21T15:30:00+03:00",
])
def test_status_and_history_timestamps_remain_in_utc(timestamp):
    assert status._fmt_ts(timestamp) == "[21.10 12:30 UTC]"
    assert history._fmt_ts(timestamp) == "[21.10 12:30 UTC]"


@pytest.mark.parametrize("destination, format_, rotate", [
    ("console", "pretty", "size"), ("console", "json", "size"),
    ("file", "json", "size"), ("file", "pretty", "time"),
])
def test_logging_uses_validated_partial_configuration(tmp_path, destination, format_, rotate):
    log_path = tmp_path / "logs" / "monitor.log"
    config = {"logging": {"destination": destination, "format": format_,
        "third_party_levels": {"telegram": "ERROR"}, "file": {
        "path": str(log_path), "rotate": rotate,
    }}}
    run = subprocess.run([
        sys.executable, "-c",
        "import json, logging, sys; from sitewatcher.config import AppConfig; "
        "from sitewatcher.logging_setup import setup_logging; "
        "setup_logging(AppConfig.model_validate(json.loads(sys.argv[1])).logging); "
        "logging.getLogger('httpx').info('noisy httpx'); "
        "logging.getLogger('telegram').warning('noisy telegram'); "
        "logging.getLogger('sitewatcher').info('probe', extra={'domain': 'example.com'})",
        json.dumps(config),
    ], capture_output=True, text=True, check=True)
    output = run.stdout if destination == "console" else log_path.read_text()
    assert "noisy" not in output
    if format_ == "json":
        record = json.loads(output.splitlines()[-1])
        assert record["message"] == "probe" and record["domain"] == "example.com"
    else:
        assert "INFO sitewatcher - probe" in output and '"domain":"example.com"' in output
