import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from sitewatcher import scheduler, storage
from sitewatcher.bot.alerts import AlertDeduper, maybe_send_alert
from sitewatcher.checks.base import CheckOutcome, Status
from sitewatcher.config import AppConfig, ChecksModel


@pytest.fixture
def alert_context(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DEFAULT_DB", tmp_path / "alerts.db")
    storage.add_domain(1, "example.com")
    storage.set_user_alert_chat_id(1, 100)
    cfg = AppConfig()
    cfg.defaults.checks = ChecksModel.model_validate({
        name: name == "ping" for name in ChecksModel.model_fields
    })
    sent = []

    class Bot:
        fail = False

        async def send_message(self, **kwargs):
            await asyncio.sleep(0)
            if self.fail:
                raise RuntimeError("temporary delivery failure")
            sent.append(kwargs)

    context = SimpleNamespace(
        bot=Bot(), application=SimpleNamespace(bot_data={
            "cfg": cfg, "alert_deduper": AlertDeduper(cooldown_sec=300),
        }),
    )
    return context, cfg, sent


def establish_baseline(status="OK", *, minutes_ago=10):
    storage.upsert_alert_state(1, "example.com", status,
        (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat())


def test_failed_delivery_is_retried_without_consuming_transition(alert_context):
    context, cfg, sent = alert_context
    establish_baseline()
    result = [CheckOutcome("ping", Status.CRIT, "offline", {})]
    context.bot.fail = True
    with pytest.raises(RuntimeError):
        asyncio.run(maybe_send_alert(None, context, 1, "example.com", result))
    assert storage.get_alert_state(1, "example.com")["last_overall"] == "OK"
    context.bot.fail = False
    asyncio.run(maybe_send_alert(None, context, 1, "example.com", result))
    assert len(sent) == 1 and "CRIT" in sent[0]["text"]


@pytest.mark.parametrize("before, after", [("WARN", "CRIT"), ("CRIT", "OK")])
def test_transition_is_not_discarded_by_previous_alert_cooldown(alert_context, before, after):
    context, cfg, sent = alert_context
    cfg.alerts.cooldown_sec = 600
    establish_baseline(before, minutes_ago=0)
    asyncio.run(maybe_send_alert(None, context, 1, "example.com", [
        CheckOutcome("ping", after, "changed", {}),
    ]))
    assert len(sent) == 1
    assert storage.get_alert_state(1, "example.com")["last_overall"] == after


def test_repeated_problem_respects_debounce_when_cooldown_is_unset(alert_context):
    context, cfg, sent = alert_context
    cfg.alerts.policy = "all"
    cfg.alerts.debounce_sec = 300
    cfg.alerts.cooldown_sec = None
    establish_baseline("CRIT", minutes_ago=0)
    asyncio.run(maybe_send_alert(None, context, 1, "example.com", [
        CheckOutcome("ping", Status.CRIT, "still offline", {}),
    ]))
    assert sent == []


def test_missing_destination_does_not_consume_transition(alert_context):
    context, cfg, sent = alert_context
    establish_baseline()
    storage.set_user_alert_chat_id(1, 0)
    result = [CheckOutcome("ping", Status.CRIT, "offline", {})]
    asyncio.run(maybe_send_alert(None, context, 1, "example.com", result))
    assert storage.get_alert_state(1, "example.com")["last_overall"] == "OK"
    storage.set_user_alert_chat_id(1, 100)
    asyncio.run(maybe_send_alert(None, context, 1, "example.com", result))
    assert len(sent) == 1


def test_simultaneous_manual_and_scheduled_results_send_one_transition(alert_context):
    context, cfg, sent = alert_context
    establish_baseline()
    result = [CheckOutcome("ping", Status.CRIT, "offline", {})]

    async def concurrent():
        await asyncio.gather(*(
            maybe_send_alert(None, context, 1, "example.com", result) for _ in range(2)
        ))

    asyncio.run(concurrent())
    assert len(sent) == 1


def test_removed_domain_cannot_send_or_restore_alert_state(alert_context):
    context, cfg, sent = alert_context
    establish_baseline()
    storage.remove_domain(1, "example.com")
    asyncio.run(maybe_send_alert(None, context, 1, "example.com", [
        CheckOutcome("ping", Status.CRIT, "offline", {}),
    ]))
    assert sent == [] and storage.get_alert_state(1, "example.com") is None


def test_scheduler_retries_saved_result_without_rerunning_recent_check(alert_context, monkeypatch):
    from sitewatcher.bot import jobs

    context, cfg, sent = alert_context
    establish_baseline()
    runs = []

    class Dispatcher:
        def __init__(self, cfg):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            pass

        async def run_for(self, owner, domain, **kwargs):
            runs.append(domain)
            return [CheckOutcome("ping", Status.CRIT, "offline", {})]

    monkeypatch.setattr(scheduler, "Dispatcher", Dispatcher)
    context.bot.fail = True
    asyncio.run(jobs._run_checks_for_all_domains(context, warmup=False, run_id="failed"))
    context.bot.fail = False
    asyncio.run(jobs._run_checks_for_all_domains(context, warmup=False, run_id="retry"))
    assert runs == ["example.com"] and len(sent) == 1
    assert len(storage.last_results(1, "example.com")) == 1


def test_large_alert_is_delivered_in_valid_bounded_messages(alert_context):
    from html.parser import HTMLParser

    context, cfg, sent = alert_context
    establish_baseline()
    asyncio.run(maybe_send_alert(None, context, 1, "example.com", [
        CheckOutcome("ping", Status.CRIT, "offline 😀 " * 1000, {}),
    ]))
    assert len(sent) > 1
    for message in sent:
        assert len(message["text"].encode("utf-16-le")) // 2 <= 4096
        HTMLParser().feed(message["text"])


def test_recovery_requires_daily_metadata_even_with_long_domain_interval(alert_context):
    from contextlib import closing
    from sitewatcher.config import DomainConfig

    context, cfg, sent = alert_context
    cfg.defaults.checks.tls_cert = True
    cfg.domains = [DomainConfig(name="example.com", interval_minutes=10080)]
    storage.save_history(1, "example.com", "tls_cert", "OK", "valid", {})
    with closing(storage._connect()) as connection:
        connection.execute("UPDATE history SET created_at=datetime('now', '-2 days')")
    establish_baseline("CRIT")
    asyncio.run(maybe_send_alert(None, context, 1, "example.com", [
        CheckOutcome("ping", Status.OK, "online", {}),
    ]))
    assert sent == []  # Two-day-old TLS evidence cannot confirm recovery.
    storage.save_history(1, "example.com", "tls_cert", "OK", "fresh", {})
    asyncio.run(maybe_send_alert(None, context, 1, "example.com", [
        CheckOutcome("ping", Status.OK, "online", {}),
    ]))
    assert len(sent) == 1 and "— OK" in sent[0]["text"]
