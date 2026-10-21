import asyncio
from types import SimpleNamespace

import pytest

from sitewatcher import storage
from sitewatcher.bot import alerts, jobs
from sitewatcher.bot.alerts import AlertDeduper, _AlertKey
from sitewatcher.config import AppConfig


@pytest.fixture
def summaries(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, 'DEFAULT_DB', tmp_path / 'summaries.db')
    storage.add_domain(1, 'example.com')
    storage.set_user_alert_chat_id(1, 10)
    now = [100.0]
    monkeypatch.setattr(alerts.time, 'time', lambda: now[0])
    deduper = AlertDeduper(cooldown_sec=10)
    key = _AlertKey(1, 'example.com', 'CRIT')
    deduper.mark_sent(key, 'problem')
    now[0] = 101
    assert deduper.should_send_now(key, 'problem') == (False, None)
    now[0] = 111
    sent = []

    class Bot:
        fail = False
        add_during_send = False

        async def send_message(self, *, chat_id, text, **kwargs):
            if self.fail:
                raise RuntimeError('temporary delivery failure')
            if self.add_during_send:
                now[0] = 109
                deduper.should_send_now(key, 'new repetition')
                now[0] = 111
                self.add_during_send = False
            sent.append((chat_id, text))

    context = SimpleNamespace(bot=Bot(), application=SimpleNamespace(bot_data={
        'cfg': AppConfig(), 'alert_deduper': deduper,
    }))
    return context, deduper, key, now, sent


def test_summary_failed_delivery_is_retried(summaries):
    context, deduper, key, now, sent = summaries
    context.bot.fail = True
    asyncio.run(jobs._flush_alert_summaries_job(context))
    context.bot.fail = False
    asyncio.run(jobs._flush_alert_summaries_job(context))
    assert sent == [(10, '1 repetition(s) in last 10s for owner 1, example.com [CRIT]')]
    now[0] = 200
    asyncio.run(jobs._flush_alert_summaries_job(context))
    assert len(sent) == 1


def test_missing_destination_does_not_consume_summary(summaries):
    context, deduper, key, now, sent = summaries
    storage.set_user_alert_chat_id(1, 0)
    asyncio.run(jobs._flush_alert_summaries_job(context))
    storage.set_user_alert_chat_id(1, 11)
    asyncio.run(jobs._flush_alert_summaries_job(context))
    assert len(sent) == 1 and sent[0][0] == 11


@pytest.mark.parametrize('disabled', ['global', 'owner'])
def test_disabled_alerts_do_not_send_or_consume_summary(summaries, disabled):
    context, deduper, key, now, sent = summaries
    cfg = context.application.bot_data['cfg']
    if disabled == 'global':
        cfg.alerts.enabled = False
    else:
        storage.set_user_alerts_enabled(1, False)
    asyncio.run(jobs._flush_alert_summaries_job(context))
    assert sent == []
    cfg.alerts.enabled = True
    storage.set_user_alerts_enabled(1, True)
    asyncio.run(jobs._flush_alert_summaries_job(context))
    assert len(sent) == 1


def test_summary_ack_retains_repetitions_arriving_during_send(summaries):
    context, deduper, key, now, sent = summaries
    context.bot.add_during_send = True
    asyncio.run(jobs._flush_alert_summaries_job(context))
    now[0] = 122
    asyncio.run(jobs._flush_alert_summaries_job(context))
    assert len(sent) == 2
    assert all(text.startswith('1 repetition(s)') for _, text in sent)


def test_deleted_domain_summary_is_not_sent(summaries):
    context, deduper, key, now, sent = summaries
    storage.remove_domain(1, 'example.com')
    asyncio.run(jobs._flush_alert_summaries_job(context))
    assert sent == []
    assert deduper.pending_summaries() == []


def test_cancelled_summary_delivery_remains_pending(summaries):
    context, deduper, key, now, sent = summaries
    original_send = context.bot.send_message

    async def cancelled(**kwargs):
        raise asyncio.CancelledError()

    context.bot.send_message = cancelled
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(jobs._flush_alert_summaries_job(context))
    context.bot.send_message = original_send
    asyncio.run(jobs._flush_alert_summaries_job(context))
    assert len(sent) == 1


def test_overlapping_summary_jobs_deliver_once(summaries):
    context, deduper, key, now, sent = summaries
    original_send = context.bot.send_message

    async def scenario():
        entered = asyncio.Event()
        release = asyncio.Event()

        async def delayed_send(**kwargs):
            entered.set()
            await release.wait()
            return await original_send(**kwargs)

        context.bot.send_message = delayed_send
        first = asyncio.create_task(jobs._flush_alert_summaries_job(context))
        await entered.wait()
        second = asyncio.create_task(jobs._flush_alert_summaries_job(context))
        await asyncio.sleep(0)
        release.set()
        await asyncio.gather(first, second)

    asyncio.run(scenario())
    assert len(sent) == 1


def test_normal_alert_consuming_pending_counts_prevents_stale_summary(summaries):
    context, deduper, key, now, sent = summaries

    async def scenario():
        lock = asyncio.Lock()
        context.application.bot_data['alert_locks'] = {(1, 'example.com'): lock}
        await lock.acquire()
        task = asyncio.create_task(jobs._flush_alert_summaries_job(context))
        await asyncio.sleep(0)
        deduper.mark_sent(key, 'normal alert includes suppressed count')
        lock.release()
        await task

    asyncio.run(scenario())
    assert sent == []


@pytest.mark.parametrize('blocked', ['disabled', 'deleted', 'missing_chat'])
def test_twenty_blocked_keys_do_not_starve_later_eligible_owner(summaries, blocked):
    context, previous_deduper, eligible_key, now, sent = summaries
    deduper = AlertDeduper(cooldown_sec=10)
    context.application.bot_data['alert_deduper'] = deduper
    blocked_keys = [_AlertKey(2, f'blocked-{index}.example', 'CRIT') for index in range(20)]
    for key in blocked_keys:
        storage.add_domain(key.owner_id, key.domain)
    storage.set_user_alert_chat_id(2, 20)
    if blocked == 'disabled':
        storage.set_user_alerts_enabled(2, False)
    elif blocked == 'deleted':
        for key in blocked_keys:
            storage.remove_domain(key.owner_id, key.domain)
    else:
        storage.set_user_alert_chat_id(2, 0)
    now[0] = 100
    for key in [*blocked_keys, eligible_key]:
        deduper.mark_sent(key, 'problem')
    now[0] = 101
    for key in [*blocked_keys, eligible_key]:
        deduper.should_send_now(key, 'problem')
    now[0] = 111
    asyncio.run(jobs._flush_alert_summaries_job(context))
    assert sent == [(10, '1 repetition(s) in last 10s for owner 1, example.com [CRIT]')]
