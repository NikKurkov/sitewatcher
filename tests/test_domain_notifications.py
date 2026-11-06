"""Subscriptions are owner scoped and delivery commits independently per channel."""
import asyncio
from types import SimpleNamespace

import pytest

from sitewatcher import email_delivery, email_settings, storage, web_actions
from sitewatcher.bot.alerts import AlertDeduper, maybe_send_alert
from sitewatcher.bot.jobs import process_results, _flush_alert_summaries_job
from sitewatcher.checks.base import CheckOutcome
from sitewatcher.config import AppConfig, ChecksModel, resolve_settings


@pytest.fixture
def notifications(monkeypatch):
    cfg = AppConfig()
    cfg.defaults.checks = ChecksModel.model_validate({
        name: name == 'ping' for name in ChecksModel.model_fields
    })
    storage.add_domain(1, 'example.com')
    storage.set_user_alert_chat_id(1, 100)
    storage.set_domain_override(1, 'example.com', {'notify_email': True})
    monkeypatch.setattr(email_settings, 'email_ready', lambda owner: owner == 1)
    sent = {'telegram': [], 'email': []}
    failed = set()

    async def email(owner, subject, html):
        if 'email' in failed:
            raise RuntimeError('email unavailable')
        sent['email'].append((owner, subject, html))

    class Bot:
        async def send_message(self, **kwargs):
            if 'telegram' in failed:
                raise RuntimeError('telegram unavailable')
            sent['telegram'].append(kwargs)

    monkeypatch.setattr(email_delivery, 'send_notification_email', email)
    context = SimpleNamespace(bot=Bot(), application=SimpleNamespace(bot_data={
        'cfg': cfg, 'alert_deduper': AlertDeduper(300),
    }))
    for channel in ('telegram', 'email'):
        storage.upsert_alert_state(1, 'example.com', 'OK', None, channel=channel)
    return cfg, context, sent, failed


def deliver(context, status='CRIT'):
    asyncio.run(maybe_send_alert(None, context, 1, 'example.com', [
        CheckOutcome('ping', status, 'status changed', {}),
    ]))


@pytest.mark.parametrize('failing', ['email', 'telegram'])
def test_retry_only_failed_channel_even_after_process_restart(notifications, failing):
    cfg, context, sent, failed = notifications
    failed.add(failing)
    with pytest.raises(RuntimeError):
        deliver(context)
    other = 'email' if failing == 'telegram' else 'telegram'
    assert len(sent[other]) == 1 and not sent[failing]
    failed.clear()
    context.application.bot_data = {'cfg': cfg, 'alert_deduper': AlertDeduper(300)}
    deliver(context)
    assert len(sent[other]) == len(sent[failing]) == 1
    deliver(context, 'OK')
    assert len(sent[other]) == len(sent[failing]) == 2


def test_email_works_without_telegram_connection_and_global_telegram_switch(notifications):
    cfg, context, sent, failed = notifications
    context.bot = None
    storage.set_user_alerts_enabled(1, False)
    deliver(context)
    assert len(sent['email']) == 1 and not sent['telegram']
    assert storage.get_alert_state(1, 'example.com')['last_overall'] == 'OK'


def test_unsubscribed_channels_do_not_send_or_flush_pending_summaries(notifications):
    cfg, context, sent, failed = notifications
    storage.set_domain_override(1, 'example.com', {
        'notify_email': False, 'notify_telegram': False,
    })
    deliver(context)
    assert not sent['email'] and not sent['telegram']
    asyncio.run(_flush_alert_summaries_job(context))
    assert not sent['email'] and not sent['telegram']


def test_warmup_initializes_both_channel_baselines(notifications):
    cfg, context, sent, failed = notifications
    storage.add_domain(1, 'new.example')
    asyncio.run(process_results(context, 1, 'new.example', [
        CheckOutcome('ping', 'CRIT', 'offline', {}),
    ], warmup=True))
    for channel in ('email', 'telegram'):
        assert storage.get_alert_state(1, 'new.example', channel=channel)['last_overall'] == 'CRIT'
    assert not sent['email'] and not sent['telegram']


def test_subscriptions_form_preserves_legacy_posts_and_validates_new_choices(monkeypatch):
    cfg = AppConfig()
    storage.add_domain(1, 'example.com')
    storage.set_domain_override(1, 'example.com', {'notify_email': True, 'notify_telegram': False})
    monkeypatch.setattr(email_settings, 'email_ready', lambda owner: False)
    context = web_actions.settings_context(cfg, 1, 'example.com')
    web_actions.save_domain(cfg, 1, {'domain': 'example.com', 'revision': context['revision']})
    assert storage.get_domain_override(1, 'example.com') == {
        'notify_email': True, 'notify_telegram': False,
    }
    context = web_actions.settings_context(cfg, 1, 'example.com')
    web_actions.save_domain(cfg, 1, {'domain': 'example.com', 'revision': context['revision'],
                                  'notifications_present': '1'})
    assert storage.get_domain_override(1, 'example.com') == {
        'notify_email': False, 'notify_telegram': False,
    }
    context = web_actions.settings_context(cfg, 1, 'example.com')
    with pytest.raises(ValueError, match='Configure the email recipient'):
        web_actions.save_domain(cfg, 1, {'domain': 'example.com', 'revision': context['revision'],
                                      'notifications_present': '1', 'notify_email': 'on'})
    assert not storage.get_domain_override(1, 'example.com')['notify_email']
    with pytest.raises(ValueError, match='Domain not found'):
        web_actions.settings_context(cfg, 2, 'example.com')


def test_rename_retains_subscriptions_and_discards_channel_state(notifications):
    cfg, context, sent, failed = notifications
    revision = web_actions.settings_context(cfg, 1, 'example.com')['revision']
    web_actions.save_domain(cfg, 1, {'domain': 'renamed.example', 'original_domain': 'example.com',
                                  'revision': revision})
    assert storage.domain_notifications(cfg, 1, 'renamed.example')['email']
    for channel in ('email', 'telegram'):
        assert storage.get_alert_state(1, 'example.com', channel=channel) is None
        assert storage.get_alert_state(1, 'renamed.example', channel=channel) is None
    assert resolve_settings(cfg, 'renamed.example',
                            storage.get_domain_override(1, 'renamed.example')).name == 'renamed.example'


def test_summary_failures_and_acknowledgments_are_isolated_by_channel(notifications):
    from sitewatcher.bot.alerts import _AlertKey, _channel_deduper
    cfg, context, sent, failed = notifications
    key = _AlertKey(1, 'example.com', 'CRIT')
    for channel in ('telegram', 'email'):
        deduper = _channel_deduper(context, channel)
        deduper.cooldown = 0
        deduper.mark_sent(key, 'problem')
        deduper._state[key].suppressed = 2
    failed.add('email')
    asyncio.run(_flush_alert_summaries_job(context))
    assert len(sent['telegram']) == 1 and not sent['email']
    failed.clear()
    asyncio.run(_flush_alert_summaries_job(context))
    assert len(sent['telegram']) == len(sent['email']) == 1
    assert context.application.bot_data['email_alert_deduper'].pending_summary(key) is None


def test_notification_defaults_and_reset_are_backward_compatible(notifications):
    cfg, context, sent, failed = notifications
    assert storage.domain_notifications(cfg, 1, 'example.com') == {'email': True, 'telegram': True}
    web_actions.act_on_domain(cfg, 1, 'reset', 'example.com')
    assert storage.domain_notifications(cfg, 1, 'example.com') == {'email': False, 'telegram': True}


def test_new_telegram_subscription_requires_ready_global_settings(monkeypatch):
    monkeypatch.setattr(web_actions, 'telegram_notifications_ready', lambda cfg, owner: False)
    with pytest.raises(ValueError, match='Configure and enable Telegram'):
        web_actions.save_domain(AppConfig(), 1, {
            'domain': 'example.com', 'notifications_present': '1', 'notify_telegram': 'on',
        }, create=True)
    assert not storage.domain_exists(1, 'example.com')


@pytest.mark.parametrize('form_choices, expected', [
    ({}, {'email': True, 'telegram': False}),
    ({'notifications_present': '1'}, {'email': False, 'telegram': False}),
])
def test_rename_snapshots_yaml_subscriptions_unless_form_submits_choices(form_choices, expected):
    cfg = AppConfig.model_validate({'domains': [
        {'name': 'example.com', 'notify_email': True, 'notify_telegram': False},
    ]})
    storage.add_domain(1, 'example.com')
    revision = web_actions.settings_context(cfg, 1, 'example.com')['revision']
    web_actions.save_domain(cfg, 1, {
        'domain': 'renamed.example', 'original_domain': 'example.com', 'revision': revision,
        **form_choices,
    })
    assert storage.domain_notifications(cfg, 1, 'renamed.example') == expected


def test_delete_cascades_both_channel_states_and_foreign_actions_cannot_mutate(notifications):
    cfg, context, sent, failed = notifications
    with pytest.raises(ValueError, match='Domain not found'):
        web_actions.act_on_domain(cfg, 2, 'reset', 'example.com')
    with pytest.raises(ValueError, match='Domain not found'):
        web_actions.act_on_domain(cfg, 2, 'delete', 'example.com')
    assert storage.domain_notifications(cfg, 1, 'example.com')['email']
    web_actions.act_on_domain(cfg, 1, 'delete', 'example.com')
    assert not storage.domain_exists(1, 'example.com')
    assert storage.get_domain_override(1, 'example.com') is None
    for channel in ('telegram', 'email'):
        assert storage.get_alert_state(1, 'example.com', channel=channel) is None
