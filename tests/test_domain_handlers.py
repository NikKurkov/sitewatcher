import asyncio
from contextlib import closing
from types import SimpleNamespace

import pytest
from telegram.ext import ConversationHandler

from sitewatcher import storage
from sitewatcher.bot.handlers import add_wizard, domains
from sitewatcher.config import AppConfig, ChecksModel, DomainConfig, resolve_settings


@pytest.fixture
def boundary(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, 'DEFAULT_DB', tmp_path / 'monitor.db')
    replies = []

    class Message:
        text = ''

        async def reply_html(self, text, **kwargs):
            assert len(text.encode('utf-16-le')) // 2 <= 4096
            replies.append(text)

        async def reply_text(self, text, **kwargs):
            assert len(text.encode('utf-16-le')) // 2 <= 4096
            replies.append(text)

    cfg = AppConfig()
    cfg.defaults.checks = ChecksModel.model_validate({
        name: name == 'ping' for name in ChecksModel.model_fields
    })
    update = SimpleNamespace(effective_message=Message(), effective_user=SimpleNamespace(id=1),
                             effective_chat=SimpleNamespace(id=10))
    context = SimpleNamespace(args=[], user_data={}, application=SimpleNamespace(bot_data={'cfg': cfg}))
    return update, context, replies, cfg


def test_wizard_inherits_global_yaml_and_owner_checks_and_reports_actual_enabled(boundary):
    update, context, replies, cfg = boundary
    cfg.domains = [DomainConfig(name='example.com', checks={'deface': True})]
    storage.add_domain(1, 'example.com')
    storage.set_domain_override(1, 'example.com', {'checks': {'ping': False, 'ports': True},
                                                'ports': [443]})
    storage.add_domain(2, 'example.com')
    storage.set_domain_override(2, 'example.com', {'checks': {'rkn_block': True}})
    context.args = ['https://EXAMPLE.com/path']
    asyncio.run(add_wizard.cmd_add_start(update, context))
    asyncio.run(add_wizard.cmd_add_keywords_none(update, context))
    result = asyncio.run(add_wizard.cmd_add_interval_none(update, context))
    assert result == ConversationHandler.END
    override = storage.get_domain_override(1, 'example.com')
    assert override == {'checks': {'ping': False, 'ports': True, 'keywords': False},
                        'ports': [443], 'interval_minutes': 0}
    enabled = resolve_settings(cfg, 'example.com', override).checks.model_dump()
    assert {name for name, value in enabled.items() if value} == {'deface', 'ports'}
    assert '<code>deface</code>' in replies[-1] and '<code>ports</code>' in replies[-1]
    assert '<code>rkn_block</code>' not in replies[-1]
    assert '<code>ip_blacklist</code>' not in replies[-1]
    assert storage.get_domain_override(2, 'example.com') == {'checks': {'rkn_block': True}}


def test_wizard_keyword_choice_is_explicit_but_cancel_saves_no_domain_settings(boundary):
    update, context, replies, cfg = boundary
    context.args = ['new.example']
    asyncio.run(add_wizard.cmd_add_start(update, context))
    update.effective_message.text = 'first first second'
    asyncio.run(add_wizard.cmd_add_keywords_text(update, context))
    assert context.user_data['add_state']['keywords'] == ['first', 'second']
    assert not storage.domain_exists(1, 'new.example')
    asyncio.run(add_wizard.cmd_add_cancel(update, context))
    assert 'add_state' not in context.user_data
    assert storage.get_domain_override(1, 'new.example') is None


@pytest.mark.parametrize('existing', [False, True])
def test_wizard_settings_failure_is_atomic_and_does_not_claim_domain_added(boundary, existing):
    update, context, replies, cfg = boundary
    if existing:
        storage.add_domain(1, 'fail.example')
        storage.set_domain_override(1, 'fail.example', {'checks': {'ping': False}})
    else:
        storage.ensure_user(1)
    with closing(storage._connect()) as connection:
        connection.execute("""
            CREATE TRIGGER reject_settings BEFORE INSERT ON domain_overrides
            WHEN NEW.domain='fail.example'
            BEGIN SELECT RAISE(ABORT,'private-sql-error'); END
        """)
    context.args = ['fail.example']
    asyncio.run(add_wizard.cmd_add_start(update, context))
    asyncio.run(add_wizard.cmd_add_keywords_none(update, context))
    asyncio.run(add_wizard.cmd_add_interval_none(update, context))
    assert storage.domain_exists(1, 'fail.example') is existing
    expected = {'checks': {'ping': False}} if existing else None
    assert storage.get_domain_override(1, 'fail.example') == expected
    assert '✅ Added' not in '\n'.join(replies)
    assert 'private-sql-error' not in '\n'.join(replies)


def test_wizard_enables_only_explicit_keywords_and_saves_paused_domain(boundary):
    update, context, replies, cfg = boundary
    context.args = ['new.example']
    asyncio.run(add_wizard.cmd_add_start(update, context))
    update.effective_message.text = 'needle'
    asyncio.run(add_wizard.cmd_add_keywords_text(update, context))
    asyncio.run(add_wizard.cmd_add_interval_none(update, context))
    override = storage.get_domain_override(1, 'new.example')
    assert override == {'checks': {'keywords': True}, 'keywords': ['needle'], 'interval_minutes': 0}
    assert '<code>ping</code>' in replies[-1] and '<code>keywords</code>' in replies[-1]
    assert '<code>deface</code>' not in replies[-1]


@pytest.mark.parametrize('value', ['https://ПРИМЕР.РФ./path', 'ПРИМЕР.РФ.'])
def test_domain_add_and_remove_use_shared_url_idna_normalization(boundary, value):
    update, context, replies, cfg = boundary
    context.args = [value]
    asyncio.run(domains.cmd_add_domain(update, context))
    assert storage.list_domains(1) == ['xn--e1afmkfd.xn--p1ai']
    storage.add_domain(2, 'xn--e1afmkfd.xn--p1ai')
    asyncio.run(domains.cmd_remove_domain(update, context))
    assert storage.list_domains(1) == []
    assert storage.list_domains(2) == ['xn--e1afmkfd.xn--p1ai']


def test_long_domain_list_is_delivered_without_truncation(boundary):
    update, context, replies, cfg = boundary
    expected = [f'domain-{index:04}.example' for index in range(400)]
    for domain in expected:
        storage.add_domain(1, domain)
    storage.add_domain(2, 'private.example')
    asyncio.run(domains.cmd_list_domain(update, context))
    assert ''.join(replies) == '\n'.join(expected)


def test_wizard_reports_different_checks_per_domain_and_global_pause(boundary):
    update, context, replies, cfg = boundary
    cfg.scheduler.enabled = False
    cfg.domains = [DomainConfig(name='special.example', checks={'ping': False, 'deface': True})]
    context.args = ['normal.example', 'special.example']
    asyncio.run(add_wizard.cmd_add_start(update, context))
    asyncio.run(add_wizard.cmd_add_keywords_none(update, context))
    update.effective_message.text = '5'
    asyncio.run(add_wizard.cmd_add_interval_text(update, context))
    assert '• <b>normal.example</b>: <code>ping</code>' in replies[-1]
    assert '• <b>special.example</b>: <code>deface</code>' in replies[-1]
    assert 'global scheduler disabled' in replies[-1]
    assert storage.get_domain_override(1, 'special.example')['interval_minutes'] == 5
