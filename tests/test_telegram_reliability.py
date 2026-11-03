import asyncio
import html
from html.parser import HTMLParser
from types import SimpleNamespace

import pytest
from telegram.error import BadRequest, RetryAfter

from sitewatcher import storage
from sitewatcher.bot import utils


class Message:
    text = '/help'

    def __init__(self):
        self.replies = []

    async def reply_html(self, text, **kwargs):
        assert len(text.encode('utf-16-le')) // 2 <= 4096
        self.replies.append(text)


@pytest.fixture
def boundary(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, 'DEFAULT_DB', tmp_path / 'monitor.db')
    update = SimpleNamespace(
        effective_user=SimpleNamespace(id=7, username='tester', first_name='Test', last_name='User'),
        effective_chat=SimpleNamespace(id=70), effective_message=Message(),
    )
    context = SimpleNamespace(application=SimpleNamespace(bot_data={'allowed_user_ids': {7}}))
    return update, context


def test_authorized_interaction_remembers_profile_and_alert_chat(boundary):
    update, context = boundary

    @utils.requires_auth
    async def command(update, context):
        return 42

    assert asyncio.run(command(update, context)) == 42
    assert storage.get_user_alert_chat_id(7) == 70
    with storage._connect() as conn:
        row = conn.execute('SELECT username, first_name, last_name FROM users').fetchone()
    assert tuple(row) == ('tester', 'Test', 'User')
    storage.set_user_alerts_enabled(7, False)
    update.effective_chat.id = 71
    asyncio.run(command(update, context))
    assert storage.get_user_alert_chat_id(7) == 71
    assert storage.is_user_alerts_enabled(7) is False


def test_denied_interaction_does_not_write_database(boundary):
    update, context = boundary
    context.application.bot_data['allowed_user_ids'] = {8}

    @utils.requires_auth
    async def command(update, context):
        pytest.fail('unauthorized handler ran')

    asyncio.run(command(update, context))
    assert not storage.DEFAULT_DB.exists()
    assert update.effective_message.replies


def test_nested_auth_preserves_busy_opt_out(boundary):
    update, context = boundary
    context.application.bot_data[utils.BUSY_USERS_KEY] = {7: {'started_at': 0, 'cmd': '/check'}}

    @utils.requires_auth(allow_while_busy=True)
    async def command(update, context):
        return 42

    assert asyncio.run(utils.requires_auth(command)(update, context)) == 42
    assert 7 in context.application.bot_data[utils.BUSY_USERS_KEY]


def test_busy_guard_is_per_owner_and_releases_on_cancellation(boundary):
    update, context = boundary

    async def scenario():
        entered = asyncio.Event()
        release = asyncio.Event()
        calls = []

        @utils.requires_auth
        async def command(update, context):
            calls.append(update.effective_user.id)
            entered.set()
            await release.wait()

        task = asyncio.create_task(command(update, context))
        await entered.wait()
        await command(update, context)
        other = SimpleNamespace(effective_user=SimpleNamespace(id=8), effective_chat=None,
                                effective_message=Message())
        context.application.bot_data['allowed_user_ids'].add(8)
        other_task = asyncio.create_task(command(other, context))
        await asyncio.sleep(0)
        assert calls == [7, 8]
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert 7 not in context.application.bot_data[utils.BUSY_USERS_KEY]
        release.set()
        await other_task
        assert context.application.bot_data[utils.BUSY_USERS_KEY] == {}

    asyncio.run(scenario())


class ParsedHTML(HTMLParser):
    def __init__(self):
        super().__init__()
        self.stack = []
        self.text = ''

    def handle_starttag(self, tag, attrs):
        self.stack.append(tag)

    def handle_endtag(self, tag):
        assert self.stack.pop() == tag

    def handle_data(self, data):
        self.text += data


def test_long_escaped_single_line_arrives_as_complete_valid_html():
    message = Message()
    body = ('Привет 😀 <>&"' * 1000) + 'END'
    asyncio.run(utils.safe_reply_html(message, '<b>Title</b><pre>' + html.escape(body) + '</pre>'))
    assert len(message.replies) > 1
    visible = []
    for reply in message.replies:
        parsed = ParsedHTML()
        parsed.feed(reply)
        assert parsed.stack == []
        visible.append(parsed.text)
    assert ''.join(visible) == 'Title' + body


def test_retry_after_timedelta_retries_without_sleep_after_final_attempt(monkeypatch):
    from datetime import timedelta

    monkeypatch.setenv('PTB_TIMEDELTA', 'true')

    class LimitedMessage(Message):
        attempts = 0

        async def reply_html(self, text, **kwargs):
            self.attempts += 1
            if self.attempts < 2:
                raise RetryAfter(timedelta(seconds=2))
            await super().reply_html(text, **kwargs)

    sleeps = []

    async def sleep(delay):
        sleeps.append(delay)

    monkeypatch.setattr(utils.asyncio, 'sleep', sleep)
    message = LimitedMessage()
    asyncio.run(utils.safe_reply_html(message, 'hello'))
    assert message.replies == ['hello']
    assert sleeps == [2]

    class InvalidMessage:
        async def reply_html(self, text, **kwargs):
            raise BadRequest('invalid markup')

    sleeps.clear()
    asyncio.run(utils.safe_reply_html(InvalidMessage(), 'hello'))
    assert sleeps == []


def test_conversation_updates_are_processed_sequentially(monkeypatch):
    from telegram.ext import Application
    from sitewatcher.bot import app
    from sitewatcher.config import AppConfig

    processors = []
    monkeypatch.setattr(app, 'get_bot_token_from_env', lambda: '123:offline')
    monkeypatch.setattr(Application, 'run_polling',
                        lambda self, **kwargs: processors.append(self.update_processor))
    app.run_bot(AppConfig())
    assert processors[0].max_concurrent_updates == 1


def test_split_html_preserves_nested_links_entities_and_unicode():
    from sitewatcher.bot.html import split_html

    text = '<b><a href="https://example.com/?x=1&amp;y=2">α &amp; 😀 &#128512; β</a></b>'
    chunks = split_html(text, limit=65)
    assert len(chunks) > 1
    visible = []
    for chunk in chunks:
        assert len(chunk.encode('utf-16-le')) // 2 <= 65
        assert 'href="https://example.com/?x=1&amp;y=2"' in chunk
        parser = ParsedHTML()
        parser.feed(chunk)
        assert parser.stack == []
        visible.append(parser.text)
    assert ''.join(visible) == 'α & 😀 😀 β'
    assert split_html('') == []


def test_failed_final_attempt_has_no_delay_and_cancellation_propagates(monkeypatch):
    from telegram.error import TimedOut

    sleeps = []

    async def sleep(delay):
        sleeps.append(delay)

    class UnavailableMessage:
        async def reply_html(self, text, **kwargs):
            raise TimedOut()

    monkeypatch.setattr(utils.asyncio, 'sleep', sleep)
    asyncio.run(utils.safe_reply_html(UnavailableMessage(), 'hello', retries=2))
    assert sleeps == [1]

    class CancelledMessage:
        async def reply_html(self, text, **kwargs):
            raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(utils.safe_reply_html(CancelledMessage(), 'hello'))


@pytest.mark.parametrize('value', ['invalid', '7,invalid', '0', '-7', '7,-8', ' , '])
def test_malformed_allowlist_fails_closed_without_echoing_value(monkeypatch, value):
    monkeypatch.setenv('TELEGRAM_ALLOWED_USER_IDS', value)
    with pytest.raises(ValueError, match='TELEGRAM_ALLOWED_USER_IDS') as error:
        utils._parse_allowed_user_ids()
    assert value.strip() not in str(error.value)


@pytest.mark.parametrize(('value', 'expected'), [('', set()), ('  ', set()), ('7, 8\n9', {7, 8, 9})])
def test_empty_allowlist_is_open_and_valid_allowlist_is_restricted(monkeypatch, value, expected):
    monkeypatch.setenv('TELEGRAM_ALLOWED_USER_IDS', value)
    assert utils._parse_allowed_user_ids() == expected
