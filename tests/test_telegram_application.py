"""Registered Telegram routes exercised through PTB's public update boundary."""
import asyncio
from contextlib import asynccontextmanager
from urllib.parse import parse_qs

import httpx
from telegram import Update
from telegram.ext import Application
from telegram.request import HTTPXRequest

from sitewatcher import storage
from sitewatcher.bot.router import register_handlers
from sitewatcher.config import AppConfig, ChecksModel, resolve_settings


class TelegramBoundary:
    def __init__(self):
        self.messages = []
        self.errors = []
        self.next_update = 1
        self.application = None

    def respond(self, request):
        method = request.url.path.rsplit('/', 1)[-1]
        bot_user = {'id': 123, 'is_bot': True, 'first_name': 'Offline bot',
                    'username': 'sitewatcher_test_bot'}
        if method == 'getMe':
            result = bot_user
        elif method == 'sendMessage':
            payload = {key: values[0] for key, values in parse_qs(
                request.content.decode('utf-8'), keep_blank_values=True,
            ).items()}
            self.messages.append(payload)
            result = {
                'message_id': len(self.messages), 'date': 1_700_000_000,
                'chat': {'id': int(payload['chat_id']),
                         'type': 'group' if int(payload['chat_id']) < 0 else 'private'},
                'from': bot_user, 'text': payload['text'],
            }
        else:
            raise AssertionError(f'Unexpected offline Telegram method: {method}')
        return httpx.Response(200, json={'ok': True, 'result': result})

    async def send(self, text, *, owner=1, chat=1):
        entities = []
        if text.startswith('/'):
            command = text.split()[0]
            entities = [{'type': 'bot_command', 'offset': 0, 'length': len(command)}]
        update = Update.de_json({
            'update_id': self.next_update,
            'message': {
                'message_id': self.next_update, 'date': 1_700_000_000,
                'chat': {'id': chat, 'type': 'group' if chat < 0 else 'private'},
                'from': {'id': owner, 'is_bot': False, 'first_name': 'Offline owner'},
                'text': text, 'entities': entities,
            },
        }, self.application.bot)
        self.next_update += 1
        await self.application.process_update(update)
        assert self.errors == []

    async def capture_error(self, update, context):
        self.errors.append(type(context.error).__name__)


@asynccontextmanager
async def registered_bot(allowed=(1, 2)):
    boundary = TelegramBoundary()
    cfg = AppConfig()
    cfg.defaults.checks = ChecksModel.model_validate({
        name: name == 'ping' for name in ChecksModel.model_fields
    })

    def request():
        return HTTPXRequest(httpx_kwargs={
            'transport': httpx.MockTransport(boundary.respond), 'trust_env': False,
        })

    application = (Application.builder().token('123:offline-only')
                   .request(request()).get_updates_request(request())
                   .updater(None).job_queue(None).concurrent_updates(False).build())
    boundary.application = application
    application.bot_data.update(cfg=cfg, allowed_user_ids=set(allowed))
    register_handlers(application)
    application.add_error_handler(boundary.capture_error)
    async with application:
        yield boundary, cfg


def test_registered_wizard_keeps_interleaved_owner_state_and_configured_checks():
    async def scenario():
        async with registered_bot() as (bot, cfg):
            await bot.send('/add first.example')
            await bot.send('/add second.example', owner=2, chat=2)
            assert storage.list_domains(1) == storage.list_domains(2) == []
            await bot.send('needle needle')
            await bot.send('/none', owner=2, chat=2)
            assert storage.list_domains(1) == storage.list_domains(2) == []
            await bot.send('/none')
            await bot.send('5', owner=2, chat=2)

            assert storage.list_domains(1) == ['first.example']
            assert storage.list_domains(2) == ['second.example']
            first = resolve_settings(cfg, 'first.example',
                                     storage.get_domain_override(1, 'first.example'))
            second = resolve_settings(cfg, 'second.example',
                                      storage.get_domain_override(2, 'second.example'))
            assert first.interval_minutes == 0 and first.keywords == ['needle']
            assert second.interval_minutes == 5 and not second.checks.keywords
            assert {name for name, on in first.checks.model_dump().items() if on} == {
                'ping', 'keywords',
            }
            assert {name for name, on in second.checks.model_dump().items() if on} == {'ping'}
            confirmations = [message for message in bot.messages if '✅ Added' in message['text']]
            assert len(confirmations) == 2
            assert confirmations[0]['chat_id'] == '1'
            assert 'first.example' in confirmations[0]['text']
            assert 'second.example' not in confirmations[0]['text']
            assert confirmations[1]['chat_id'] == '2'
            assert 'second.example' in confirmations[1]['text']
            assert 'first.example' not in confirmations[1]['text']
            assert storage.get_user_alert_chat_id(1) == 1
            assert storage.get_user_alert_chat_id(2) == 2

    asyncio.run(scenario())


def test_registered_auth_denial_never_writes_and_cancel_discards_unfinished_wizard():
    async def scenario():
        async with registered_bot(allowed=(1,)) as (bot, cfg):
            assert not storage.DEFAULT_DB.exists()
            await bot.send('/add forbidden.example', owner=9, chat=9)
            await bot.send('/stop_alerts', owner=9, chat=9)
            assert not storage.DEFAULT_DB.exists()
            assert len(bot.messages) == 2
            assert all('not allowed' in message['text'] for message in bot.messages)

            await bot.send('/add cancelled.example')
            await bot.send('keyword')
            await bot.send('/cancel')
            count_after_cancel = len(bot.messages)
            await bot.send('5')
            assert len(bot.messages) == count_after_cancel
            assert storage.list_domains(1) == []
            assert storage.get_domain_override(1, 'cancelled.example') is None
            await bot.send('/add saved.example')
            await bot.send('/none')
            await bot.send('/none')
            assert storage.list_domains(1) == ['saved.example']

    asyncio.run(scenario())


def test_registered_settings_removal_and_alert_preferences_stay_owner_scoped():
    async def scenario():
        async with registered_bot() as (bot, cfg):
            await bot.send('/add_domain shared.example')
            await bot.send('/add_domain shared.example', owner=2, chat=2)
            await bot.send('/cfg_set shared.example checks.ping false')
            assert storage.get_domain_override(1, 'shared.example') == {'checks': {'ping': False}}
            assert storage.get_domain_override(2, 'shared.example') is None
            await bot.send('/cfg_set shared.example interval_minutes 0')
            await bot.send('/cfg_set shared.example interval_minutes 10', owner=2, chat=2)
            await bot.send('/cfg_unset shared.example checks.ping')
            own = resolve_settings(cfg, 'shared.example',
                                   storage.get_domain_override(1, 'shared.example'))
            assert own.checks.ping and own.interval_minutes == 0
            await bot.send('/cfg_unset shared.example')
            assert storage.get_domain_override(1, 'shared.example') is None
            assert storage.get_domain_override(2, 'shared.example') == {'interval_minutes': 10}

            await bot.send('/stop_alerts')
            assert not storage.is_user_alerts_enabled(1)
            assert storage.is_user_alerts_enabled(2)
            await bot.send('/stop_alerts', owner=2, chat=2)
            await bot.send('/start_alerts', chat=-303)
            assert storage.is_user_alerts_enabled(1)
            assert not storage.is_user_alerts_enabled(2)
            assert storage.get_user_alert_chat_id(1) == -303
            assert storage.get_user_alert_chat_id(2) == 2

            await bot.send('/add_domain temporary.example')
            await bot.send('/remove shared.example')
            assert storage.list_domains(1) == ['temporary.example']
            assert storage.list_domains(2) == ['shared.example']
            await bot.send('/remove_all')
            await bot.send('delete')
            assert storage.list_domains(1) == []
            assert storage.list_domains(2) == ['shared.example']
            assert storage.get_domain_override(2, 'shared.example') == {'interval_minutes': 10}

    asyncio.run(scenario())
