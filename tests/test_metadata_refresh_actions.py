"""Owner-only metadata refresh never becomes an unrestricted manual check."""
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from django.contrib.auth import get_user_model
from django.test import Client

from sitewatcher import main, storage
from sitewatcher.checks.base import CheckOutcome, Status
from sitewatcher.config import AppConfig


@pytest.fixture
def refresh_owner(web_database, client):
    from sitewatcher.webapp.models import Workspace
    user = get_user_model().objects.create_user(username='refresh-owner')
    Workspace.objects.create(user=user, owner_id=31)
    storage.add_domain(31, 'one.example')
    storage.add_domain(99, 'private.example')
    client.force_login(user)
    return user


def test_refresh_selected_check_and_cached_notice(refresh_owner, client, monkeypatch):
    from sitewatcher.webapp import domains
    calls = []

    class Dispatcher:
        def __init__(self, cfg):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def run_for(self, owner, name, **kwargs):
            calls.append((owner, name, kwargs))
            return [CheckOutcome('tls_cert', Status.OK, 'cached', {}, cached=True)]

    monkeypatch.setattr(domains, 'Dispatcher', Dispatcher)
    save = []
    monkeypatch.setattr(storage, 'save_histories', lambda *a, **kw: save.append((a, kw)))
    response = client.post('/domains/refresh', {'domain': 'one.example', 'check': 'tls_cert',
                           'days': '7', 'q': 'one', 'status': 'all'}, HTTP_HOST='localhost')
    assert response.status_code == 303
    assert calls == [(31, 'one.example', {'only_checks': ['tls_cert'],
                                         'refresh_checks': ['tls_cert']})]
    assert save[0][1] == {'create_missing': False, 'source': 'manual'}
    assert 'cached' in response['Location'].lower()
    assert 'days=7' in response['Location'] and 'q=one' in response['Location']


@pytest.mark.parametrize('fields, expected', [
    ({'domain': 'private.example', 'check': 'tls_cert'}, 404),
    ({'domain': '*', 'check': 'tls_cert'}, 404),
    ({'domain': 'one.example', 'check': 'http_basic'}, 400),
    ({'domain': 'one.example', 'check': 'tls_cert,whois'}, 400),
    ({'domain': 'one.example', 'check': 'tls_cert', 'owner_id': '99'}, 400),
    ({'domain': 'one.example'}, 400),
])
def test_refresh_rejects_invalid_requests(refresh_owner, client, fields, expected):
    assert client.post('/domains/refresh', fields, HTTP_HOST='localhost').status_code == expected


def test_refresh_auth_csrf_readonly_and_disabled(refresh_owner, client, settings):
    fields = {'domain': 'one.example', 'check': 'tls_cert'}
    assert Client().post('/domains/refresh', fields, HTTP_HOST='localhost').status_code == 302
    csrf = Client(enforce_csrf_checks=True)
    csrf.force_login(refresh_owner)
    assert csrf.post('/domains/refresh', fields, HTTP_HOST='localhost').status_code == 403
    assert client.get('/domains/refresh', HTTP_HOST='localhost').status_code == 405
    settings.SITEWATCHER_READ_ONLY = True
    assert client.post('/domains/refresh', fields, HTTP_HOST='localhost').status_code == 405
    settings.SITEWATCHER_READ_ONLY = False
    storage.set_domain_override(31, 'one.example', {'checks': {'tls_cert': False}})
    assert client.post('/domains/refresh', fields, HTTP_HOST='localhost').status_code == 400


@pytest.mark.parametrize('argv', [
    ['scan', 'one.example', '--refresh-metadata', 'whois'],
    ['check_all', '--refresh-metadata', 'tls_cert'],
    ['check_domain', 'one.example', '--owner', '31', '--refresh-metadata', 'vt'],
    ['check_domain', 'one.example', '--refresh-metadata', 'whois'],
])
def test_cli_rejects_wrong_refresh_scope(monkeypatch, argv):
    monkeypatch.setattr('sys.argv', ['sitewatcher', *argv])
    with pytest.raises(SystemExit):
        main._parse_args()


def test_cli_refresh_only_selected_metadata(monkeypatch):
    from sitewatcher import main
    storage.add_domain(31, 'one.example')
    run = AsyncMock(return_value=[CheckOutcome('whois', Status.OK, 'cached', {}, cached=True)])
    monkeypatch.setattr(main, '_run_and_persist', run)
    asyncio.run(main._cmd_check_one(AppConfig(), 31, 'one.example', only=None, use_cache=True,
                                  run_id='run', refresh_checks=['whois']))
    assert run.call_args.kwargs['only_checks'] == ['whois']
    assert run.call_args.kwargs['refresh_checks'] == ['whois']


def test_refresh_ui_owner_only(refresh_owner, client, settings):
    html = client.get('/', HTTP_HOST='localhost').content.decode()
    assert '/domains/refresh' in html
    assert 'name="check" value="tls_cert"' in html
    history = client.get('/domains/history?domain=one.example', HTTP_HOST='localhost')
    assert b'/domains/refresh' in history.content
    settings.SITEWATCHER_READ_ONLY = True
    assert b'/domains/refresh' not in client.get('/', HTTP_HOST='localhost').content
    assert b'/domains/refresh' not in client.get('/domains/history?domain=one.example',
                                               HTTP_HOST='localhost').content


def test_refresh_deletion_cannot_recreate_domain(refresh_owner, monkeypatch):
    from sitewatcher.webapp import domains

    class Dispatcher:
        def __init__(self, cfg):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def run_for(self, owner, name, **kwargs):
            storage.remove_domain(owner, name)
            return [CheckOutcome('tls_cert', Status.OK, 'fresh', {})]

    monkeypatch.setattr(domains, 'Dispatcher', Dispatcher)
    asyncio.run(domains._refresh_metadata(AppConfig(), 31, 'one.example', 'tls_cert'))
    assert not storage.domain_exists(31, 'one.example')


def test_bot_refresh_uses_selected_check_without_alerts(monkeypatch):
    from sitewatcher.bot.handlers import checks
    storage.add_domain(31, 'one.example')
    run = AsyncMock(return_value=[CheckOutcome('whois', Status.OK, 'cached', {}, cached=True)])

    class Dispatcher:
        def __init__(self, cfg):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        run_for = run

    monkeypatch.setattr(checks, 'Dispatcher', Dispatcher)
    alert = AsyncMock()
    monkeypatch.setattr(checks, 'maybe_send_alert', alert)
    message = SimpleNamespace(reply_html=AsyncMock(), reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=31))
    context = SimpleNamespace(args=['one.example', '--refresh=whois'],
                              application=SimpleNamespace(bot_data={'cfg': AppConfig()}))
    asyncio.run(checks.cmd_check_domain(update, context))
    assert run.call_args.args == (31, 'one.example')
    assert run.call_args.kwargs == {'only_checks': ['whois'], 'refresh_checks': ['whois']}
    assert 'Cached metadata reused' in message.reply_html.call_args.args[0]
    alert.assert_not_called()


@pytest.mark.parametrize('args', [
    ['private.example', '--refresh=whois'],
    ['one.example', '--refresh=vt'],
    ['one.example', 'other.example', '--refresh=whois'],
    ['one.example', '--refresh=whois,tls_cert'],
])
def test_bot_refresh_rejects_unowned_and_unsupported(monkeypatch, args):
    from sitewatcher.bot.handlers import checks
    run = AsyncMock()
    monkeypatch.setattr(checks, 'Dispatcher', run)
    message = SimpleNamespace(reply_html=AsyncMock(), reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=31))
    context = SimpleNamespace(args=args,
                              application=SimpleNamespace(bot_data={'cfg': AppConfig()}))
    asyncio.run(checks.cmd_check_domain(update, context))
    run.assert_not_called()
    message.reply_text.assert_called_once()


def test_refresh_duplicate_fields_lock_and_history_redirect(refresh_owner, client, monkeypatch):
    from sitewatcher.webapp import domains
    fields = {'domain': 'one.example', 'check': 'tls_cert'}
    duplicate = client.post('/domains/refresh', 'domain=one.example&check=tls_cert&check=whois',
                            content_type='application/x-www-form-urlencoded',
                            HTTP_HOST='localhost')
    assert duplicate.status_code == 400
    assert domains._check_lock.acquire(blocking=False)
    try:
        assert client.post('/domains/refresh', fields, HTTP_HOST='localhost').status_code == 409
    finally:
        domains._check_lock.release()
    monkeypatch.setattr(domains, '_refresh_metadata', AsyncMock(return_value=[
        CheckOutcome('tls_cert', Status.OK, 'fresh', {}),
    ]))
    response = client.post('/domains/refresh', {**fields, 'history': '1', 'days': '30'},
                           HTTP_HOST='localhost')
    assert response.status_code == 303
    assert response['Location'].startswith('/domains/history?domain=one.example&days=30&notice=')


def test_cli_refresh_parser_accepts_only_owned_metadata_scope(monkeypatch):
    monkeypatch.setattr('sys.argv', ['sitewatcher', 'check_domain', 'one.example', '--owner',
                                   '31', '--refresh-metadata', 'tls_cert,whois'])
    args = main._parse_args()
    assert args.refresh_metadata == 'tls_cert,whois'


def test_cli_refresh_rejects_unowned_before_dispatch(monkeypatch):
    run = AsyncMock()
    monkeypatch.setattr(main, '_run_and_persist', run)
    with pytest.raises(SystemExit, match='owned domain'):
        asyncio.run(main._cmd_check_one(AppConfig(), 31, 'private.example', only=None,
                                       use_cache=True, run_id='run', refresh_checks=['whois']))
    run.assert_not_called()
