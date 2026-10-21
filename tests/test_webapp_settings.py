"""Owner preferences preserve identity, UTC history, and private Telegram configuration."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
import stat

import httpx
import pytest
from django.contrib.auth import get_user_model
from django.test import Client

from sitewatcher import storage
from sitewatcher.config import AppConfig, get_bot_token_from_env
from sitewatcher.webapp.presentation import local_time


@pytest.fixture
def owner(web_database, client, monkeypatch):
    from sitewatcher.webapp.models import Workspace
    monkeypatch.delenv('TELEGRAM_TOKEN', raising=False)
    monkeypatch.delenv('TELEGRAM_ALERT_CHAT_ID', raising=False)
    user = get_user_model().objects.create_user(username='settings-owner')
    workspace = Workspace.objects.create(user=user, owner_id=31)
    storage.ensure_user(31)
    storage.ensure_user(99)
    storage.add_domain(31, 'one.example')
    client.force_login(user)
    return workspace


def post(client, fields, path='/settings'):
    return client.post(path, fields, HTTP_HOST='localhost')


def test_timezone_save_preserves_owner_destination_history_and_omitted_preferences(owner, client):
    assert owner.timezone == 'Europe/Moscow'
    storage.set_user_alert_chat_id(31, -100123)
    storage.set_user_alerts_enabled(31, False)
    with storage._write_connection() as conn:
        conn.execute("INSERT INTO history(owner_id, domain, check_name, status, message, created_at) "
                     "VALUES (31, 'one.example', 'http_basic', 'OK', 'ok', '2026-10-21 22:30:00')")
    for route in ('/settings', '/workspace'):
        response = client.get(route, HTTP_HOST='localhost')
        assert response.status_code == 200
        assert b'Europe/Moscow' in response.content
        assert b'Change password' in response.content
    response = post(client, {'timezone': 'America/New_York'})
    assert response.status_code == 303
    owner.refresh_from_db()
    assert owner.timezone == 'America/New_York' and owner.owner_id == 31
    assert storage.get_user_alert_chat_id(31) == -100123
    assert not storage.is_user_alerts_enabled(31)
    with storage._connect() as conn:
        assert conn.execute('SELECT created_at FROM history').fetchone()[0] == '2026-10-21 22:30:00'
    assert local_time('2026-10-21 22:30:00', 'Europe/Moscow')['label'].startswith('22 Oct')
    # The repeated autumn hour must retain distinct offsets while keeping UTC instants.
    summer = local_time('2026-11-01 05:30:00', owner.timezone)
    winter = local_time('2026-11-01 06:30:00', owner.timezone)
    assert summer['label'] != winter['label']
    assert summer['iso'] != winter['iso']


def test_invalid_timezone_and_chat_have_adjacent_errors_and_no_partial_save(owner, client):
    response = post(client, {'timezone': 'Invalid/Zone', 'chat_id': 'not-a-number', 'enabled': 'off'})
    assert response.status_code == 400
    assert b'id_timezone' in response.content and b'aria-invalid="true"' in response.content
    assert b'id_chat_id' in response.content
    owner.refresh_from_db()
    assert owner.timezone == 'Europe/Moscow'
    assert storage.is_user_alerts_enabled(31)
    assert storage.get_user_alert_chat_id(31) is None


def test_settings_auth_csrf_owner_binding_and_readonly(owner, client, settings):
    assert Client().get('/settings', HTTP_HOST='localhost').status_code == 302
    secure = Client(enforce_csrf_checks=True)
    secure.force_login(owner.user)
    assert post(secure, {'timezone': 'UTC'}).status_code == 403
    for fields in ({'owner_id': '99', 'enabled': 'off'}, {'chat_id': '0'},
                   {'chat_id': str(2**63)}, {'action': 'unknown'}):
        assert post(client, fields).status_code == 400
    assert storage.is_user_alerts_enabled(99)
    settings.SITEWATCHER_READ_ONLY = True
    for route in ('/workspace', '/settings'):
        assert post(client, {'enabled': 'off'}, route).status_code == 405
        response = client.get(route, HTTP_HOST='localhost')
        assert response.status_code == 200 and b'disabled' in response.content
    assert client.get('/password/', HTTP_HOST='localhost').status_code == 200


def test_optional_token_stored_privately_and_env_override_visible(owner, client, monkeypatch):
    from sitewatcher.telegram_connection import token_path, load_bot_token
    token = '123456:private_test_token_abcdefghijklmnopqrstuvwxyz'
    assert post(client, {'enabled': 'off', 'chat_id': '-100123', 'bot_token': token}).status_code == 303
    path = token_path()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.read_text() == token
    assert load_bot_token() == token == get_bot_token_from_env()
    for route in ('/settings', '/workspace', '/api/status', '/'):
        response = client.get(route, HTTP_HOST='localhost')
        assert token.encode() not in response.content
    monkeypatch.setenv('TELEGRAM_TOKEN', '654321:deployment_override_abcdefghijklmnopqrstuvwxyz')
    assert load_bot_token().startswith('654321:')
    response = client.get('/settings', HTTP_HOST='localhost')
    assert b'Environment override' in response.content
    assert b'deployment_override' not in response.content
    assert post(client, {'timezone': 'UTC'}).status_code == 303
    assert path.read_text() == token


def test_secret_file_concurrent_atomic_publication_and_permission_rejection(tmp_path, monkeypatch):
    from sitewatcher.telegram_connection import save_bot_token, load_bot_token, token_path
    monkeypatch.delenv('TELEGRAM_TOKEN', raising=False)
    tokens = [f'{123456 + index}:abcdefghijklmnopqrstuvwxyz_private_token' for index in range(10)]
    with ThreadPoolExecutor(max_workers=5) as pool:
        list(pool.map(save_bot_token, tokens))
    assert load_bot_token() in tokens
    assert stat.S_IMODE(token_path().stat().st_mode) == 0o600
    assert not list(tmp_path.glob('.telegram-token-*'))
    token_path().chmod(0o644)
    with pytest.raises(ValueError, match='0600'):
        load_bot_token()


def test_blank_token_preserved_and_invalid_token_never_echoed(owner, client):
    from sitewatcher.telegram_connection import save_bot_token, load_bot_token
    token = '123456:abcdefghijklmnopqrstuvwxyz_private_token'
    save_bot_token(token)
    assert post(client, {'bot_token': '', 'chat_id': '-100222'}).status_code == 303
    assert load_bot_token() == token
    response = post(client, {'bot_token': 'private-invalid-token', 'enabled': 'off'})
    assert response.status_code == 400
    assert b'private-invalid-token' not in response.content
    assert storage.is_user_alerts_enabled(31)
    assert storage.get_user_alert_chat_id(31) == -100222


def test_test_notification_explicit_post_uses_effective_config_destination(owner, client, settings, monkeypatch):
    from sitewatcher.webapp import preferences
    from sitewatcher.telegram_connection import save_bot_token
    save_bot_token('123456:abcdefghijklmnopqrstuvwxyz_private_token')
    storage.set_user_alert_chat_id(31, -100123)
    cfg = AppConfig()
    cfg.alerts.chat_id = -100999
    settings.SITEWATCHER_CONFIG = cfg
    calls = []
    async def send(token, chat_id):
        calls.append(chat_id)
    monkeypatch.setattr(preferences, 'send_test_notification', send)
    assert client.get('/settings', HTTP_HOST='localhost').status_code == 200
    assert calls == []
    response = post(client, {'action': 'test'})
    assert response.status_code == 200 and calls == [-100999]
    assert b'Test notification sent' in response.content
    assert b'-100999' in response.content and b'managed by your installation' in response.content
    assert storage.get_user_alert_chat_id(31) == -100123
    response = post(client, {'chat_id': '-100777'})
    assert response.status_code == 303
    response = client.get('/settings', HTTP_HOST='localhost')
    assert b'-100999' in response.content and b'managed by your installation' in response.content


def test_actual_destination_precedence_missing_configuration_and_safe_errors(owner, client, monkeypatch):
    from sitewatcher.webapp import preferences
    from sitewatcher.telegram_connection import save_bot_token
    assert post(client, {'timezone': 'UTC'}).status_code == 303
    response = post(client, {'action': 'test'})
    assert response.status_code == 400 and b'bot token' in response.content
    save_bot_token('123456:abcdefghijklmnopqrstuvwxyz_private_token')
    response = post(client, {'action': 'test'})
    assert response.status_code == 400 and b'destination' in response.content
    monkeypatch.setenv('TELEGRAM_ALERT_CHAT_ID', '-100333')
    async def fail(token, chat_id):
        assert chat_id == -100333
        raise RuntimeError(f'https://api.telegram.org/bot{token}/sendMessage')
    monkeypatch.setattr(preferences, 'send_test_notification', fail)
    response = post(client, {'action': 'test'})
    assert response.status_code == 400
    assert b'api.telegram.org' not in response.content and b'private_token' not in response.content
    storage.set_user_alert_chat_id(31, -100444)
    async def send(token, chat_id):
        assert chat_id == -100444
    monkeypatch.setattr(preferences, 'send_test_notification', send)
    assert post(client, {'action': 'test'}).status_code == 200


def test_telegram_adapter_timeout_proxy_payload_and_safe_network_errors(monkeypatch, caplog):
    from sitewatcher.telegram_connection import send_test_notification, find_chats, TelegramConnectionError
    token = '123456:abcdefghijklmnopqrstuvwxyz_private_token'
    seen = []
    def handler(request):
        seen.append(request)
        if request.url.path.endswith('/getUpdates'):
            return httpx.Response(200, json={'ok': True, 'result': [
                {'message': {'chat': {'id': -100123, 'title': 'My alerts'}}},
                {'message': {'chat': {'id': -100123, 'title': 'My alerts'}}}]})
        return httpx.Response(200, json={'ok': True, 'result': {}})
    original = httpx.AsyncClient
    def client(**kwargs):
        assert kwargs['proxy'] == 'socks5://localhost:1080'
        assert 0 < kwargs['timeout'] <= 15
        return original(transport=httpx.MockTransport(handler), timeout=kwargs['timeout'])
    monkeypatch.setenv('TELEGRAM_PROXY', 'socks5://localhost:1080')
    monkeypatch.setattr(httpx, 'AsyncClient', client)
    caplog.set_level('DEBUG')
    asyncio.run(send_test_notification(token, -100123))
    chats = asyncio.run(find_chats(token))
    assert chats == [{'id': -100123, 'label': 'My alerts'}]
    assert b'SiteWatcher test notification' in seen[0].content
    assert b'"timeout":0' in seen[1].content and b'offset' not in seen[1].content
    assert token not in caplog.text
    def broken(request):
        return httpx.Response(409, json={'description': token})
    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kwargs: original(
        transport=httpx.MockTransport(broken)))
    with pytest.raises(TelegramConnectionError, match='polling|webhook') as error:
        asyncio.run(find_chats(token))
    assert token not in str(error.value)


def test_find_chats_explicit_choice_never_silently_binds(owner, client, monkeypatch):
    from sitewatcher.telegram_connection import save_bot_token
    from sitewatcher.webapp import preferences
    save_bot_token('123456:abcdefghijklmnopqrstuvwxyz_private_token')
    async def find(token):
        return [{'id': -100123, 'label': 'Alerts group'}]
    monkeypatch.setattr(preferences, 'find_chats', find)
    response = post(client, {'action': 'find_chats'})
    assert response.status_code == 200 and b'Alerts group' in response.content
    assert storage.get_user_alert_chat_id(31) is None
    assert post(client, {'chat_id': '-100123'}).status_code == 303
    assert storage.get_user_alert_chat_id(31) == -100123
    assert storage.list_domains(31) == ['one.example']
    async def empty(token):
        return []
    monkeypatch.setattr(preferences, 'find_chats', empty)
    response = post(client, {'action': 'find_chats'})
    assert response.status_code == 200 and b'No chats found' in response.content


def test_empty_notification_toggle_is_rejected_without_disabling(owner, client):
    assert post(client, {'enabled': ''}).status_code == 400
    assert storage.is_user_alerts_enabled(31)


def test_doctor_reads_private_token_without_database_initialization(tmp_path, monkeypatch):
    from sitewatcher.diagnostics import diagnose, format_diagnostics
    from sitewatcher.telegram_connection import save_bot_token, token_path
    monkeypatch.delenv('TELEGRAM_TOKEN', raising=False)
    config = tmp_path / 'checks.yaml'
    config.write_text('{}')
    save_bot_token('123456:abcdefghijklmnopqrstuvwxyz_private_token')
    def no_database(*args, **kwargs):
        raise AssertionError('Token loading must not initialize a database')
    monkeypatch.setattr(storage, '_ensure_initialized', no_database)
    report = diagnose(config)
    assert report['telegram']['token_present'] and not storage.DEFAULT_DB.exists()
    token_path().chmod(0o644)
    report = diagnose(config)
    assert not report['ok']
    assert '0600' in format_diagnostics(report)
    assert 'private_token' not in format_diagnostics(report)


@pytest.mark.parametrize('reader', ['telegram', 'web', 'doctor'])
def test_private_secret_fifo_is_rejected_without_waiting_for_a_writer(tmp_path, reader):
    import os
    import subprocess
    import sys

    database = tmp_path / 'absent.db'
    suffix = '.web-secret' if reader == 'web' else '.telegram-token'
    private_path = database.with_name(database.name + suffix)
    os.mkfifo(private_path, mode=0o600)
    config = tmp_path / 'checks.yaml'
    config.write_text('{}')
    program = '''
import sys
from sitewatcher import storage
if sys.argv[1] == 'doctor':
    from sitewatcher.diagnostics import diagnose, format_diagnostics
    report = diagnose(sys.argv[2])
    assert not report['ok']
    assert not report['telegram']['token_present']
    assert 'error' in report['telegram']
    print(format_diagnostics(report))
else:
    from sitewatcher.telegram_connection import load_bot_token
    from sitewatcher.webapp.bootstrap import load_secret_key
    try:
        if sys.argv[1] == 'web':
            load_secret_key(storage.DEFAULT_DB)
        else:
            load_bot_token()
    except ValueError as error:
        print(str(error))
    else:
        raise AssertionError('A FIFO must never be accepted as a secret file')
assert not storage.DEFAULT_DB.exists()
'''
    environment = {**os.environ, 'DATABASE_PATH': str(database)}
    environment.pop('TELEGRAM_TOKEN', None)
    environment.pop('SITEWATCHER_WEB_SECRET_KEY', None)
    try:
        result = subprocess.run([sys.executable, '-c', program, reader, str(config)],
                                env=environment, capture_output=True, text=True, timeout=3)
    except subprocess.TimeoutExpired:
        pytest.fail(f'{reader} reader blocked on a FIFO with no writer')
    assert result.returncode == 0, result.stderr
    assert '0600' in result.stdout
    assert str(private_path) not in result.stdout + result.stderr
    assert 'Traceback' not in result.stderr
