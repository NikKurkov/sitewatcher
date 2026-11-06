"""Private SMTP configuration, account recipient boundaries and safe mocked delivery."""
import asyncio
import stat
import time

import pytest
from django.contrib.auth import get_user_model
from django.test import Client

from sitewatcher import email_delivery, email_settings, storage
from sitewatcher.webapp.models import Workspace


@pytest.fixture(autouse=True)
def private_smtp_file(tmp_path, monkeypatch):
    monkeypatch.setattr(email_settings, 'smtp_path', lambda: tmp_path / 'smtp.json')


@pytest.fixture
def smtp_config():
    return {'host': 'smtp.example.com', 'port': 587, 'security': 'starttls',
            'username': 'mailer', 'password': 'private-smtp-password',
            'from_email': 'monitor@example.com'}


@pytest.fixture
def email_owner(web_database, client):
    user = get_user_model().objects.create_user(username='email-owner')
    workspace = Workspace.objects.create(user=user, owner_id=31,
                                         notification_email='owner@example.com')
    client.defaults['HTTP_HOST'] = 'localhost'
    client.force_login(user)
    return workspace


def smtp_fields(config):
    return {'smtp_settings': '1', **{'smtp_' + key: value for key, value in config.items()}}


def test_smtp_private_atomic_validation_and_permissions(smtp_config):
    email_settings.save_smtp_config(smtp_config)
    path = email_settings.smtp_path()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert email_settings.load_smtp_config() == smtp_config
    with pytest.raises(ValueError):
        email_settings.save_smtp_config({**smtp_config, 'security': 'none'})
    assert email_settings.load_smtp_config() == smtp_config
    path.chmod(0o644)
    with pytest.raises(ValueError):
        email_settings.load_smtp_config()
    assert not email_settings.email_ready(31)


def test_email_recipient_read_is_owner_scoped_and_missing_database_is_not_created(email_owner):
    assert email_settings.get_notification_email(31) == 'owner@example.com'
    assert email_settings.get_notification_email(99) is None
    assert email_settings.get_notification_email(-1) is None


def test_legacy_worker_without_web_table_remains_unconfigured():
    assert not storage.DEFAULT_DB.exists()
    assert email_settings.get_notification_email(31) is None
    assert not storage.DEFAULT_DB.exists()
    storage.ensure_user(31)
    assert email_settings.get_notification_email(31) is None


@pytest.mark.parametrize('security', ['starttls', 'tls'])
def test_email_transport_uses_saved_owner_recipient_and_verified_tls(
        email_owner, smtp_config, monkeypatch, security):
    config = {**smtp_config, 'security': security}
    email_settings.save_smtp_config(config)
    events = []

    class SMTP:
        def __init__(self, host, port, **kwargs):
            assert host == config['host'] and port == config['port']
            assert kwargs['timeout'] == 10
            if security == 'tls':
                assert kwargs['context'].check_hostname
            events.append('connect')

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def starttls(self, *, context):
            assert context.check_hostname
            events.append('starttls')

        def login(self, username, password):
            assert (username, password) == (config['username'], config['password'])
            events.append('login')

        def send_message(self, message):
            assert message['To'] == 'owner@example.com'
            assert message['From'] == 'monitor@example.com'
            assert message.get_body(preferencelist=('plain',)).get_content().strip() == 'Site failed & recovered'
            assert message.get_body(preferencelist=('html',)) is not None
            events.append('send')

    monkeypatch.setattr(email_delivery.smtplib, 'SMTP', SMTP)
    monkeypatch.setattr(email_delivery.smtplib, 'SMTP_SSL', SMTP)
    assert email_settings.email_ready(31)
    asyncio.run(email_delivery.send_notification_email(31, 'Site status', '<p>Site failed &amp; recovered</p>'))
    assert events == ['connect', *(['starttls'] if security == 'starttls' else []), 'login', 'send']


def test_transport_failure_is_generic(email_owner, smtp_config, monkeypatch):
    email_settings.save_smtp_config(smtp_config)

    def fail(*args, **kwargs):
        raise RuntimeError('private-smtp-password owner@example.com')

    monkeypatch.setattr(email_delivery, '_send', fail)
    with pytest.raises(email_delivery.EmailDeliveryError) as error:
        asyncio.run(email_delivery.send_notification_email(31, 'Test', '<p>Test</p>'))
    assert 'private-smtp-password' not in str(error.value)
    assert 'owner@example.com' not in str(error.value)


def test_settings_save_preserves_password_and_does_not_disclose_it(email_owner, smtp_config, client):
    fields = {**smtp_fields(smtp_config), 'notification_email': 'new@example.com'}
    assert client.post('/settings', fields).status_code == 303
    email_owner.refresh_from_db()
    assert email_owner.notification_email == 'new@example.com'
    page = client.get('/settings')
    assert smtp_config['password'].encode() not in page.content
    assert page.context['form']['smtp_username'].value() == 'mailer'
    fields['smtp_password'] = ''
    assert client.post('/settings', fields).status_code == 303
    assert email_settings.load_smtp_config()['password'] == smtp_config['password']
    fields['remove_smtp_password'] = 'on'
    assert client.post('/settings', fields).status_code == 303
    assert email_settings.load_smtp_config()['password'] == ''
    assert client.post('/settings', {'timezone': 'UTC'}).status_code == 303
    email_owner.refresh_from_db()
    assert email_owner.notification_email == 'new@example.com'


def test_invalid_settings_do_not_save_any_email_fields(email_owner, smtp_config, client):
    fields = smtp_fields({**smtp_config, 'host': 'bad host'})
    fields['notification_email'] = 'changed@example.com'
    response = client.post('/settings', fields)
    assert response.status_code == 400
    assert smtp_config['password'].encode() not in response.content
    assert 'smtp_password' in response.wsgi_request.sensitive_post_parameters
    email_owner.refresh_from_db()
    assert email_owner.notification_email == 'owner@example.com'
    assert email_settings.load_smtp_config() is None


def test_email_test_has_owner_csrf_readonly_and_cooldown_boundaries(
        email_owner, client, monkeypatch, settings):
    from sitewatcher.webapp import preferences
    sent = []

    async def send(owner_id, subject, html):
        sent.append(owner_id)

    monkeypatch.setattr(preferences, 'send_notification_email', send)
    assert client.post('/settings', {'action': 'test_email', 'notification_email': 'other@example.com'}).status_code == 400
    assert client.post('/settings', {'action': 'test_email'}).status_code == 200
    assert client.post('/settings', {'action': 'test_email'}).status_code == 429
    assert sent == [31]
    csrf = Client(enforce_csrf_checks=True, HTTP_HOST='localhost')
    csrf.force_login(email_owner.user)
    assert csrf.post('/settings', {'action': 'test_email'}).status_code == 403
    settings.SITEWATCHER_READ_ONLY = True
    assert client.post('/settings', {'action': 'test_email'}).status_code == 405
    client.logout()
    assert client.post('/settings', {'action': 'test_email'}).status_code == 302
    assert sent == [31]


def test_unreadable_smtp_can_be_replaced_explicitly(email_owner, smtp_config, client):
    email_settings.save_smtp_config(smtp_config)
    email_settings.smtp_path().chmod(0o644)
    blank = smtp_fields({**smtp_config, 'password': ''})
    assert client.post('/settings', blank).status_code == 400
    assert client.post('/settings', smtp_fields(smtp_config)).status_code == 303
    assert stat.S_IMODE(email_settings.smtp_path().stat().st_mode) == 0o600
    assert email_settings.load_smtp_config() == smtp_config


@pytest.mark.parametrize('address', ['a@@example.com', 'a\r\n@example.com', 'owner'])
def test_invalid_recipient_is_not_ready(email_owner, smtp_config, address):
    email_owner.notification_email = address
    email_owner.save(update_fields=['notification_email'])
    email_settings.save_smtp_config(smtp_config)
    assert email_settings.get_notification_email(email_owner.owner_id) is None
    assert not email_settings.email_ready(email_owner.owner_id)


def test_slow_smtp_completion_is_not_reported_as_a_timeout(
        email_owner, smtp_config, monkeypatch):
    email_settings.save_smtp_config(smtp_config)
    delivered = []
    wait_for = asyncio.wait_for

    async def scaled_deadline(awaitable, timeout):
        # Scale the former outer deadline below the mocked SMTP completion time.
        return await wait_for(awaitable, timeout=0.01)

    def slow_send(*args):
        time.sleep(0.05)
        delivered.append(True)

    monkeypatch.setattr(email_delivery.asyncio, 'wait_for', scaled_deadline)
    monkeypatch.setattr(email_delivery, '_send', slow_send)
    asyncio.run(email_delivery.send_notification_email(31, 'Test', '<p>Test</p>'))
    assert delivered == [True]


def test_smtp_socket_timeout_is_generic(email_owner, smtp_config, monkeypatch):
    email_settings.save_smtp_config(smtp_config)

    def timeout(*args):
        raise TimeoutError('private-smtp-password owner@example.com')

    monkeypatch.setattr(email_delivery, '_send', timeout)
    with pytest.raises(email_delivery.EmailDeliveryError) as error:
        asyncio.run(email_delivery.send_notification_email(31, 'Test', '<p>Test</p>'))
    assert str(error.value) == 'Email delivery failed. Check your SMTP connection and recipient.'
    assert 'private-smtp-password' not in str(error.value)


def test_public_report_never_exposes_notification_recipients_or_smtp_credentials(
        email_owner, smtp_config):
    import json
    from sitewatcher.webapp.public import public_report

    email_settings.save_smtp_config(smtp_config)
    storage.add_domain(31, 'public.example')
    storage.set_domain_override(31, 'public.example', {'notify_email': True})
    storage.save_history(31, 'public.example', 'http_basic', 'OK', 'healthy',
                         {'final_code': 200, 'response_latency_ms': 120})
    email_owner.public_domains = ['public.example']
    payload = json.dumps(public_report(email_owner, days=1))
    for private in ('owner@example.com', 'private-smtp-password', 'smtp.example.com',
                    'notify_email', 'notify_telegram'):
        assert private not in payload
