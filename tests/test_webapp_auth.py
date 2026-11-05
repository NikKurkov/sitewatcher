"""Owner authentication never derives authority from caller-supplied owner IDs."""
from datetime import timedelta
import secrets

import pytest
from django.contrib.auth import get_user_model
from django.test import Client, RequestFactory
from django.utils import timezone


@pytest.fixture
def password():
    return secrets.token_urlsafe(32)


@pytest.fixture
def owner(web_database, password):
    from sitewatcher.webapp.models import Workspace
    user = get_user_model().objects.create_user(username='local-owner', password=password)
    return Workspace.objects.create(user=user, owner_id=4821)


def login(client, password, **headers):
    return client.post('/login/', {'username': 'local-owner', 'password': password},
                       HTTP_HOST='localhost', **headers)


def test_anonymous_owner_pages_and_apis_are_protected(web_database, client):
    response = client.get('/', HTTP_HOST='localhost')
    assert response.status_code == 302
    assert response.url.startswith('/login/?next=')
    response = client.get('/api/status?owner=4821', HTTP_HOST='localhost')
    assert response.status_code == 401
    assert response.json() == {'error': 'Authentication required'}
    assert client.get('/logout/', HTTP_HOST='localhost').status_code == 405


def test_login_rotates_session_and_ignores_claimed_owner(owner, client, password):
    session = client.session
    session['before_login'] = True
    session.save()
    previous = session.session_key
    response = login(client, password)
    assert response.status_code == 302
    assert client.session.session_key != previous
    assert client.session.get_expiry_age() <= 12 * 60 * 60
    response = client.get('/api/status?owner=99999', HTTP_HOST='localhost')
    assert response.status_code == 200
    assert response.json()['owner_id'] == owner.owner_id


def test_csrf_required_for_login_logout_and_password(owner, password):
    client = Client(enforce_csrf_checks=True)
    assert login(client, password).status_code == 403
    client.force_login(owner.user)
    assert client.post('/logout/', HTTP_HOST='localhost').status_code == 403
    assert client.post('/password/', HTTP_HOST='localhost').status_code == 403
    response = client.get('/password/', HTTP_HOST='localhost')
    assert b'csrfmiddlewaretoken' in response.content
    token = client.cookies['csrftoken'].value
    assert client.post('/logout/', {'csrfmiddlewaretoken': token},
                       HTTP_HOST='localhost').status_code == 302


def test_password_change_invalidates_other_sessions(owner, password):
    first, second = Client(), Client()
    assert login(first, password).status_code == 302
    assert login(second, password).status_code == 302
    replacement = secrets.token_urlsafe(32)
    response = first.post('/password/', {'old_password': password,
        'new_password1': replacement, 'new_password2': replacement}, HTTP_HOST='localhost')
    assert response.status_code == 302
    assert first.get('/api/status', HTTP_HOST='localhost').status_code == 200
    assert second.get('/api/status', HTTP_HOST='localhost').status_code == 401


def test_unmapped_account_cannot_claim_legacy_owner(web_database, client, password):
    from django.core.exceptions import PermissionDenied
    from sitewatcher import storage
    from sitewatcher.webapp.accounts import require_workspace
    storage.ensure_user(4821)
    user = get_user_model().objects.create_user(username='unmapped', password=password)
    client.force_login(user)
    assert client.get('/?owner=4821', HTTP_HOST='localhost').status_code == 403
    assert client.get('/api/status?owner=4821', HTTP_HOST='localhost').status_code == 403
    request = RequestFactory().get('/?owner=4821')
    request.user = user
    with pytest.raises(PermissionDenied):
        require_workspace(request)


def test_failed_login_locks_pair_persistently_ignoring_proxy_headers(owner, password):
    from axes.models import AccessAttempt
    client = Client()
    wrong = secrets.token_urlsafe(32)
    for i in range(5):
        response = login(client, wrong, HTTP_X_FORWARDED_FOR=f'198.51.100.{i + 1}')
        assert response.status_code in (200, 429)
    attempt = AccessAttempt.objects.get(username=owner.user.username)
    assert attempt.failures_since_start == 5
    assert attempt.ip_address == '127.0.0.1'
    assert password not in str(attempt.__dict__)
    assert wrong not in str(attempt.__dict__)
    assert login(Client(), password, HTTP_X_FORWARDED_FOR='203.0.113.1').status_code == 429
    assert login(Client(), password, REMOTE_ADDR='192.0.2.2').status_code == 302
    # A correct attempt at a different address must not reset the locked pair.
    assert login(Client(), password).status_code == 429
    AccessAttempt.objects.filter(pk=attempt.pk).update(
        attempt_time=timezone.now() - timedelta(minutes=16))
    assert login(Client(), password).status_code == 302


def test_generic_authentication_errors_for_unknown_inactive_and_unmapped(owner, password):
    client = Client()
    wrong = secrets.token_urlsafe(32)
    normal = login(client, wrong).content
    unknown = client.post('/login/', {'username': 'unknown', 'password': wrong},
                          HTTP_HOST='localhost').content
    assert b'Unable to sign in with these credentials.' in normal
    assert b'Unable to sign in with these credentials.' in unknown
    owner.user.is_active = False
    owner.user.save()
    assert b'Unable to sign in with these credentials.' in login(client, password).content


def prompts(monkeypatch, password, username='local-owner'):
    from sitewatcher.webapp import accounts
    monkeypatch.setattr('builtins.input', lambda _: username)
    responses = iter([password, password])
    monkeypatch.setattr(accounts.getpass, 'getpass', lambda _: next(responses))


def test_setup_fresh_identity_never_adopts_existing_telegram_data(web_database, monkeypatch,
                                                                 password, capsys):
    from sitewatcher import storage
    from sitewatcher.webapp.accounts import setup_owner
    from sitewatcher.webapp.models import Workspace
    storage.ensure_user(4821)
    storage.add_domain(4821, 'private.example')
    prompts(monkeypatch, password)
    setup_owner()
    workspace = Workspace.objects.get()
    assert workspace.owner_id > 0 and workspace.owner_id != 4821
    assert workspace.owner_id in storage.list_users()
    assert storage.list_domains(workspace.owner_id) == []
    assert workspace.user.check_password(password)
    assert workspace.timezone == 'Europe/Moscow'
    assert password not in capsys.readouterr().out
    with pytest.raises(ValueError, match='already configured'):
        setup_owner(owner_id=4821)


def test_setup_explicit_binding_and_rejects_another_account(web_database, monkeypatch, password):
    from sitewatcher import storage
    from sitewatcher.webapp.accounts import setup_owner
    from sitewatcher.webapp.models import Workspace
    storage.ensure_user(4821)
    prompts(monkeypatch, password)
    setup_owner(owner_id=4821)
    workspace = Workspace.objects.get()
    assert workspace.owner_id == 4821
    with pytest.raises(ValueError):
        setup_owner(owner_id=4822)
    assert Workspace.objects.get().owner_id == 4821


@pytest.mark.parametrize('owner_id', [0, -1, 2**63])
def test_setup_rejects_invalid_owner_before_prompt(web_database, owner_id):
    from sitewatcher.webapp.accounts import setup_owner
    with pytest.raises(ValueError, match='positive'):
        setup_owner(owner_id=owner_id)


def test_setup_does_not_take_over_existing_account(web_database, monkeypatch, password):
    from sitewatcher.webapp.accounts import setup_owner
    get_user_model().objects.create_user(username='local-owner', password=secrets.token_urlsafe(32))
    prompts(monkeypatch, password)
    with pytest.raises(ValueError, match='already exists'):
        setup_owner(owner_id=4821)


def test_setup_validates_password_and_confirmation_before_writing(web_database, monkeypatch):
    from sitewatcher.webapp.accounts import setup_owner
    from sitewatcher.webapp.models import Workspace
    prompts(monkeypatch, str(secrets.randbelow(10)))
    with pytest.raises(ValueError, match='password'):
        setup_owner()
    assert not Workspace.objects.exists()
    assert not get_user_model().objects.exists()


def test_local_reset_clears_lockout_and_invalidates_sessions_without_browser(owner, password,
                                                                           monkeypatch, capsys):
    from axes.models import AccessAttempt
    from sitewatcher import storage
    from sitewatcher.webapp.accounts import reset_password
    storage.ensure_user(owner.owner_id)
    storage.add_domain(owner.owner_id, 'private.example')
    client = Client()
    login(client, password)
    for _ in range(5):
        login(Client(), secrets.token_urlsafe(32))
    assert AccessAttempt.objects.exists()
    replacement = secrets.token_urlsafe(32)
    prompts(monkeypatch, replacement)
    reset_password()
    assert not AccessAttempt.objects.filter(username=owner.user.username).exists()
    assert client.get('/api/status', HTTP_HOST='localhost').status_code == 401
    assert login(Client(), replacement).status_code == 302
    assert storage.list_domains(owner.owner_id) == ['private.example']
    assert replacement not in capsys.readouterr().out


def test_cli_setup_and_password_use_configured_framework(web_database, monkeypatch):
    import sys
    from sitewatcher import main
    from sitewatcher.webapp import accounts
    calls = []
    monkeypatch.setattr(accounts, 'setup_owner', lambda **kwargs: calls.append(('setup', kwargs)))
    monkeypatch.setattr(accounts, 'reset_password', lambda: calls.append(('password', {})))
    for arguments in (['setup', '--owner', '4821'], ['password']):
        monkeypatch.setattr(sys, 'argv', ['sitewatcher', *arguments])
        main.main()
    assert calls == [('setup', {'owner_id': 4821}), ('password', {})]


def test_unmapped_user_cannot_sign_in(web_database, password):
    get_user_model().objects.create_user(username='local-owner', password=password)
    client = Client()
    response = login(client, password)
    assert response.status_code == 200
    assert b'Unable to sign in with these credentials.' in response.content
    assert client.get('/api/status', HTTP_HOST='localhost').status_code == 401


def test_csrf_login_rotates_token_and_rejects_external_next(owner, password):
    client = Client(enforce_csrf_checks=True)
    response = client.get('/login/?next=https://attacker.example/', HTTP_HOST='localhost')
    assert response.status_code == 200
    previous_token = client.cookies['csrftoken'].value
    response = client.post('/login/', {'username': owner.user.username, 'password': password,
        'csrfmiddlewaretoken': previous_token, 'next': 'https://attacker.example/'},
        HTTP_HOST='localhost')
    assert response.status_code == 302 and response.url == '/'
    assert client.cookies['csrftoken'].value != previous_token


def test_setup_refuses_password_entry_without_hidden_terminal(web_database, monkeypatch, password):
    import warnings
    from sitewatcher.webapp import accounts
    from sitewatcher.webapp.models import Workspace
    prompts(monkeypatch, password)

    def unavailable_terminal(_):
        warnings.warn('Terminal does not support hidden entry', accounts.getpass.GetPassWarning,
                      stacklevel=2)
        raise AssertionError('Must stop before fallback can echo the password')

    monkeypatch.setattr(accounts.getpass, 'getpass', unavailable_terminal)
    with pytest.raises(ValueError, match='terminal'):
        accounts.setup_owner()
    assert not Workspace.objects.exists()


def test_setup_rejects_mismatched_passwords_before_writing(web_database, monkeypatch, password):
    from sitewatcher.webapp import accounts
    from sitewatcher.webapp.models import Workspace
    prompts(monkeypatch, password)
    responses = iter([password, secrets.token_urlsafe(32)])
    monkeypatch.setattr(accounts.getpass, 'getpass', lambda _: next(responses))
    with pytest.raises(ValueError, match='confirmation'):
        accounts.setup_owner()
    assert not Workspace.objects.exists()


def test_setup_and_password_cli_work_on_fresh_database_without_telegram(tmp_path):
    import os
    import subprocess
    import sys

    program = '''
import builtins
import getpass
import secrets
import sys
from sitewatcher import main, storage
from sitewatcher.webapp.bootstrap import configure_web
from sitewatcher.config import AppConfig
builtins.input = lambda _: 'local-owner'
first = secrets.token_urlsafe(32)
getpass.getpass = lambda _: first
sys.argv = ['sitewatcher', 'setup']
main.main()
from sitewatcher.webapp.models import Workspace
workspace = Workspace.objects.select_related('user').get()
assert workspace.user.check_password(first)
assert workspace.owner_id in storage.list_users()
second = secrets.token_urlsafe(32)
getpass.getpass = lambda _: second
sys.argv = ['sitewatcher', 'password']
main.main()
workspace.user.refresh_from_db()
assert workspace.user.check_password(second)
assert not workspace.user.check_password(first)
'''
    environment = {**os.environ, 'DATABASE_PATH': str(tmp_path / 'fresh.sqlite3')}
    environment.pop('TELEGRAM_TOKEN', None)
    result = subprocess.run([sys.executable, '-c', program], env=environment,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        'Owner configured. Sign in at /login/.',
        'Password updated and login lockout cleared. Sign in again.',
    ]


def test_cli_auth_database_failure_is_generic(web_database, monkeypatch):
    import sys
    from django.db import DatabaseError
    from sitewatcher import main
    from sitewatcher.webapp import accounts

    def fail(**kwargs):
        raise DatabaseError('internal database details')

    monkeypatch.setattr(accounts, 'setup_owner', fail)
    monkeypatch.setattr(sys, 'argv', ['sitewatcher', 'setup'])
    with pytest.raises(SystemExit, match='Cannot update local account') as error:
        main.main()
    assert 'internal database details' not in str(error.value)


@pytest.mark.parametrize('trust_proxy', [False, True])
def test_production_uvicorn_boundary_preserves_peer_and_login_limit(
        owner, password, monkeypatch, trust_proxy):
    """Changing the production adapter's proxy default must not let XFF evade Axes."""
    import asyncio
    import io

    import httpx
    import uvicorn
    from axes.models import AccessAttempt
    from django.core.handlers.asgi import ASGIRequest
    from sitewatcher.config import AppConfig
    from sitewatcher.webapp import bootstrap

    monkeypatch.setenv('SITEWATCHER_WEB_TRUST_PROXY', '1' if trust_proxy else '0')
    observed = []

    def serve(application, **options):
        async def boundary(scope, receive, send):
            request = ASGIRequest(scope, io.BytesIO())
            observed.append((request.META['REMOTE_ADDR'], request.is_secure()))
            await application(scope, receive, send)

        config = uvicorn.Config(boundary, **options)
        config.load()

        async def exercise():
            transport = httpx.ASGITransport(app=config.loaded_app, client=('127.0.0.1', 42123))
            async with httpx.AsyncClient(transport=transport, base_url='http://localhost') as browser:
                for attempt in range(6):
                    headers = {'x-forwarded-for': f'198.51.100.{attempt + 1}',
                               'x-forwarded-proto': 'https', 'referer': 'https://localhost/'}
                    assert (await browser.get('/login/', headers=headers)).status_code == 200
                    result = await browser.post('/login/', headers=headers, data={
                        'username': owner.user.username,
                        'password': password if attempt == 5 else 'wrong-synthetic-password',
                        'csrfmiddlewaretoken': browser.cookies['csrftoken'],
                    })
                    if attempt < 4:
                        assert result.status_code == 200
                    else:
                        assert result.status_code == 429
        asyncio.run(exercise())

    monkeypatch.setattr(uvicorn, 'run', serve)
    bootstrap.run_asgi(AppConfig(), port=0)
    assert set(observed) == {('127.0.0.1', trust_proxy)}
    assert set(AccessAttempt.objects.values_list('ip_address', flat=True)) == {'127.0.0.1'}


def test_remember_me_sets_month_cookie_and_survives_browser_reopen(owner, password):
    client = Client()
    response = client.post('/login/', {'username': owner.user.username, 'password': password,
                           'remember_me': 'on'}, HTTP_HOST='localhost')
    assert response.status_code == 302
    assert client.session.get_expiry_age() == 30 * 24 * 60 * 60
    cookie = response.cookies['sessionid']
    assert cookie['max-age'] == 30 * 24 * 60 * 60
    assert cookie['expires'] and cookie['httponly'] and cookie['samesite'] == 'Lax'
    reopened = Client()
    reopened.cookies['sessionid'] = cookie.value
    assert reopened.get('/api/status', HTTP_HOST='localhost').status_code == 200
    assert reopened.post('/logout/', HTTP_HOST='localhost').status_code == 302
    assert client.get('/api/status', HTTP_HOST='localhost').status_code == 401


def test_login_without_remember_me_keeps_twelve_hour_cookie(owner, client, password):
    response = login(client, password)
    assert response.status_code == 302
    assert response.cookies['sessionid']['max-age'] == 12 * 60 * 60
    form = Client().get('/login/', HTTP_HOST='localhost').context['form']
    assert form.fields['remember_me'].required is False
    assert not form['remember_me'].value()


def test_remembered_session_expires_and_password_change_revokes_it(owner, password):
    from django.contrib.sessions.models import Session
    remembered = Client()
    response = remembered.post('/login/', {'username': owner.user.username, 'password': password,
                               'remember_me': 'on'}, HTTP_HOST='localhost')
    assert response.status_code == 302
    key = remembered.session.session_key
    Session.objects.filter(session_key=key).update(expire_date=timezone.now()-timedelta(seconds=1))
    assert remembered.get('/api/status', HTTP_HOST='localhost').status_code == 401
    assert remembered.post('/login/', {'username': owner.user.username, 'password': password,
                           'remember_me': 'on'}, HTTP_HOST='localhost').status_code == 302
    other = Client()
    assert login(other, password).status_code == 302
    replacement = secrets.token_urlsafe(32)
    assert other.post('/password/', {'old_password': password,
        'new_password1': replacement, 'new_password2': replacement}, HTTP_HOST='localhost').status_code == 302
    assert remembered.get('/api/status', HTTP_HOST='localhost').status_code == 401


def test_failed_remembered_login_does_not_authenticate_and_https_cookie_stays_secure(
        owner, password, settings):
    client = Client()
    response = client.post('/login/', {'username': owner.user.username, 'password': 'invalid',
                           'remember_me': 'on'}, HTTP_HOST='localhost')
    assert response.status_code == 200
    assert 'sessionid' not in response.cookies
    assert client.get('/api/status', HTTP_HOST='localhost').status_code == 401
    settings.SESSION_COOKIE_SECURE = True
    response = client.post('/login/', {'username': owner.user.username, 'password': password,
                           'remember_me': 'on'}, HTTP_HOST='localhost')
    assert response.status_code == 302
    assert response.cookies['sessionid']['secure']
