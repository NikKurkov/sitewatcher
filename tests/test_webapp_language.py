"""Panel language is an owner preference, never an implicit browser-language decision."""
import pytest
from django.contrib.auth import get_user_model
from django.test import Client
from django.utils import translation

from sitewatcher import storage


@pytest.fixture
def owner(web_database, client):
    from sitewatcher.webapp.models import Workspace
    user = get_user_model().objects.create_user(username='language-owner')
    workspace = Workspace.objects.create(user=user, owner_id=73)
    storage.ensure_user(73)
    storage.add_domain(73, 'example.com')
    client.force_login(user)
    return workspace


def get(client, path, **kwargs):
    return client.get(path, HTTP_HOST='localhost', **kwargs)


def post(client, fields):
    return client.post('/settings', fields, HTTP_HOST='localhost')


def test_english_default_ignores_browser_language(owner, client):
    assert owner.language == 'en'
    body = get(client, '/settings', HTTP_ACCEPT_LANGUAGE='ru').content.decode()
    assert '<html lang="en"' in body and 'Language' in body
    assert 'English' in body and 'Русский' in body
    assert get(client, '/')['Content-Language'] == 'en'


def test_language_save_translates_panel_and_preserves_other_settings(owner, client):
    storage.set_user_alerts_enabled(73, False)
    storage.set_user_alert_chat_id(73, -100123)
    response = post(client, {'language': 'ru'})
    assert response.status_code == 303
    owner.refresh_from_db()
    assert owner.language == 'ru' and owner.timezone == 'Europe/Moscow'
    assert not storage.is_user_alerts_enabled(73)
    assert storage.get_user_alert_chat_id(73) == -100123
    body = get(client, '/settings?saved=1').content.decode()
    assert '<html lang="ru"' in body and 'Настройки' in body and 'Язык' in body
    overview = get(client, '/').content.decode()
    assert 'Добавить в избранное' in overview and 'Обновить сейчас' in overview
    assert 'auto-refresh-toggle' not in overview
    assert 'Настройки сохранены.' in body
    assert 'Включены' in body and 'Выключены' in body
    body = get(client, '/domains/new').content.decode()
    assert 'Добавить домен' in body and 'Интервал проверки' in body
    assert 'Блокировка домена РКН' in body
    assert 'Default (On)' not in body
    assert 'доменов через запятую' in body and 'data-add-domain' not in body
    storage.save_history(73, 'example.com', 'http_basic', 'CRIT', 'raw probe diagnostic', {})
    body = get(client, '/domains/history?domain=example.com').content.decode()
    assert 'Критическая ошибка' in body and 'Доступность сайта' in body
    assert 'raw probe diagnostic' in body
    assert 'Дата с' in body and 'Дата по' in body and 'Все проверки' in body
    assert 'Все состояния' in body and 'Сбросить фильтры' in body
    assert get(client, '/')['Content-Language'] == 'ru'
    assert post(client, {'language': 'en'}).status_code == 303
    assert 'Settings' in get(client, '/settings').content.decode()


@pytest.mark.parametrize('language', ['', 'de', 'ru-RU', '../ru'])
def test_invalid_language_rejects_entire_form(owner, client, language):
    response = post(client, {'language': language, 'timezone': 'UTC', 'enabled': 'off'})
    assert response.status_code == 400
    owner.refresh_from_db()
    assert owner.language == 'en' and owner.timezone == 'Europe/Moscow'
    assert storage.is_user_alerts_enabled(73)


def test_omitted_language_and_other_owners_do_not_reset_preference(owner, client):
    from sitewatcher.webapp.models import Workspace
    assert post(client, {'language': 'ru'}).status_code == 303
    assert post(client, {'timezone': 'UTC'}).status_code == 303
    owner.refresh_from_db()
    assert owner.language == 'ru'
    other_user = get_user_model().objects.create_user(username='other-language-owner')
    other = Workspace.objects.create(user=other_user, owner_id=74)
    storage.ensure_user(74)
    client.force_login(other_user)
    assert 'Settings' in get(client, '/settings').content.decode()
    assert other.language == 'en'
    assert post(client, {'language': 'en', 'owner_id': '73'}).status_code == 400
    owner.refresh_from_db()
    assert owner.language == 'ru'


def test_login_language_cookie_is_explicit_and_does_not_leak(owner, client):
    assert post(client, {'language': 'ru'}).status_code == 303
    assert client.post('/logout/', HTTP_HOST='localhost').status_code == 302
    assert 'Войти' in get(client, '/login/').content.decode()
    fresh = Client()
    assert 'Sign in' in get(fresh, '/login/', HTTP_ACCEPT_LANGUAGE='ru').content.decode()
    fresh.cookies['django_language'] = 'unsupported'
    assert '<html lang="en"' in get(fresh, '/login/').content.decode()
    assert translation.get_language() == 'en'


def test_language_still_obeys_readonly_and_csrf(owner, client, settings):
    secure = Client(enforce_csrf_checks=True)
    secure.force_login(owner.user)
    assert post(secure, {'language': 'ru'}).status_code == 403
    settings.SITEWATCHER_READ_ONLY = True
    assert post(client, {'language': 'ru'}).status_code == 405
    owner.refresh_from_db()
    assert owner.language == 'en'


def test_public_status_uses_publishers_language_without_sessions(owner, client):
    import hashlib
    token = 'a' * 43
    owner.language = 'ru'
    owner.public_enabled = True
    owner.public_domains = ['example.com']
    owner.public_token_hash = hashlib.sha256(token.encode()).hexdigest()
    owner.save()
    from sitewatcher.webapp.models import StatusPage
    StatusPage.objects.create(workspace=owner, public_enabled=True, public_domains=['example.com'],
        public_slug=owner.public_slug, public_token_hash=owner.public_token_hash)
    guest = Client()
    response = get(guest, '/status/' + token + '/')
    assert response.status_code == 200
    assert '<html lang="ru"' in response.content.decode()
    assert response['Content-Language'] == 'ru'
    assert 'sessionid' not in response.cookies
    assert get(Client(), '/login/')['Content-Language'] == 'en'
    assert translation.get_language() == 'en'


def test_russian_chart_coordinates_keep_svg_decimal_points(owner, client):
    from html.parser import HTMLParser
    owner.language = 'ru'
    owner.save(update_fields=['language'])
    storage.save_history(73, 'example.com', 'http_basic', 'OK', '',
                         {'final_code': 200, 'response_latency_ms': 125})
    class Circles(HTMLParser):
        def __init__(self):
            super().__init__()
            self.coordinates = []
        def handle_starttag(self, tag, attrs):
            if tag == 'circle':
                self.coordinates.append(dict(attrs))
    parsed = Circles()
    parsed.feed(get(client, '/domains/history?domain=example.com').content.decode())
    assert parsed.coordinates
    for point in parsed.coordinates:
        assert 0 <= float(point['cx']) <= 1000
        assert 0 <= float(point['cy']) <= 150
