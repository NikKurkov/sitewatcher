import asyncio

import httpx
import pytest

from sitewatcher import storage, web_actions
from sitewatcher.config import AppConfig, DomainConfig, resolve_settings
from sitewatcher.dispatcher import Dispatcher
from sitewatcher.utils import domains


@pytest.mark.parametrize(('raw', 'expected'), [
    ('site.ru', 'https://site.ru/'),
    ('http://SITE.ru', 'http://site.ru/'),
    ('https://site.ru/catalog/', 'https://site.ru/catalog/'),
    ('site.ru/?next=https://other.ru/', 'https://site.ru/?next=https://other.ru/'),
    ('site.ru/Catalog/?page=2', 'https://site.ru/Catalog/?page=2'),
    ('https://пример.рф/Каталог', 'https://xn--e1afmkfd.xn--p1ai/Каталог'),
])
def test_site_address_preserves_protocol_and_path(raw, expected):
    assert domains.normalize_site_url(raw) == expected


@pytest.mark.parametrize('raw', ['ftp://site.ru/catalog/', 'https://u:password@site.ru/',
    'https://site.ru:bad/', 'https://site.ru:0/', 'https://site.ru\\@other.ru/',
    'https://site.ru/\nsecret', 'https://site.ru:99999/', 'javascript:alert(1)'])
def test_invalid_site_address_is_rejected(raw):
    assert domains.normalize_site_url(raw) is None


def test_url_targets_survive_bulk_add_edit_and_config():
    cfg = AppConfig()
    web_actions.add_domains(cfg, 41, {'domain':'http://site.ru/catalog/, other.ru/Shop/'})
    assert storage.list_domains(41) == ['other.ru', 'site.ru']
    assert resolve_settings(cfg, 'site.ru', storage.get_domain_override(41, 'site.ru')).http_url == 'http://site.ru/catalog/'
    context = web_actions.settings_context(cfg, 41, 'site.ru')
    assert context['values']['http_url'] == 'http://site.ru/catalog/'
    web_actions.save_domain(cfg, 41, {'domain':'site.ru', 'http_url':'site.ru/NEW/', 'revision':context['revision']})
    assert storage.get_domain_override(41, 'site.ru')['http_url'] == 'https://site.ru/NEW/'
    with pytest.raises(ValueError):
        resolve_settings(cfg, 'site.ru', {'http_url':'https://other.ru/catalog/'})
    configured = AppConfig(domains=[DomainConfig(name='http://site.ru/catalog/')])
    assert configured.domains[0].name == 'site.ru'
    assert resolve_settings(configured, 'site.ru').http_url == 'http://site.ru/catalog/'


def test_http_checks_use_target_while_host_checks_keep_hostname():
    async def scenario():
        seen = []
        def respond(request):
            seen.append(str(request.url))
            return httpx.Response(200, text='welcome')
        cfg = AppConfig()
        settings = resolve_settings(cfg, 'site.ru', {'http_url':'http://site.ru/catalog/',
            'keywords':['welcome'], 'checks':{'http_basic':True, 'keywords':True, 'deface':True}})
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            dispatcher = Dispatcher(cfg)
            dispatcher._client = client
            checks = dispatcher._build_checks(settings, owner_id=41)
            assert all(check.domain == 'site.ru' for check in checks)
            for check in checks:
                if check.name in {'http_basic', 'keywords', 'deface'}:
                    await check.run()
        assert seen == ['http://site.ru/catalog/'] * 3
    asyncio.run(scenario())


def test_target_change_bypasses_cached_http_result():
    from sitewatcher.config import ChecksModel
    async def scenario():
        seen = []
        def respond(request):
            seen.append(str(request.url))
            return httpx.Response(200, text='welcome')
        cfg = AppConfig()
        cfg.defaults.checks = ChecksModel(**{key: key == 'http_basic' for key in ChecksModel.model_fields})
        cfg.schedules.http_basic.cache_ttl_minutes = 60
        storage.add_domain(41, 'site.ru')
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            dispatcher = Dispatcher(cfg)
            dispatcher._client = client
            first = await dispatcher.run_for(41, 'site.ru', use_cache=True)
            assert not first[0].cached
            outcome = first[0]
            storage.save_history(41, 'site.ru', outcome.check, outcome.status.value,
                                 outcome.message, outcome.metrics)
            cached = await dispatcher.run_for(41, 'site.ru', use_cache=True)
            assert cached[0].cached
            storage.set_domain_override(41, 'site.ru', {'http_url':'http://site.ru/catalog/'})
            changed = await dispatcher.run_for(41, 'site.ru', use_cache=True)
            assert not changed[0].cached
        assert seen == ['https://site.ru/', 'http://site.ru/catalog/']
    asyncio.run(scenario())


def test_csv_preserves_http_target_and_accepts_previous_headers():
    import csv
    import io
    from sitewatcher.utils.domains_csv import export_domains_csv, import_domains_csv, RKN_HEADERS
    web_actions.add_domains(AppConfig(), 41, {'domain':'http://site.ru/catalog/'})
    exported = export_domains_csv(41)
    report = import_domains_csv(42, exported, cfg=AppConfig())
    assert report.added == 1 and not report.errors
    assert storage.get_domain_override(42, 'site.ru')['http_url'] == 'http://site.ru/catalog/'
    stream = io.StringIO()
    writer = csv.DictWriter(stream, fieldnames=RKN_HEADERS, delimiter=';')
    writer.writeheader()
    writer.writerow({'domain':'other.ru/Shop/'})
    report = import_domains_csv(43, stream.getvalue().encode(), cfg=AppConfig())
    assert report.added == 1 and not report.errors
    assert storage.get_domain_override(43, 'other.ru')['http_url'] == 'https://other.ru/Shop/'


def test_owner_can_add_and_edit_address_and_invalid_bulk_is_atomic(web_database, client):
    from django.contrib.auth import get_user_model
    from sitewatcher.webapp.models import Workspace
    user = get_user_model().objects.create_user(username='url-owner')
    Workspace.objects.create(user=user, owner_id=41)
    client.force_login(user)
    response = client.post('/domains/add', {'domain':'http://site.ru/catalog/,other.ru/Shop/'}, HTTP_HOST='localhost')
    assert response.status_code == 303
    edit = client.get('/domains/edit?domain=site.ru', HTTP_HOST='localhost')
    assert b'site.ru/catalog/' in edit.content and b'name="http_scheme"' in edit.content
    revision = edit.context['revision']
    assert client.post('/domains/save', {'domain':'site.ru','http_url':'https://site.ru/NEW/', 'revision':revision}, HTTP_HOST='localhost').status_code == 303
    assert storage.get_domain_override(41, 'site.ru')['http_url'] == 'https://site.ru/NEW/'
    revision = web_actions.settings_context(AppConfig(), 41, 'site.ru')['revision']
    assert client.post('/domains/save', {'domain':'site.ru','http_url':'https://other.ru/private/', 'revision':revision}, HTTP_HOST='localhost').status_code == 400
    assert storage.get_domain_override(41, 'site.ru')['http_url'] == 'https://site.ru/NEW/'
    assert client.post('/domains/add', {'domain':'valid.ru/Shop/,ftp://bad.ru/'}, HTTP_HOST='localhost').status_code == 400
    assert not storage.domain_exists(41, 'valid.ru')


def test_edit_can_rename_host_and_switch_protocol_preserving_history_and_favorite():
    cfg = AppConfig()
    web_actions.add_domains(cfg, 41, {'domain':'http://old.ru/catalog/', 'interval_minutes':'15'})
    storage.add_domain(99, 'old.ru')
    storage.set_domain_favorite(41, 'old.ru', True)
    storage.save_history(41, 'old.ru', 'http_basic', 'OK', 'before rename', {'latency_ms':23})
    context = web_actions.settings_context(cfg, 41, 'old.ru')
    assert context['values']['domain'] == 'old.ru/catalog/'
    assert context['values']['http_scheme'] == 'http'
    saved = web_actions.save_domain(cfg, 41, {**context['values'], 'domain':'new.ru/Shop/',
        'http_scheme':'https', 'original_domain':'old.ru'})
    assert saved == 'new.ru' and not storage.domain_exists(41, 'old.ru')
    assert storage.domain_exists(99, 'old.ru')
    assert storage.get_domain_override(41, 'new.ru')['http_url'] == 'https://new.ru/Shop/'
    assert storage.get_domain_override(41, 'new.ru')['interval_minutes'] == 15
    import sqlite3
    with sqlite3.connect(storage.DEFAULT_DB) as db:
        assert db.execute('SELECT favorite FROM domains WHERE owner_id=41 AND name=?', ('new.ru',)).fetchone()[0] == 1
    assert storage.last_results(41, 'new.ru')[0]['message'] == 'before rename'
    assert Dispatcher(cfg)._maybe_cached_result(41, 'new.ru', 'http_basic', lambda _:60) is None
    assert storage.latest_check_results(41, 'new.ru') == {}
    from sitewatcher.reporting import build_snapshot
    from sitewatcher.scheduler import due_checks
    snapshot = build_snapshot(cfg, 41)['domains'][0]
    assert all(check['missing'] for check in snapshot['checks'])
    assert 'http_basic' in due_checks(cfg, 41, 'new.ru')
    from sitewatcher import check_activity
    assert check_activity.domain_roster(41)[0]['status'] == 'UNKNOWN'
    assert check_activity.published_http(41, ['new.ru'])[1][0]['status'] == 'UNKNOWN'
    storage.add_domain(41, 'taken.ru')
    current = web_actions.settings_context(cfg, 41, 'new.ru')
    with pytest.raises(ValueError, match='already exists'):
        web_actions.save_domain(cfg, 41, {**current['values'], 'domain':'taken.ru',
            'http_scheme':'https', 'original_domain':'new.ru'})
    assert storage.domain_exists(41, 'new.ru')


def test_rename_rolls_back_and_rejects_stale_settings(monkeypatch):
    cfg = AppConfig()
    web_actions.add_domains(cfg, 41, {'domain':'old.ru/catalog/'})
    context = web_actions.settings_context(cfg, 41, 'old.ru')
    form = {**context['values'], 'domain':'new.ru/Shop/', 'original_domain':'old.ru'}
    storage.set_domain_override(41, 'old.ru', {'interval_minutes':20})
    with pytest.raises(ValueError, match='Settings changed'):
        web_actions.save_domain(cfg, 41, form)
    assert not storage.domain_exists(41, 'new.ru')
    form['revision'] = web_actions.settings_context(cfg, 41, 'old.ru')['revision']
    def failed_write(*args):
        raise RuntimeError('synthetic write failure')
    monkeypatch.setattr(storage, '_store_domain_override', failed_write)
    with pytest.raises(RuntimeError):
        web_actions.save_domain(cfg, 41, form)
    assert storage.domain_exists(41, 'old.ru') and not storage.domain_exists(41, 'new.ru')
    assert storage.get_domain_override(41, 'old.ru')['interval_minutes'] == 20


def test_rename_preserves_workspace_selections_and_owner_boundary(web_database, client):
    from django.contrib.auth import get_user_model
    from sitewatcher.webapp.models import Workspace
    user = get_user_model().objects.create_user(username='rename-owner')
    workspace = Workspace.objects.create(user=user, owner_id=41,
        domain_order=['old.ru','other.ru'], public_domains=['old.ru'], public_enabled=True)
    web_actions.add_domains(AppConfig(), 41, {'domain':'http://old.ru/catalog/'})
    storage.add_domain(99, 'private.ru')
    client.force_login(user)
    page = client.get('/domains/edit?domain=old.ru', HTTP_HOST='localhost')
    assert b'name="http_scheme"' in page.content and b'readonly' not in page.content
    form = {**page.context['values'], 'domain':'new.ru/Shop/', 'http_scheme':'https'}
    assert client.post('/domains/save', form, HTTP_HOST='localhost').status_code == 303
    workspace.refresh_from_db()
    assert workspace.domain_order == ['new.ru','other.ru']
    assert workspace.public_domains == ['new.ru'] and workspace.public_enabled
    form = {**web_actions.settings_context(AppConfig(),41,'new.ru')['values'],
            'original_domain':'private.ru','domain':'stolen.ru'}
    assert client.post('/domains/save', form, HTTP_HOST='localhost').status_code == 404
    assert storage.domain_exists(99, 'private.ru') and not storage.domain_exists(41, 'stolen.ru')
