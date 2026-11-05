"""Independent status pages keep selection and bearer access inside one workspace."""
import hashlib
import re

import pytest
from django.contrib.auth import get_user_model
from django.test import Client

from sitewatcher import storage
from sitewatcher.webapp.models import StatusPage, Workspace


@pytest.fixture
def owner(web_database, client):
    user = get_user_model().objects.create_user(username='pages-owner')
    workspace = Workspace.objects.create(user=user, owner_id=731)
    for name in ('one.example', 'two.example'):
        storage.add_domain(731, name)
        storage.save_history(731, name, 'http_basic', 'OK', 'private diagnostic',
                             {'final_code': 200, 'response_latency_ms': 123})
    other = get_user_model().objects.create_user(username='other-pages-owner')
    Workspace.objects.create(user=other, owner_id=973)
    storage.add_domain(973, 'foreign.example')
    client.force_login(user)
    return workspace


def create(client, *, title='Service status', mode='public', domain='one.example'):
    return client.post('/settings/status-pages/new', {
        'title': title, 'access_mode': mode, 'enabled': 'on', 'domain.' + domain: 'on',
    }, HTTP_HOST='localhost')


def private_path(response):
    match = re.search(r'http://localhost(/status/([A-Za-z0-9_-]{43})/)', response.content.decode())
    assert match is not None
    return match[1], match[2]


def edit(client, page, **patch):
    values = {'title': page.title or 'Service status', 'access_mode': page.access_mode,
              'enabled': 'on', 'revision': page.updated_at.isoformat(),
              **{'domain.' + name: 'on' for name in page.public_domains}, **patch}
    return client.post(f'/settings/status-pages/{page.pk}', values, HTTP_HOST='localhost')


def test_multiple_public_pages_have_independent_titles_and_domain_selection(owner, client):
    assert create(client, title='Shop availability').status_code == 303
    assert create(client, title='Other services', domain='two.example').status_code == 303
    first, second = StatusPage.objects.filter(workspace=owner)
    guest = Client()
    for page, included, excluded in [(first, 'one.example', 'two.example'),
                                     (second, 'two.example', 'one.example')]:
        response = guest.get(page.public_path, HTTP_HOST='localhost')
        assert response.status_code == 200
        body = response.content.decode()
        assert page.title in body and included in body and excluded not in body
        assert 'private diagnostic' not in body and 'foreign.example' not in body
        assert 'sessionid' not in response.cookies
        assert response['Referrer-Policy'] == 'no-referrer'
    listing = client.get('/settings/status-pages', HTTP_HOST='localhost').content.decode()
    assert 'Shop availability' in listing and 'Other services' in listing


def test_private_page_link_is_recoverable_only_in_owner_settings(owner, client):
    response = create(client, mode='private')
    assert response.status_code == 200
    path, token = private_path(response)
    page = StatusPage.objects.get(workspace=owner)
    assert page.public_token_hash == hashlib.sha256(token.encode()).hexdigest()
    guest = Client()
    assert guest.get(path, HTTP_HOST='localhost').status_code == 200
    for suffix in ('', '/data', '/activity'):
        assert guest.get(page.public_path + suffix, HTTP_HOST='localhost').status_code == 404
    for route in ('/settings/status-pages', f'/settings/status-pages/{page.pk}'):
        assert token in client.get(route, HTTP_HOST='localhost').content.decode()
    assert token not in guest.get(path, HTTP_HOST='localhost').content.decode()
    assert token not in Client().get('/settings/status-pages', HTTP_HOST='localhost').content.decode()
    assert 'data-copy-target' in client.get('/settings/status-pages', HTTP_HOST='localhost').content.decode()


def test_access_changes_revoke_previous_paths_and_rotation_revokes_old_tokens(owner, client):
    create(client)
    page = StatusPage.objects.get(workspace=owner)
    public_path = page.public_path
    response = edit(client, page, access_mode='private')
    path, token = private_path(response)
    page.refresh_from_db()
    assert Client().get(public_path, HTTP_HOST='localhost').status_code == 404
    response = edit(client, page, action='rotate')
    replacement, _ = private_path(response)
    assert replacement != path and Client().get(path, HTTP_HOST='localhost').status_code == 404
    page.refresh_from_db()
    assert edit(client, page, access_mode='public').status_code == 303
    assert Client().get(replacement, HTTP_HOST='localhost').status_code == 404
    assert Client().get(public_path, HTTP_HOST='localhost').status_code == 200
    assert token not in client.get('/settings/status-pages', HTTP_HOST='localhost').content.decode()


def test_foreign_pages_domains_and_invalid_form_fields_are_rejected(owner, client):
    other = Workspace.objects.get(owner_id=973)
    foreign = StatusPage.objects.create(workspace=other, title='Hidden page',
        public_slug='hidden-foreign-page', public_domains=['foreign.example'])
    assert client.get(f'/settings/status-pages/{foreign.pk}', HTTP_HOST='localhost').status_code == 404
    assert edit(client, foreign).status_code == 404
    for data in [
        {'title': 'Wrong', 'access_mode': 'public', 'domain.foreign.example': 'on'},
        {'title': 'Wrong', 'access_mode': 'invalid'},
        {'title': 'Wrong', 'access_mode': 'public', 'owner_id': '973'},
    ]:
        assert client.post('/settings/status-pages/new', data, HTTP_HOST='localhost').status_code == 400
    assert not StatusPage.objects.filter(workspace=owner).exists()


def test_native_actions_require_auth_csrf_and_obey_readonly(owner, client, settings):
    assert Client().get('/settings/status-pages', HTTP_HOST='localhost').status_code == 302
    secure = Client(enforce_csrf_checks=True)
    secure.force_login(owner.user)
    assert create(secure).status_code == 403
    settings.SITEWATCHER_READ_ONLY = True
    assert create(client).status_code == 405
    assert client.get('/settings/status-pages', HTTP_HOST='localhost').status_code == 200


def test_stale_edit_cannot_republish_a_page_after_it_became_private(owner, client):
    create(client)
    page = StatusPage.objects.get(workspace=owner)
    assert edit(client, page, access_mode='private').status_code == 200
    assert edit(client, page, access_mode='public').status_code == 409
    assert Client().get(page.public_path, HTTP_HOST='localhost').status_code == 404


def test_deleting_page_revokes_its_link_without_deleting_monitoring(owner, client):
    response = create(client, mode='private')
    path, _ = private_path(response)
    page = StatusPage.objects.get(workspace=owner)
    assert edit(client, page, action='delete').status_code == 303
    assert Client().get(path, HTTP_HOST='localhost').status_code == 404
    assert set(storage.list_domains(731)) == {'one.example', 'two.example'}
    assert storage.latest_check_results(731, 'one.example')['http_basic']['status'] == 'OK'


def test_title_is_escaped_and_does_not_change_the_address(owner, client):
    create(client, title='<script>private-title</script>')
    page = StatusPage.objects.get(workspace=owner)
    path = page.public_path
    body = Client().get(path, HTTP_HOST='localhost').content.decode()
    assert '<script>private-title</script>' not in body and '&lt;script&gt;' in body
    assert edit(client, page, title='New title').status_code == 303
    page.refresh_from_db()
    assert page.public_path == path


def test_disabled_private_page_revokes_link_and_reenable_issues_new_one(owner, client):
    path, _ = private_path(create(client, mode='private'))
    page = StatusPage.objects.get(workspace=owner)
    assert edit(client, page, enabled='').status_code == 303
    page.refresh_from_db()
    assert not page.public_token_hash
    assert Client().get(path, HTTP_HOST='localhost').status_code == 404
    replacement, _ = private_path(edit(client, page))
    assert replacement != path
    assert Client().get(replacement, HTTP_HOST='localhost').status_code == 200
    assert Client().get(path, HTTP_HOST='localhost').status_code == 404


def test_large_domain_selection_and_duplicate_fields(owner, client):
    domains = [f'site-{index}.example' for index in range(50)]
    for name in domains:
        storage.add_domain(owner.owner_id, name)
    fields = {'title': 'Many sites', 'access_mode': 'public', 'enabled': 'on',
              **{'domain.' + name: 'on' for name in domains}}
    assert client.post('/settings/status-pages/new', fields, HTTP_HOST='localhost').status_code == 303
    assert set(StatusPage.objects.get(workspace=owner).public_domains) == set(domains)
    response = client.post('/settings/status-pages/new',
        'title=One&title=Two&access_mode=public', content_type='application/x-www-form-urlencoded',
        HTTP_HOST='localhost')
    assert response.status_code == 400
    assert StatusPage.objects.filter(workspace=owner).count() == 1


def test_migration_preserves_existing_public_and_bearer_addresses(web_database):
    from django.db import connection
    from django.db.migrations.executor import MigrationExecutor
    old_target = [('webapp', '0005_workspace_public_slug')]
    previous_target = [('webapp', '0007_statuspage_private_token_nonce')]
    new_target = [('webapp', '0008_statuspage_public_groups')]
    executor = MigrationExecutor(connection)
    executor.migrate(old_target)
    try:
        apps = executor.loader.project_state(old_target).apps
        user = apps.get_model('auth', 'User').objects.create(username='legacy-status-owner')
        token = 'm' * 43
        workspace = apps.get_model('webapp', 'Workspace').objects.create(
            user_id=user.pk, owner_id=891, public_enabled=True, public_slug='legacy-status',
            public_domains=['legacy.example'], public_token_hash=hashlib.sha256(token.encode()).hexdigest())
        storage.add_domain(891, 'legacy.example')
        previous_executor = MigrationExecutor(connection)
        previous_executor.migrate(previous_target)
        previous_apps = previous_executor.loader.project_state(previous_target).apps
        previous_page = previous_apps.get_model('webapp', 'StatusPage').objects.get(
            workspace_id=workspace.pk)
        assert previous_page.public_domains == ['legacy.example']
        MigrationExecutor(connection).migrate(new_target)
        page = StatusPage.objects.get(workspace_id=workspace.pk)
        assert page.public_groups == []
        assert page.legacy_primary and page.public_enabled
        assert page.public_domains == ['legacy.example']
        assert page.public_slug == 'legacy-status' and page.public_token_hash == workspace.public_token_hash
        for path in ('/legacy-status', '/status/' + token + '/'):
            assert Client().get(path, HTTP_HOST='localhost').status_code == 200
    finally:
        MigrationExecutor(connection).migrate(new_target)


def test_public_address_can_be_edited_and_old_address_stops_working(owner, client):
    create(client)
    page = StatusPage.objects.get(workspace=owner)
    old_path = page.public_path
    response = edit(client, page, public_slug='shop-health')
    assert response.status_code == 303
    page.refresh_from_db()
    assert page.public_path == '/shop-health'
    assert Client().get(old_path, HTTP_HOST='localhost').status_code == 404
    assert Client().get('/shop-health', HTTP_HOST='localhost').status_code == 200
    body = client.get(f'/settings/status-pages/{page.pk}', HTTP_HOST='localhost').content.decode()
    assert 'name="public_slug"' in body and 'value="shop-health"' in body


def test_page_address_rejects_reserved_invalid_and_occupied_paths(owner, client):
    create(client)
    page = StatusPage.objects.get(workspace=owner)
    other = Workspace.objects.get(owner_id=973)
    StatusPage.objects.create(workspace=other, public_slug='occupied-status')
    for slug in ['settings', 'assets', 'status/demo', '../login', 'Bad name', 'occupied-status',
                 other.public_slug, owner.public_slug]:
        assert edit(client, page, public_slug=slug).status_code == 400
    page.refresh_from_db()
    assert page.public_slug != 'occupied-status'


def test_private_page_does_not_change_alias_from_address_field(owner, client):
    create(client, mode='private')
    page = StatusPage.objects.get(workspace=owner)
    before = page.public_slug
    assert edit(client, page, public_slug='ignored-private-alias').status_code == 303
    page.refresh_from_db()
    assert page.public_slug == before
    assert Client().get('/ignored-private-alias', HTTP_HOST='localhost').status_code == 404


def test_legacy_primary_address_can_stay_or_change_and_syncs_workspace(owner, client):
    page = StatusPage.objects.create(workspace=owner, public_slug=owner.public_slug,
        legacy_primary=True, title='Legacy', public_domains=['one.example'])
    assert edit(client, page, public_slug=page.public_slug).status_code == 303
    page.refresh_from_db()
    assert edit(client, page, public_slug='renamed-legacy').status_code == 303
    owner.refresh_from_db()
    assert owner.public_slug == 'renamed-legacy'



def test_legacy_private_link_stays_valid_but_requires_reissue_to_display(owner, client):
    token = 'l' * 43
    page = StatusPage.objects.create(workspace=owner, title='Old private page',
        access_mode='private', public_slug='old-private-page',
        public_token_hash=hashlib.sha256(token.encode()).hexdigest(), public_domains=['one.example'])
    guest = Client()
    assert guest.get('/status/' + token + '/', HTTP_HOST='localhost').status_code == 200
    body = client.get('/settings/status-pages', HTTP_HOST='localhost').content.decode()
    assert token not in body and 'Reissue the private link' in body
    replacement, _ = private_path(edit(client, page, action='rotate'))
    assert guest.get('/status/' + token + '/', HTTP_HOST='localhost').status_code == 404
    assert guest.get(replacement, HTTP_HOST='localhost').status_code == 200
    assert replacement in client.get('/settings/status-pages', HTTP_HOST='localhost').content.decode()


def test_recovered_link_uses_server_secret_and_is_bound_to_its_workspace(owner, client, settings):
    path, token = private_path(create(client, mode='private'))
    page = StatusPage.objects.get(workspace=owner)
    assert page.private_token_nonce and token not in page.private_token_nonce
    assert page.private_path == path
    other = Workspace.objects.get(owner_id=973)
    copied = StatusPage.objects.create(workspace=other, title='Copied private page',
        access_mode='private', public_slug='copied-private-page',
        private_token_nonce=page.private_token_nonce, public_token_hash=page.public_token_hash)
    assert copied.private_path == ''
    settings.SECRET_KEY = 'changed-test-secret'
    assert page.private_path == ''
    body = client.get('/settings/status-pages', HTTP_HOST='localhost').content.decode()
    assert token not in body
