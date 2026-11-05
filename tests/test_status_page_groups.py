"""Status-page group selection publishes only current authorized members."""
import hashlib
import json

import pytest
from django.contrib.auth import get_user_model
from django.test import Client

from sitewatcher import check_activity, domain_groups, storage
from sitewatcher.webapp.models import StatusPage, Workspace


@pytest.fixture
def owner(web_database, client):
    user = get_user_model().objects.create_user(username='group-publisher')
    workspace = Workspace.objects.create(user=user, owner_id=731)
    other = get_user_model().objects.create_user(username='other-group-publisher')
    Workspace.objects.create(user=other, owner_id=973)
    for identity, name in [(731, 'one.example'), (731, 'two.example'),
                           (731, 'explicit.example'), (973, 'foreign.example')]:
        storage.add_domain(identity, name)
        storage.save_history(identity, name, 'http_basic', 'OK', 'private diagnostic',
                             {'final_code': 200})
        event = check_activity.start(identity, name, 'http_basic')
        check_activity.finish(event, 'OK', 10)
    client.force_login(user)
    return workspace


def save(client, page=None, **fields):
    data = {'title': 'Published services', 'access_mode': 'public', 'enabled': 'on', **fields}
    if page:
        data.setdefault('revision', page.updated_at.isoformat())
    return client.post(f'/settings/status-pages/{page.pk if page else "new"}', data,
                       HTTP_HOST='localhost')


def get(path):
    return Client().get(path, HTTP_HOST='localhost')


def test_editor_persists_groups_and_preserves_selection_on_errors(owner, client):
    gid = domain_groups.create_group(731, 'Published group')
    assert save(client, **{f'group.{gid}': 'on'}).status_code == 303
    page = StatusPage.objects.get(workspace=owner)
    assert page.public_groups == [gid] and page.public_domains == []
    response = client.get(f'/settings/status-pages/{page.pk}', HTTP_HOST='localhost')
    assert f'name="group.{gid}" checked' in response.content.decode()
    response = save(client, page, title='', **{f'group.{gid}': 'on'})
    assert response.status_code == 400
    assert f'name="group.{gid}" checked' in response.content.decode()
    assert save(client, page, **{'group.0': 'on'}).status_code == 303
    assert save(client, page, **{f'group.{gid}': 'on'}).status_code == 409
    page.refresh_from_db()
    assert page.public_groups == [0]


def test_forged_foreign_deleted_and_invalid_group_choices_rejected(owner, client):
    foreign = domain_groups.create_group(973, 'Private foreign group')
    deleted = domain_groups.create_group(731, 'Deleted group')
    domain_groups.delete_group(731, deleted)
    for key, value in [(str(foreign), 'on'), (str(deleted), 'on'), ('-1', 'on'),
                       ('invalid', 'on'), ('00', 'on'), ('0', 'bad')]:
        assert save(client, **{'group.' + key: value}).status_code == 400
    assert not StatusPage.objects.filter(workspace=owner).exists()
    body = client.get('/settings/status-pages/new', HTTP_HOST='localhost').content.decode()
    assert 'Private foreign group' not in body


def test_selected_groups_use_current_members_in_data_and_activity_without_duplicates(owner, client):
    gid = domain_groups.create_group(731, 'Publish me')
    domain_groups.move_domains(731, ['one.example'], gid)
    assert save(client, **{f'group.{gid}': 'on', 'domain.one.example': 'on',
                           'domain.explicit.example': 'on'}).status_code == 303
    page = StatusPage.objects.get(workspace=owner)

    def names(suffix):
        payload = get(page.public_path + suffix).json()
        return [row['name' if suffix == '/activity' else 'domain'] for row in payload['domains']], payload

    included, payload = names('/data')
    assert included == ['explicit.example', 'one.example']
    assert len(included) == len(set(included))
    assert 'group' not in json.dumps(payload)
    domain_groups.move_domains(731, ['two.example'], gid)
    included, _ = names('/data')
    assert included == ['explicit.example', 'one.example', 'two.example']
    activity, payload = names('/activity')
    assert set(activity) == set(included)
    assert {event['domain'] for event in payload['events']} == set(included)
    domain_groups.move_domains(731, ['one.example', 'two.example'], 0)
    assert names('/data')[0] == ['explicit.example', 'one.example']
    assert set(names('/activity')[0]) == {'explicit.example', 'one.example'}


def test_public_html_names_only_selected_groups_and_json_stays_flat(owner, client):
    first = domain_groups.create_group(731, 'Published A')
    second = domain_groups.create_group(731, 'Published B')
    hidden = domain_groups.create_group(731, 'Secret private group')
    domain_groups.move_domains(731, ['one.example'], first)
    domain_groups.move_domains(731, ['two.example'], second)
    domain_groups.move_domains(731, ['explicit.example'], hidden)
    save(client, **{f'group.{first}': 'on', f'group.{second}': 'on',
                    'domain.explicit.example': 'on'})
    page = StatusPage.objects.get(workspace=owner)
    body = get(page.public_path).content.decode()
    assert 'Published A' in body and 'Published B' in body
    assert 'Other sites' in body and 'Secret private group' not in body
    assert 'data-group-id' not in body and 'group_id' not in body
    payload = get(page.public_path + '/data').json()
    assert set(payload) == {'days', 'timezone', 'totals', 'domains'}
    encoded = json.dumps(payload)
    for forbidden in ('Published A', 'Published B', 'Secret private group', 'group_id', 'groups'):
        assert forbidden not in encoded


def test_one_group_has_no_extra_heading_and_deleted_group_safe(owner, client):
    gid = domain_groups.create_group(731, 'Single published group')
    domain_groups.move_domains(731, ['one.example'], gid)
    save(client, **{f'group.{gid}': 'on'})
    page = StatusPage.objects.get(workspace=owner)
    body = get(page.public_path).content.decode()
    assert 'one.example' in body and 'Single published group' not in body
    domain_groups.delete_group(731, gid)
    assert get(page.public_path + '/data').json()['domains'] == []
    assert get(page.public_path + '/activity').json()['domains'] == []


def test_main_group_membership_dynamic_and_old_pages_remain_explicit(owner, client):
    old = StatusPage.objects.create(workspace=owner, title='Old', public_slug='old-page',
                                    public_domains=['one.example'])
    save(client, **{'group.0': 'on'})
    page = StatusPage.objects.exclude(pk=old.pk).get(workspace=owner)
    assert len(get(page.public_path + '/data').json()['domains']) == 3
    assert [row['domain'] for row in get(old.public_path + '/data').json()['domains']] == ['one.example']
    assert old.public_groups == []


def test_bearer_and_legacy_paths_share_group_scope_and_legacy_sync_preserves_groups(owner, client):
    gid = domain_groups.create_group(731, 'Private selected')
    domain_groups.move_domains(731, ['one.example'], gid)
    token = 'x' * 43
    page = StatusPage.objects.create(workspace=owner, public_slug='legacy-group-page',
        legacy_primary=True, access_mode='private', public_groups=[gid],
        public_token_hash=hashlib.sha256(token.encode()).hexdigest())
    path = '/status/' + token + '/'
    assert [row['domain'] for row in get(path + 'data').json()['domains']] == ['one.example']
    assert [row['name'] for row in get(path + 'activity').json()['domains']] == ['one.example']
    assert 'one.example' in get(path).content.decode()
    from sitewatcher.webapp.public import _sync_legacy_page
    owner.public_enabled = True
    owner.public_token_hash = page.public_token_hash
    owner.public_domains = ['explicit.example']
    owner.save()
    _sync_legacy_page(owner)
    page.refresh_from_db()
    assert page.public_groups == [gid]
    assert {row['domain'] for row in get(path + 'data').json()['domains']} == {'one.example', 'explicit.example'}


def test_status_page_group_choices_enforce_csrf_and_readonly(owner, client, settings):
    secure = Client(enforce_csrf_checks=True)
    secure.force_login(owner.user)
    assert save(secure, **{'group.0': 'on'}).status_code == 403
    settings.SITEWATCHER_READ_ONLY = True
    assert save(client, **{'group.0': 'on'}).status_code == 405
    assert not StatusPage.objects.filter(workspace=owner).exists()


def test_group_removed_while_editor_is_saving_is_rejected(owner, client, monkeypatch):
    from sitewatcher.webapp import status_pages
    gid = domain_groups.create_group(731, 'Removed while saving')
    original = status_pages.domain_groups.list_groups

    def deleted_after_lookup(owner_id):
        choices = original(owner_id)
        domain_groups.delete_group(owner_id, gid)
        return choices

    monkeypatch.setattr(status_pages.domain_groups, 'list_groups', deleted_after_lookup)
    assert save(client, **{f'group.{gid}': 'on'}).status_code == 400
    assert not StatusPage.objects.filter(workspace=owner).exists()


def test_persisted_foreign_group_never_expands_public_scope(owner, client):
    foreign = domain_groups.create_group(973, 'Foreign secret name')
    domain_groups.move_domains(973, ['foreign.example'], foreign)
    page = StatusPage.objects.create(workspace=owner, public_slug='forged-groups-page',
        public_groups=[foreign], public_domains=['one.example', 'foreign.example'])
    assert [row['domain'] for row in get(page.public_path + '/data').json()['domains']] == ['one.example']
    payload = get(page.public_path + '/activity').json()
    assert [row['name'] for row in payload['domains']] == ['one.example']
    assert all(event['domain'] == 'one.example' for event in payload['events'])
    body = get(page.public_path).content.decode()
    assert 'Foreign secret name' not in body and 'foreign.example' not in body


def test_listing_counts_effective_members_from_groups(owner, client):
    gid = domain_groups.create_group(731, 'Published group')
    domain_groups.move_domains(731, ['one.example', 'two.example'], gid)
    assert save(client, **{f'group.{gid}': 'on'}).status_code == 303
    response = client.get('/settings/status-pages', HTTP_HOST='localhost')
    assert '2 domains' in response.content.decode()
    assert '0 domains' not in response.content.decode()
