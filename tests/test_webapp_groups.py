import json

import pytest
from django.contrib.auth import get_user_model
from django.conf import settings

from sitewatcher import storage


@pytest.fixture
def owner(web_database, client):
    from sitewatcher.webapp.models import Workspace
    user = get_user_model().objects.create_user(username='groups-owner')
    workspace = Workspace.objects.create(user=user, owner_id=41)
    storage.ensure_user(41)
    client.force_login(user)
    return workspace


def get(client, path):
    return client.get(path, HTTP_HOST='localhost')


def post(client, data):
    return client.post('/settings/groups', data, HTTP_HOST='localhost')


def test_default_group_and_group_controls(owner, client):
    storage.add_domain(41, 'first.example')
    body = get(client, '/').content.decode()
    assert 'data-domain-group="0"' in body
    assert 'data-group-toggle' in body
    assert '/settings/groups' in body
    assert 'domain_groups.js' in body
    assert 'Expand all' in body and 'Collapse all' in body
    assert 'name="group_id"' in get(client, '/domains/new').content.decode()
    assert get(client, '/settings/groups').status_code == 200


def test_group_crud_and_private_names(owner, client):
    from sitewatcher import domain_groups
    assert post(client, {'operation': 'create', 'name': 'Shops'}).status_code == 303
    group = domain_groups.list_groups(41)[1]
    assert group['name'] == 'Shops'
    assert post(client, {'operation': 'rename', 'group_id': group['id'],
                         'name': 'My shops'}).status_code == 303
    assert 'My shops' in get(client, '/settings/groups').content.decode()
    assert post(client, {'operation': 'delete', 'group_id': group['id'],
                         'confirm': 'on'}).status_code == 303
    assert len(domain_groups.list_groups(41)) == 1


def test_bulk_move_is_atomic_and_owner_isolated(owner, client):
    from sitewatcher import domain_groups
    group = domain_groups.create_group(41, 'Shops')
    storage.add_domain(41, 'first.example')
    storage.add_domain(42, 'other.example')
    request = {'operation': 'move', 'group_id': group,
               'domains': json.dumps(['first.example', 'other.example'])}
    assert post(client, request).status_code == 400
    assert domain_groups.group_for_domain(41, 'first.example') == 0
    request['domains'] = json.dumps(['first.example'])
    assert post(client, request).status_code == 303
    assert domain_groups.group_for_domain(41, 'first.example') == group
    foreign = domain_groups.create_group(42, 'Private group')
    assert post(client, {'operation': 'rename', 'group_id': foreign, 'name': 'Hacked'}).status_code == 400
    assert 'Private group' not in get(client, '/').content.decode()


def test_group_actions_obey_read_only_and_auth(owner, client, monkeypatch):
    monkeypatch.setattr(settings, 'SITEWATCHER_READ_ONLY', True)
    assert post(client, {'operation': 'create', 'name': 'Shops'}).status_code == 405
    assert 'data-bulk-move' not in get(client, '/').content.decode()
    client.logout()
    assert get(client, '/settings/groups').status_code == 302


def test_search_opens_matching_groups_and_keeps_overall_counts(owner, client):
    from sitewatcher import domain_groups
    group = domain_groups.create_group(41, 'Shops')
    for name in ('first.example', 'second.example'):
        storage.add_domain(41, name)
    domain_groups.move_domains(41, ['second.example'], group)
    body = get(client, '/?q=second').content.decode()
    assert 'data-group-filtered="true"' in body
    assert f'data-domain-group="{group}"' in body
    assert 'data-domain-key="second.example"' in body
    assert 'data-domain-key="first.example"' not in body
    assert 'data-group-domain-count="1"' in body


def test_reorder_rejects_cross_group_sequence(owner, client):
    from sitewatcher import domain_groups
    group = domain_groups.create_group(41, 'Shops')
    for name in ('a.example', 'b.example', 'c.example'):
        storage.add_domain(41, name)
    domain_groups.move_domains(41, ['b.example'], group)
    response = client.post('/domains/reorder', {'order': json.dumps(
        ['b.example', 'a.example', 'c.example'])}, HTTP_HOST='localhost')
    assert response.status_code == 400


def test_group_names_are_not_published(owner, client):
    from sitewatcher import domain_groups
    from sitewatcher.webapp.models import StatusPage
    group = domain_groups.create_group(41, 'private-group-sentinel')
    storage.add_domain(41, 'public.example')
    domain_groups.move_domains(41, ['public.example'], group)
    page = StatusPage.objects.create(workspace=owner, title='Published', access_mode='public',
                                    public_slug='group-privacy', public_domains=['public.example'])
    client.logout()
    for path in (page.public_path, page.public_path + '/data'):
        response = get(client, path)
        assert response.status_code == 200
        body = response.content.decode()
        assert 'private-group-sentinel' not in body
        assert 'group_id' not in body
        assert 'data-domain-group' not in body


def test_group_mutations_require_csrf(owner):
    from django.test import Client
    guarded = Client(enforce_csrf_checks=True)
    guarded.force_login(owner.user)
    response = post(guarded, {'operation': 'create', 'name': 'CSRF attempt'})
    assert response.status_code == 403


def test_empty_group_has_collapsible_content(owner, client):
    from sitewatcher import domain_groups
    storage.add_domain(41, 'first.example')
    group = domain_groups.create_group(41, 'Empty')
    body = get(client, '/').content.decode()
    assert f'class="domain-group-empty" data-group-id="{group}"' in body
