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
    assert 'data-domain-group="0"' not in body
    assert 'data-group-toggle' not in body
    assert 'data-domain-move-dialog' not in body
    assert '/settings/groups' not in body
    assert '/settings/groups' in get(client, '/settings').content.decode()
    assert 'domain_groups.js' in body
    assert 'data-groups-expand' not in body and 'data-groups-collapse' not in body
    assert 'data-select-visible' not in body
    assert 'data-domain-select' not in body
    assert 'data-bulk-move' not in body
    assert 'name="group_id"' in get(client, '/domains/new').content.decode()
    assert get(client, '/settings/groups').status_code == 200


def test_second_group_enables_headers_even_when_search_matches_only_one(owner, client):
    from sitewatcher import domain_groups
    storage.add_domain(41, 'first.example')
    domain_groups.create_group(41, 'Empty')
    body = get(client, '/?q=first').content.decode()
    assert 'data-domain-group="0"' in body
    assert 'data-group-toggle' in body
    assert 'data-groups-expand' not in body


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


def test_domain_form_offers_transactional_new_group(owner, client):
    body = get(client, '/domains/new').content.decode()
    assert '<option value="new"' in body
    assert 'name="new_group_name"' in body
    assert 'data-new-group-field' in body
    assert 'group_form.js' in body


def test_inline_group_creation_through_add_and_edit_forms(owner, client):
    from sitewatcher import domain_groups
    from sitewatcher.config import AppConfig
    from sitewatcher.web_actions import settings_context
    form = settings_context(AppConfig(), 41)['values']
    form.update(domain='new.example', group_id='new', new_group_name='Inline add')
    response = client.post('/domains/add', form, HTTP_HOST='localhost')
    assert response.status_code == 303
    first = domain_groups.group_for_domain(41, 'new.example')
    assert first != 0
    form = settings_context(AppConfig(), 41, 'new.example')['values']
    form.update(group_id='new', new_group_name='Inline edit')
    response = client.post('/domains/save', form, HTTP_HOST='localhost')
    assert response.status_code == 303
    assert domain_groups.group_for_domain(41, 'new.example') not in {0, first}


def test_drag_move_returns_confirmation_without_redirect(owner, client):
    from sitewatcher import domain_groups
    storage.add_domain(41, 'move.example')
    group = domain_groups.create_group(41, 'Destination')
    response = client.post('/settings/groups', {'operation': 'move', 'group_id': group,
                          'domains': json.dumps(['move.example'])}, HTTP_HOST='localhost',
                          HTTP_ACCEPT='application/json')
    assert response.status_code == 200
    assert response.json()['saved'] is True
    assert domain_groups.group_for_domain(41, 'move.example') == group


@pytest.mark.parametrize('status,paused,critical', [
    ('CRIT', False, True), ('WARN', False, False), ('UNKNOWN', False, False),
    ('OK', False, False), ('CRIT', True, False),
])
def test_group_uses_domain_critical_badge_and_clears_after_recovery(
        owner, client, status, paused, critical):
    from sitewatcher import domain_groups
    from sitewatcher.config import ChecksModel

    group = domain_groups.create_group(41, 'Important sites')
    storage.add_domain(41, 'critical.example')
    domain_groups.move_domains(41, ['critical.example'], group)
    storage.set_domain_override(41, 'critical.example', {
        'checks': {name: name == 'http_basic' for name in ChecksModel.model_fields},
        **({'interval_minutes': 0} if paused else {}),
    })
    storage.save_history(41, 'critical.example', 'http_basic', status, 'saved', {})

    def header():
        return get(client, '/').content.decode().split(
            f'data-domain-group="{group}"', 1)[1].split('</tbody>', 1)[0]

    assert ('class="badge crit"' in header()) is critical
    if critical:
        assert 'Critical' in header()
        storage.add_domain(41, 'healthy.example')
        domain_groups.move_domains(41, ['healthy.example'], group)
        filtered = get(client, '/?q=healthy').content.decode().split(
            f'data-domain-group="{group}"', 1)[1].split('</tbody>', 1)[0]
        assert 'class="badge crit"' in filtered
        storage.save_history(41, 'critical.example', 'http_basic', 'OK', 'recovered', {})
        assert 'class="badge crit"' not in header()


def test_move_response_contains_authoritative_group_headings_and_rejects_stale_source(owner, client):
    from sitewatcher import domain_groups
    from sitewatcher.config import ChecksModel
    source = domain_groups.create_group(41, 'Source')
    target = domain_groups.create_group(41, 'Target <safe>')
    storage.add_domain(41, 'instant.example')
    domain_groups.move_domains(41, ['instant.example'], source)
    storage.set_domain_override(41, 'instant.example', {'checks': {
        name: name == 'http_basic' for name in ChecksModel.model_fields}})
    storage.save_history(41, 'instant.example', 'http_basic', 'CRIT', 'saved', {})
    data = {'operation': 'move', 'group_id': str(target), 'original_group_id': str(source),
            'domains': '["instant.example"]'}
    response = client.post('/settings/groups', data, HTTP_HOST='localhost',
                           HTTP_ACCEPT='application/json')
    assert response.status_code == 200
    payload = response.json()
    groups = {group['id']: group for group in payload['groups']}
    assert payload['saved'] and payload['order'] == ['instant.example']
    assert groups[source]['total'] == 0 and groups[target]['total'] == 1
    assert 'class="badge crit"' in groups[target]['heading']
    assert 'Target &lt;safe&gt;' in groups[target]['heading']
    assert 'data-group-id' in groups[source]['empty']
    data['group_id'] = '0'
    response = client.post('/settings/groups', data, HTTP_HOST='localhost',
                           HTTP_ACCEPT='application/json')
    assert response.status_code == 409
    assert domain_groups.group_for_domain(41, 'instant.example') == target


def test_group_move_snapshot_is_owner_scoped_without_raw_check_data(owner, client):
    from sitewatcher import domain_groups
    storage.add_domain(41, 'mine.example')
    storage.save_history(41, 'mine.example', 'http_basic', 'CRIT',
                         'private-provider-sentinel', {'secret': 'private-metric-sentinel'})
    storage.ensure_user(42)
    storage.add_domain(42, 'foreign.example')
    domain_groups.create_group(42, 'Foreign private group')
    response = client.get('/settings/groups', HTTP_HOST='localhost', HTTP_ACCEPT='application/json')
    assert response.status_code == 200
    payload = response.json()
    assert payload['membership'] == {'mine.example': 0}
    body = response.content.decode()
    for private in ('foreign.example', 'Foreign private group', 'private-provider-sentinel',
                    'private-metric-sentinel'):
        assert private not in body


@pytest.mark.parametrize('url', ['https://link.example/', 'http://link.example:8080/status'])
def test_domain_name_opens_configured_website_in_new_tab(owner, client, url):
    from html.parser import HTMLParser
    storage.add_domain(41, 'link.example')
    storage.set_domain_override(41, 'link.example', {'http_url': url})
    links = []
    class Links(HTMLParser):
        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            if tag == 'a' and attrs.get('class') == 'domain-name':
                links.append(attrs)
    Links().feed(get(client, '/').content.decode())
    assert len(links) == 1
    assert links[0]['href'] == url
    assert links[0].get('target') == '_blank'
    assert {'noopener', 'noreferrer'} <= set(links[0].get('rel', '').split())
