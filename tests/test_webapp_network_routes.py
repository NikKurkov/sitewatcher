"""Only an authenticated owner can request and inspect private route diagnostics."""
import hashlib
import json

import pytest
from django.contrib.auth import get_user_model
from django.test import Client

from sitewatcher import storage
from sitewatcher.config import ChecksModel


@pytest.fixture
def owner(web_database, client):
    from sitewatcher.webapp.models import Workspace
    user = get_user_model().objects.create_user(username='route-owner')
    workspace = Workspace.objects.create(user=user, owner_id=41)
    for identity, name in [(41, 'route.example'), (99, 'private.example')]:
        storage.add_domain(identity, name)
    storage.set_domain_override(41, 'route.example', {'checks': {
        key: key == 'http_basic' for key in ChecksModel.model_fields}})
    storage.save_history(41, 'route.example', 'http_basic', 'OK', 'saved', {'final_code': 200})
    client.force_login(user)
    return workspace


def test_owner_can_queue_disable_and_read_route_without_changing_monitor_health(owner, client, monkeypatch):
    import asyncio
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', lambda *a, **kw: pytest.fail('POST must only queue'))
    response = client.post('/domains/route', {'domain': 'route.example', 'action': 'refresh'}, HTTP_HOST='localhost')
    assert response.status_code == 200 and response.json()['saved'] is True
    from sitewatcher import network_routes
    queued = network_routes.read_owner(41)['route.example']
    assert queued['state'] == 'queued' and queued['enabled'] is True
    from sitewatcher import check_activity
    check_activity.finish(check_activity.start(41, 'route.example', 'traceroute'), 'UNKNOWN', 1000)
    data = client.get('/api/activity', HTTP_HOST='localhost').json()
    assert data['domains'][0]['route']['state'] == 'queued'
    row, = client.get('/', HTTP_HOST='localhost').context['rows']
    assert row['overall'] == 'OK' and not row['error']
    assert client.post('/domains/route', {'domain': 'route.example', 'action': 'refresh'}, HTTP_HOST='localhost').status_code == 409
    assert client.post('/domains/route', {'domain': 'route.example', 'action': 'disable'}, HTTP_HOST='localhost').status_code == 200
    assert network_routes.read_owner(41)['route.example']['enabled'] is False


def test_route_mutations_require_owner_csrf_and_writable_mode(owner, client, settings):
    fields = {'domain': 'route.example', 'action': 'refresh'}
    secure = Client(enforce_csrf_checks=True)
    secure.force_login(owner.user)
    assert secure.post('/domains/route', fields, HTTP_HOST='localhost').status_code == 403
    assert client.get('/domains/route', HTTP_HOST='localhost').status_code == 405
    assert client.post('/domains/route', {**fields, 'domain': 'private.example'}, HTTP_HOST='localhost').status_code == 404
    for extra in ({'action': 'invalid'}, {'owner_id': '99'}):
        assert client.post('/domains/route', {**fields, **extra}, HTTP_HOST='localhost').status_code == 400
    settings.SITEWATCHER_READ_ONLY = True
    assert client.post('/domains/route', fields, HTTP_HOST='localhost').status_code == 405
    assert Client().post('/domains/route', fields, HTTP_HOST='localhost').status_code == 401


def test_public_capability_never_contains_private_route_data(owner, client):
    from sitewatcher.webapp.models import StatusPage
    secret = 'route-private-sentinel'
    page = StatusPage.objects.create(workspace=owner, public_enabled=True,
        public_domains=['route.example'], public_slug=owner.public_slug,
        public_token_hash=hashlib.sha256(secret.encode()).hexdigest())
    from sitewatcher import network_routes
    network_routes.request_trace(41, 'route.example')
    with storage._write_connection() as connection:
        connection.execute('UPDATE domain_routes SET result_json=? WHERE owner_id=41',
            (json.dumps({'hops': [{'ttl': 1, 'ip': '10.0.0.1', 'hostname': 'private-router-sentinel.local', 'rtt_ms': 1}], 'destination_ip': '198.51.100.5'}),))
    guest = Client()
    response = guest.get('/status/' + secret.ljust(43, 'x') + '/activity', HTTP_HOST='localhost')
    assert response.status_code == 404
    token = 'r' * 43
    StatusPage.objects.filter(pk=page.pk).update(public_token_hash=hashlib.sha256(token.encode()).hexdigest())
    payload = guest.get('/status/' + token + '/activity', HTTP_HOST='localhost').json()
    serialized = json.dumps(payload)
    assert 'route' not in payload['domains'][0] and 'hops' not in serialized
    assert '10.0.0.1' not in serialized and 'private-router-sentinel' not in serialized
    body = guest.get('/status/' + token + '/', HTTP_HOST='localhost').content.decode()
    assert 'route_view.js' not in body and 'data-route-controls' not in body
    assert guest.post('/domains/route', {'domain': 'route.example', 'action': 'refresh'}, HTTP_HOST='localhost').status_code in {401, 403}


def test_route_cache_failure_returns_retryable_activity_response(owner, client, monkeypatch):
    import sqlite3
    from sitewatcher import network_routes
    def unavailable(_owner):
        raise sqlite3.OperationalError('locked')
    monkeypatch.setattr(network_routes, 'read_owner', unavailable)
    response = client.get('/api/activity', HTTP_HOST='localhost')
    assert response.status_code == 503
    assert response['Cache-Control'] == 'no-store'
