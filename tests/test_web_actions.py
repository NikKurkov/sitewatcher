import json
import sqlite3

import pytest

from sitewatcher import storage, web_actions
from sitewatcher.config import AppConfig, resolve_settings


def edit(cfg, owner_id, form):
    revision = web_actions.settings_context(cfg, owner_id, form['domain'])['revision']
    return web_actions.save_domain(cfg, owner_id, {**form, 'revision': revision})


OWNER = 11
DOMAIN = 'example.com'


def test_new_context_and_create_normalizes_full_form():
    cfg = AppConfig()
    context = web_actions.settings_context(cfg, OWNER)
    assert context['domain'] == ''
    assert context['values']['proxy'] == ''
    assert context['values']['check.ping'] == ''
    domain = web_actions.save_domain(cfg, OWNER, {
        'domain': 'HTTPS://Example.COM/path', 'interval_minutes': '0',
        'keywords': '[]', 'ports': '[80, {"port": 443}]', 'check.ping': 'off',
        'tls_warn_days': '0',
    }, create=True)
    assert domain == DOMAIN
    override = storage.get_domain_override(OWNER, DOMAIN)
    assert override == {
        'interval_minutes': 0, 'keywords': [], 'ports': [80, {'port': 443}],
        'checks': {'ping': False}, 'tls_warn_days': 0,
    }
    context = web_actions.settings_context(cfg, OWNER, DOMAIN)
    assert context['values']['interval_minutes'] == '0'
    assert json.loads(context['values']['ports']) == [80, {'port': 443}]
    assert context['values']['check.ping'] == 'off'


def test_duplicate_preserves_existing_settings_and_invalid_create_writes_nothing():
    cfg = AppConfig()
    storage.add_domain(OWNER, DOMAIN)
    storage.set_domain_override(OWNER, DOMAIN, {'interval_minutes': 9})
    with pytest.raises(ValueError):
        web_actions.save_domain(cfg, OWNER, {'domain': DOMAIN}, create=True)
    assert storage.get_domain_override(OWNER, DOMAIN) == {'interval_minutes': 9}
    with pytest.raises(ValueError):
        web_actions.save_domain(cfg, OWNER, {'domain': 'new.example', 'http_timeout_s': '0'},
                                create=True)
    assert not storage.domain_exists(OWNER, 'new.example')


def test_edit_replaces_fields_and_preserves_proxy_until_explicit_change():
    cfg = AppConfig.model_validate({'defaults': {'keywords': ['inherited']}})
    storage.add_domain(OWNER, DOMAIN)
    secret = 'http://user:private-password@proxy.example:8080'
    storage.set_domain_override(OWNER, DOMAIN, {
        'proxy': secret, 'interval_minutes': 0, 'checks': {'ping': False},
    })
    context = web_actions.settings_context(cfg, OWNER, DOMAIN)
    assert secret not in str(context) and 'private-password' not in str(context)
    assert context['proxy_present'] is True
    assert context['effective']['proxy'] == '[configured]'
    assert context['values']['proxy'] == ''
    edit(cfg, OWNER, {'domain': DOMAIN, 'proxy_mode': 'keep'})
    assert storage.get_domain_override(OWNER, DOMAIN) == {'proxy': secret}
    assert resolve_settings(cfg, DOMAIN, storage.get_domain_override(OWNER, DOMAIN)).keywords == [
        'inherited',
    ]
    edit(cfg, OWNER, {'domain': DOMAIN, 'proxy_mode': 'clear'})
    assert storage.get_domain_override(OWNER, DOMAIN) == {'proxy': None}
    edit(cfg, OWNER, {'domain': DOMAIN})
    assert storage.get_domain_override(OWNER, DOMAIN) == {'proxy': None}
    edit(cfg, OWNER, {'domain': DOMAIN, 'proxy_mode': 'inherit'})
    assert storage.get_domain_override(OWNER, DOMAIN) == {}
    edit(cfg, OWNER, {
        'domain': DOMAIN, 'proxy_mode': 'set', 'proxy': secret,
    })
    assert storage.get_domain_override(OWNER, DOMAIN) == {'proxy': secret}


@pytest.mark.parametrize('form', [
    {'keywords': '{}'}, {'ports': 'not json'}, {'check.ping': 'bad'},
    {'interval_minutes': '-1'}, {'http_timeout_s': '1.5'},
    {'latency_warn_ms': '3000'}, {'proxy_mode': 'bad'},
    {'proxy_mode': 'set', 'proxy': 'bad://user:private-password@example.com'},
    {'proxy_mode': 'set', 'proxy': ''},
])
def test_invalid_edits_are_sanitized_and_preserve_settings(form):
    cfg = AppConfig()
    storage.add_domain(OWNER, DOMAIN)
    storage.set_domain_override(OWNER, DOMAIN, {'interval_minutes': 9})
    with pytest.raises(ValueError) as error:
        edit(cfg, OWNER, {'domain': DOMAIN, **form})
    assert 'private-password' not in str(error.value)
    assert storage.get_domain_override(OWNER, DOMAIN) == {'interval_minutes': 9}


def test_actions_pause_resume_reset_delete():
    cfg = AppConfig()
    storage.add_domain(OWNER, DOMAIN)
    web_actions.act_on_domain(cfg, OWNER, 'pause', DOMAIN)
    assert storage.get_domain_override(OWNER, DOMAIN) == {'interval_minutes': 0}
    web_actions.act_on_domain(cfg, OWNER, 'resume', DOMAIN)
    assert resolve_settings(cfg, DOMAIN, storage.get_domain_override(OWNER, DOMAIN)).interval_minutes is None
    web_actions.act_on_domain(cfg, OWNER, 'reset', DOMAIN)
    assert storage.get_domain_override(OWNER, DOMAIN) is None
    web_actions.act_on_domain(cfg, OWNER, 'delete', DOMAIN)
    assert not storage.domain_exists(OWNER, DOMAIN)


def test_resume_overrides_inherited_yaml_pause_with_positive_interval():
    cfg = AppConfig.model_validate({'domains': [{'name': DOMAIN, 'interval_minutes': 0}]})
    storage.add_domain(OWNER, DOMAIN)
    web_actions.act_on_domain(cfg, OWNER, 'resume', DOMAIN)
    assert resolve_settings(cfg, DOMAIN, storage.get_domain_override(OWNER, DOMAIN)).interval_minutes > 0


def test_reset_repairs_corrupt_storage_without_reading_override():
    cfg = AppConfig()
    storage.add_domain(OWNER, DOMAIN)
    storage.set_domain_override(OWNER, DOMAIN, {'interval_minutes': 1})
    with sqlite3.connect(storage.DEFAULT_DB) as conn:
        conn.execute('UPDATE domain_overrides SET data_json=?', ('{private-password',))
    with pytest.raises(ValueError) as error:
        web_actions.settings_context(cfg, OWNER, DOMAIN)
    assert 'private-password' not in str(error.value)
    web_actions.act_on_domain(cfg, OWNER, 'reset', DOMAIN)
    assert storage.get_domain_override(OWNER, DOMAIN) is None


def test_every_existing_domain_operation_is_owner_scoped():
    cfg = AppConfig()
    storage.add_domain(OWNER, DOMAIN)
    storage.set_domain_override(OWNER, DOMAIN, {'interval_minutes': 9})
    for action in ['pause', 'resume', 'reset', 'delete', 'unknown']:
        with pytest.raises(ValueError):
            web_actions.act_on_domain(cfg, OWNER + 1, action, DOMAIN)
    with pytest.raises(ValueError):
        web_actions.settings_context(cfg, OWNER + 1, DOMAIN)
    with pytest.raises(ValueError):
        web_actions.save_domain(cfg, OWNER + 1, {'domain': DOMAIN})
    with pytest.raises(ValueError):
        web_actions.history_context(OWNER + 1, DOMAIN)
    assert storage.get_domain_override(OWNER, DOMAIN) == {'interval_minutes': 9}


def test_history_is_bounded_domain_scoped_and_excludes_metrics():
    storage.add_domain(OWNER, DOMAIN)
    storage.save_history(OWNER, DOMAIN, 'ping', 'OK', 'one', {'private': 'hidden'})
    storage.save_history(OWNER, DOMAIN, 'ping', 'WARN', 'two', {})
    storage.save_history(OWNER + 1, DOMAIN, 'ping', 'OK', 'other-owner', {})
    storage.save_history(OWNER, 'other.example', 'ping', 'OK', 'other-domain', {})
    rows = web_actions.history_context(OWNER, DOMAIN, limit=1)
    assert len(rows) == 1 and rows[0]['message'] == 'two'
    assert 'metrics_json' not in rows[0]
    assert rows[0]['check_name'] == 'ping'


def test_atomic_creation_rejects_duplicate_without_replacing_data():
    storage.set_domain_override(OWNER, DOMAIN, {'interval_minutes': 8}, create_missing=True)
    with pytest.raises(ValueError):
        storage.set_domain_override(OWNER, DOMAIN, {'interval_minutes': 1},
                                    replace=True, create_missing=True, create_only=True)
    assert storage.get_domain_override(OWNER, DOMAIN) == {'interval_minutes': 8}


def test_stale_or_missing_edit_revision_rejects_write():
    cfg = AppConfig()
    storage.add_domain(OWNER, DOMAIN)
    context = web_actions.settings_context(cfg, OWNER, DOMAIN)
    storage.set_domain_override(OWNER, DOMAIN, {'interval_minutes': 8})
    for form in [{'domain': DOMAIN}, {'domain': DOMAIN, 'revision': context['revision']}]:
        with pytest.raises(ValueError, match='reload'):
            web_actions.save_domain(cfg, OWNER, form)
    assert storage.get_domain_override(OWNER, DOMAIN) == {'interval_minutes': 8}
    with pytest.raises(ValueError):
        storage.set_domain_override(OWNER, DOMAIN, {}, replace=True,
                                    expected_revision=context['revision'])
    assert storage.get_domain_override(OWNER, DOMAIN) == {'interval_minutes': 8}


def test_revision_canonicalizes_key_order_and_empty_override():
    assert storage.domain_override_revision(None) == storage.domain_override_revision({})
    assert storage.domain_override_revision({'checks': {'ping': False}, 'ports': [80]}) == (
        storage.domain_override_revision({'ports': [80], 'checks': {'ping': False}})
    )


def test_resume_does_not_replace_an_existing_positive_interval():
    cfg = AppConfig()
    storage.add_domain(OWNER, DOMAIN)
    storage.set_domain_override(OWNER, DOMAIN, {'interval_minutes': 37})
    web_actions.act_on_domain(cfg, OWNER, 'resume', DOMAIN)
    assert storage.get_domain_override(OWNER, DOMAIN) == {'interval_minutes': 37}


def test_new_settings_preview_does_not_inherit_an_unrelated_yaml_domain():
    cfg = AppConfig.model_validate({'domains': [{'name': DOMAIN, 'interval_minutes': 0}]})
    assert web_actions.settings_context(cfg, OWNER)['effective']['interval_minutes'] is None
