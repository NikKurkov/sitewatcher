import asyncio
from types import SimpleNamespace

import pytest

from sitewatcher import storage
from sitewatcher.bot.handlers.cfg import cmd_cfg_set, cmd_cfg_unset
from sitewatcher.config import AppConfig, load_config, resolve_settings, validate_config


@pytest.mark.parametrize("override", [
    {"http_timeout_s": 0}, {"latency_warn_ms": -1}, {"tls_warn_days": -1},
    {"interval_minutes": -1}, {"ports": [0]}, {"ports": [65536]},
    {"ports": [{"port": 443, "timeout_s": 0}]}, {"checks": {"typo": True}},
    {"checks": {"ping": "invalid"}}, {"keywords": "not-a-list"},
    {"latency_warn_ms": 3000}, {"proxy": "invalid-proxy"},
])
def test_invalid_domain_override_fails_before_monitoring(override):
    with pytest.raises(ValueError):
        resolve_settings(AppConfig(), "example.com", override)


def test_valid_legacy_ports_are_normalized_and_zero_interval_is_preserved():
    settings = resolve_settings(AppConfig(), "example.com", {
        "ports": [80, "443", {"port": 22, "host": "ssh.example"}],
        "interval_minutes": 0, "tls_warn_days": 0,
    })
    assert [port.port for port in settings.ports] == [80, 443, 22]
    assert settings.interval_minutes == 0 and settings.tls_warn_days == 0


def test_yaml_domain_settings_normalize_names_and_drive_schedule(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("domains:\n  - name: 'HTTPS://ПРИМЕР.РФ/path'\n    interval_minutes: 7\n    http_timeout_s: 3\n")
    cfg = load_config(path)
    settings = resolve_settings(cfg, "xn--e1afmkfd.xn--p1ai")
    assert settings.http_timeout_s == 3 and settings.interval_minutes == 7


@pytest.mark.parametrize("config", [
    {"schedulre": {}}, {"defaults": {"checks": {"typo": True}}},
    {"domains": [{"name": "bad!domain"}]}, {"logging": {"destination": "unknown"}},
    {"ipchange": {"refresh_hours": -1}}, {"malware": {"timeout_s": 0}},
])
def test_invalid_configuration_is_rejected(config):
    with pytest.raises(ValueError):
        validate_config(AppConfig.model_validate(config))


def test_cfg_set_rejects_invalid_settings_without_mutating_database(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DEFAULT_DB", tmp_path / "settings.db")
    storage.add_domain(1, "example.com")
    replies = []

    class Message:
        async def reply_html(self, text, **kwargs):
            replies.append(text)

        async def reply_text(self, text, **kwargs):
            replies.append(text)

    update = SimpleNamespace(effective_user=SimpleNamespace(id=1), effective_message=Message())
    context = SimpleNamespace(args=["example.com", "interval_minutes", "-1"],
        application=SimpleNamespace(bot_data={"cfg": AppConfig()}))
    asyncio.run(cmd_cfg_set(update, context))
    assert storage.get_domain_override(1, "example.com") is None
    assert "Invalid" in replies[0]


def test_cfg_unset_cannot_expose_an_invalid_inherited_threshold(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DEFAULT_DB", tmp_path / "unset.db")
    storage.add_domain(1, "example.com")
    original = {"latency_warn_ms": 2500, "latency_crit_ms": 3000}
    storage.set_domain_override(1, "example.com", original)
    replies = []

    class Message:
        async def reply_html(self, text, **kwargs):
            replies.append(text)

        async def reply_text(self, text, **kwargs):
            replies.append(text)

    update = SimpleNamespace(effective_user=SimpleNamespace(id=1), effective_message=Message())
    context = SimpleNamespace(args=["example.com", "latency_crit_ms"],
        application=SimpleNamespace(bot_data={"cfg": AppConfig()}))
    asyncio.run(cmd_cfg_unset(update, context))
    assert storage.get_domain_override(1, "example.com") == original
    assert "Invalid" in replies[0]


def test_safe_validation_message_identifies_known_field_without_values():
    from pydantic import ValidationError
    from sitewatcher.config import AppConfig, validation_message
    import pytest

    with pytest.raises(ValidationError) as caught:
        AppConfig.model_validate({'defaults': {'http_timeout_s': 'private-secret-value'},
                                  'private-secret-field': True})
    message = validation_message(caught.value)
    assert 'defaults.http_timeout_s' in message
    assert 'int_parsing' in message
    assert 'private-secret' not in message


def test_runtime_validation_message_is_actionable_without_private_path(tmp_path):
    from sitewatcher.config import AppConfig, validate_config, validation_message
    import pytest

    cfg = AppConfig()
    cfg.deface.phrases_path = str(tmp_path / 'private-secret-path')
    with pytest.raises(ValueError) as caught:
        validate_config(cfg)
    message = validation_message(caught.value)
    assert 'deface.phrases_path' in message
    assert 'does not exist' in message
    assert 'private-secret-path' not in message


@pytest.mark.parametrize('logging_settings', [
    {'level': 'private-invalid-level'},
    {'third_party_levels': {'private-logger': 'private-invalid-level'}},
    {'file': {'interval': 0}}, {'file': {'max_bytes': -1}},
    {'file': {'backup_count': -1}},
    {'file': {'rotate': 'time', 'when': 'private-invalid-time'}},
    {'destination': 'file', 'file': {'path': '   '}},
])
def test_invalid_logging_fails_before_runtime_without_echoing_values(logging_settings):
    from sitewatcher.config import AppConfig, validate_config, validation_message
    cfg = AppConfig.model_validate({'logging': logging_settings})
    with pytest.raises(ValueError) as caught:
        validate_config(cfg)
    message = validation_message(caught.value)
    assert 'logging' in message
    assert 'private-' not in message


def test_logging_standard_aliases_case_and_unlimited_size_are_valid():
    from sitewatcher.config import AppConfig, validate_config
    validate_config(AppConfig.model_validate({'logging': {
        'level': ' debug ', 'third_party_levels': {'httpx': ' warn '},
        'file': {'rotate': 'time', 'when': ' w6 ', 'max_bytes': 0, 'backup_count': 0},
    }}))


@pytest.mark.parametrize('settings', [
    {'proxy': 'private-invalid-proxy'},
    {'proxy': 'ftp://user:private-password@example.test'},
    {'proxies': {'https': 'private-invalid-proxy'}},
    {'proxies': {'private-protocol': 'http://example.test'}},
])
def test_global_http_proxy_errors_are_rejected_at_configuration_boundary(settings):
    from sitewatcher.config import AppConfig, validation_message
    with pytest.raises(ValueError) as caught:
        AppConfig.model_validate({'http': settings})
    assert 'private-' not in validation_message(caught.value)


def test_global_proxy_mapping_accepts_legacy_scheme_spelling():
    from sitewatcher.config import AppConfig, validate_config
    validate_config(AppConfig.model_validate({'http': {'proxies': {
        'http': 'http://127.0.0.1:3128', 'https://': 'socks5://127.0.0.1:1080',
        'all': 'http://user:password@127.0.0.1:3128',
    }}}))


@pytest.mark.parametrize('settings', [
    {'ports': {'targets': [{'port': 443, 'expect': '['}]}},
    {'domains': [{'name': 'example.test', 'ports': [{'port': 443, 'expect': '['}]}]},
])
def test_invalid_port_expectation_cannot_silently_disable_banner_check(settings):
    from sitewatcher.config import AppConfig
    with pytest.raises(ValueError):
        AppConfig.model_validate(settings)


@pytest.mark.parametrize('other_cache', [None, 'whois', 'ipchange'])
def test_rkn_index_cannot_share_a_database_that_contains_application_state(tmp_path, monkeypatch, other_cache):
    from sitewatcher import storage
    from sitewatcher.config import AppConfig, validate_config, validation_message
    main = tmp_path / 'private-monitor.db'
    monkeypatch.setattr(storage, 'DEFAULT_DB', main)
    cfg = AppConfig()
    target = main
    if other_cache:
        target = tmp_path / 'private-cache.db'
        getattr(cfg, other_cache).db_path = str(target)
    cfg.rkn.index_db_path = str(target)
    with pytest.raises(ValueError) as caught:
        validate_config(cfg)
    assert 'rkn' in validation_message(caught.value)
    assert 'private-' not in validation_message(caught.value)
    assert not target.exists()


@pytest.mark.parametrize(('section', 'field', 'value'), [
    ('scheduler', 'interval_minutes', 0), ('scheduler', 'jitter_seconds', -1),
    ('alerts', 'cooldown_sec', -1), ('ports', 'read_bytes', 0),
    ('whois', 'warn_days', -1), ('http', 'max_connections', 0),
    ('ipbl', 'concurrency', 0), ('history', 'retention_days', -1),
])
def test_scalar_bounds_are_enforced_on_load_and_mutable_runtime_config(section, field, value):
    from sitewatcher.config import validation_message

    settings = {section: {field: value}}
    with pytest.raises(ValueError) as caught:
        AppConfig.model_validate(settings)
    assert f'{section}.{field}' in validation_message(caught.value)

    cfg = AppConfig.model_validate({'http': {}})
    setattr(getattr(cfg, section), field, value)
    with pytest.raises(ValueError) as caught:
        validate_config(cfg)
    assert f'{section}.{field}' in validation_message(caught.value)
