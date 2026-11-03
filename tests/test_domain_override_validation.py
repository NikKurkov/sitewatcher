import pytest

from sitewatcher.config import (
    AppConfig, resolve_settings, validate_domain_override, validation_message,
)


def test_validated_patch_merges_checks_without_mutating_inputs_or_port_representation():
    current = {"checks": {"ping": False}, "ports": [80, "443"]}
    patch = {"checks": {"keywords": True}, "keywords": ["hello"]}
    result = validate_domain_override(AppConfig(), "example.com", patch, current)
    assert result == {
        "checks": {"ping": False, "keywords": True}, "ports": [80, "443"],
        "keywords": ["hello"],
    }
    assert current == {"checks": {"ping": False}, "ports": [80, "443"]}
    assert patch == {"checks": {"keywords": True}, "keywords": ["hello"]}


def test_none_keywords_and_ports_inherit_while_empty_lists_and_none_proxy_clear():
    cfg = AppConfig.model_validate({
        "defaults": {"proxy": "http://proxy.example:8080"},
        "domains": [{"name": "example.com", "keywords": ["hello"], "ports": [443]}],
    })
    inherited = resolve_settings(cfg, "example.com", {"keywords": None, "ports": None})
    assert inherited.keywords == ["hello"]
    assert [port.port for port in inherited.ports] == [443]
    cleared = resolve_settings(cfg, "example.com", {"keywords": [], "ports": [], "proxy": None})
    assert cleared.keywords == [] and cleared.ports == [] and cleared.proxy is None


def test_override_unknown_keys_and_invalid_target_read_bytes_are_rejected():
    for patch in ({"unknown": True}, {"ports": [{"port": 443, "read_bytes": 0}]}):
        with pytest.raises(ValueError):
            validate_domain_override(AppConfig(), "example.com", patch)


def test_error_message_hides_proxy_credentials_and_unknown_input_keys():
    secret = "private-password"
    for patch in ({"proxy": f"bad://user:{secret}@proxy.example"}, {secret: True}):
        with pytest.raises(ValueError) as error:
            validate_domain_override(AppConfig(), "example.com", patch)
        assert secret not in validation_message(error.value)
        assert "Invalid" in validation_message(error.value)
