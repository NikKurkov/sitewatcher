"""VirusTotal routing stays private and isolated; failures remain actionable."""

import asyncio
import stat

import httpx
import pytest

from sitewatcher.checks.malware_scan import MalwareScanCheck, _VTConfig


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_PROXY", raising=False)


@pytest.mark.parametrize(
    ("failure", "message"),
    [
        ("connect_timeout", "VirusTotal connection timed out. Check network or proxy settings."),
        ("read_timeout", "VirusTotal response timed out. Try again later."),
        ("proxy", "Could not connect to the VirusTotal proxy. Check proxy settings."),
        ("connection", "Could not connect to VirusTotal. Check network or proxy settings."),
        (401, "VirusTotal rejected the API key. Check your API key."),
        (403, "VirusTotal denied access. Check the API key permissions."),
        (429, "VirusTotal request quota exceeded. Try again later."),
        (503, "VirusTotal is temporarily unavailable. Try again later."),
        ("json", "VirusTotal returned an invalid response. Try again later."),
    ],
)
def test_provider_failures_are_actionable_and_never_expose_secrets(failure, message, caplog):
    def handler(request):
        if isinstance(failure, int):
            return httpx.Response(failure, json={"error": {"message": "private-secret"}})
        if failure == "json":
            return httpx.Response(200, text="private-secret")
        error = {
            "connect_timeout": httpx.ConnectTimeout,
            "read_timeout": httpx.ReadTimeout,
            "proxy": httpx.ProxyError,
            "connection": httpx.ConnectError,
        }[failure]
        raise error("private-secret", request=request)

    async def scenario():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await MalwareScanCheck(
                "example.test", client=client, vt_cfg=_VTConfig(api_key="private-secret")
            ).run()

    result = asyncio.run(scenario())
    assert result.status.value == "UNKNOWN" and result.message == message
    assert result.metrics["vt_error"]["kind"]
    assert "private-secret" not in str(result) and "private-secret" not in caplog.text


def test_private_proxy_storage_precedence_and_symlink_safety(tmp_path, monkeypatch):
    from sitewatcher.virustotal_settings import (
        load_vt_proxy,
        save_vt_proxy,
        remove_vt_proxy,
        vt_proxy_path,
    )

    assert load_vt_proxy() is None
    save_vt_proxy("http://user:private-secret@proxy.example:8080")
    assert stat.S_IMODE(vt_proxy_path().stat().st_mode) == 0o600
    assert load_vt_proxy().endswith("@proxy.example:8080")
    assert load_vt_proxy("socks5://config.example:1080") == "socks5://config.example:1080"
    monkeypatch.setenv("VIRUSTOTAL_PROXY", "http://env.example:3128")
    assert load_vt_proxy("socks5://config.example:1080") == "http://env.example:3128"
    monkeypatch.delenv("VIRUSTOTAL_PROXY")
    vt_proxy_path().chmod(0o644)
    with pytest.raises(ValueError):
        load_vt_proxy()
    remove_vt_proxy()
    target = tmp_path / "target"
    target.write_text("preserve")
    vt_proxy_path().symlink_to(target)
    with pytest.raises(ValueError):
        load_vt_proxy()
    save_vt_proxy("socks5://proxy.example:1080")
    assert target.read_text() == "preserve" and not vt_proxy_path().is_symlink()
    remove_vt_proxy()
    assert load_vt_proxy() is None


def test_proxy_reload_is_isolated_from_shared_http_client(monkeypatch, expire_vt_report):
    from sitewatcher.virustotal_settings import (
        save_vt_proxy, remove_vt_proxy, save_vt_proxy_enabled, load_vt_proxy,
    )

    original_client = httpx.AsyncClient
    created = []
    shared_calls = []
    proxied_calls = []

    def shared(request):
        shared_calls.append(str(request.url))
        return httpx.Response(404)

    def proxied(request):
        assert request.headers["x-apikey"] == "synthetic-key"
        proxied_calls.append(request.method)
        if request.method == 'POST':
            return httpx.Response(200, json={'data': {'id': 'queued'}})
        return httpx.Response(404)

    def client_factory(**kwargs):
        created.append(kwargs.pop("proxy"))
        assert kwargs.pop("trust_env") is False
        return original_client(transport=httpx.MockTransport(proxied), **kwargs)

    async def scenario():
        async with original_client(transport=httpx.MockTransport(shared)) as client:
            monkeypatch.setattr(httpx, "AsyncClient", client_factory)
            probe = MalwareScanCheck(
                "example.test", client=client, vt_cfg=_VTConfig(api_key="synthetic-key")
            )
            save_vt_proxy("http://first.example:3128")
            assert (await probe.run()).message == 'VirusTotal analysis is pending'
            expire_vt_report()
            save_vt_proxy_enabled(False)
            await probe.run()
            assert load_vt_proxy() == "http://first.example:3128"
            expire_vt_report()
            save_vt_proxy_enabled(True)
            save_vt_proxy("socks5://second.example:1080")
            await probe.run()
            expire_vt_report()
            remove_vt_proxy()
            await probe.run()

    asyncio.run(scenario())
    assert created == ["http://first.example:3128", "socks5://second.example:1080"]
    assert len(shared_calls) == 2
    assert proxied_calls == ['GET', 'POST', 'GET']


@pytest.mark.parametrize(
    "value",
    [
        "ftp://private-user:private-pass@proxy.example",
        "http://proxy.example:3128/path",
        "socks5://proxy.example",
        "http://user:" + "é" * 500 + "@proxy.example:3128",
    ],
)
def test_proxy_validation_rejects_invalid_or_unreadable_settings_without_echo(value):
    from sitewatcher.virustotal_settings import validate_vt_proxy

    with pytest.raises(ValueError) as error:
        validate_vt_proxy(value)
    assert value not in str(error.value)


def test_proxy_validation_normalizes_case_and_hides_config_repr():
    from sitewatcher.config import AppConfig
    from sitewatcher.virustotal_settings import validate_vt_proxy

    assert validate_vt_proxy("HTTP://proxy.example:3128") == "http://proxy.example:3128"
    cfg = AppConfig.model_validate(
        {"malware": {"vt_proxy": "http://user:private-pass@proxy.example:3128"}}
    )
    assert "private-pass" not in repr(cfg.malware)
