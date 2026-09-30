import asyncio

from sitewatcher import storage
from sitewatcher.checks.base import CheckOutcome, Status
from sitewatcher.config import AppConfig
from sitewatcher.dispatcher import Dispatcher
from sitewatcher.main import _cmd_check_one


def test_owner_override_does_not_change_defaults(monkeypatch):
    cfg = AppConfig()
    monkeypatch.setattr(storage, "get_domain_override", lambda owner, domain: {"checks": {"ping": False}} if owner == 1 else {})
    dispatcher = Dispatcher(cfg)

    assert dispatcher._resolve(1, "example.com").checks.ping is False
    assert dispatcher._resolve(2, "example.com").checks.ping is True
    assert cfg.defaults.checks.ping is True


def test_empty_check_selection_returns_empty_result(monkeypatch):
    dispatcher = Dispatcher(AppConfig())
    dispatcher._client = object()
    monkeypatch.setattr(dispatcher, "_build_checks", lambda settings: [])

    assert asyncio.run(dispatcher.run_for(1, "example.com", run_id="run-42")) == []


def test_ephemeral_run_does_not_create_database(tmp_path, monkeypatch):
    db = tmp_path / "monitor.db"
    monkeypatch.setattr(storage, "DEFAULT_DB", db)
    dispatcher = Dispatcher(AppConfig())
    dispatcher._client = object()
    monkeypatch.setattr(dispatcher, "_build_checks", lambda settings: [])

    assert asyncio.run(dispatcher.run_for(0, "example.com", ephemeral=True)) == []
    assert not db.exists()


def test_cli_check_domain_runs_and_saves(monkeypatch, capsys):
    seen = []

    class FakeDispatcher:
        def __init__(self, cfg):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            pass

        async def run_for(self, owner_id, domain, **kwargs):
            seen.append(kwargs)
            return [CheckOutcome("http_basic", Status.OK, "healthy", {})]

    monkeypatch.setattr("sitewatcher.main.Dispatcher", FakeDispatcher)
    monkeypatch.setattr(storage, "save_histories", lambda *args: None)
    asyncio.run(_cmd_check_one(AppConfig(), 42, "example.com", only=None, use_cache=True, run_id="run-42"))

    assert "example.com" in capsys.readouterr().out
    assert seen == [{"only_checks": None, "use_cache": True, "run_id": "run-42"}]
