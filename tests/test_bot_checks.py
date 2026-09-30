import asyncio
from types import SimpleNamespace

from sitewatcher import storage
from sitewatcher.bot.handlers import checks
from sitewatcher.checks.base import CheckOutcome, Status
from sitewatcher.config import AppConfig


def test_ephemeral_check_uses_dispatcher_without_persistence(monkeypatch):
    calls = []

    class FakeDispatcher:
        def __init__(self, cfg):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            pass

        async def run_for(self, owner, domain, **kwargs):
            calls.append((owner, domain, kwargs))
            return [CheckOutcome("ping", Status.OK, "up", {})]

    class FakeMessage:
        async def reply_html(self, text, **kwargs):
            calls.append(text)

        async def reply_text(self, text, **kwargs):
            calls.append(text)

    cfg = AppConfig()
    cfg.defaults.checks.keywords = True
    monkeypatch.setattr(checks, "Dispatcher", FakeDispatcher)
    monkeypatch.setattr(storage, "domain_exists", lambda *args: False)
    monkeypatch.setattr(storage, "save_history", lambda *args: (_ for _ in ()).throw(AssertionError("saved")))
    update = SimpleNamespace(message=FakeMessage(), effective_user=SimpleNamespace(id=7))
    context = SimpleNamespace(args=["example.com"], application=SimpleNamespace(bot_data={"cfg": cfg}))

    asyncio.run(checks.cmd_check_domain(update, context))

    assert calls[0][0:2] == (7, "example.com")
    assert calls[0][2]["use_cache"] is False
    assert "keywords" not in calls[0][2]["only_checks"]
    assert "example.com" in calls[1]
