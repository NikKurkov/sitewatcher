import asyncio
from types import SimpleNamespace

import pytest

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


@pytest.mark.parametrize('args, use_cache', [
    (['example.com'], True),
    (['example.com', '--force'], False),
    (['example.com', '-f'], False),
    (['example.com', 'force'], False),
    (['--force', 'example.com'], False),
    (['-f', 'example.com'], False),
    (['force', 'example.com'], False),
])
def test_owned_check_honors_force_before_or_after_domain(monkeypatch, args, use_cache):
    from unittest.mock import AsyncMock

    storage.add_domain(7, 'example.com')
    calls = []

    class Dispatcher:
        def __init__(self, cfg):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            pass

        async def run_for(self, owner, domain, **kwargs):
            calls.append((owner, domain, kwargs))
            return [CheckOutcome('ping', Status.OK, 'synthetic', {})]

    monkeypatch.setattr(checks, 'Dispatcher', Dispatcher)
    notify = AsyncMock()
    monkeypatch.setattr(checks, 'maybe_send_alert', notify)
    message = SimpleNamespace(reply_html=AsyncMock(), reply_text=AsyncMock())
    update = SimpleNamespace(message=message, effective_user=SimpleNamespace(id=7))
    context = SimpleNamespace(args=args, application=SimpleNamespace(bot_data={'cfg': AppConfig()}))
    asyncio.run(checks.cmd_check_domain(update, context))
    assert calls == [(7, 'example.com', {'use_cache': use_cache})]
    assert len(storage.last_results(7, 'example.com')) == 1
    assert storage.last_results(7, 'example.com')[0]['source'] == 'manual'
    notify.assert_awaited_once()
