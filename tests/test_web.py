"""Web compatibility wrapper cannot select an anonymous server."""
from sitewatcher.config import AppConfig


def test_run_web_always_uses_authenticated_asgi(monkeypatch):
    from sitewatcher import web
    from sitewatcher.webapp import bootstrap
    calls = []
    monkeypatch.setattr(bootstrap, 'run_asgi', lambda cfg, **kwargs: calls.append(kwargs))
    assert not hasattr(web, 'create_server')
    web.run_web(AppConfig(), None, port=3210, read_only=True)
    assert calls == [{'port': 3210, 'read_only': True, 'owner_id': None}]
