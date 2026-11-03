"""The web command starts the authenticated Django application directly."""


def test_web_cli_uses_authenticated_asgi(monkeypatch):
    from sitewatcher import main
    from sitewatcher.webapp import bootstrap
    calls = []
    monkeypatch.setattr(bootstrap, 'run_asgi', lambda cfg, **kwargs: calls.append(kwargs))
    monkeypatch.setattr('sys.argv', ['sitewatcher', 'web', '--owner', '42',
                                    '--port', '3210', '--read-only'])
    main.main()
    assert calls == [{'port': 3210, 'read_only': True, 'owner_id': 42}]
