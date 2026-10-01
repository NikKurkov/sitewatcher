import sys

from sitewatcher import main
from sitewatcher.web.auth import verify_password


def test_hash_password_cli_prompts_twice_and_prints_only_hash(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["sitewatcher", "hash-password"])
    prompts = iter(["some long private password", "some long private password"])
    monkeypatch.setattr("getpass.getpass", lambda prompt: next(prompts))
    main.main()
    output = capsys.readouterr().out.strip()
    assert output.startswith("WEB_PASSWORD_HASH=scrypt:")
    assert "some long private password" not in output
    assert verify_password("some long private password", output.split("=", 1)[1])
