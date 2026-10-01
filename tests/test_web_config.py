import os
import stat

import pytest

from sitewatcher.config import load_config
from sitewatcher.web.config_edit import save_config_yaml


def test_missing_environment_config_uses_defaults(monkeypatch, tmp_path):
    monkeypatch.setenv("SITEWATCHER_CONFIG", str(tmp_path / "missing.yaml"))
    assert load_config().scheduler.interval_minutes == 1


def test_environment_config_is_loaded_unless_path_is_explicit(monkeypatch, tmp_path):
    shared = tmp_path / "shared.yaml"
    shared.write_text("scheduler:\n  interval_minutes: 7\n")
    explicit = tmp_path / "explicit.yaml"
    explicit.write_text("scheduler:\n  interval_minutes: 9\n")
    monkeypatch.setenv("SITEWATCHER_CONFIG", str(shared))

    assert load_config().scheduler.interval_minutes == 7
    assert load_config(explicit).scheduler.interval_minutes == 9
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "absent.yaml")


def test_save_config_validates_and_replaces_with_private_permissions(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("scheduler:\n  interval_minutes: 2\n")
    os.chmod(path, 0o644)

    cfg = save_config_yaml("scheduler:\n  interval_minutes: 7\n", path)

    assert cfg.scheduler.interval_minutes == 7
    assert load_config(path).scheduler.interval_minutes == 7
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.parametrize("text", [
    "scheduler:\n  interval_minutes: 0\n",
    "scheduler: [",
    "scheduler: null\n",
    "[]\n",
    "false\n",
])
def test_invalid_yaml_preserves_existing_config(tmp_path, text):
    path = tmp_path / "config.yaml"
    original = "scheduler:\n  interval_minutes: 3\n"
    path.write_text(original)

    with pytest.raises((ValueError, TypeError)):
        save_config_yaml(text, path)

    assert path.read_text() == original
    assert list(tmp_path.iterdir()) == [path]
