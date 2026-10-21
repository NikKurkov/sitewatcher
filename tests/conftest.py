"""Every test starts with isolated storage and working-directory side effects."""
import pytest

from sitewatcher import storage


@pytest.fixture(autouse=True)
def isolated_workspace(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(storage, 'DEFAULT_DB', tmp_path / 'sitewatcher.db')
