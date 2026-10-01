from sitewatcher import storage
from sitewatcher.checks.whois_info import WhoisInfoCheck
from sitewatcher.config import WhoisConfig


def test_whois_check_can_start_with_empty_database(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DEFAULT_DB", tmp_path / "sitewatcher.db")
    check = WhoisInfoCheck("example.com", client=None, cfg=WhoisConfig())
    assert check._db_get() is None
