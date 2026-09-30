from sitewatcher import storage
from sitewatcher.checks.rkn_block_sqlite import RknBlockCheck, rkn_index_path
from sitewatcher.config import RknConfig


def test_rkn_index_and_cache_clear_use_same_writable_path(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DEFAULT_DB", tmp_path / "sitewatcher.db")
    cfg = RknConfig()
    check = RknBlockCheck("example.com", client=None, rkn_cfg=cfg)
    assert check.db_path == tmp_path / "z_i_index.db"
    assert rkn_index_path(cfg) == check.db_path
