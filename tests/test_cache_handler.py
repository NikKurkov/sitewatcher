import asyncio
from contextlib import closing
from types import SimpleNamespace

import pytest

from sitewatcher import storage
from sitewatcher.bot.handlers import cache
from sitewatcher.config import AppConfig


@pytest.fixture
def boundary(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(storage, 'DEFAULT_DB', tmp_path / 'main.db')
    cfg = AppConfig()
    cfg.whois.db_path = str(tmp_path / 'whois.db')
    cfg.rkn.index_db_path = str(tmp_path / 'index <unsafe>.db')
    for path in (storage.DEFAULT_DB, tmp_path / 'whois.db'):
        storage._ensure_initialized(path)
        with closing(storage._connect(path)) as connection:
            connection.execute("INSERT INTO whois_state(domain,snapshot_json,fetched_at) "
                               "VALUES('example.com','{}','2026-10-21')")
    replies = []

    class Message:
        async def reply_html(self, text, **kwargs):
            replies.append(text)

    update = SimpleNamespace(effective_message=Message(), effective_user=SimpleNamespace(id=1),
                             effective_chat=SimpleNamespace(id=10))
    context = SimpleNamespace(application=SimpleNamespace(bot_data={'cfg': cfg}))
    return update, context, cfg, replies


def row_count(path):
    with closing(storage._connect(path)) as connection:
        return connection.execute('SELECT COUNT(*) FROM whois_state').fetchone()[0]


def test_clear_cache_uses_configured_whois_database_and_escapes_summary(boundary):
    from pathlib import Path

    update, context, cfg, replies = boundary
    index = Path(cfg.rkn.index_db_path)
    index.write_bytes(b'index placeholder')
    asyncio.run(cache.cmd_clear_cache(update, context))
    assert row_count(Path(cfg.whois.db_path)) == 0
    assert row_count(storage.DEFAULT_DB) == 1
    assert not index.exists()
    assert 'index &lt;unsafe&gt;.db' in replies[-1]


@pytest.mark.parametrize('error_type', [ValueError, OSError])
def test_clear_cache_handles_rejected_rkn_path_without_exposing_error(
    boundary, monkeypatch, error_type,
):
    update, context, cfg, replies = boundary

    def reject(cfg):
        raise error_type('private-path-or-sql-error')

    monkeypatch.setattr(cache, 'rkn_index_path', reject)
    asyncio.run(cache.cmd_clear_cache(update, context))
    assert storage.DEFAULT_DB.exists()
    assert row_count(storage.DEFAULT_DB) == 1
    assert replies and 'private-path-or-sql-error' not in replies[-1]
    assert 'rkn' in replies[-1].lower()
    assert '✅ Cache cleared' not in replies[-1]


def test_default_whois_cache_uses_current_main_database(boundary):
    from pathlib import Path

    update, context, cfg, replies = boundary
    configured_path = Path(cfg.whois.db_path)
    cfg.whois.db_path = None
    asyncio.run(cache.cmd_clear_cache(update, context))
    assert row_count(storage.DEFAULT_DB) == 0
    assert row_count(configured_path) == 1
