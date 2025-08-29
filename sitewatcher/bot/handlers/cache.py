# sitewatcher/bot/handlers/cache.py
from __future__ import annotations

import sqlite3
from pathlib import Path

from telegram import Update
from telegram.ext import ContextTypes

from ... import storage
from ...config import AppConfig
from ..utils import requires_auth


@requires_auth
async def cmd_clear_cache(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Clear WHOIS cache and RKN index artifacts."""
    cfg: AppConfig = context.application.bot_data["cfg"]
    msg = getattr(update, "effective_message", None)

    # 1) WHOIS cache (table whois_state in main DB)
    try:
        whois_deleted = storage.clear_whois_cache()
    except Exception as e:
        whois_deleted = -1

    # 2) RKN index (SQLite file) + legacy artifacts
    base_dir = Path(__file__).resolve().parents[2]  # .../sitewatcher
    data_dir = base_dir / "data"
    rkn_db_path = Path(cfg.rkn.index_db_path) if getattr(cfg.rkn, "index_db_path", None) else (data_dir / "z_i_index.db")

    rkn_removed = False
    rkn_fallback_clear = False
    rkn_error: str | None = None

    if rkn_db_path.exists():
        try:
            rkn_db_path.unlink()
            rkn_removed = True
        except Exception as e:
            rkn_error = f"unlink failed: {e}"
            try:
                conn = sqlite3.connect(rkn_db_path)
                with conn:
                    conn.execute("DELETE FROM domains")
                    conn.execute("DELETE FROM ips")
                    conn.execute("DELETE FROM meta")
                conn.close()
                rkn_fallback_clear = True
            except Exception as e2:
                rkn_error += f"; fallback failed: {e2}"

    removed_extra: list[str] = []
    for extra in (data_dir / "z_i_dump.csv.gz", data_dir / "z_i_index.json.gz"):
        try:
            if extra.exists():
                extra.unlink()
                removed_extra.append(extra.name)
        except Exception:
            pass

    parts = []
    parts.append(f"WHOIS: {'cleared ' + str(whois_deleted) + ' rows' if whois_deleted >= 0 else 'error'}")
    if rkn_removed:
        parts.append(f"RKN: removed file {rkn_db_path.name}")
    elif rkn_fallback_clear:
        parts.append("RKN: file busy, tables cleared")
    else:
        parts.append("RKN: nothing to remove" if not rkn_error else f"RKN: error ({rkn_error})")
    if removed_extra:
        parts.append(f"extra: removed {', '.join(removed_extra)}")

    if msg:
        await msg.reply_text("✅ Cache cleared: " + "; ".join(parts))
