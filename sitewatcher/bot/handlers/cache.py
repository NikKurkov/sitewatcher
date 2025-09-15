# sitewatcher/bot/handlers/cache.py
from __future__ import annotations

import logging
import sqlite3
from pathlib import Path

from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes

from ... import storage
from ...config import AppConfig
from ..utils import requires_auth, safe_reply_html

log = logging.getLogger(__name__)


@requires_auth(allow_while_busy=True)
async def cmd_clear_cache(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Clear in-process caches / on-disk indices:
      - WHOIS cache (DB table via storage)
      - RKN index SQLite file (path from cfg.rkn.index_db_path or ./data/z_i_index.db)
    """
    cfg: AppConfig = context.application.bot_data["cfg"]
    msg = getattr(update, "effective_message", None)
    owner_id = update.effective_user.id

    log.info("cache.clear.start", extra={"event": "cache.clear.start", "owner_id": owner_id})

    # ---- WHOIS cache (in storage) ----
    try:
        whois_deleted = storage.clear_whois_cache()
    except Exception:
        whois_deleted = -1
        log.exception(
            "cache.clear.whois.error",
            extra={"event": "cache.clear.whois.error", "owner_id": owner_id},
        )

    # ---- RKN index (SQLite file) ----
    rkn_cfg = getattr(cfg, "rkn", None)
    idx_path = getattr(rkn_cfg, "index_db_path", None) if rkn_cfg is not None else None

    # Choose a sensible default ./data directory if package data/ is missing
    base_dir = Path(__file__).resolve().parents[2]  # .../sitewatcher
    data_dir = (base_dir / "data") if (base_dir / "data").exists() else (Path.cwd() / "data")
    rkn_db_path = Path(idx_path) if idx_path else (data_dir / "z_i_index.db")

    existed_before = rkn_db_path.exists()
    rkn_removed = False
    rkn_fallback_clear = False
    rkn_error: str | None = None
    removed_extra: list[str] = []

    if existed_before:
        try:
            rkn_db_path.unlink()
            rkn_removed = True
            # Remove SQLite sidecar files if present
            for suffix in ("-wal", "-shm", "-journal"):
                p = Path(str(rkn_db_path) + suffix)
                if p.exists():
                    try:
                        p.unlink()
                        removed_extra.append(p.name)
                    except Exception:
                        # Non-fatal; keep going
                        pass
        except Exception as e:
            rkn_error = f"unlink failed: {e}"
            # Fallback: clear tables in-place if the file is locked by another process
            try:
                with sqlite3.connect(rkn_db_path) as conn:
                    conn.execute("DELETE FROM domains")
                    conn.execute("DELETE FROM ips")
                    conn.execute("DELETE FROM meta")
                rkn_fallback_clear = True
            except Exception as e2:
                rkn_error += f"; fallback failed: {e2}"
                log.exception(
                    "cache.clear.rkn.error",
                    extra={"event": "cache.clear.rkn.error", "owner_id": owner_id},
                )

    # ---- Build human summary ----
    parts: list[str] = []
    parts.append(
        f"whois: {whois_deleted} row(s) deleted" if whois_deleted >= 0 else "whois: error"
    )
    if existed_before:
        if rkn_removed:
            msg_rkn = f"rkn index removed ({rkn_db_path.name})"
            if removed_extra:
                msg_rkn += f", extras: {', '.join(removed_extra)}"
            parts.append(msg_rkn)
        elif rkn_fallback_clear:
            parts.append("rkn tables cleared (fallback)")
        else:
            parts.append(f"rkn index kept ({rkn_error or 'no action'})")
    else:
        parts.append("rkn index not found")

    summary = "; ".join(parts)

    log.info(
        "cache.clear.done",
        extra={
            "event": "cache.clear.done",
            "owner_id": owner_id,
            "whois_deleted": whois_deleted,
            "rkn_removed": rkn_removed,
            "rkn_fallback_clear": rkn_fallback_clear,
            "rkn_error": rkn_error,
            "rkn_db": str(rkn_db_path),
            "removed_extra": ",".join(removed_extra) if removed_extra else "",
        },
    )

    if msg:
        await safe_reply_html(msg, "✅ Cache cleared: " + summary)


# ------------------------------ registry --------------------------------

def register_handlers(app: Application) -> None:
    """Register cache-related handlers."""
    app.add_handler(CommandHandler("clear_cache", cmd_clear_cache, block=False), group=0)


def register_cache_handlers(app: Application) -> None:
    """Backward-compatible alias expected by router.py (if used)."""
    register_handlers(app)
