from __future__ import annotations

import html
import logging
import sqlite3
from pathlib import Path

from telegram import Update
from telegram.ext import ContextTypes

from ... import storage
from ...config import AppConfig
from ...checks.rkn_block_sqlite import rkn_index_path
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
        whois_deleted = storage.clear_whois_cache(
            Path(cfg.whois.db_path) if cfg.whois.db_path else storage.DEFAULT_DB
        )
    except Exception:
        whois_deleted = -1
        log.exception(
            "cache.clear.whois.error",
            extra={"event": "cache.clear.whois.error", "owner_id": owner_id},
        )

    # ---- RKN index (SQLite file) ----
    try:
        rkn_db_path = rkn_index_path(cfg.rkn)
    except (OSError, ValueError):
        rkn_db_path = None

    existed_before = rkn_db_path is not None and rkn_db_path.exists()
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
        except Exception:
            rkn_error = "index could not be removed"
            # Fallback: clear tables in-place if the file is locked by another process
            try:
                with sqlite3.connect(rkn_db_path) as conn:
                    conn.execute("DELETE FROM domains")
                    conn.execute("DELETE FROM ips")
                    conn.execute("DELETE FROM meta")
                rkn_fallback_clear = True
            except Exception:
                rkn_error += "; fallback clear failed"
                log.exception(
                    "cache.clear.rkn.error",
                    extra={"event": "cache.clear.rkn.error", "owner_id": owner_id},
                )

    # ---- Build human summary ----
    parts: list[str] = []
    parts.append(
        f"whois: {whois_deleted} row(s) deleted" if whois_deleted >= 0 else "whois: error"
    )
    if rkn_db_path is None:
        parts.append("rkn index path rejected; index kept")
    elif existed_before:
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
        await safe_reply_html(msg, "Cache maintenance: " + html.escape(summary))
