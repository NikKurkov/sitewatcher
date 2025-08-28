# sitewatcher/storage.py
from __future__ import annotations

"""
Lightweight SQLite storage layer for Sitewatcher.

Goals:
- SSOT: single source of truth for DB path and schema.
- DRY/KISS: keep helpers minimal, only what's needed now.
- Safety: context managers for connections/transactions, FK enabled.
"""

import json
import os
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

# --- Single source of truth (SSOT) for DB path --------------------------------
DEFAULT_DB = Path(os.getenv("DATABASE_PATH", "./sitewatcher.db"))

# --- Schema -------------------------------------------------------------------
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS domains (
  name TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS domain_overrides (
  domain TEXT PRIMARY KEY,
  data_json TEXT NOT NULL,
  updated_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY(domain) REFERENCES domains(name) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain TEXT NOT NULL,
  check_name TEXT,                -- целевая колонка (может быть NULL в старых БД, миграция заполнит)
  status TEXT NOT NULL,
  message TEXT NOT NULL,
  metrics_json TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY(domain) REFERENCES domains(name) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS whois_state (
  domain TEXT PRIMARY KEY,
  snapshot_json TEXT NOT NULL,
  fetched_at TEXT NOT NULL,
  updated_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY(domain) REFERENCES domains(name) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS dns_state (
  domain TEXT PRIMARY KEY,
  snapshot_json TEXT NOT NULL,
  fetched_at TEXT NOT NULL,
  updated_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY(domain) REFERENCES domains(name) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS alert_state (
  domain TEXT PRIMARY KEY,
  last_overall TEXT,
  last_sent_at TEXT,
  FOREIGN KEY(domain) REFERENCES domains(name) ON DELETE CASCADE
);
"""

# --- Initialization guard (avoid running schema on every call) ----------------
_INITIALIZED: bool = False


def _connect(db_path: Path = DEFAULT_DB) -> sqlite3.Connection:
    """
    Open a connection with sane defaults:
    - row_factory=sqlite3.Row for dict-like access
    - foreign_keys ON so the declared FKs actually apply
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    cols = set()
    for r in conn.execute(f"PRAGMA table_info({table})").fetchall():
        # r[1] = name
        cols.add(r[1])
    return cols


def _run_migrations(conn: sqlite3.Connection) -> None:
    """Idempotent lightweight migrations to align old DBs with current code."""
    # 1) history: check_name vs check_type/check, created_at vs ts, indexes
    hcols = _table_columns(conn, "history")
    with conn:
        if "check_name" not in hcols:
            conn.execute("ALTER TABLE history ADD COLUMN check_name TEXT")
            hcols.add("check_name")
        # заполняем check_name из старых колонок, если пусто
        if "check_type" in hcols:
            conn.execute("UPDATE history SET check_name = check_type WHERE check_name IS NULL")
        elif "check" in hcols:
            conn.execute("UPDATE history SET check_name = check WHERE check_name IS NULL")

        if "created_at" not in hcols and "ts" in hcols:
            conn.execute("ALTER TABLE history ADD COLUMN created_at TEXT")
            conn.execute("UPDATE history SET created_at = ts WHERE created_at IS NULL")

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_history_domain_check_created "
            "ON history(domain, check_name, created_at)"
        )

    # 2) domain_overrides: data_json vs legacy json
    ocols = _table_columns(conn, "domain_overrides")
    with conn:
        if "data_json" not in ocols:
            conn.execute("ALTER TABLE domain_overrides ADD COLUMN data_json TEXT")
            ocols.add("data_json")
        if "json" in ocols:
            # скопируем данные в новую колонку, если там пусто
            conn.execute(
                "UPDATE domain_overrides SET data_json = json "
                "WHERE (data_json IS NULL OR data_json = '') AND json IS NOT NULL"
            )
        # индекс на случай частых чтений
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_overrides_domain ON domain_overrides(domain)"
        )


def _ensure_initialized(db_path: Path = DEFAULT_DB) -> None:
    """Run schema and migrations once per process lifetime."""
    global _INITIALIZED
    if _INITIALIZED:
        return
    with _connect(db_path) as conn:
        conn.executescript(SCHEMA_SQL)
        _run_migrations(conn)
    _INITIALIZED = True


# -------------------- Domains --------------------------------------------------

def add_domain(name: str) -> None:
    name = (name or "").strip().lower()
    if not name:
        return
    _ensure_initialized()
    with _connect() as conn, conn:
        conn.execute("INSERT OR IGNORE INTO domains(name) VALUES (?)", (name,))


def remove_domain(name: str) -> bool:
    name = (name or "").strip().lower()
    if not name:
        return False
    _ensure_initialized()
    with _connect() as conn, conn:
        cur = conn.execute("DELETE FROM domains WHERE name = ?", (name,))
        return cur.rowcount > 0


def list_domains() -> List[str]:
    """List all domain names in ascending order."""
    _ensure_initialized()
    with _connect() as conn:
        rows = conn.execute("SELECT name FROM domains ORDER BY name").fetchall()
        return [r["name"] for r in rows]


# -------------------- History --------------------------------------------------

def save_history(domain: str, check_name: str, status: Any, message: str, metrics: Dict[str, Any]) -> None:
    """Append a check result to history for a domain."""
    _ensure_initialized()
    domain = (domain or "").strip().lower()
    status_str = getattr(status, "value", str(status))
    with _connect() as conn, conn:
        conn.execute(
            """
            INSERT INTO history(domain, check_name, status, message, metrics_json, created_at)
            VALUES(?,?,?,?,?, datetime('now'))
            """,
            (domain, check_name, status_str, message, json.dumps(metrics, ensure_ascii=False)),
        )


def last_results(domain: str, limit: int = 10) -> List[sqlite3.Row]:
    """Return the N most recent history rows for a domain (newest first)."""
    _ensure_initialized()
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM history WHERE domain = ? ORDER BY id DESC LIMIT ?",
            (domain.lower(), limit),
        ).fetchall()
        return rows


def last_history_for_check(domain: str, check_name: str) -> Optional[sqlite3.Row]:
    """Return the most recent history row for a specific check of a domain."""
    _ensure_initialized()
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM history WHERE domain = ? AND check_name = ? ORDER BY id DESC LIMIT 1",
            (domain.lower(), check_name),
        ).fetchone()
        return row


def minutes_since_last(domain: str, check_name: str) -> Optional[int]:
    """
    Return minutes elapsed since the last history row for (domain, check_name).
    Returns None if no history found or on parsing error.
    """
    row = last_history_for_check(domain, check_name)
    if not row:
        return None
    ts = row["created_at"]
    if not ts:
        return None
    try:
        # SQLite datetime('now') -> 'YYYY-MM-DD HH:MM:SS'
        # datetime.fromisoformat понимает такой формат.
        dt = datetime.fromisoformat(str(ts))
    except ValueError:
        try:
            dt = datetime.strptime(str(ts), "%Y-%m-%d %H:%M:%S")
        except Exception:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    return max(0, int((now - dt).total_seconds() // 60))


# -------------------- WHOIS cache ---------------------------------------------

def clear_whois_cache(db_path: Path = DEFAULT_DB) -> int:
    """
    Clear WHOIS cache (table whois_state). Returns count of deleted rows.
    Returns 0 if the table does not exist.
    """
    _ensure_initialized(db_path)
    with _connect(db_path) as conn:
        try:
            cur = conn.execute("SELECT COUNT(*) FROM whois_state")
            count = int(cur.fetchone()[0])
        except sqlite3.OperationalError:
            return 0
        with conn:
            conn.execute("DELETE FROM whois_state")
        return count


# -------------------- Alerts state --------------------------------------------

def get_alert_state(domain: str) -> Optional[sqlite3.Row]:
    """Read alert state for a domain (last_overall, last_sent_at)."""
    _ensure_initialized()
    with _connect() as conn:
        row = conn.execute(
            "SELECT last_overall, last_sent_at FROM alert_state WHERE domain = ?",
            (domain.lower(),),
        ).fetchone()
        return row


def upsert_alert_state(domain: str, last_overall: str, last_sent_at: Optional[str]) -> None:
    """Insert or update alert state for a domain."""
    _ensure_initialized()
    with _connect() as conn, conn:
        conn.execute(
            """
            INSERT INTO alert_state(domain,last_overall,last_sent_at)
            VALUES(?,?,?)
            ON CONFLICT(domain) DO UPDATE SET
                last_overall=excluded.last_overall,
                last_sent_at=excluded.last_sent_at
            """,
            (domain.lower(), last_overall, last_sent_at),
        )


# -------------------- Domain overrides (per-domain config) --------------------

def get_domain_override(domain: str) -> Optional[dict]:
    """Return override json for domain (dict) or None."""
    _ensure_initialized()
    domain = (domain or "").strip().lower()
    with _connect() as conn:
        # поддержим старые БД, где была колонка 'json'
        row = conn.execute(
            "SELECT data_json FROM domain_overrides WHERE domain = ?",
            (domain,),
        ).fetchone()
        if not row or not row["data_json"]:
            return None
        try:
            return json.loads(row["data_json"])
        except Exception:
            return None


def set_domain_override(domain: str, patch: dict) -> dict:
    """
    Merge patch into current override and persist into domain_overrides.data_json.
    Returns merged dict.
    """
    _ensure_initialized()
    domain = (domain or "").strip().lower()
    current = get_domain_override(domain) or {}

    def _merge(dst, src):
        for k, v in src.items():
            if isinstance(v, dict) and isinstance(dst.get(k), dict):
                _merge(dst[k], v)
            else:
                dst[k] = v

    _merge(current, patch)

    with _connect() as conn, conn:
        conn.execute(
            """
            INSERT INTO domain_overrides(domain, data_json, updated_at)
            VALUES(?, ?, datetime('now'))
            ON CONFLICT(domain) DO UPDATE SET
                data_json=excluded.data_json,
                updated_at=excluded.updated_at
            """,
            (domain, json.dumps(current, ensure_ascii=False)),
        )
    return current


def unset_domain_override(domain: str, key: str | None) -> None:
    _ensure_initialized()
    domain = (domain or "").strip().lower()
    if key is None:
        with _connect() as conn, conn:
            conn.execute("DELETE FROM domain_overrides WHERE domain = ?", (domain,))
        return

    cur = get_domain_override(domain) or {}
    parts = key.split(".")
    ref = cur
    for p in parts[:-1]:
        if not isinstance(ref.get(p), dict):
            # ничего не меняем, если путь не существует
            return
        ref = ref[p]
    ref.pop(parts[-1], None)
    set_domain_override(domain, cur)
