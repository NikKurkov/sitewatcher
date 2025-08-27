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

# --- Single source of truth (SSOT) for DB path --------------------------------
DEFAULT_DB = Path(os.getenv("DATABASE_PATH", "./sitewatcher.db"))

# --- Schema -------------------------------------------------------------------
SCHEMA_SQL = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS domains (
    name TEXT PRIMARY KEY,
    settings_json TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    check_type TEXT NOT NULL,
    status TEXT NOT NULL,
    message TEXT NOT NULL,
    metrics_json TEXT NOT NULL,
    FOREIGN KEY(domain) REFERENCES domains(name)
);
CREATE INDEX IF NOT EXISTS idx_history_domain_id ON history(domain,id);
CREATE INDEX IF NOT EXISTS idx_history_domain_check ON history(domain,check_type);

CREATE TABLE IF NOT EXISTS whois_state (
  domain TEXT PRIMARY KEY,
  snapshot_json TEXT NOT NULL,
  fetched_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS dns_state (
  domain TEXT PRIMARY KEY,
  snapshot_json TEXT NOT NULL,   -- {"ips_v4":[...], "ips_v6":[...]}
  fetched_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS alert_state (
  domain TEXT PRIMARY KEY,
  last_overall TEXT NOT NULL,
  last_sent_at TIMESTAMP
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
    # Enable FK checks per-connection (SQLite default is OFF).
    # If some legacy flows insert history before domain, this may raise.
    # That's desirable: fail fast instead of silently drifting.
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def _ensure_initialized(db_path: Path = DEFAULT_DB) -> None:
    """Run schema once per process lifetime."""
    global _INITIALIZED
    if _INITIALIZED:
        return
    with _connect(db_path) as conn:
        conn.executescript(SCHEMA_SQL)
    _INITIALIZED = True


# -------------------- Domains --------------------------------------------------

def add_domain(name: str, settings: Optional[Dict[str, Any]] = None) -> bool:
    """Insert or replace a domain with optional settings JSON."""
    _ensure_initialized()
    payload = json.dumps(settings or {}, ensure_ascii=False)
    with _connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO domains(name, settings_json) VALUES(?, ?)",
            (name.lower(), payload),
        )
    return True


def remove_domain(name: str) -> bool:
    """Remove a domain. Returns True if a row was deleted."""
    _ensure_initialized()
    with _connect() as conn:
        cur = conn.execute("DELETE FROM domains WHERE name = ?", (name.lower(),))
        return cur.rowcount > 0


def list_domains() -> List[str]:
    """List all domain names in ascending order."""
    _ensure_initialized()
    with _connect() as conn:
        rows = conn.execute("SELECT name FROM domains ORDER BY name").fetchall()
        return [r["name"] for r in rows]


# -------------------- History --------------------------------------------------

def save_history(domain: str, check: str, status: str, message: str, metrics: Dict[str, Any]) -> None:
    """Append a check result to history for a domain."""
    _ensure_initialized()
    with _connect() as conn:
        conn.execute(
            "INSERT INTO history(domain, check_type, status, message, metrics_json) VALUES(?,?,?,?,?)",
            (domain.lower(), check, status, message, json.dumps(metrics, ensure_ascii=False)),
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


def last_history_for_check(domain: str, check_type: str) -> Optional[sqlite3.Row]:
    """Return the most recent history row for a specific check of a domain."""
    _ensure_initialized()
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM history WHERE domain = ? AND check_type = ? ORDER BY id DESC LIMIT 1",
            (domain.lower(), check_type),
        ).fetchone()
        return row


def minutes_since_last(domain: str, check_type: str) -> Optional[int]:
    """
    Return minutes elapsed since the last history row for (domain, check_type).
    Returns None if no history found or on parsing error.
    """
    row = last_history_for_check(domain, check_type)
    if not row:
        return None
    try:
        from datetime import datetime, timezone
        ts = row["ts"]  # 'YYYY-MM-DD HH:MM:SS'
        dt = datetime.fromisoformat(str(ts))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        return int((now - dt).total_seconds() // 60)
    except Exception:
        return None


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
    with _connect() as conn:
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
# Separate table to patch per-domain behavior without touching global config.

def _ensure_overrides_table() -> None:
    """Create domain_overrides table if missing."""
    _ensure_initialized()
    with _connect() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS domain_overrides (
            domain TEXT PRIMARY KEY,
            json   TEXT NOT NULL,
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
        """)


def _deep_merge(dst, src):
    """
    Deep-merge dictionaries. Scalars/lists are replaced fully.
    Returns a new dict (dst is not mutated).
    """
    if not isinstance(src, dict):
        return src
    if not isinstance(dst, dict):
        return src
    out = dict(dst)
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def get_domain_override(domain: str) -> dict:
    """Return per-domain override JSON (dict) or empty dict if not set."""
    _ensure_overrides_table()
    with _connect() as conn:
        row = conn.execute(
            "SELECT json FROM domain_overrides WHERE domain = ?",
            (domain.lower(),)
        ).fetchone()
        if not row:
            return {}
        try:
            return json.loads(row["json"]) or {}
        except Exception:
            return {}


def _write_domain_override(domain: str, data: dict) -> dict:
    """Persist override JSON as-is (no merge). Returns the saved dict."""
    with _connect() as conn:
        conn.execute(
            "INSERT INTO domain_overrides(domain,json,updated_at) VALUES(?,?,CURRENT_TIMESTAMP) "
            "ON CONFLICT(domain) DO UPDATE SET json=excluded.json, updated_at=CURRENT_TIMESTAMP",
            (domain.lower(), json.dumps(data or {}, ensure_ascii=False)),
        )
    return data or {}


def set_domain_override(domain: str, patch: dict) -> dict:
    """Merge patch with existing override and persist. Returns merged dict."""
    _ensure_overrides_table()
    current = get_domain_override(domain)
    merged = _deep_merge(current, patch or {})
    return _write_domain_override(domain, merged)


def unset_domain_override(domain: str, keypath: str | None = None) -> None:
    """
    Remove a key by dotted path (e.g., 'checks.http_basic') or the whole override
    if keypath is None or empty.
    """
    _ensure_overrides_table()

    # Delete entire record.
    if not keypath:
        with _connect() as conn:
            conn.execute("DELETE FROM domain_overrides WHERE domain = ?", (domain.lower(),))
        return

    # Partial delete by key path.
    data = get_domain_override(domain)
    parts = [p for p in keypath.split(".") if p]
    if not parts:
        return

    node = data
    for p in parts[:-1]:
        if not isinstance(node, dict) or p not in node:
            return
        node = node[p]

    last = parts[-1]
    if isinstance(node, dict) and last in node:
        node.pop(last, None)
        # If empty => drop the row entirely, else rewrite JSON.
        if not data:
            with _connect() as conn:
                conn.execute("DELETE FROM domain_overrides WHERE domain = ?", (domain.lower(),))
        else:
            _write_domain_override(domain, data)
