# sitewatcher/storage.py (v2)
from __future__ import annotations

import json
import hashlib
import os
import sqlite3
import logging
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

DEFAULT_DB = Path(os.getenv("DATABASE_PATH", "./sitewatcher.db"))

SCHEMA_SQL = """
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS users (
  telegram_id   INTEGER PRIMARY KEY,
  username      TEXT,
  first_name    TEXT,
  last_name     TEXT,
  alert_chat_id INTEGER,
  alerts_enabled INTEGER DEFAULT 1,
  created_at    TEXT DEFAULT (datetime('now')),
  updated_at    TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS domains (
  owner_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  favorite INTEGER NOT NULL DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  PRIMARY KEY(owner_id, name),
  FOREIGN KEY(owner_id) REFERENCES users(telegram_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS domain_overrides (
  owner_id INTEGER NOT NULL,
  domain TEXT NOT NULL,
  data_json TEXT NOT NULL,
  updated_at TEXT DEFAULT (datetime('now')),
  PRIMARY KEY(owner_id, domain),
  FOREIGN KEY(owner_id, domain) REFERENCES domains(owner_id, name) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS domain_routes (
  owner_id INTEGER NOT NULL,
  domain TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  state TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  result_json TEXT,
  PRIMARY KEY(owner_id, domain),
  FOREIGN KEY(owner_id, domain) REFERENCES domains(owner_id, name) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_id INTEGER NOT NULL,
  domain TEXT NOT NULL,
  check_name TEXT,
  status TEXT NOT NULL,
  message TEXT NOT NULL,
  metrics_json TEXT,
  source TEXT NOT NULL DEFAULT 'legacy',
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY(owner_id, domain) REFERENCES domains(owner_id, name) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_history_owner_domain_check_created
  ON history(owner_id, domain, check_name, created_at);

CREATE INDEX IF NOT EXISTS idx_history_owner_domain_check_id
  ON history(owner_id, domain, check_name, id DESC);

CREATE TABLE IF NOT EXISTS check_activity (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_id INTEGER NOT NULL,
  domain TEXT NOT NULL,
  check_name TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  status TEXT NOT NULL,
  elapsed_ms INTEGER,
  FOREIGN KEY(owner_id, domain) REFERENCES domains(owner_id, name) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_check_activity_owner_id ON check_activity(owner_id, id DESC);

CREATE TABLE IF NOT EXISTS whois_state (
  domain TEXT PRIMARY KEY,
  snapshot_json TEXT NOT NULL,
  fetched_at TEXT NOT NULL,
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS dns_state (
  domain TEXT PRIMARY KEY,
  snapshot_json TEXT NOT NULL,
  fetched_at TEXT NOT NULL,
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS owner_dns_state (
  owner_id INTEGER NOT NULL,
  domain TEXT NOT NULL,
  snapshot_json TEXT NOT NULL,
  fetched_at TEXT NOT NULL,
  updated_at TEXT DEFAULT (datetime('now')),
  PRIMARY KEY(owner_id, domain)
);

CREATE TABLE IF NOT EXISTS alert_state (
  owner_id INTEGER NOT NULL,
  domain TEXT NOT NULL,
  last_overall TEXT,
  last_sent_at TEXT,
  PRIMARY KEY(owner_id, domain),
  FOREIGN KEY(owner_id, domain) REFERENCES domains(owner_id, name) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS hx_owner_created ON history(owner_id, created_at DESC);
CREATE INDEX IF NOT EXISTS hx_owner_domain_created ON history(owner_id, domain, created_at DESC);
"""

_INITIALIZED_PATHS: set[Path] = set()

log = logging.getLogger(__name__)


def _connect(db_path: Path | None = None) -> sqlite3.Connection:
    # Use WAL for better concurrency with jobs + handlers, and longer busy timeout.
    conn = sqlite3.connect(
        db_path or DEFAULT_DB,
        isolation_level=None,          # autocommit; writes use explicit BEGIN IMMEDIATE
        timeout=30.0,                  # 30s busy timeout at driver-level
        check_same_thread=False,       # safer when used across async contexts/threads
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA busy_timeout=3000;")   # 3s at SQL level
    return conn


@contextmanager
def _write_connection():
    """Serialize read-modify-write operations and roll back every write on failure."""
    with closing(_connect()) as conn:
        conn.execute("BEGIN IMMEDIATE")
        with conn:
            yield conn


def _ensure_initialized(db_path: Path | None = None) -> None:
    db_path = db_path or DEFAULT_DB
    if db_path in _INITIALIZED_PATHS and db_path.exists():
        return
    with closing(_connect(db_path)) as conn:
        conn.executescript(SCHEMA_SQL)
        # Serialize the additive migration across bot/web workers starting together.
        conn.execute("BEGIN IMMEDIATE")
        with conn:
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(history)")}
            if "source" not in columns:
                conn.execute("ALTER TABLE history ADD COLUMN source TEXT NOT NULL DEFAULT 'legacy'")
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(domains)")}
            if "favorite" not in columns:
                conn.execute("ALTER TABLE domains ADD COLUMN favorite INTEGER NOT NULL DEFAULT 0")
    _INITIALIZED_PATHS.add(db_path)


# ---------- users ----------

def ensure_user(
    telegram_id: int,
    username: str | None = None,
    first_name: str | None = None,
    last_name: str | None = None,
    alert_chat_id: int | None = None
) -> None:
    _ensure_initialized()
    with _write_connection() as conn:
        conn.execute(
            """
            INSERT INTO users(telegram_id, username, first_name, last_name, alert_chat_id)
            VALUES(?,?,?,?,?)
            ON CONFLICT(telegram_id) DO UPDATE SET
              username     = COALESCE(excluded.username,  users.username),
              first_name   = COALESCE(excluded.first_name,users.first_name),
              last_name    = COALESCE(excluded.last_name, users.last_name),
              alert_chat_id= COALESCE(excluded.alert_chat_id, users.alert_chat_id),
              updated_at   = datetime('now')
            """,
            (int(telegram_id), username, first_name, last_name, alert_chat_id),
        )


def list_users() -> List[int]:
    _ensure_initialized()
    with closing(_connect()) as conn:
        rows = conn.execute("SELECT telegram_id FROM users ORDER BY telegram_id").fetchall()
        return [int(r[0]) for r in rows]


def set_user_alert_chat_id(owner_id: int, chat_id: int) -> None:
    _ensure_initialized()
    with _write_connection() as conn:
        conn.execute(
            "UPDATE users SET alert_chat_id=?, updated_at=datetime('now') WHERE telegram_id=?",
            (int(chat_id), int(owner_id)),
        )


def get_user_alert_chat_id(owner_id: int) -> Optional[int]:
    _ensure_initialized()
    with closing(_connect()) as conn:
        row = conn.execute("SELECT alert_chat_id FROM users WHERE telegram_id=?", (int(owner_id),)).fetchone()
        return int(row[0]) if row and row[0] is not None else None


def is_user_alerts_enabled(owner_id: int) -> bool:
    _ensure_initialized()
    with closing(_connect()) as conn:
        row = conn.execute(
            "SELECT alerts_enabled FROM users WHERE telegram_id=?",
            (int(owner_id),)
        ).fetchone()
        if not row or row[0] is None:
            return True  # default ON if user row missing
        return bool(int(row[0]))


def set_user_alerts_enabled(owner_id: int, enabled: bool) -> None:
    _ensure_initialized()
    with _write_connection() as conn:
        # ensure user row exists
        conn.execute("INSERT OR IGNORE INTO users(telegram_id) VALUES(?)", (int(owner_id),))
        conn.execute(
            "UPDATE users SET alerts_enabled=?, updated_at=datetime('now') WHERE telegram_id=?",
            (1 if enabled else 0, int(owner_id))
        )


# ---------- domains ----------

def add_domain(owner_id: int, name: str) -> None:
    _ensure_initialized()
    name = (name or "").strip().lower()
    if not name:
        return
    with _write_connection() as conn:
        # страховка от FK: создаём пользователя, если его ещё нет
        conn.execute("INSERT OR IGNORE INTO users(telegram_id) VALUES (?)", (int(owner_id),))
        conn.execute(
            "INSERT OR IGNORE INTO domains(owner_id, name) VALUES(?,?)",
            (int(owner_id), name),
        )


def remove_domain(owner_id: int, name: str) -> bool:
    _ensure_initialized()
    name = (name or "").strip().lower()
    if not name:
        return False
    with _write_connection() as conn:
        cur = conn.execute("DELETE FROM domains WHERE owner_id=? AND name=?", (int(owner_id), name))
        return cur.rowcount > 0


def set_domain_favorite(owner_id: int, name: str, favorite: bool) -> bool:
    """Set an existing owned domain's display preference without touching monitoring settings."""
    _ensure_initialized()
    with _write_connection() as conn:
        result = conn.execute("UPDATE domains SET favorite=? WHERE owner_id=? AND name=?",
                              (int(favorite), int(owner_id), (name or '').strip().lower()))
        return result.rowcount > 0


def list_domains(owner_id: int) -> List[str]:
    _ensure_initialized()
    with closing(_connect()) as conn:
        rows = conn.execute(
            "SELECT name FROM domains WHERE owner_id=? ORDER BY name",
            (int(owner_id),),
        ).fetchall()
        return [r["name"] for r in rows]


def domain_exists(owner_id: int, name: str) -> bool:
    _ensure_initialized()
    name = (name or "").strip().lower()
    if not name:
        return False
    with closing(_connect()) as conn:
        row = conn.execute(
            "SELECT 1 FROM domains WHERE owner_id=? AND name=? LIMIT 1",
            (int(owner_id), name),
        ).fetchone()
        return row is not None

# ---------- history ----------

def save_history(
    owner_id: int,
    domain: str,
    check_name: str,
    status: Any,
    message: str,
    metrics: Dict[str, Any],
    *,
    create_missing: bool = True,
    source: str = "legacy",
) -> None:
    _save_history_rows(
        owner_id, domain, [(check_name, status, message, metrics)],
        create_missing=create_missing, source=source,
    )


def save_histories(
    owner_id: int, domain: str, results: list, *, create_missing: bool = True,
    source: str = "legacy",
) -> None:
    """Persist a domain run in one SQLite transaction."""
    _save_history_rows(owner_id, domain, [
        (result.check, result.status, result.message, result.metrics)
        for result in results if not getattr(result, "cached", False)
    ], create_missing=create_missing, source=source)


def _save_history_rows(
    owner_id: int, domain: str, results: list, *, create_missing: bool, source: str,
) -> None:
    if source not in {"legacy", "scheduled", "manual"}:
        raise ValueError("Invalid history source")
    _ensure_initialized()
    domain = (domain or "").strip().lower()
    if not domain or not results:
        return
    rows = [
        (int(owner_id), domain, check, getattr(status, "value", str(status)), message,
         json.dumps(metrics, ensure_ascii=False, default=str), source)
        for check, status, message, metrics in results
    ]
    with _write_connection() as conn:
        if create_missing:
            conn.execute("INSERT OR IGNORE INTO users(telegram_id) VALUES (?)", (int(owner_id),))
            conn.execute(
                "INSERT OR IGNORE INTO domains(owner_id, name) VALUES(?,?)", (int(owner_id), domain),
            )
        elif not conn.execute(
            "SELECT 1 FROM domains WHERE owner_id=? AND name=?", (int(owner_id), domain),
        ).fetchone():
            return
        conn.executemany(
            "INSERT INTO history(owner_id, domain, check_name, status, message, "
            "metrics_json, source, created_at) "
            "VALUES (?,?,?,?,?,?,?,datetime('now'))",
            rows,
        )
    log.debug("history.saved", extra={"owner_id": owner_id, "domain": domain, "count": len(rows)})


def last_results(owner_id: int, domain: str, limit: int = 10) -> List[sqlite3.Row]:
    _ensure_initialized()
    with closing(_connect()) as conn:
        rows = conn.execute(
            "SELECT * FROM history WHERE owner_id=? AND domain=? ORDER BY id DESC LIMIT ?",
            (int(owner_id), (domain or "").lower(), int(limit)),
        ).fetchall()
        return rows


def last_history_for_check(owner_id: int, domain: str, check_name: str) -> Optional[sqlite3.Row]:
    _ensure_initialized()
    with closing(_connect()) as conn:
        row = conn.execute(
            "SELECT * FROM history WHERE owner_id=? AND domain=? AND check_name=? ORDER BY id DESC LIMIT 1",
            (int(owner_id), (domain or "").lower(), check_name),
        ).fetchone()
        log.debug(
            "history.last",
            extra={
                "event": "history.last",
                "owner_id": int(owner_id),
                "domain": (domain or "").lower(),
                "check": check_name,
                "found": bool(row),
            },
        )
        return row


def minutes_since_last(owner_id: int, domain: str, check_name: str) -> Optional[int]:
    row = last_history_for_check(owner_id, domain, check_name)
    if not row:
        return None
    ts = row["created_at"]
    if not ts:
        return None

    try:
        dt = datetime.fromisoformat(str(ts))
    except ValueError:
        return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)

    now = datetime.now(timezone.utc)
    age_min = max(0, int((now - dt).total_seconds() // 60))
    log.debug(
        "history.age_min",
        extra={
            "event": "history.age_min",
            "owner_id": int(owner_id),
            "domain": (domain or "").lower(),
            "check": check_name,
            "minutes": age_min,
        },
    )
    return age_min



def is_current_observation(domain: str, metrics_json: str | None) -> bool:
    """Keep a renamed monitor's archived host measurements out of its current state."""
    try:
        metrics = json.loads(metrics_json or '{}')
    except (ValueError, TypeError):
        return True  # Existing consumers classify malformed legacy metrics themselves.
    return not isinstance(metrics, dict) or metrics.get('original_domain', domain) == domain


def last_check_ages(owner_id: int, domain: str) -> dict[str, float]:
    """Minutes since each check's latest result, from a single owner-scoped query."""
    _ensure_initialized()
    with closing(_connect()) as conn:
        rows = conn.execute(
            "SELECT h.check_name,h.created_at,h.metrics_json FROM history h JOIN "
            "(SELECT MAX(id) AS id FROM history WHERE owner_id=? AND domain=? "
            "GROUP BY check_name) latest ON h.id=latest.id",
            (int(owner_id), domain.lower()),
        ).fetchall()
    now = datetime.now(timezone.utc)
    ages = {}
    for name, timestamp, metrics in rows:
        if not name or not timestamp or not is_current_observation(domain, metrics):
            continue
        try:
            observed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            if observed.tzinfo is None:
                observed = observed.replace(tzinfo=timezone.utc)
            ages[name] = max(0.0, (now - observed).total_seconds() / 60)
        except ValueError:
            continue
    return ages


def latest_check_results(owner_id: int, domain: str) -> dict[str, sqlite3.Row]:
    """Latest recorded result per check for one owner's domain."""
    _ensure_initialized()
    with closing(_connect()) as conn:
        rows = conn.execute(
            "SELECT h.* FROM history h JOIN ("
            "SELECT check_name, MAX(id) AS latest_id FROM history "
            "WHERE owner_id=? AND domain=? GROUP BY check_name"
            ") latest ON h.id=latest.latest_id",
            (int(owner_id), domain.lower()),
        ).fetchall()
    return {row["check_name"]: row for row in rows
            if is_current_observation(domain, row["metrics_json"])}


# ---------- WHOIS cache (shared) ----------

def clear_whois_cache(db_path: Path = DEFAULT_DB) -> int:
    _ensure_initialized(db_path)
    with closing(_connect(db_path)) as conn:
        try:
            cur = conn.execute("SELECT COUNT(*) FROM whois_state")
            count = int(cur.fetchone()[0])
        except sqlite3.OperationalError:
            return 0
        with conn:
            conn.execute("DELETE FROM whois_state")
        return count


# ---------- Alerts ----------

def get_alert_state(owner_id: int, domain: str) -> Optional[sqlite3.Row]:
    _ensure_initialized()
    with closing(_connect()) as conn:
        row = conn.execute(
            "SELECT last_overall, last_sent_at FROM alert_state WHERE owner_id=? AND domain=?",
            (int(owner_id), (domain or "").lower()),
        ).fetchone()
        return row


def upsert_alert_state(owner_id: int, domain: str, last_overall: str, last_sent_at: Optional[str]) -> None:
    _ensure_initialized()
    domain = (domain or "").strip().lower()
    if not domain:
        return
    with _write_connection() as conn:
        if not conn.execute(
            "SELECT 1 FROM domains WHERE owner_id=? AND name=?", (int(owner_id), domain),
        ).fetchone():
            return
        conn.execute(
            """
            INSERT INTO alert_state(owner_id,domain,last_overall,last_sent_at)
            VALUES(?,?,?,?)
            ON CONFLICT(owner_id,domain) DO UPDATE SET
              last_overall=excluded.last_overall,
              last_sent_at=excluded.last_sent_at
            """,
            (int(owner_id), domain, last_overall, last_sent_at),
        )


# ---------- Overrides ----------

class InvalidDomainOverride(ValueError):
    """Stored settings cannot safely be used or merged."""


def _read_domain_override(conn: sqlite3.Connection, owner_id: int, domain: str) -> dict | None:
    row = conn.execute(
        "SELECT data_json FROM domain_overrides WHERE owner_id=? AND domain=?",
        (int(owner_id), domain),
    ).fetchone()
    if not row:
        return None
    try:
        data = json.loads(row["data_json"])
        if isinstance(data, dict):
            return data
    except (TypeError, ValueError, RecursionError):
        pass
    raise InvalidDomainOverride(
        "Invalid stored domain settings. Reset with /cfg_unset <domain>."
    ) from None


def get_domain_override(owner_id: int, domain: str) -> Optional[dict]:
    _ensure_initialized()
    domain = (domain or "").strip().lower()
    with closing(_connect()) as conn:
        return _read_domain_override(conn, owner_id, domain)


def _store_domain_override(conn: sqlite3.Connection, owner_id: int, domain: str, data: dict):
    conn.execute(
        """
        INSERT INTO domain_overrides(owner_id, domain, data_json, updated_at)
        VALUES(?, ?, ?, datetime('now'))
        ON CONFLICT(owner_id,domain) DO UPDATE SET
          data_json=excluded.data_json,
          updated_at=excluded.updated_at
        """,
        (int(owner_id), domain, json.dumps(data, ensure_ascii=False)),
    )


def domain_override_revision(data: dict | None) -> str:
    """Fingerprint an override for optimistic form writes without exposing its values."""
    payload = json.dumps(data or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def set_domain_override(
    owner_id: int, domain: str, patch: dict, *, replace: bool = False,
    create_missing: bool = False, create_only: bool = False,
    expected_revision: str | None = None,
) -> dict:
    """Atomically merge settings; explicit creation includes the domain in the same transaction."""
    _ensure_initialized()
    domain = (domain or "").strip().lower()
    if not domain:
        return {}

    def _merge(dst, src):
        for k, v in src.items():
            if isinstance(v, dict) and isinstance(dst.get(k), dict):
                _merge(dst[k], v)
            else:
                dst[k] = v

    with _write_connection() as conn:
        exists = conn.execute(
            "SELECT 1 FROM domains WHERE owner_id=? AND name=?", (int(owner_id), domain),
        ).fetchone()
        if create_only and exists:
            raise ValueError("Domain already exists")
        if expected_revision is not None:
            if not exists or domain_override_revision(
                _read_domain_override(conn, owner_id, domain)
            ) != expected_revision:
                raise ValueError("Settings changed; reload this page before saving")
        if create_missing:
            conn.execute("INSERT OR IGNORE INTO users(telegram_id) VALUES(?)", (int(owner_id),))
            conn.execute("INSERT OR IGNORE INTO domains(owner_id,name) VALUES(?,?)",
                         (int(owner_id), domain))
        if not conn.execute(
            "SELECT 1 FROM domains WHERE owner_id=? AND name=?", (int(owner_id), domain),
        ).fetchone():
            return {}
        current = {} if replace else (_read_domain_override(conn, owner_id, domain) or {})
        _merge(current, patch)
        _store_domain_override(conn, owner_id, domain, current)
    return current



def rename_domain(owner_id: int, old: str, new: str, override: dict, *,
                  expected_revision: str) -> None:
    """Move one owned monitor atomically, retaining history/order and resetting host state."""
    _ensure_initialized()
    with _write_connection() as conn:
        row = conn.execute('SELECT * FROM domains WHERE owner_id=? AND name=?',
                           (owner_id, old)).fetchone()
        if row is None:
            raise ValueError('Domain not found')
        if domain_override_revision(_read_domain_override(conn, owner_id, old)) != expected_revision:
            raise ValueError('Settings changed; reload this page before saving')
        if conn.execute('SELECT 1 FROM domains WHERE owner_id=? AND name=?',
                        (owner_id, new)).fetchone():
            raise ValueError('Domain already exists')
        conn.execute('INSERT INTO domains(owner_id,name,favorite,created_at) VALUES(?,?,?,?)',
                     (owner_id, new, row['favorite'], row['created_at']))
        # Keep historical measurements, but never use the previous host's last result as cache.
        latest = conn.execute('SELECT id,metrics_json FROM history WHERE id IN '
                              '(SELECT MAX(id) FROM history WHERE owner_id=? AND domain=? '
                              'GROUP BY check_name)', (owner_id, old)).fetchall()
        for result in latest:
            try:
                metrics = json.loads(result['metrics_json'] or '{}')
            except (ValueError, TypeError):
                metrics = {}
            if not isinstance(metrics, dict):
                metrics = {}
            metrics.setdefault('original_domain', old)
            conn.execute('UPDATE history SET metrics_json=? WHERE id=?',
                         (json.dumps(metrics), result['id']))
        conn.execute('UPDATE history SET domain=? WHERE owner_id=? AND domain=?',
                     (new, owner_id, old))
        _store_domain_override(conn, owner_id, new, override)
        if conn.execute("SELECT 1 FROM sqlite_master WHERE name='webapp_workspace'").fetchone():
            workspace = conn.execute('SELECT domain_order,public_domains FROM webapp_workspace '
                                     'WHERE owner_id=?', (owner_id,)).fetchone()
            if workspace:
                for field in ('domain_order', 'public_domains'):
                    names = json.loads(workspace[field])
                    if isinstance(names, list):
                        names = list(dict.fromkeys(new if name == old else name for name in names))
                        conn.execute(f'UPDATE webapp_workspace SET {field}=? WHERE owner_id=?',
                                     (json.dumps(names), owner_id))
        conn.execute('DELETE FROM owner_dns_state WHERE owner_id=? AND domain IN (?,?)',
                     (owner_id, old, new))
        # Cascades discard old route/activity/alert state rather than attaching it to another host.
        conn.execute('DELETE FROM domains WHERE owner_id=? AND name=?', (owner_id, old))

def create_domains_with_overrides(owner_id: int, overrides: dict[str, dict]) -> None:
    """Create a validated batch for one owner, rolling back on conflicts or write errors."""
    _ensure_initialized()
    with _write_connection() as conn:
        conn.execute("INSERT OR IGNORE INTO users(telegram_id) VALUES(?)", (int(owner_id),))
        for domain, data in overrides.items():
            if conn.execute("SELECT 1 FROM domains WHERE owner_id=? AND name=?",
                            (int(owner_id), domain)).fetchone():
                raise ValueError("Domain already exists")
            conn.execute("INSERT INTO domains(owner_id,name) VALUES(?,?)", (int(owner_id), domain))
            _store_domain_override(conn, owner_id, domain, data)


def _domain_reset_revision(conn: sqlite3.Connection, owner_id: int, domain: str) -> str:
    row = conn.execute(
        "SELECT data_json FROM domain_overrides WHERE owner_id=? AND domain=?",
        (int(owner_id), domain),
    ).fetchone()
    # Fingerprint the raw value so even malformed JSON can be reset without exposing it.
    return hashlib.sha256(repr(row[0] if row else None).encode("utf-8")).hexdigest()


def domain_reset_revision(owner_id: int, domain: str) -> str:
    _ensure_initialized()
    with closing(_connect()) as conn:
        return _domain_reset_revision(conn, owner_id, domain)


def unset_domain_override(
    owner_id: int, domain: str, key: str | None, *, expected_revision: str | None = None,
) -> None:
    _ensure_initialized()
    domain = (domain or "").strip().lower()
    if not domain:
        return
    with _write_connection() as conn:
        if expected_revision is not None and (
            not conn.execute("SELECT 1 FROM domains WHERE owner_id=? AND name=?",
                             (int(owner_id), domain)).fetchone()
            or _domain_reset_revision(conn, owner_id, domain) != expected_revision
        ):
            raise ValueError("Settings changed; reload this page before saving")
        if key is None:
            conn.execute(
                "DELETE FROM domain_overrides WHERE owner_id=? AND domain=?", (int(owner_id), domain),
            )
            return
        current = _read_domain_override(conn, owner_id, domain)
        if current is None:
            return
        parts = key.split(".")
        ref = current
        for part in parts[:-1]:
            if not isinstance(ref.get(part), dict):
                return
            ref = ref[part]
        ref.pop(parts[-1], None)
        _store_domain_override(conn, owner_id, domain, current)


def iter_history(
    owner_id: int,
    domain: str | None = None,
    check: str | None = None,
    statuses: set[str] | None = None,
    since: datetime | None = None,
    limit: int = 20,
    until: datetime | None = None,
):
    """
    Yield last history rows for the owner with optional filters.
    Returned rows are sqlite3.Row with keys:
      id, domain, check, status, message, metrics_json, created_at
    Ordered by created_at DESC, id DESC, limited by 'limit'.
    """
    _ensure_initialized()
    conn = _connect()
    try:
        where = ["owner_id = ?"]
        args: list = [int(owner_id)]

        if domain:
            where.append("domain = ?")
            args.append(domain.lower())

        if check:
            where.append("check_name = ?")
            args.append(check)

        if statuses:
            qs = ",".join("?" for _ in statuses)
            where.append(f"UPPER(status) IN ({qs})")
            args.extend(s.upper() for s in statuses)

        for bound, operator in ((since, ">="), (until, "<")):
            if bound is not None:
                where.append(f"created_at {operator} ?")
                # History uses SQLite UTC timestamps with a space, not ISO's T separator.
                cutoff = bound if bound.tzinfo is not None else bound.replace(tzinfo=timezone.utc)
                args.append(cutoff.astimezone(timezone.utc).replace(tzinfo=None).isoformat(sep=" "))

        sql = (
            'SELECT id, domain, check_name AS "check", status, message, metrics_json, created_at '
            "FROM history "
            f"WHERE {' AND '.join(where)} "
            "ORDER BY created_at DESC, id DESC "
            "LIMIT ?"
        )
        args.append(int(limit))
        cur = conn.execute(sql, tuple(args))
        rows = cur.fetchall()
        for row in rows:
            yield row
    finally:
        conn.close()


# ---------- Maintenance: history retention & DB care ----------

def cleanup_history(retention_days: int, batch_size: int = 10_000) -> int:
    """
    Delete history rows older than 'retention_days' days, in batches.
    Returns total deleted rows. Uses TEXT DATETIME format: created_at < datetime('now', ?).
    """
    batch_size = int(batch_size)
    if batch_size <= 0:
        raise ValueError("batch_size must be positive")
    _ensure_initialized()
    retention_days = max(0, int(retention_days))
    cutoff = f"-{retention_days} days"
    total_deleted = 0

    with closing(_connect()) as conn:
        while True:
            # Batched delete by rowid to avoid long-running write locks
            cur = conn.execute(
                """
                DELETE FROM history
                WHERE rowid IN (
                    SELECT rowid FROM history
                    WHERE created_at < datetime('now', ?)
                    LIMIT ?
                )
                """,
                (cutoff, int(batch_size)),
            )
            deleted = cur.rowcount or 0
            total_deleted += deleted
            if deleted < batch_size:
                break

    log.info(
        "history.cleanup",
        extra={"event": "history.cleanup", "retention_days": retention_days, "deleted": total_deleted},
    )
    return total_deleted


def vacuum_and_optimize() -> None:
    """
    Run VACUUM and PRAGMA optimize to reclaim space and refresh stats.
    Safe to call occasionally (e.g., weekly). Autocommit is enabled.
    """
    _ensure_initialized()
    with closing(_connect()) as conn:
        # VACUUM cannot run inside a transaction; isolation_level=None ensures autocommit.
        conn.execute("VACUUM")
        conn.execute("PRAGMA optimize")
    log.info("db.vacuum.optimize", extra={"event": "db.vacuum.optimize"})
