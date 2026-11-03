"""Short-lived check lifecycle telemetry shared by workers and the web process.

Activity never replaces history. Writes are best effort and must not create storage
or prevent monitoring when the database is unavailable or an older schema is present.
"""
from contextlib import closing
from datetime import datetime, timezone
import sqlite3

from . import storage


def _connect(mode: str) -> sqlite3.Connection:
    conn = sqlite3.connect(storage.DEFAULT_DB.resolve().as_uri() + '?mode=' + mode,
                           uri=True, timeout=0.1)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys=ON')
    return conn


def start(owner_id: int, domain: str, check_name: str) -> int | None:
    """Record an actual probe start only for an existing owner/domain."""
    try:
        with closing(_connect('rw')) as conn, conn:
            cursor = conn.execute(
                'INSERT INTO check_activity(owner_id, domain, check_name, started_at, status) '
                "SELECT ?, ?, ?, ?, 'UNKNOWN' WHERE EXISTS "
                '(SELECT 1 FROM domains WHERE owner_id=? AND name=?)',
                (owner_id, domain, check_name, datetime.now(timezone.utc).isoformat(),
                 owner_id, domain),
            )
            if not cursor.rowcount:
                return None
            event_id = cursor.lastrowid
            conn.execute(
                'DELETE FROM check_activity WHERE owner_id=? AND id NOT IN '
                '(SELECT id FROM check_activity WHERE owner_id=? ORDER BY id DESC LIMIT 1000)',
                (owner_id, owner_id),
            )
            return event_id
    except (sqlite3.Error, OSError):
        return None


def finish(event_id: int | None, status: str, elapsed_ms: int) -> None:
    if event_id is None:
        return
    try:
        with closing(_connect('rw')) as conn, conn:
            conn.execute(
                'UPDATE check_activity SET finished_at=?, status=?, elapsed_ms=? '
                'WHERE id=? AND finished_at IS NULL',
                (datetime.now(timezone.utc).isoformat(), status, elapsed_ms, event_id),
            )
    except (sqlite3.Error, OSError):
        pass


def recent(owner_id: int, *, limit: int = 100) -> list[dict]:
    """Read only; callers handle unavailable storage without initializing it."""
    if not 1 <= limit <= 1000:
        raise ValueError('Invalid activity limit')
    with closing(_connect('ro')) as conn:
        rows = conn.execute(
            'SELECT id, domain, check_name, started_at, finished_at, status, elapsed_ms '
            'FROM check_activity WHERE owner_id=? ORDER BY id DESC LIMIT ?',
            (owner_id, limit),
        ).fetchall()
    return [dict(row) for row in reversed(rows)]
