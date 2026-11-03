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
            'FROM check_activity WHERE owner_id=? '
            'ORDER BY COALESCE(finished_at, started_at) DESC, id DESC LIMIT ?',
            (owner_id, limit),
        ).fetchall()
    return [dict(row) for row in reversed(rows)]


def domain_roster(owner_id: int) -> list[dict]:
    """All owned domains, including those outside the bounded lifecycle feed.

    The color describes the last saved individual check, not aggregate availability.
    Only public display fields are selected; diagnostics never enter this DTO.
    """
    with closing(_connect('ro')) as conn:
        rows = conn.execute(
            'SELECT d.name, COALESCE(h.status, \'UNKNOWN\') AS status, h.check_name '
            'FROM domains d LEFT JOIN history h ON h.id=('
            'SELECT MAX(id) FROM history WHERE owner_id=d.owner_id AND domain=d.name) '
            'WHERE d.owner_id=? ORDER BY d.name', (owner_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def published_http(owner_id: int, names: list[str]) -> tuple[list[dict], list[dict]]:
    """Read only published HTTP lifecycle rows, applying scope before the feed limit."""
    if not names:
        return [], []
    placeholders = ','.join('?' for _ in names)
    with closing(_connect('ro')) as conn:
        domains = conn.execute(
            "SELECT d.name, COALESCE(h.status, 'UNKNOWN') AS status FROM domains d "
            "LEFT JOIN history h ON h.id=(SELECT MAX(id) FROM history "
            "WHERE owner_id=d.owner_id AND domain=d.name AND check_name='http_basic') "
            f'WHERE d.owner_id=? AND d.name IN ({placeholders}) ORDER BY d.name',
            (owner_id, *names),
        ).fetchall()
        events = conn.execute(
            'SELECT a.id, a.domain, a.check_name, a.started_at, a.finished_at, a.status, '
            'a.elapsed_ms FROM check_activity a JOIN domains d '
            'ON d.owner_id=a.owner_id AND d.name=a.domain '
            f"WHERE a.owner_id=? AND a.check_name='http_basic' AND d.name IN ({placeholders}) "
            'ORDER BY COALESCE(a.finished_at, a.started_at) DESC, a.id DESC LIMIT 100',
            (owner_id, *names),
        ).fetchall()
    return [dict(row) for row in reversed(events)], [dict(row) for row in domains]
