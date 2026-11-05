"""Durable RKN refresh lease, fencing and provider failure cooldown."""
from contextlib import closing, contextmanager
from pathlib import Path
import sqlite3
import time
import uuid

LEASE_SECONDS = 600
RETRY_SECONDS = 30 * 60


class RefreshLeaseLost(RuntimeError):
    """A different process owns publication rights or the lease expired."""


class RefreshState:
    def __init__(self, index: Path):
        self.path = index.with_name(index.name + '.refresh.sqlite3')

    @contextmanager
    def transaction(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.path, timeout=60)) as con, con:
            con.execute('BEGIN IMMEDIATE')
            con.execute('CREATE TABLE IF NOT EXISTS refresh ('
                        'id INTEGER PRIMARY KEY CHECK(id=1), token TEXT, lease REAL NOT NULL, '
                        'failures INTEGER NOT NULL, retry_at REAL NOT NULL)')
            con.execute('INSERT OR IGNORE INTO refresh VALUES (1,NULL,0,0,0)')
            yield con

    def claim(self) -> str | None:
        now = time.time()
        with self.transaction() as con:
            token, lease, _, retry = con.execute('SELECT token,lease,failures,retry_at '
                                                'FROM refresh WHERE id=1').fetchone()
            if lease > now or retry > now:
                return None
            token = uuid.uuid4().hex
            con.execute('UPDATE refresh SET token=?,lease=? WHERE id=1',
                        (token, now + LEASE_SECONDS))
            return token

    def renew(self, token: str) -> None:
        with self.transaction() as con:
            con.execute('UPDATE refresh SET lease=? WHERE id=1 AND token=? AND lease>?',
                        (time.time() + LEASE_SECONDS, token, time.time()))

    @contextmanager
    def publishing(self, token: str):
        # Hold the claim DB writer lock until the atomic index publication finishes.
        with self.transaction() as con:
            row = con.execute('SELECT token,lease FROM refresh WHERE id=1').fetchone()
            if row[0] != token or row[1] <= time.time():
                raise RefreshLeaseLost('RKN registry refresh lease expired')
            yield

    def finish(self, token: str, success: bool) -> None:
        with self.transaction() as con:
            row = con.execute('SELECT failures FROM refresh WHERE id=1 AND token=?',
                              (token,)).fetchone()
            if row is None:
                return
            failures = 0 if success else min(row[0] + 1, 8)
            retry = 0 if success else time.time() + min(
                RETRY_SECONDS * 2 ** (failures - 1), 24 * 60 * 60)
            con.execute('UPDATE refresh SET token=NULL,lease=0,failures=?,retry_at=? '
                        'WHERE id=1 AND token=?', (failures, retry, token))

    def deadline(self) -> float | None:
        if not self.path.exists():
            return None
        try:
            with closing(sqlite3.connect(self.path.as_uri() + '?mode=ro', uri=True)) as con:
                row = con.execute('SELECT lease,retry_at FROM refresh WHERE id=1').fetchone()
                return max(row) or None if row else None
        except sqlite3.Error:
            return None
