"""Owner-private monitor groups; an absent membership means the default group."""
from __future__ import annotations

from contextlib import closing
import sqlite3
import unicodedata

from . import storage


def _default_group() -> dict:
    return {'id': 0, 'name': '', 'is_default': True}


def _name(value: str) -> tuple[str, str]:
    if not isinstance(value, str):
        raise ValueError('Invalid group name')
    value = unicodedata.normalize('NFKC', value)
    if any(unicodedata.category(char).startswith('C') for char in value):
        raise ValueError('Invalid group name')
    value = value.strip()
    key = value.casefold()
    if not value or len(value) > 80 or key in {'main', 'основная'}:
        raise ValueError('Invalid group name')
    return value, key


def _validate_group(conn: sqlite3.Connection, owner_id: int, group_id: int) -> None:
    if type(group_id) is not int or group_id < 0 or (group_id and not conn.execute(
        'SELECT 1 FROM domain_groups WHERE owner_id=? AND id=?', (owner_id, group_id),
    ).fetchone()):
        raise ValueError('Group not found')


def _assign(conn: sqlite3.Connection, owner_id: int, names: list[str], group_id: int) -> None:
    """Validate and assign inside the caller's settings transaction."""
    _validate_group(conn, owner_id, group_id)
    for name in names:
        if not conn.execute('SELECT 1 FROM domains WHERE owner_id=? AND name=?',
                            (owner_id, name)).fetchone():
            raise ValueError('Domain not found')
    for name in names:
        if group_id:
            conn.execute('INSERT INTO domain_group_members(owner_id,domain,group_id) VALUES(?,?,?) '
                         'ON CONFLICT(owner_id,domain) DO UPDATE SET group_id=excluded.group_id',
                         (owner_id, name, group_id))
        else:
            conn.execute('DELETE FROM domain_group_members WHERE owner_id=? AND domain=?',
                         (owner_id, name))


def _list_groups(conn: sqlite3.Connection, owner_id: int) -> list[dict]:
    groups = [_default_group()]
    if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='domain_groups'").fetchone():
        groups += [dict(row, is_default=False) for row in conn.execute(
            'SELECT id,name FROM domain_groups WHERE owner_id=? ORDER BY id', (owner_id,),
        )]
    return groups


def _group_for_domain(conn: sqlite3.Connection, owner_id: int, name: str) -> int:
    if not conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='domain_group_members'").fetchone():
        return 0
    row = conn.execute('SELECT group_id FROM domain_group_members WHERE owner_id=? AND domain=?',
                       (owner_id, name)).fetchone()
    return row['group_id'] if row else 0


def list_groups(owner_id: int) -> list[dict]:
    # Reads must not initialize a legacy database or change its journal mode.
    if not storage.DEFAULT_DB.exists():
        return [_default_group()]
    with closing(sqlite3.connect(storage.DEFAULT_DB.resolve().as_uri() + '?mode=ro', uri=True)) as conn:
        conn.row_factory = sqlite3.Row
        return _list_groups(conn, owner_id)


def group_for_domain(owner_id: int, name: str) -> int:
    if not storage.DEFAULT_DB.exists():
        return 0
    with closing(sqlite3.connect(storage.DEFAULT_DB.resolve().as_uri() + '?mode=ro', uri=True)) as conn:
        conn.row_factory = sqlite3.Row
        return _group_for_domain(conn, owner_id, name)


def create_group(owner_id: int, name: str) -> int:
    name, key = _name(name)
    storage._ensure_initialized()
    try:
        with storage._write_connection() as conn:
            conn.execute('INSERT OR IGNORE INTO users(telegram_id) VALUES(?)', (owner_id,))
            return conn.execute('INSERT INTO domain_groups(owner_id,name,name_key) VALUES(?,?,?)',
                                (owner_id, name, key)).lastrowid
    except sqlite3.IntegrityError:
        raise ValueError('Group already exists') from None


def rename_group(owner_id: int, group_id: int, name: str) -> None:
    name, key = _name(name)
    storage._ensure_initialized()
    try:
        with storage._write_connection() as conn:
            _validate_group(conn, owner_id, group_id)
            if group_id == 0:
                raise ValueError('Default group cannot be changed')
            conn.execute('UPDATE domain_groups SET name=?,name_key=? WHERE owner_id=? AND id=?',
                         (name, key, owner_id, group_id))
    except sqlite3.IntegrityError:
        raise ValueError('Group already exists') from None


def delete_group(owner_id: int, group_id: int) -> None:
    storage._ensure_initialized()
    with storage._write_connection() as conn:
        _validate_group(conn, owner_id, group_id)
        if group_id == 0:
            raise ValueError('Default group cannot be changed')
        conn.execute('DELETE FROM domain_groups WHERE owner_id=? AND id=?', (owner_id, group_id))


def move_domains(owner_id: int, names: list[str], group_id: int) -> None:
    storage._ensure_initialized()
    with storage._write_connection() as conn:
        _assign(conn, owner_id, names, group_id)
