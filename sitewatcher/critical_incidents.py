"""Durable unresolved critical checks; event/history retention cannot acknowledge recovery."""
from contextlib import closing
from pathlib import Path
import sqlite3


def initialize(connection):
    """Called once inside storage's additive migration transaction."""
    if connection.execute(
        "SELECT 1 FROM sqlite_master WHERE name='critical_incidents'",
    ).fetchone():
        return
    connection.execute('''CREATE TABLE critical_incidents (
        owner_id INTEGER NOT NULL, domain TEXT NOT NULL, check_name TEXT NOT NULL,
        opened_at TEXT NOT NULL, last_critical_at TEXT NOT NULL,
        PRIMARY KEY(owner_id,domain,check_name),
        FOREIGN KEY(owner_id,domain) REFERENCES domains(owner_id,name) ON DELETE CASCADE
    )''')
    from .storage import is_current_observation
    rows = connection.execute('''
        WITH bounds AS (
            SELECT h.owner_id,h.domain,h.check_name,
                MAX(CASE WHEN h.status='OK' THEN h.id ELSE 0 END) AS ok_id,
                MAX(CASE WHEN h.status='CRIT' THEN h.id ELSE 0 END) AS crit_id
            FROM history h JOIN domains d ON d.owner_id=h.owner_id AND d.name=h.domain
            WHERE h.status IN ('OK','CRIT') GROUP BY h.owner_id,h.domain,h.check_name
        )
        SELECT h.*, b.ok_id FROM bounds b JOIN history h ON h.id=b.crit_id
        WHERE b.crit_id>b.ok_id
    ''').fetchall()
    for row in rows:
        # A renamed monitor retains history, not the previous host's active problems.
        renamed = connection.execute(
            "SELECT id,metrics_json FROM history WHERE owner_id=? AND domain=? "
            "AND check_name=? AND id>? AND metrics_json LIKE '%original_domain%'",
            (row['owner_id'], row['domain'], row['check_name'], row['ok_id']),
        ).fetchall()
        barrier = max((item['id'] for item in renamed
                       if not is_current_observation(row['domain'], item['metrics_json'])),
                      default=row['ok_id'])
        if barrier >= row['id']:
            continue
        opened = connection.execute(
            "SELECT MIN(created_at) FROM history WHERE owner_id=? AND domain=? "
            "AND check_name=? AND id>? AND status='CRIT'",
            (row['owner_id'], row['domain'], row['check_name'], barrier),
        ).fetchone()[0]
        connection.execute('INSERT INTO critical_incidents VALUES(?,?,?,?,?)', (
            row['owner_id'], row['domain'], row['check_name'], opened, row['created_at'],
        ))


def record(connection, owner_id, domain, check_name, status):
    """Share history's transaction: UNKNOWN/WARN never falsely confirm recovery."""
    if status == 'CRIT':
        connection.execute('''
            INSERT INTO critical_incidents VALUES(?,?,?,datetime('now'),datetime('now'))
            ON CONFLICT(owner_id,domain,check_name) DO UPDATE
            SET last_critical_at=excluded.last_critical_at
        ''', (owner_id, domain, check_name))
    elif status == 'OK':
        connection.execute(
            'DELETE FROM critical_incidents WHERE owner_id=? AND domain=? AND check_name=?',
            (owner_id, domain, check_name),
        )


def read(cfg, owner_id):
    """Read owner-scoped display fields; never initialize on GET or expose diagnostics."""
    from . import storage
    from .reporting import build_snapshot
    snapshot = build_snapshot(cfg, owner_id)
    uri = Path(storage.DEFAULT_DB).resolve().as_uri() + '?mode=ro'
    with closing(sqlite3.connect(uri, uri=True, timeout=3)) as connection:
        connection.row_factory = sqlite3.Row
        if not connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name='critical_incidents'",
        ).fetchone():
            raise sqlite3.OperationalError('Incident state unavailable')
        incidents = connection.execute(
            'SELECT domain,check_name,opened_at,last_critical_at FROM critical_incidents '
            'WHERE owner_id=? ORDER BY opened_at,domain,check_name', (owner_id,),
        ).fetchall()
    domains = {row['name']: row for row in snapshot['domains']}
    grouped = {}
    for incident in incidents:
        domain = domains.get(incident['domain'])
        if domain is None:
            continue
        check = next((row for row in domain['checks'] if row['name'] == incident['check_name']), None)
        if check is None:
            continue
        item = grouped.setdefault(incident['domain'], {
            'domain': incident['domain'], 'paused': domain['paused'], 'checks': [],
        })
        item['checks'].append({
            'name': incident['check_name'], 'opened_at': incident['opened_at'],
            'last_critical_at': incident['last_critical_at'],
            'status': check['status'], 'stale': check['stale'] or check['missing'],
        })
    return list(grouped.values())
