"""Read-only, owner-scoped reporting of saved monitoring results."""
from __future__ import annotations

from contextlib import closing
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3

from . import storage
from .config import AppConfig, ChecksModel, resolve_settings
from .utils.results import (
    current_rkn_result, is_missing_malware_report, overall_from_statuses, status_text,
)


class SnapshotError(RuntimeError):
    """The monitoring database cannot provide a readable snapshot."""


def _timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return None


def _domain_snapshot(cfg, name, raw_override, histories, now):
    row = {
        'name': name, 'overall': 'UNKNOWN', 'paused': not cfg.scheduler.enabled,
        'stale': False, 'overdue': False, 'last_checked_at': None, 'next_due_at': None, 'checks': [], 'error': None,
    }
    try:
        override = json.loads(raw_override) if raw_override is not None else None
        if raw_override is not None and not isinstance(override, dict):
            raise ValueError('Invalid override')
        settings = resolve_settings(cfg, name, override)
    except (ValueError, TypeError, RecursionError):
        row['error'] = 'Invalid domain settings'
        return row

    row['paused'] = not cfg.scheduler.enabled or settings.interval_minutes == 0
    timestamps = []
    due_times = []
    statuses = []
    has_results = False
    for check_name, enabled in settings.checks.model_dump().items():
        if not enabled:
            continue
        saved = histories.get((name, check_name))
        if saved is not None and not current_rkn_result(
                check_name, saved['metrics_json'], cfg.rkn.max_source_age_hours,
                status=saved['status']):
            saved = None
        checked_at = _timestamp(saved['created_at']) if saved is not None else None
        due_at = now
        stale_at = now
        if checked_at is not None:
            timestamps.append(checked_at)
            interval = settings.interval_minutes
            if interval is None:
                interval = getattr(cfg.schedules, check_name).interval_minutes
            try:
                due_at = checked_at + timedelta(minutes=interval)
                stale_at = checked_at + timedelta(minutes=3 * interval)
            except OverflowError:
                due_at = stale_at = now
        # Allow normal scheduler/network delays; the next run is still due after one interval.
        stale = not row['paused'] and stale_at <= now
        if checked_at is not None and not row['paused']:
            row['overdue'] |= stale
        raw_status = saved['status'] if saved is not None else 'UNKNOWN'
        status = status_text(raw_status)
        if status not in {'OK', 'WARN', 'CRIT', 'UNKNOWN'} or (stale and status == 'OK'):
            status = 'UNKNOWN'
        statuses.append('OK' if saved is not None and is_missing_malware_report(
            check_name, raw_status, saved['message']) else status)
        has_results = has_results or saved is not None
        due_times.append(due_at)
        row['checks'].append({
            'name': check_name, 'status': raw_status,
            'message': saved['message'] if saved is not None else 'No saved result',
            'checked_at': checked_at.isoformat() if checked_at else None,
            'stale': stale, 'missing': saved is None,
        })
    row['overall'] = overall_from_statuses(statuses) if has_results else 'UNKNOWN'
    row['stale'] = any(check['stale'] for check in row['checks'])
    row['last_checked_at'] = max(timestamps).isoformat() if timestamps else None
    if due_times and not row['paused']:
        row['next_due_at'] = min(due_times).isoformat()
    return row


def build_snapshot(cfg: AppConfig, owner_id: int, *, now: datetime | None = None) -> dict:
    """Read one consistent snapshot without initializing or modifying monitoring data."""
    if type(owner_id) is not int or owner_id <= 0:
        raise ValueError('A positive owner ID is required')
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    now = now.astimezone(timezone.utc)
    try:
        uri = Path(storage.DEFAULT_DB).resolve().as_uri() + '?mode=ro'
        with closing(sqlite3.connect(uri, uri=True, timeout=3)) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute('BEGIN')
            domain_columns = {column['name'] for column in conn.execute('PRAGMA table_info(domains)')}
            favorite = 'd.favorite' if 'favorite' in domain_columns else '0'
            domains = conn.execute(
                f'SELECT d.name, {favorite} AS favorite, o.data_json '
                'FROM domains d LEFT JOIN domain_overrides o '
                'ON o.owner_id=d.owner_id AND o.domain=d.name '
                'WHERE d.owner_id=? ORDER BY d.name', (owner_id,),
            ).fetchall()
            has_latest_index = any(
                index['name'] == 'idx_history_owner_domain_check_id'
                for index in conn.execute("PRAGMA index_list('history')")
            )
            if has_latest_index:
                check_names = list(ChecksModel.model_fields)
                history = conn.execute(
                    'WITH checks(name) AS (VALUES '
                    + ','.join('(?)' for _ in check_names) + ') '
                    'SELECT h.domain, h.check_name, h.status, h.message, h.created_at, h.metrics_json '
                    'FROM domains d CROSS JOIN checks c JOIN history h ON h.id=('
                    'SELECT id FROM history WHERE owner_id=d.owner_id '
                    'AND domain=d.name AND check_name=c.name ORDER BY id DESC LIMIT 1'
                    ') WHERE d.owner_id=?', (*check_names, owner_id),
                ).fetchall()
            else:
                # Legacy databases remain readable until the monitoring process initializes them.
                history = conn.execute(
                    'SELECT h.domain, h.check_name, h.status, h.message, h.created_at, h.metrics_json '
                    'FROM history h JOIN ('
                    'SELECT MAX(id) AS latest_id FROM history WHERE owner_id=? '
                    'GROUP BY domain, check_name'
                    ') latest ON h.id=latest.latest_id WHERE h.owner_id=?', (owner_id, owner_id),
                ).fetchall()
            conn.rollback()
    except (sqlite3.Error, OSError, ValueError):
        raise SnapshotError('Monitoring database is unavailable') from None

    histories = {(row['domain'], row['check_name']): row for row in history
                 if storage.is_current_observation(row['domain'], row['metrics_json'])}
    rows = [{**_domain_snapshot(cfg, row['name'], row['data_json'], histories, now),
             'favorite': bool(row['favorite'])} for row in domains]
    summary = dict.fromkeys(('total', 'ok', 'warn', 'crit', 'unknown', 'paused', 'stale'), 0)
    summary['total'] = len(rows)
    for row in rows:
        summary[row['overall'].lower()] += 1
        summary['paused'] += int(row['paused'])
        summary['stale'] += int(row['stale'])
    return {'generated_at': now.isoformat(), 'summary': summary, 'domains': rows}
