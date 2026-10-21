"""Safe owner-scoped observation summaries, never continuous-time uptime.

Reports aggregate HTTP rows in SQLite into at most 120 occupied UTC buckets. Empty buckets are
absent: consumers MUST use start_at/bucket_seconds on the time axis and must not
connect lines across missing bucket indices. A populated bucket with latency_ms
None also breaks a latency line. No samples are interpolated.

A small process-local cache retains detached safe DTOs for at most 60 seconds,
invalidated immediately by owner history append/delete or owned-domain changes.
Historical in-place edits can remain cached until expiry. Authorization and share
selection always happen in callers; this module caches no access decisions.
"""
from __future__ import annotations

import json
import sys
from collections import OrderedDict
from copy import deepcopy
from time import monotonic
from threading import RLock
from contextlib import closing
from datetime import datetime, timedelta, timezone as dt_timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .. import storage

SOURCES = ('legacy', 'scheduled', 'manual')
_CACHE: OrderedDict[tuple, tuple[float, int, dict]] = OrderedDict()
_CACHE_LOCK = RLock()


def _now() -> datetime:
    return datetime.now(dt_timezone.utc)


def _utc(value: datetime) -> str:
    return value.isoformat(timespec='microseconds').replace('+00:00', 'Z')


def _window(days: int, timezone: str) -> dict:
    if type(days) is not int or days not in {1, 7, 30}:
        raise ValueError('Days must be 1, 7 or 30')
    try:
        zone = ZoneInfo(timezone)
    except (ZoneInfoNotFoundError, ValueError, TypeError):
        raise ValueError('Invalid IANA timezone') from None
    end = _now()
    start = end - timedelta(days=days)
    return {'days': days, 'timezone': zone.key, 'window_start': _utc(start),
            'window_end': _utc(end), 'bucket_seconds': days * 86400 // 120,
            'metric_label': 'Successful checks'}


def _number(value) -> bool:
    return type(value) in (int, float) and 0 <= value <= sys.float_info.max


def _invalid_json_constant(value: str):
    raise ValueError('Non-standard JSON numeric literal')


def _classification(raw: str | None) -> tuple[str, float | None]:
    try:
        # Match SQLite JSON1's rejection of non-standard NaN/Infinity literals.
        metrics = json.loads(raw, parse_constant=_invalid_json_constant)
    except (ValueError, TypeError, RecursionError):
        return 'unknown', None
    if not isinstance(metrics, dict):
        return 'unknown', None
    # New explicit failure/unknown evidence also covers exceptions with no HTTP response.
    availability = metrics.get('availability')
    if availability in ('unavailable', 'unknown'):
        return ('failed' if availability == 'unavailable' else 'unknown'), None
    if isinstance(metrics.get('redirect_error'), (dict, list)):
        return 'unknown', None
    if metrics.get('redirect_error'):
        return ('failed' if isinstance(metrics['redirect_error'], str) else 'unknown'), None
    code = metrics.get('final_code', metrics.get('code_initial'))
    if type(code) is not int or not 100 <= code <= 599:
        # A body-read failure is not proof of a successful complete response.
        code = metrics.get('status_code')
        if type(code) is int and 400 <= code <= 599:
            return 'failed', None
        return 'unknown', None
    if code >= 400:
        return 'failed', None
    if code < 200:
        return 'unknown', None
    latency = metrics.get('response_latency_ms', metrics.get('latency_ms_total'))
    return 'successful', latency if _number(latency) else None


def _counts() -> dict:
    return {'successful': 0, 'failed': 0, 'unknown': 0, 'sample_count': 0,
            'latency_sample_count': 0, '_latency_mean': 0.0,
            'sources': dict.fromkeys(SOURCES, 0)}


def _merge(counts: dict, row):
    count = row['sample_count']
    counts[row['classification']] += count
    counts['sample_count'] += count
    counts['sources'][row['source']] += count
    latency_count = row['latency_sample_count']
    if latency_count:
        counts['latency_sample_count'] += latency_count
        weight = latency_count / counts['latency_sample_count']
        counts['_latency_mean'] += (row['latency_ms'] - counts['_latency_mean']) * weight


def _finish(counts: dict) -> dict:
    known = counts['successful'] + counts['failed']
    mean_latency = counts.pop('_latency_mean')
    count_latency = counts['latency_sample_count']
    counts['success_percent'] = counts['successful'] / known * 100 if known else None
    counts['latency_ms'] = mean_latency if count_latency else None
    return counts


def _aggregate(owner_id: int, domain: str | None, window: dict) -> dict:
    storage._ensure_initialized()
    start = datetime.fromisoformat(window['window_start'].replace('Z', '+00:00'))
    end = datetime.fromisoformat(window['window_end'].replace('Z', '+00:00'))
    zone = ZoneInfo(window['timezone'])
    width = window['bucket_seconds']
    with closing(storage._connect()) as conn:
        names = [row[0] for row in conn.execute(
            'SELECT name FROM domains WHERE owner_id=? ORDER BY name', (int(owner_id),),
        )]
        if domain is not None:
            if domain not in names:
                raise ValueError('Domain not found')
            names = [domain]
        reports = {name: {'domain': name, 'totals': _counts(), '_buckets': {},
                          'latest_observed_at': None, 'latest_availability': 'unknown'}
                   for name in names}
        totals, buckets = _counts(), {}
        args = [int(owner_id), start.replace(tzinfo=None).isoformat(sep=' '),
                end.replace(tzinfo=None).isoformat(sep=' ')]
        domain_filter = ''
        if domain is not None:
            domain_filter = ' AND h.domain=?'
            args.append(domain)
        # No fetchall/sort of raw observations: index bounds the owner/window read;
        # aggregates retain only configured domains x 120 buckets in Python memory.
        cursor = conn.execute(
            _AGGREGATE_SQL.replace("{domain_filter}", domain_filter),
            [start.replace(tzinfo=None).isoformat(sep=' '), width, *args],
        )
        for row in cursor:
            index = row['bucket_index']
            item = reports[row['domain']]
            if index not in buckets:
                buckets[index] = _counts()
            if index not in item['_buckets']:
                item['_buckets'][index] = _counts()
            for count in (totals, item['totals'], buckets[index], item['_buckets'][index]):
                _merge(count, row)
        for name, item in reports.items():
            latest = conn.execute(
                "SELECT metrics_json,created_at FROM history WHERE owner_id=? AND domain=? "
                "AND check_name='http_basic' AND created_at>=? AND created_at<=? "
                "ORDER BY created_at DESC,id DESC LIMIT 1",
                (int(owner_id), name, args[1], args[2]),
            ).fetchone()
            if latest:
                observed = datetime.fromisoformat(latest['created_at']).replace(tzinfo=dt_timezone.utc)
                item['latest_observed_at'] = _utc(observed)
                status, _ = _classification(latest['metrics_json'])
                item['latest_availability'] = {
                    'successful': 'available', 'failed': 'unavailable', 'unknown': 'unknown',
                }[status]

    def finish_buckets(values):
        points = []
        for index, counts in sorted(values.items()):
            stamp = start + timedelta(seconds=index * width)
            points.append({'index': index, 'start_at': _utc(stamp),
                           'label': stamp.astimezone(zone).strftime('%Y-%m-%d %H:%M %Z'),
                           **_finish(counts)})
        return points

    for item in reports.values():
        item.update(window)
        item['totals'] = _finish(item['totals'])
        item['buckets'] = finish_buckets(item.pop('_buckets'))
    return {**window, 'totals': _finish(totals), 'buckets': finish_buckets(buckets),
            'domains': list(reports.values())}


def _cached_report(owner_id: int, domain: str | None, days: int, timezone: str) -> dict:
    window = _window(days, timezone)
    storage._ensure_initialized()
    path = storage.DEFAULT_DB.resolve()
    with closing(storage._connect()) as conn:
        # Append/delete revision, owner scoped; account/session writes do not invalidate it.
        revision = tuple(conn.execute(
            'SELECT COUNT(*),MAX(id) FROM history WHERE owner_id=?', (int(owner_id),),
        ).fetchone())
        names = tuple(row[0] for row in conn.execute(
            'SELECT name FROM domains WHERE owner_id=? ORDER BY name', (int(owner_id),),
        ))
    key = (str(path), path.stat().st_ino, int(owner_id), domain, days, timezone, revision, names)
    now = monotonic()
    with _CACHE_LOCK:
        cached = _CACHE.get(key)
        if cached and cached[0] > now:
            _CACHE.move_to_end(key)
            return deepcopy(cached[2])
    result = _aggregate(owner_id, domain, window)
    size = len(json.dumps(result, allow_nan=False).encode('utf-8'))
    with _CACHE_LOCK:
        for stale in [key for key, entry in _CACHE.items() if entry[0] <= now]:
            del _CACHE[stale]
        if size <= 4 * 1024 * 1024:
            _CACHE[key] = (now + 60, size, result)
            while len(_CACHE) > 8 or sum(entry[1] for entry in _CACHE.values()) > 4 * 1024 * 1024:
                _CACHE.popitem(last=False)
            return deepcopy(result)

    return result


def domain_report(owner_id: int, domain: str, *, days: int, timezone: str) -> dict:
    """Return safe aggregates for an existing owned domain; otherwise raise ValueError."""
    result = _cached_report(owner_id, (domain or '').strip().lower(), days, timezone)
    return result['domains'][0]


def overview_report(owner_id: int, *, days: int, timezone: str) -> dict:
    """Return portfolio totals, <=120 combined buckets, and per-domain reports."""
    return _cached_report(owner_id, None, days, timezone)


# JSON1 runs inside SQLite; only grouped scalar rows cross the Python boundary.
# CASE protects every JSON call from malformed legacy payloads. JSON booleans are
# deliberately excluded from HTTP codes and latencies. Scale before AVG so even
# enormous finite legacy numeric values cannot overflow SQLite's running SUM.
_AGGREGATE_SQL = """
WITH raw AS (
    SELECT h.domain,h.created_at,h.source,
      CASE WHEN json_valid(h.metrics_json) THEN
        CASE WHEN json_type(h.metrics_json)='object' THEN h.metrics_json ELSE '{}' END
      ELSE '{}' END AS payload
    FROM history h JOIN domains d ON d.owner_id=h.owner_id AND d.name=h.domain
    WHERE h.owner_id=?3 AND h.created_at>=?4 AND h.created_at<=?5
      AND h.check_name='http_basic' {domain_filter}
), fields AS (
    SELECT *,
      json_extract(payload,'$.availability') AS availability,
      json_extract(payload,'$.redirect_error') AS redirect_error,
      json_type(payload,'$.redirect_error') AS redirect_type,
      CASE WHEN json_type(payload,'$.final_code') IS NOT NULL
        THEN json_extract(payload,'$.final_code')
        ELSE json_extract(payload,'$.code_initial') END AS code,
      CASE WHEN json_type(payload,'$.final_code') IS NOT NULL
        THEN json_type(payload,'$.final_code')
        ELSE json_type(payload,'$.code_initial') END AS code_type,
      json_extract(payload,'$.status_code') AS body_code,
      json_type(payload,'$.status_code') AS body_type,
      CASE WHEN json_type(payload,'$.response_latency_ms') IS NOT NULL
        THEN json_extract(payload,'$.response_latency_ms')
        ELSE json_extract(payload,'$.latency_ms_total') END AS latency,
      CASE WHEN json_type(payload,'$.response_latency_ms') IS NOT NULL
        THEN json_type(payload,'$.response_latency_ms')
        ELSE json_type(payload,'$.latency_ms_total') END AS latency_type
    FROM raw
), classified AS MATERIALIZED (
    SELECT domain,
      MAX(0,MIN(119,CAST((julianday(created_at)-julianday(?1))*86400/?2 AS INTEGER)))
        AS bucket_index,
      CASE WHEN source IN ('legacy','scheduled','manual') THEN source ELSE 'legacy' END AS source,
      CASE
        WHEN availability='unavailable' THEN 'failed'
        WHEN availability='unknown' THEN 'unknown'
        WHEN redirect_type='text' AND redirect_error<>'' THEN 'failed'
        WHEN redirect_type IN ('object','array') THEN 'unknown'
        WHEN redirect_type IN ('true','integer','real') AND redirect_error<>0 THEN 'unknown'
        WHEN code_type='integer' AND code BETWEEN 400 AND 599 THEN 'failed'
        WHEN code_type='integer' AND code BETWEEN 200 AND 399 THEN 'successful'
        WHEN code_type='integer' AND code BETWEEN 100 AND 199 THEN 'unknown'
        WHEN body_type='integer' AND body_code BETWEEN 400 AND 599 THEN 'failed'
        ELSE 'unknown'
      END AS classification,
      CASE WHEN latency_type IN ('integer','real')
        AND latency>=0 AND latency<=1.7976931348623157e308 THEN latency ELSE NULL END AS latency
    FROM fields
)
SELECT domain,bucket_index,source,classification,COUNT(*) AS sample_count,
  COUNT(CASE WHEN classification='successful' THEN latency END) AS latency_sample_count,
  AVG(CASE WHEN classification='successful' THEN latency/1e100 END)*1e100 AS latency_ms
FROM classified
GROUP BY domain,bucket_index,source,classification
"""
