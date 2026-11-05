"""Shared network deadlines and local freshness for monitoring, reporting and alerts."""
from datetime import datetime, timedelta, timezone
import json

DAILY_CHECKS = frozenset({'tls_cert', 'whois', 'malware', 'ip_blacklist', 'rkn_domain', 'rkn_ip'})
REFRESHABLE_CHECKS = frozenset({'tls_cert', 'whois'})


def timestamp(value):
    if not value:
        return None
    try:
        date = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        return date.replace(tzinfo=timezone.utc) if date.tzinfo is None else date.astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError):
        return None


def metrics_from(row):
    try:
        value = row['metrics_json']
        value = json.loads(value) if isinstance(value, str) else value
        return value if isinstance(value, dict) else {}
    except (ValueError, TypeError, KeyError, IndexError):
        return {}


def interval_minutes(cfg, check_name, domain_interval=None):
    if domain_interval == 0:
        return 0
    scheduled = int(getattr(cfg.schedules, check_name).interval_minutes)
    if check_name in DAILY_CHECKS:
        return max(1440, scheduled)
    return int(domain_interval) if domain_interval is not None else scheduled


def result_deadlines(cfg, check_name, domain_interval, row, *, now=None):
    now = now or datetime.now(timezone.utc)
    try:
        checked = timestamp(row['created_at']) if row else None
    except (KeyError, IndexError, TypeError):
        checked = None
    if checked is None:
        return None, now, now
    interval = interval_minutes(cfg, check_name, domain_interval)
    metrics = metrics_from(row)
    observed = timestamp(metrics.get('observed_at')) if check_name in DAILY_CHECKS else None
    if observed is None and check_name in {'tls_cert', 'whois'} and row['status'] != 'UNKNOWN':
        observed = timestamp(metrics.get('fetched_at'))
    observed = observed or checked
    try:
        due = observed + timedelta(minutes=interval)
        if check_name in DAILY_CHECKS:
            due = timestamp(metrics.get('next_refresh_at') or metrics.get('next_retry_at')) or due
            stale = due + timedelta(minutes=5)
        else:
            stale = observed + timedelta(minutes=3 * interval)
    except OverflowError:
        due = stale = now
    return observed, due, stale


def expiry_assessment_due(check_name, row, cfg, settings, *, now=None):
    if check_name not in REFRESHABLE_CHECKS or not row:
        return False
    expires = timestamp(metrics_from(row).get('expires_at'))
    if expires is None:
        return False
    now = now or datetime.now(timezone.utc)
    days = int((expires - now).total_seconds() // 86400)
    critical = 3 if check_name == 'tls_cert' else cfg.whois.expiry_crit_days
    warning = settings.tls_warn_days if check_name == 'tls_cert' else cfg.whois.expiry_warn_days
    predicted = 2 if days <= critical else 1 if days <= warning else 0
    previous = {'CRIT': 2, 'WARN': 1, 'OK': 0, 'UNKNOWN': 0}.get(str(row['status']), 0)
    return predicted > previous


def ip_context_current(check_name, row, latest):
    """Operational DNS changes invalidate only address-dependent reputation evidence."""
    if check_name not in {'ip_blacklist', 'rkn_ip'} or not row:
        return True
    dns = latest.get('ip_change')
    if (not dns or not timestamp(dns['created_at']) or not timestamp(row['created_at'])
            or timestamp(dns['created_at']) <= timestamp(row['created_at'])):
        return True
    before, current = metrics_from(row), metrics_from(dns)
    if 'ips_v4' not in before or 'ips_v4' not in current:
        return True
    return set(before['ips_v4']) == set(current['ips_v4'])


def assessment_context(metrics):
    """Identity of cached evidence and its retry state, excluding runtime timings."""
    keys = ('ips_v4', 'ips_v6', 'zones', 'dns_servers', 'check_ipv6', 'dnsbl_version',
            'registry_generation', 'registry_version', 'source', 'source_updated_at',
            'source_stale', 'cache_state', 'next_refresh_at', 'next_retry_at',
            'zones_completed', 'partial_coverage', 'hits', 'original_domain', 'port')
    return {key: metrics[key] for key in keys if key in metrics}
