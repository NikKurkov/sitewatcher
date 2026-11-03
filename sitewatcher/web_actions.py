"""Owner-scoped management operations shared by browser request handlers."""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime

from . import storage
from .config import (
    AppConfig, ChecksModel, ConfigurationError, DomainOverride, resolve_settings,
    validate_domain_override,
    validation_message,
)
from .utils.domains import normalize_domain


NUMERIC_FIELDS = (
    'interval_minutes', 'http_timeout_s', 'latency_warn_ms', 'latency_crit_ms', 'tls_warn_days',
)
LIST_FIELDS = ('keywords', 'ports')
MAX_ADD_DOMAINS = 50


def _format_list(key: str, items: list) -> str:
    if not items:
        return '-'
    if key == 'ports':
        return ', '.join(str(item['port'] if isinstance(item, dict) else item) for item in items)
    output = io.StringIO()
    csv.writer(output, lineterminator='\n', quoting=csv.QUOTE_ALL).writerow(items)
    return output.getvalue().removesuffix('\n')


def _parse_list(key: str, value: str, current: dict) -> list:
    try:
        if value == '-':
            return []
        # Accept existing form submissions as well as the human-readable format.
        if value.startswith(('[', '{')):
            parsed = json.loads(value)
            if not isinstance(parsed, list):
                raise ValueError
            return parsed
        if key == 'keywords':
            return [item for row in csv.reader(io.StringIO(value), skipinitialspace=True,
                                               strict=True) for item in row]
        ranges = []
        for part in value.split(','):
            bounds = part.strip().split('-')
            if len(bounds) not in (1, 2) or any(not b.strip().isascii() or
                                               not b.strip().isdecimal() for b in bounds):
                raise ValueError
            start, end = int(bounds[0]), int(bounds[-1])
            if not 1 <= start <= end <= 65535:
                raise ValueError
            ranges.append((start, end))
        merged = []
        for start, end in sorted(ranges):
            if merged and start <= merged[-1][1] + 1:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        ports = [port for start, end in merged for port in range(start, end + 1)]
        # Keep TLS, host and other probe options for retained port numbers.
        saved = {}
        for item in current.get('ports') or []:
            port = int(item['port'] if isinstance(item, dict) else item)
            saved.setdefault(port, []).append(item)
        return [item for port in ports for item in saved.get(port, [port])]
    except (ValueError, csv.Error, RecursionError):
        raise ConfigurationError(f'{key}: Enter a valid comma-separated list.') from None


def _message(error: Exception) -> str:
    for message in (
        'Domain already exists', 'Domain not found', 'Invalid domain',
        'Settings changed; reload this page before saving',
    ):
        if type(error) is ValueError and str(error) == message:
            return message
    return validation_message(error)


def _domain(owner_id: int, raw: str, *, existing: bool = True) -> str:
    domain = normalize_domain(raw)
    if not domain:
        raise ValueError('Invalid domain')
    if existing and not storage.domain_exists(owner_id, domain):
        raise ValueError('Domain not found')
    return domain


def settings_context(cfg: AppConfig, owner_id: int, domain: str | None = None) -> dict:
    """Return editable overrides and defaults without exposing proxy credentials."""
    name = _domain(owner_id, domain) if domain is not None else ''
    try:
        override = (storage.get_domain_override(owner_id, name) or {}) if name else {}
        preview_cfg = cfg if name else cfg.model_copy(update={'domains': []})
        effective = resolve_settings(preview_cfg, name or 'example.com', override)
        defaults = resolve_settings(preview_cfg, name or 'example.com', {})
        values = {'domain': name, 'proxy_mode': 'keep', 'proxy': ''}
        for key in NUMERIC_FIELDS:
            values[key] = str(override[key]) if override.get(key) is not None else ''
        for key in LIST_FIELDS:
            values[key] = _format_list(key, override[key]) if (
                override.get(key) is not None
            ) else ''
        checks = DomainOverride.model_validate(override).model_dump(exclude_unset=True).get(
            'checks') or {}
        for key in ChecksModel.model_fields:
            values[f'check.{key}'] = (
                'on' if checks[key] else 'off'
            ) if key in checks else ''
        revision = storage.domain_override_revision(override)
        values['revision'] = revision
        return {
            'domain': name, 'values': values, 'check_names': list(ChecksModel.model_fields),
            'proxy_present': bool(effective.proxy),
            'defaults': {**{key: getattr(defaults, key) for key in NUMERIC_FIELDS},
                         'checks': defaults.checks.model_dump(), 'interval_minutes': (
                defaults.interval_minutes if defaults.interval_minutes is not None
                else cfg.schedules.http_basic.interval_minutes)},
            'revision': revision,
        }
    except (ValueError, TypeError, AttributeError, RecursionError) as error:
        raise ValueError(_message(error)) from None


def _domain_settings(cfg: AppConfig, owner_id: int, form: dict[str, str], *, create: bool):
    """Validate a complete form without writing any settings."""
    domain = _domain(owner_id, form.get('domain', ''), existing=not create)
    if create and storage.domain_exists(owner_id, domain):
        raise ValueError('Domain already exists')
    revision = form.get('revision')
    if not create and not revision:
        raise ValueError('Settings changed; reload this page before saving')
    try:
        override = {}
        current = (storage.get_domain_override(owner_id, domain) or {}) if not create else {}
        checks = {}
        for key in ChecksModel.model_fields:
            value = form.get(f'check.{key}', '').strip()
            if value not in ('', 'on', 'off'):
                raise ValueError('Invalid check')
            if value:
                checks[key] = value == 'on'
        if checks:
            override['checks'] = checks
        for key in NUMERIC_FIELDS:
            value = form.get(key, '').strip()
            if value:
                try:
                    override[key] = int(value)
                except ValueError:
                    raise ConfigurationError(f'{key}: Enter a whole number.') from None
        for key in LIST_FIELDS:
            value = form.get(key, '').strip()
            if value:
                override[key] = _parse_list(key, value, current)
        mode = form.get('proxy_mode', 'keep')
        if mode == 'keep':
            if 'proxy' in current:
                override['proxy'] = current['proxy']
        elif mode == 'clear':
            override['proxy'] = None
        elif mode == 'set':
            proxy = form.get('proxy', '').strip()
            if not proxy:
                raise ConfigurationError('proxy: Enter a proxy URL.')
            override['proxy'] = proxy
        elif mode != 'inherit':
            raise ConfigurationError('proxy_mode: Choose a valid proxy action.')
        validated = validate_domain_override(cfg, domain, override)
    except (ValueError, TypeError, RecursionError) as error:
        raise ValueError(_message(error)) from None
    return domain, validated, revision


def save_domain(cfg: AppConfig, owner_id: int, form: dict[str, str], *, create: bool = False) -> str:
    """Validate a complete form before atomically replacing its owner's overrides."""
    domain, validated, revision = _domain_settings(cfg, owner_id, form, create=create)
    try:
        storage.set_domain_override(
            owner_id, domain, validated, replace=True, create_missing=create,
            create_only=create, expected_revision=None if create else revision,
        )
    except (ValueError, TypeError, RecursionError) as error:
        raise ValueError(_message(error)) from None
    if not storage.domain_exists(owner_id, domain):
        raise ValueError('Domain not found')
    return domain


def add_domains(cfg: AppConfig, owner_id: int, form: dict[str, str]) -> int:
    """Validate comma-separated hostnames before atomically creating their shared settings."""
    names = [name.strip() for name in form.get('domain', '').split(',') if name.strip()]
    if not names:
        raise ValueError('Invalid domain')
    if len(names) > MAX_ADD_DOMAINS:
        raise ValueError('Enter at most 50 domains.')
    overrides = {}
    for name in names:
        domain, validated, _ = _domain_settings(cfg, owner_id, {**form, 'domain': name},
                                               create=True)
        if domain in overrides:
            raise ValueError('Domain already exists')
        overrides[domain] = validated
    storage.create_domains_with_overrides(owner_id, overrides)
    return len(overrides)


def act_on_domain(
    cfg: AppConfig, owner_id: int, action: str, domain: str, *, revision: str | None = None,
) -> None:
    """Apply an explicit management action without running checks or sending messages."""
    domain = _domain(owner_id, domain)
    try:
        if action == 'delete':
            storage.remove_domain(owner_id, domain)
        elif action == 'reset':
            validate_domain_override(cfg, domain, {})
            storage.unset_domain_override(owner_id, domain, None, expected_revision=revision)
        elif action in ('pause', 'resume'):
            current = storage.get_domain_override(owner_id, domain) or {}
            revision = storage.domain_override_revision(current)
            if action == 'pause':
                current['interval_minutes'] = 0
            else:
                if current.get('interval_minutes') == 0:
                    current.pop('interval_minutes')
                if resolve_settings(cfg, domain, current).interval_minutes == 0:
                    # A YAML pause needs a positive override to resume from the browser.
                    current['interval_minutes'] = max(1, cfg.schedules.http_basic.interval_minutes)
            validated = validate_domain_override(cfg, domain, current)
            storage.set_domain_override(
                owner_id, domain, validated, replace=True, expected_revision=revision,
            )
        else:
            raise ValueError('Invalid action')
    except (ValueError, TypeError, RecursionError) as error:
        raise ValueError(_message(error)) from None


def history_context(
    owner_id: int, domain: str, limit: int = 100, *, check: str | None = None,
    status: str | None = None, since: datetime | None = None, until: datetime | None = None,
) -> list[dict]:
    """Read recent history for one existing owned domain without private metric payloads."""
    domain = _domain(owner_id, domain)
    return [
        {**{key: row[key] for key in ('id', 'domain', 'status', 'message', 'created_at')},
         'check_name': row['check']}
        for row in storage.iter_history(owner_id, domain=domain, limit=max(0, min(100, limit)),
                                        check=check, statuses={status} if status else None,
                                        since=since, until=until)
    ]
