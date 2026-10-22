"""Owner-scoped management operations shared by browser request handlers."""
from __future__ import annotations

import json
from dataclasses import asdict

from . import storage
from .config import (
    AppConfig, ChecksModel, ConfigurationError, resolve_settings, validate_domain_override,
    validation_message,
)
from .utils.domains import normalize_domain
from .utils.secrets import redact_configuration


NUMERIC_FIELDS = (
    'interval_minutes', 'http_timeout_s', 'latency_warn_ms', 'latency_crit_ms', 'tls_warn_days',
)
LIST_FIELDS = ('keywords', 'ports')


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
    """Return raw editable overrides and a credential-redacted effective preview."""
    name = _domain(owner_id, domain) if domain is not None else ''
    try:
        override = (storage.get_domain_override(owner_id, name) or {}) if name else {}
        preview_cfg = cfg if name else cfg.model_copy(update={'domains': []})
        effective = resolve_settings(preview_cfg, name or 'example.com', override)
        values = {'domain': name, 'proxy_mode': 'keep', 'proxy': ''}
        for key in NUMERIC_FIELDS:
            values[key] = str(override[key]) if override.get(key) is not None else ''
        for key in LIST_FIELDS:
            values[key] = json.dumps(override[key], ensure_ascii=False) if (
                override.get(key) is not None
            ) else ''
        checks = override.get('checks') or {}
        for key in ChecksModel.model_fields:
            values[f'check.{key}'] = (
                'on' if checks[key] else 'off'
            ) if key in checks else ''
        preview = asdict(effective)
        preview['checks'] = effective.checks.model_dump()
        preview['ports'] = [port.model_dump() for port in effective.ports] if (
            effective.ports is not None
        ) else None
        revision = storage.domain_override_revision(override)
        values['revision'] = revision
        return {
            'domain': name, 'values': values, 'check_names': list(ChecksModel.model_fields),
            'proxy_present': bool(effective.proxy), 'effective': redact_configuration(preview),
            'revision': revision,
        }
    except (ValueError, TypeError, AttributeError, RecursionError) as error:
        raise ValueError(_message(error)) from None


def save_domain(cfg: AppConfig, owner_id: int, form: dict[str, str], *, create: bool = False) -> str:
    """Validate a complete form before atomically replacing its owner's overrides."""
    domain = _domain(owner_id, form.get('domain', ''), existing=not create)
    if create and storage.domain_exists(owner_id, domain):
        raise ValueError('Domain already exists')
    revision = form.get('revision')
    if not create and not revision:
        raise ValueError('Settings changed; reload this page before saving')
    try:
        override = {}
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
                try:
                    parsed = json.loads(value)
                except (ValueError, RecursionError):
                    raise ConfigurationError(f'{key}: Enter a valid JSON list.') from None
                if not isinstance(parsed, list):
                    raise ConfigurationError(f'{key}: Enter a valid JSON list.')
                override[key] = parsed
        mode = form.get('proxy_mode', 'keep')
        if mode == 'keep':
            current = storage.get_domain_override(owner_id, domain) if not create else None
            if current is not None and 'proxy' in current:
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
        storage.set_domain_override(
            owner_id, domain, validated, replace=True, create_missing=create,
            create_only=create, expected_revision=None if create else revision,
        )
    except (ValueError, TypeError, RecursionError) as error:
        raise ValueError(_message(error)) from None
    if not storage.domain_exists(owner_id, domain):
        raise ValueError('Domain not found')
    return domain


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


def history_context(owner_id: int, domain: str, limit: int = 100) -> list[dict]:
    """Read recent history for one existing owned domain without private metric payloads."""
    domain = _domain(owner_id, domain)
    return [
        {**{key: row[key] for key in ('id', 'domain', 'status', 'message', 'created_at')},
         'check_name': row['check']}
        for row in storage.iter_history(owner_id, domain=domain, limit=max(0, min(100, limit)))
    ]
