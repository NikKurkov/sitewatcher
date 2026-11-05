"""Framework-independent scheduled check selection, dispatch and persistence."""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from . import storage
from .config import AppConfig, resolve_settings
from .dispatcher import Dispatcher
from .checks.ip_blacklist import current_ipbl_result
from .utils.results import current_rkn_result
from .check_policy import (result_deadlines, expiry_assessment_due,
                           ip_context_current, metrics_from)
from .checks.rkn_block_sqlite import current_registry_generation

log = logging.getLogger(__name__)


def due_checks(cfg: AppConfig, owner_id: int, domain: str, *, warmup: bool = False) -> list[str]:
    """Select enabled checks whose most recent run is older than their interval."""
    if not cfg.scheduler.enabled:
        return []
    override = storage.get_domain_override(owner_id, domain) or {}
    settings = resolve_settings(cfg, domain, override)
    domain_interval = settings.interval_minutes
    if domain_interval is not None and domain_interval <= 0:
        return []
    checks = settings.checks.model_dump()
    ages = storage.last_check_ages(owner_id, domain)
    latest = storage.latest_check_results(owner_id, domain)
    now = datetime.now(timezone.utc)
    outdated = set()
    if any(checks.get(name) for name in ('rkn_domain', 'rkn_ip')):
        outdated = {name for name in ('rkn_domain', 'rkn_ip') if name in latest
                    and not current_rkn_result(name, latest[name]['metrics_json'],
                                               cfg.rkn.max_source_age_hours,
                                               status=latest[name]['status'])}
    if checks.get('ip_blacklist'):
        row = storage.last_history_for_check(owner_id, domain, 'ip_blacklist')
        if row and not current_ipbl_result(row['metrics_json'], cfg.ipbl):
            outdated.add('ip_blacklist')
    generation = current_registry_generation(cfg.rkn) if any(
        checks.get(name) for name in ('rkn_domain', 'rkn_ip')) else None
    selected = []
    for name, enabled in checks.items():
        if not enabled:
            continue
        row = latest.get(name)
        if row is None and name in ages:
            row = {'created_at': (now - timedelta(minutes=ages[name])).isoformat(),
                   'status': 'UNKNOWN', 'metrics_json': '{}'}
        due = result_deadlines(cfg, name, domain_interval, row, now=now)[1]
        if name == 'malware':
            pending_until = storage.virustotal_pending_until(
                owner_id, f'https://{domain.strip().lower().rstrip('.')}/')
            if pending_until and now < pending_until:
                continue
        changed_registry = (name in {'rkn_domain', 'rkn_ip'} and generation and row
                            and metrics_from(row).get('registry_generation') != generation)
        if (name in outdated or row is None or now >= due or changed_registry
                or not ip_context_current(name, row, latest)
                or expiry_assessment_due(name, row, cfg, settings, now=now)):
            selected.append(name)
    return selected


async def run_tick(cfg: AppConfig, *, warmup: bool, on_results, run_id: str | None = None) -> None:
    """Run due checks and await on_results(owner_id, domain, results, warmup=warmup).

    Results are persisted before delivery. A regular tick also calls on_results
    with an empty list when nothing is due, allowing failed delivery to retry
    without extra probes. Warmup calls only follow actual probes. The consumer
    owns baseline initialization, deduplication and delivery.
    """
    if not cfg.scheduler.enabled:
        return

    owners: list[int] = storage.list_users()
    if not owners:
        log.debug("No users found; nothing to check", extra={"event": "scheduler.nousers", "run_id": run_id})
        return

    domains_conc = int(getattr(cfg.scheduler, "domains_concurrency", 5) or 5)
    sem = asyncio.Semaphore(max(1, domains_conc))

    total_domains = 0
    for owner_id in owners:
        total_domains += len(storage.list_domains(owner_id))

    log.debug(
        "scheduler.batch.summary",
        extra={"event": "scheduler.batch.summary", "run_id": run_id, "owners": len(owners), "domains": total_domains, "warmup": warmup},
    )

    async with Dispatcher(cfg) as d:
        # Start one global preparation without delaying operational probes.
        rkn_enabled = False
        for owner in owners:
            for domain in storage.list_domains(owner):
                try:
                    resolved = resolve_settings(cfg, domain,
                        storage.get_domain_override(owner, domain) or {})
                    if resolved.interval_minutes != 0:
                        rkn_enabled |= resolved.checks.rkn_domain or resolved.checks.rkn_ip
                except (ValueError, TypeError):
                    continue
        if rkn_enabled:
            d.start_registry_refresh(background=True)

        async def _run_one(owner_id: int, domain: str) -> None:
            async with sem:
                try:
                    selected = due_checks(cfg, owner_id, domain, warmup=warmup)
                    override = storage.get_domain_override(owner_id, domain) or {}
                    if resolve_settings(cfg, domain, override).interval_minutes == 0:
                        return
                    if selected:
                        results = await d.run_for(owner_id, domain, only_checks=selected, use_cache=False, run_id=run_id)
                        storage.save_histories(owner_id, domain, results, create_missing=False, source="scheduled")
                    elif not warmup:
                        # Retry undelivered state changes on the next tick, without extra probes.
                        results = []
                    else:
                        return
                except Exception as e:
                    log.exception(
                        "Checks failed for owner=%s domain=%s: %s", owner_id, domain, e,
                        extra={"event": "domain.error", "run_id": run_id, "owner_id": owner_id, "domain": domain},
                    )
                    return

                try:
                    await on_results(owner_id, domain, results, warmup=warmup)
                except Exception as e:
                    log.exception(
                        "Result callback failed for owner=%s domain=%s: %s", owner_id, domain, e,
                        extra={"event": "alert.error", "run_id": run_id,
                               "owner_id": owner_id, "domain": domain},
                    )

        tasks: list[asyncio.Task[None]] = []

        for owner_id in owners:
            domains = storage.list_domains(owner_id)
            if not domains:
                continue
            for name in domains:
                tasks.append(asyncio.create_task(_run_one(owner_id, name)))

        if not tasks:
            log.debug("No domains to check", extra={"event": "scheduler.nodomains", "run_id": run_id})
            return

        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            # gather can raise while another probe is still unwinding its async cleanup.
            for task in tasks:
                if not task.done() and not task.cancelling():
                    task.cancel()
            drain = asyncio.gather(*tasks, return_exceptions=True)
            while not drain.done():
                try:
                    await asyncio.shield(drain)
                except asyncio.CancelledError:
                    pass
            raise

