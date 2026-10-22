"""Framework-independent scheduled check selection, dispatch and persistence."""
from __future__ import annotations

import asyncio
import logging

from . import storage
from .config import AppConfig, resolve_settings
from .dispatcher import Dispatcher

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
    return [
        name for name, enabled in checks.items()
        if enabled and (name not in ages or ages[name] >= (
            int(domain_interval) if domain_interval is not None
            else getattr(cfg.schedules, name).interval_minutes
        ))
    ]


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

