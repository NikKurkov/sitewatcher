# sitewatcher/bot/jobs.py
from __future__ import annotations

import asyncio
import logging
import random
from typing import Optional, Sequence

from telegram.ext import Application, ContextTypes

from .. import storage
from ..config import AppConfig
from ..dispatcher import Dispatcher
from .alerts import AlertDeduper, maybe_send_alert
from .utils import _resolve_alert_chat_id

logger = logging.getLogger("sitewatcher.bot")


def register_jobs(app: Application, cooldown: int) -> None:
    """Register periodic jobs: main checks loop and alert summaries flush.

    Args:
        app: Telegram application instance.
        cooldown: Alerts cooldown (seconds) for the in-process deduper.
    """
    cfg: AppConfig = app.bot_data["cfg"]

    # Create a process-local deduper if missing
    if app.bot_data.get("alert_deduper") is None:
        app.bot_data["alert_deduper"] = AlertDeduper(cooldown_sec=cooldown)

    jq = app.job_queue
    interval_min = int(getattr(cfg.scheduler, "interval_minutes", 1) or 1)
    first_delay = random.randint(10, 20)  # small jitter to avoid thundering herd

    # Main periodic checks
    jq.run_repeating(
        job_periodic,
        interval=interval_min * 60,
        first=first_delay,
        name="sitewatcher:periodic_checks",
    )

    # Summaries flush for suppressed alerts
    jq.run_repeating(
        _flush_alert_summaries_job,
        interval=max(60, cooldown),
        first=cooldown + random.randint(0, 5),
        name="sitewatcher:alerts_flush",
    )

    policy = getattr(cfg.alerts, "policy", "overall_change")
    logger.info(
        "Scheduler enabled: every %d min (first in ~%d s); alerts policy=%s; alerts cooldown=%ss",
        interval_min,
        first_delay,
        policy,
        cooldown,
    )


async def job_periodic(context: ContextTypes.DEFAULT_TYPE) -> None:
    """Periodic job: run checks for all users/domains and emit alerts."""
    try:
        await _run_checks_for_all_domains(context, warmup=False)
    except Exception as e:  # pragma: no cover
        logger.exception("Unhandled error in job_periodic: %s", e)


async def _run_checks_for_all_domains(
    context: ContextTypes.DEFAULT_TYPE,
    *,
    warmup: bool,
) -> None:
    """Run checks for all domains across all owners.

    Args:
        context: PTB job context.
        warmup: If True, do not send alerts (baseline initialization).
    """
    cfg: AppConfig = context.application.bot_data["cfg"]

    owners: Sequence[int] = storage.list_users()
    if not owners:
        logger.debug("No users found; nothing to check")
        return

    domains_conc = int(getattr(cfg.scheduler, "domains_concurrency", 5) or 5)
    sem = asyncio.Semaphore(max(1, domains_conc))

    async with Dispatcher(cfg) as d:

        async def _run_one(owner_id: int, domain: str) -> None:
            async with sem:
                try:
                    results = await d.run_for(owner_id, domain, use_cache=False)
                except Exception as e:
                    logger.exception("Checks failed for owner=%s domain=%s: %s", owner_id, domain, e)
                    return

                # Persist each check result to history
                for r in results:
                    storage.save_history(owner_id, domain, r.check, r.status, r.message, r.metrics)

                # Send alerts (unless warmup)
                if not warmup:
                    try:
                        await maybe_send_alert(update=None, context=context, owner_id=owner_id, domain=domain, results=results)
                    except Exception as e:
                        logger.exception("Alert send failed for owner=%s domain=%s: %s", owner_id, domain, e)

        tasks: list[asyncio.Task[None]] = []

        for owner_id in owners:
            domains = storage.list_domains(owner_id)
            if not domains:
                continue
            for name in domains:
                tasks.append(asyncio.create_task(_run_one(owner_id, name)))

        if not tasks:
            logger.debug("No domains to check")
            return

        await asyncio.gather(*tasks)


async def _flush_alert_summaries_job(context: ContextTypes.DEFAULT_TYPE) -> None:
    """Periodic job: flush deduper summaries as compact messages."""
    deduper: Optional[AlertDeduper] = context.application.bot_data.get("alert_deduper")  # type: ignore[assignment]
    if deduper is None:
        return

    cfg: AppConfig = context.application.bot_data["cfg"]
    pairs = deduper.flush_summaries(max_batch=20)
    if not pairs:
        return

    # Send summary per key to its owner's chat
    for key, text in pairs:
        try:
            chat_id = _resolve_alert_chat_id(context, update=None, cfg=cfg, owner_id=key.owner_id)
            if not chat_id:
                continue
            await context.bot.send_message(
                chat_id=chat_id,
                text=text,
                parse_mode=None,
                disable_web_page_preview=True,
            )
        except Exception as e:  # pragma: no cover
            logger.warning("Failed to flush alert summary for %s/%s: %s", key.owner_id, key.domain, e)
