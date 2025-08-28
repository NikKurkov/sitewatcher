# /bot/jobs.py
from __future__ import annotations

import logging
import random
from telegram.ext import Application, ContextTypes

from .. import storage
from ..dispatcher import Dispatcher
from .alerts import maybe_send_alert, AlertDeduper
from .utils import _strip_cached_suffix, _resolve_alert_chat_id

logger = logging.getLogger("sitewatcher.bot")


async def _run_checks_for_all_domains(context: ContextTypes.DEFAULT_TYPE, warmup: bool) -> None:
    """Background scheduler loop."""
    cfg = context.application.bot_data["cfg"]
    domains = storage.list_domains()
    if not domains:
        return

    async with Dispatcher(cfg) as d:
        for name in domains:
            try:
                # Figure out due checks per domain
                due = _due_checks_for_domain(cfg, name)
                if not due:
                    continue
                results = await d.run_for(name, only_checks=due, use_cache=False)
                for r in results:
                    storage.save_history(name, r.check, r.status, _strip_cached_suffix(r.message), r.metrics)
                await maybe_send_alert(None, context, name, results)
            except Exception as e:
                logger.exception("scheduler: %s failed: %s", name, e)


def _due_checks_for_domain(cfg, domain: str) -> list[str]:
    """
    Decide which checks are due for the domain.

    If domain override contains 'interval_minutes':
      - <=0   → no scheduled checks for this domain (auto-check disabled)
      - >0    → use this single interval for ALL checks of the domain

    Otherwise: fall back to per-check intervals from cfg.schedules.
    """
    # Domain-level override
    try:
        override = storage.get_domain_override(domain) or {}
    except Exception:
        override = {}

    from datetime import datetime
    if isinstance(override.get("interval_minutes"), int):
        iv = int(override["interval_minutes"])
        if iv <= 0:
            return []
        due: list[str] = []
        sched_names = list(cfg.schedules.model_dump().keys())
        for check_name in sched_names:
            mins = storage.minutes_since_last(domain, check_name)
            if mins is None or mins >= iv:
                due.append(check_name)
        return due

    # Default per-check schedule
    sched = cfg.schedules.model_dump()
    due: list[str] = []
    for check_name, sc in sched.items():
        interval_min = int(sc.get("interval_minutes") or 0)
        if interval_min <= 0:
            continue
        mins = storage.minutes_since_last(domain, check_name)
        if mins is None or mins >= interval_min:
            due.append(check_name)
    return due


async def job_warmup(context: ContextTypes.DEFAULT_TYPE) -> None:
    await _run_checks_for_all_domains(context, warmup=True)


async def job_periodic(context: ContextTypes.DEFAULT_TYPE) -> None:
    await _run_checks_for_all_domains(context, warmup=False)


async def _flush_alert_summaries_job(context: ContextTypes.DEFAULT_TYPE) -> None:
    """Periodic job to flush suppression summaries to the alert chat."""
    deduper: AlertDeduper | None = context.application.bot_data.get("alert_deduper")
    if deduper is None:
        return
    summaries = deduper.flush_summaries()
    if not summaries:
        return
    cfg = context.application.bot_data["cfg"]
    chat_id = _resolve_alert_chat_id(context, update=None, cfg=cfg)
    if not chat_id:
        return
    for _, summary in summaries:
        try:
            await context.bot.send_message(chat_id=chat_id, text=summary, disable_web_page_preview=True)
        except Exception as e:
            logger.warning("failed to send summary: %s", e)


def register_jobs(app: Application, cooldown: int) -> None:
    """Attach warmup/periodic jobs and summary flush."""
    jq = app.job_queue
    cfg = app.bot_data["cfg"]
    sch = cfg.scheduler

    if not getattr(sch, "enabled", True):
        logger.info("Scheduler disabled by config")
        return

    # Warmup run
    if getattr(sch, "run_on_startup", True):
        jq.run_once(job_warmup, when=5)

    interval = max(60, int(sch.interval_minutes) * 60)
    jitter = max(0, int(getattr(sch, "jitter_seconds", 0)))
    first = random.randint(1, max(1, jitter)) if jitter > 0 else interval

    jq.run_repeating(
        job_periodic,
        interval=interval,
        first=first,
        name="sitewatcher:periodic_checks",
    )

    # Periodic flush of deduper summaries
    jq.run_repeating(
        _flush_alert_summaries_job,
        interval=max(60, cooldown),
        first=cooldown + random.randint(0, 5),
        name="sitewatcher:alerts_flush",
    )

    logger.info(
        "Scheduler enabled: every %s min (first in ~%s s); alerts policy=%s; alerts cooldown=%ss",
        sch.interval_minutes,
        first,
        getattr(cfg.alerts, "policy", "overall_change"),
        cooldown,
    )
