# sitewatcher/bot/jobs.py
from __future__ import annotations

import asyncio
import logging
import uuid
import random
from typing import Optional, Sequence

from telegram.ext import Application, ContextTypes

from .. import storage
from ..config import AppConfig
from .. import scheduler
from ..scheduler import due_checks as due_checks
from .alerts import AlertDeduper, _complete_results, _overall_from_results, maybe_send_alert, safe_send_message
from .utils import _resolve_alert_chat_id

# Module-level logger
log = logging.getLogger(__name__)


def _new_run_id() -> str:
    """Generate a short correlation id for a scheduler run."""
    return uuid.uuid4().hex


def register_jobs(app: Application, cooldown: int) -> None:
    """Register periodic jobs: main checks loop, warmup, and alert summaries flush.

    Args:
        app: Telegram application instance.
        cooldown: Alerts cooldown (seconds) for the in-process deduper.
    """
    cfg: AppConfig = app.bot_data["cfg"]
    if not cfg.scheduler.enabled:
        log.info("Scheduler disabled")
        return

    # Create a process-local deduper if missing
    if app.bot_data.get("alert_deduper") is None:
        app.bot_data["alert_deduper"] = AlertDeduper(cooldown_sec=cooldown)

    jq = app.job_queue
    interval_min = cfg.scheduler.interval_minutes
    first_delay = random.randint(0, cfg.scheduler.jitter_seconds)  # small jitter to avoid thundering herd

    # A timer delay cannot guarantee baseline completion before periodic alerts.
    app.bot_data["scheduler_warmup_pending"] = cfg.scheduler.run_on_startup

    # One-time warmup job (baseline without alerts)
    if cfg.scheduler.run_on_startup:
        jq.run_once(job_warmup, when=first_delay // 2 or 5, name="sitewatcher:job_warmup")

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
    log.info(
        "Scheduler enabled: every %d min (first in ~%d s); alerts policy=%s; alerts cooldown=%ss",
        interval_min,
        first_delay,
        policy,
        cooldown,
    )


async def job_warmup(context: ContextTypes.DEFAULT_TYPE) -> None:
    """One-time warmup: run checks without sending alerts to establish baseline."""
    run_id = _new_run_id()
    try:
        log.info("scheduler.warmup.start", extra={"event": "scheduler.warmup.start", "run_id": run_id})
        await _run_checks_for_all_domains(context, warmup=True, run_id=run_id)
        log.info("scheduler.warmup.done", extra={"event": "scheduler.warmup.done", "run_id": run_id})
    except Exception as e:  # pragma: no cover
        log.exception("Unhandled error in job_warmup: %s", e, extra={"event": "scheduler.warmup.error", "run_id": run_id})
    finally:
        context.application.bot_data["scheduler_warmup_pending"] = False


async def job_periodic(context: ContextTypes.DEFAULT_TYPE) -> None:
    """Periodic job: run checks for all users/domains and emit alerts."""
    if context.application.bot_data.get("scheduler_warmup_pending", False):
        return
    run_id = _new_run_id()
    try:
        cfg: AppConfig = context.application.bot_data["cfg"]
        owners: Sequence[int] = storage.list_users()
        log.info(
            "scheduler.run",
            extra={"event": "scheduler.run", "run_id": run_id, "owners": len(owners), "interval_min": getattr(cfg.scheduler, "interval_minutes", None)},
        )
        await _run_checks_for_all_domains(context, warmup=False, run_id=run_id)
        log.info("scheduler.done", extra={"event": "scheduler.done", "run_id": run_id})
    except Exception as e:  # pragma: no cover
        log.exception("Unhandled error in job_periodic: %s", e, extra={"event": "scheduler.error", "run_id": run_id})


async def _run_checks_for_all_domains(
    context: ContextTypes.DEFAULT_TYPE,
    *,
    warmup: bool,
    run_id: Optional[str],
) -> None:
    """Connect the shared tick to Telegram baseline and alert delivery."""
    cfg: AppConfig = context.application.bot_data["cfg"]

    async def on_results(owner_id: int, domain: str, results: list, *, warmup: bool) -> None:
        if warmup and storage.get_alert_state(owner_id, domain) is None:
            baseline = _overall_from_results(_complete_results(cfg, owner_id, domain, results))
            storage.upsert_alert_state(owner_id, domain, baseline, None)
        elif not warmup:
            if not results:
                results = _complete_results(cfg, owner_id, domain, [])
            await maybe_send_alert(update=None, context=context, owner_id=owner_id,
                                   domain=domain, results=results, run_id=run_id)

    await scheduler.run_tick(cfg, warmup=warmup, on_results=on_results, run_id=run_id)


async def _flush_alert_summaries_job(context: ContextTypes.DEFAULT_TYPE) -> None:
    """Periodic job: flush deduper summaries as compact messages."""
    deduper: Optional[AlertDeduper] = context.application.bot_data.get("alert_deduper")  # type: ignore[assignment]
    if deduper is None:
        return

    cfg: AppConfig = context.application.bot_data["cfg"]
    if not cfg.alerts.enabled:
        return
    # Job invocations and ordinary alerts must not deliver the same pending count twice.
    flush_lock = context.application.bot_data.setdefault("summary_flush_lock", asyncio.Lock())
    async with flush_lock:
        keys = deduper.pending_summaries()
        for key in keys:
            locks = context.application.bot_data.setdefault("alert_locks", {})
            lock = locks.setdefault((key.owner_id, key.domain), asyncio.Lock())
            async with lock:
                try:
                    if not storage.domain_exists(key.owner_id, key.domain):
                        deduper.discard(key)
                        continue
                    if not storage.is_user_alerts_enabled(key.owner_id):
                        continue
                    chat_id = _resolve_alert_chat_id(context, update=None, cfg=cfg,
                                                     owner_id=key.owner_id)
                    if not chat_id:
                        continue
                    # An ordinary alert may have consumed these counts while waiting for its lock.
                    summary = deduper.pending_summary(key)
                    if summary is None:
                        continue
                    text, count = summary
                    await safe_send_message(
                        context.bot,
                        chat_id=chat_id,
                        text=text,
                        parse_mode=None,
                        disable_web_page_preview=True,
                    )
                    deduper.acknowledge_summary(key, count)
                    log.info(
                        "alert.summary.sent",
                        extra={"event": "alert.summary.sent", "owner_id": key.owner_id,
                               "domain": key.domain},
                    )
                except Exception as e:
                    log.warning(
                        "Failed to flush alert summary for %s/%s: %s", key.owner_id, key.domain, e,
                        extra={"event": "alert.summary.error", "owner_id": key.owner_id,
                               "domain": key.domain},
                    )
