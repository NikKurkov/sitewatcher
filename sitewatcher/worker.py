"""Unattended monitoring with optional Telegram delivery, without update polling."""
from __future__ import annotations

from asyncio import sleep
from contextlib import AsyncExitStack
from datetime import datetime, timedelta, timezone
import logging
import random
from time import monotonic
from types import SimpleNamespace
import uuid

from telegram import Bot
from telegram.request import HTTPXRequest

from . import maintenance, scheduler, scheduler_lock, storage
from .bot import jobs
from .bot.alerts import AlertDeduper
from .config import AppConfig
from .telegram_connection import load_bot_token
from .telegram_proxy import load_proxy

log = logging.getLogger(__name__)


async def run_worker(cfg: AppConfig) -> None:
    """Own scheduling until cancellation; web processes never enter this loop."""
    with scheduler_lock.acquire(storage.DEFAULT_DB):
        async with AsyncExitStack() as clients:
            context = SimpleNamespace(bot=None, application=SimpleNamespace(bot_data={
                'cfg': cfg, 'alert_deduper': AlertDeduper(cfg.alerts.effective_cooldown),
            }))
            current_connection = None

            async def refresh_telegram():
                nonlocal current_connection
                try:
                    token = load_bot_token()
                    proxy = load_proxy()
                except (OSError, ValueError):
                    token, proxy = None, None
                    log.warning('worker.telegram.configuration_invalid')
                if (token, proxy) == current_connection and (context.bot is not None or token is None):
                    return
                context.bot = None
                await clients.aclose()
                current_connection = (token, proxy)
                if not token:
                    return
                try:
                    # Own both requests explicitly so failed/partial Bot initialization closes them.
                    request = await clients.enter_async_context(HTTPXRequest(
                        proxy=proxy, connection_pool_size=32,
                        connect_timeout=10, read_timeout=30, write_timeout=30, pool_timeout=10,
                    ))
                    updates_request = await clients.enter_async_context(HTTPXRequest(
                        proxy=proxy,
                    ))
                    bot = Bot(token=token, request=request, get_updates_request=updates_request)
                    clients.push_async_callback(bot.shutdown)
                    await bot.initialize()
                    context.bot = bot
                except Exception as error:
                    await clients.aclose()
                    # PTB token rejection errors can include the credential. Log only the type.
                    log.warning('worker.telegram.unavailable', extra={'etype': type(error).__name__})

            async def tick(*, warmup):
                await refresh_telegram()
                run_id = uuid.uuid4().hex

                async def on_results(owner_id, domain, results, *, warmup):
                    if warmup or context.bot is not None:
                        await jobs.process_results(context, owner_id, domain, results,
                                                   warmup=warmup, run_id=run_id)

                await scheduler.run_tick(cfg, warmup=warmup, on_results=on_results, run_id=run_id)

            jitter = random.randint(0, cfg.scheduler.jitter_seconds)
            if cfg.scheduler.enabled and jitter:
                await sleep(jitter)
            if cfg.scheduler.enabled and cfg.scheduler.run_on_startup:
                await tick(warmup=True)

            next_tick = monotonic()
            summary_interval = max(60, cfg.alerts.effective_cooldown)
            next_summary = next_tick + summary_interval
            next_cleanup = datetime.combine(datetime.now(timezone.utc).date(),
                                            maintenance.cleanup_time(cfg))
            while True:
                now = monotonic()
                if now >= next_tick:
                    await tick(warmup=False)
                    interval = cfg.scheduler.interval_minutes * 60
                    next_tick += interval
                    if next_tick <= monotonic():
                        next_tick = monotonic() + interval
                now_utc = datetime.now(timezone.utc)
                if now_utc >= next_cleanup:
                    await maintenance.cleanup_history(cfg)
                    next_cleanup = datetime.combine(now_utc.date() + timedelta(days=1),
                                                    maintenance.cleanup_time(cfg))
                if monotonic() >= next_summary:
                    if context.bot is not None:
                        await jobs._flush_alert_summaries_job(context)
                    next_summary = monotonic() + summary_interval
                delay = min(next_tick - monotonic(), next_summary - monotonic(),
                            (next_cleanup - datetime.now(timezone.utc)).total_seconds())
                if delay > 0:
                    await sleep(delay)
