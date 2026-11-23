"""Confirm unusually slow scheduled HTTP observations without delaying the scheduler."""
from __future__ import annotations

import asyncio
from asyncio import sleep
from contextlib import closing
from datetime import datetime, timedelta, timezone
import logging
import sqlite3
from statistics import median
from time import monotonic
from uuid import uuid4

from . import storage
from .check_policy import MAX_LATENCY_RECHECK_WINDOW_S, latency_recheck_pending, metrics_from
from .checks.base import Status
from .config import AppConfig, resolve_settings
from .dispatcher import Dispatcher

log = logging.getLogger(__name__)
BASELINE_SAMPLES = 7
RECHECK_INTERVAL_S = 20


def http_latency(metrics):
    code = metrics.get('final_code', metrics.get('code_initial'))
    if (type(code) is not int or not 200 <= code < 300
            or metrics.get('availability') in ('unavailable', 'unknown')
            or metrics.get('redirect_error')):
        return None
    value = metrics.get('chart_response_latency_ms',
                        metrics.get('response_latency_ms', metrics.get('latency_ms_total')))
    return value if type(value) in (int, float) and 0 <= value <= 2**53 else None


class LatencyRechecks:
    """Keep one bounded series per owner/domain within the scheduler's lifetime."""

    def __init__(self, cfg: AppConfig):
        self.cfg = cfg
        self.tasks: dict[tuple[int, str], asyncio.Task] = {}
        self.slots = asyncio.Semaphore(cfg.scheduler.domains_concurrency)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        await self.close()

    async def close(self):
        tasks = tuple(self.tasks.values())
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    def prepare(self, owner_id, domain, results):
        if (owner_id, domain) in self.tasks:
            return None
        result = next((r for r in results if r.check == 'http_basic' and not r.cached), None)
        if result is None:
            return None
        raw = http_latency(result.metrics)
        target = result.metrics.get('http_target') or result.metrics.get('origin_url')
        if raw is None or raw < 1000 or not target:
            return None
        override = storage.get_domain_override(owner_id, domain)
        settings = resolve_settings(self.cfg, domain, override)
        if not settings.checks.http_basic or settings.interval_minutes == 0 or settings.http_url != target:
            return None
        baseline = []
        with closing(storage.iter_scheduled_http(owner_id, domain)) as rows:
            for row in rows:
                metrics = metrics_from(row)
                if (metrics.get('http_target') or metrics.get('origin_url')) != target:
                    continue
                value = http_latency(metrics)
                if value is not None:
                    baseline.append(value)
                    if len(baseline) == BASELINE_SAMPLES:
                        break
        if len(baseline) < BASELINE_SAMPLES:
            return None
        ordinary = median(baseline)
        if raw < 3 * ordinary or raw - ordinary < 1000:
            return None
        probe_budget = max(RECHECK_INTERVAL_S, settings.http_timeout_s,
                           self.cfg.scheduler.domain_timeout_s or 0)
        window = min(MAX_LATENCY_RECHECK_WINDOW_S, 3 * (RECHECK_INTERVAL_S + probe_budget) + 5)
        detail = {
            'token': uuid4().hex,
            'state': 'pending',
            'expires_at': (datetime.now(timezone.utc) + timedelta(seconds=window)).isoformat(),
            'initial_ms': raw,
            'samples': [],
        }
        result.metrics['latency_recheck'] = detail
        return detail, storage.domain_override_revision(override)

    def start(self, owner_id, domain, prepared, on_results):
        key = (owner_id, domain)
        detail, revision = prepared
        task = asyncio.create_task(self._run(owner_id, domain, detail, revision, on_results))
        self.tasks[key] = task
        task.add_done_callback(lambda _: self.tasks.pop(key, None))

    def _current(self, owner_id, domain, revision, token):
        override = storage.get_domain_override(owner_id, domain)
        if storage.domain_override_revision(override) != revision:
            return False
        metrics = metrics_from(storage.last_history_for_check(owner_id, domain, 'http_basic'))
        return (latency_recheck_pending(metrics, datetime.now(timezone.utc))
                and metrics['latency_recheck']['token'] == token)

    async def _run(self, owner_id, domain, original, revision, on_results):
        detail = {**original, 'samples': []}
        next_probe = monotonic() + RECHECK_INTERVAL_S
        expires = datetime.fromisoformat(detail['expires_at'])
        remaining = (expires - datetime.now(timezone.utc)).total_seconds()
        failed = None
        try:
            async with asyncio.timeout(remaining - 5), Dispatcher(self.cfg) as dispatcher:
                for _ in range(3):
                    delay = next_probe - monotonic()
                    if delay > 0:
                        await sleep(delay)
                    async with self.slots:
                        if not self._current(owner_id, domain, revision, detail['token']):
                            return
                        next_probe = monotonic() + RECHECK_INTERVAL_S
                        results = await dispatcher.run_for(
                            owner_id, domain, only_checks=['http_basic'], use_cache=False,
                        )
                    if not results:
                        return
                    result = results[0]
                    value = http_latency(result.metrics)
                    code = result.metrics.get('final_code', result.metrics.get('status_code'))
                    detail['samples'].append({'latency_ms': value, 'http_code': code})
                    unavailable = result.metrics.get('availability') == 'unavailable'
                    if result.status is Status.UNKNOWN or unavailable:
                        result.metrics['availability'] = 'unavailable' if unavailable else 'unknown'
                        final = {**detail, 'state': 'failed'}
                        if storage.update_latency_recheck(
                            owner_id, domain, final, expected_revision=revision, failure=result,
                        ):
                            detail = final
                            failed = result
                        break
                    if value is None or not storage.update_latency_recheck(
                        owner_id, domain, detail, expected_revision=revision,
                    ):
                        return
                else:
                    value = median(sample['latency_ms'] for sample in detail['samples'])
                    final = {**detail, 'state': 'confirmed', 'median_ms': value}
                    if storage.update_latency_recheck(
                        owner_id, domain, final, expected_revision=revision,
                    ):
                        detail = final
            if failed is not None:
                await on_results(owner_id, domain, [failed], warmup=False)
        except Exception as error:
            log.warning('HTTP latency confirmation interrupted (%s)', type(error).__name__)
        finally:
            if detail['state'] == 'pending':
                detail['state'] = 'interrupted'
                try:
                    storage.update_latency_recheck(owner_id, domain, detail)
                except sqlite3.Error as error:
                    log.warning('Could not save interrupted HTTP confirmation (%s)', type(error).__name__)
