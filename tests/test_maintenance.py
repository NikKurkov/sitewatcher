import asyncio
import datetime
import threading

import pytest
from contextlib import closing
from types import SimpleNamespace

from telegram.ext import Application

from sitewatcher import storage
from sitewatcher.bot.app import run_bot
from sitewatcher.config import AppConfig


def test_zero_retention_and_sunday_vacuum_use_scheduled_utc_timezone(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, 'DEFAULT_DB', tmp_path / 'maintenance.db')
    monkeypatch.setenv('TELEGRAM_TOKEN', '123:offline')
    monkeypatch.setenv('TELEGRAM_ALLOWED_USER_IDS', '7')
    storage.add_domain(7, 'example.com')
    with closing(storage._connect()) as connection:
        connection.execute("""
            INSERT INTO history(owner_id,domain,check_name,status,message,created_at)
            VALUES(7,'example.com','ping','OK','old',datetime('now','-1 day'))
        """)
    actual_datetime = datetime.datetime
    timezone_args = []

    class Clock(actual_datetime):
        @classmethod
        def now(cls, tz=None):
            timezone_args.append(tz)
            if tz is None:
                return actual_datetime(2026, 10, 26, 0, 30)  # Local Monday, UTC Sunday.
            return actual_datetime(2026, 10, 25, 21, 30, tzinfo=datetime.timezone.utc)

    monkeypatch.setattr(datetime, 'datetime', Clock)
    applications = []
    monkeypatch.setattr(Application, 'run_polling',
                        lambda self, **kwargs: applications.append(self))
    vacuumed = []
    monkeypatch.setattr(storage, 'vacuum_and_optimize', lambda: vacuumed.append(True))
    cfg = AppConfig()
    cfg.history.retention_days = 0
    cfg.history.cleanup_time = '03:30'
    run_bot(cfg)
    application = applications[0]
    job = application.job_queue.get_jobs_by_name('maintenance.cleanup_history')[0]
    assert job.job.trigger.timezone == datetime.timezone.utc
    asyncio.run(job.callback(SimpleNamespace(application=application)))
    assert storage.last_results(7, 'example.com') == []
    assert vacuumed == [True]
    assert timezone_args[-1] == datetime.timezone.utc


@pytest.mark.parametrize('operation', ['cleanup', 'vacuum'])
def test_sqlite_maintenance_leaves_event_loop_responsive(monkeypatch, operation):
    monkeypatch.setenv('TELEGRAM_TOKEN', '123:offline')
    monkeypatch.setenv('TELEGRAM_ALLOWED_USER_IDS', '7')
    actual_datetime = datetime.datetime

    class Sunday(actual_datetime):
        @classmethod
        def now(cls, tz=None):
            return actual_datetime(2026, 10, 25, 3, 30, tzinfo=datetime.timezone.utc)

    monkeypatch.setattr(datetime, 'datetime', Sunday)
    applications = []
    monkeypatch.setattr(Application, 'run_polling',
                        lambda self, **kwargs: applications.append(self))
    started = threading.Event()
    release = threading.Event()
    released_by_heartbeat = []

    def blocking_sqlite(*args):
        started.set()
        released_by_heartbeat.append(release.wait(timeout=2))
        return 0

    monkeypatch.setattr(storage, 'cleanup_history',
                        blocking_sqlite if operation == 'cleanup' else lambda days: 0)
    monkeypatch.setattr(storage, 'vacuum_and_optimize',
                        blocking_sqlite if operation == 'vacuum' else lambda: None)
    cfg = AppConfig()
    cfg.history.vacuum_weekly = operation == 'vacuum'
    run_bot(cfg)
    application = applications[0]
    job = application.job_queue.get_jobs_by_name('maintenance.cleanup_history')[0]

    async def scenario():
        async def heartbeat():
            while not started.is_set():
                await asyncio.sleep(0)
            release.set()

        heartbeat_task = asyncio.create_task(heartbeat())
        try:
            await job.callback(SimpleNamespace(application=application))
            await asyncio.wait_for(heartbeat_task, timeout=3)
        finally:
            release.set()
            if not heartbeat_task.done():
                heartbeat_task.cancel()

    asyncio.run(scenario())
    assert released_by_heartbeat == [True]
