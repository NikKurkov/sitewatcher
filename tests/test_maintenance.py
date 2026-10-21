import asyncio
import datetime
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
