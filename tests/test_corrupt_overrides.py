import asyncio
from contextlib import closing
import csv
import io
import sqlite3
from types import SimpleNamespace

import pytest

from sitewatcher import storage
from sitewatcher.bot.alerts import _is_fresh_ok_for_all
from sitewatcher.bot.handlers.cfg import cmd_cfg, cmd_cfg_set, cmd_cfg_unset
from sitewatcher.bot.jobs import due_checks
from sitewatcher.checks.base import CheckOutcome, Status
from sitewatcher.config import AppConfig
from sitewatcher.dispatcher import Dispatcher
from sitewatcher.utils.domains_csv import HEADERS, import_domains_csv


@pytest.fixture
def corrupt_domain():
    storage.add_domain(1, 'example.com')
    raw = '{"proxy":"http://user:private-password@proxy.example"'
    with closing(sqlite3.connect(storage.DEFAULT_DB)) as conn, conn:
        conn.execute('INSERT INTO domain_overrides(owner_id,domain,data_json) VALUES(1,?,?)',
                     ('example.com', raw))
    return raw


def raw_override():
    with closing(sqlite3.connect(storage.DEFAULT_DB)) as conn:
        return conn.execute('SELECT data_json FROM domain_overrides').fetchone()


def interaction(args):
    replies = []

    class Message:
        async def reply_text(self, text, **kwargs):
            replies.append(text)

        async def reply_html(self, text, **kwargs):
            replies.append(text)

    update = SimpleNamespace(effective_user=SimpleNamespace(id=1), effective_message=Message())
    context = SimpleNamespace(args=args, application=SimpleNamespace(bot_data={'cfg': AppConfig()}))
    return update, context, replies


def test_corrupt_settings_prevent_probes_and_due_selection(corrupt_domain, monkeypatch):
    def no_probes(*args, **kwargs):
        pytest.fail('Probes cannot run without valid owner settings')

    dispatcher = Dispatcher(AppConfig())
    dispatcher._client = object()
    monkeypatch.setattr(dispatcher, '_build_checks', no_probes)
    with pytest.raises(ValueError):
        asyncio.run(dispatcher.run_for(1, 'example.com'))
    with pytest.raises(ValueError):
        due_checks(AppConfig(), 1, 'example.com')
    assert raw_override()[0] == corrupt_domain


@pytest.mark.parametrize('command,args', [
    (cmd_cfg, ['example.com']),
    (cmd_cfg_unset, ['example.com', 'proxy']),
    (cmd_cfg_set, ['example.com', 'interval_minutes', '5']),
])
def test_settings_commands_reject_corruption_without_exposing_or_changing_values(
    corrupt_domain, command, args,
):
    update, context, replies = interaction(args)
    asyncio.run(command(update, context))
    assert replies and 'Invalid' in replies[0]
    assert 'private-password' not in ''.join(replies)
    assert 'Effective settings' not in ''.join(replies)
    assert raw_override()[0] == corrupt_domain


def test_full_reset_repairs_corrupt_settings_without_reading_them(corrupt_domain, monkeypatch):
    def no_read(*args):
        pytest.fail('A full reset must bypass the corrupt settings reader')

    monkeypatch.setattr(storage, 'get_domain_override', no_read)
    update, context, replies = interaction(['example.com'])
    asyncio.run(cmd_cfg_unset(update, context))
    assert raw_override() is None
    assert storage.domain_exists(1, 'example.com')
    assert 'Removed entire override' in ''.join(replies)


def test_corrupt_settings_csv_merge_is_rejected_but_explicit_replacement_repairs(corrupt_domain):
    stream = io.StringIO()
    writer = csv.DictWriter(stream, fieldnames=HEADERS, delimiter=';')
    writer.writeheader()
    writer.writerow({'domain': 'example.com', 'interval_minutes': '0'})
    data = stream.getvalue().encode()
    report = import_domains_csv(1, data, mode='merge')
    assert report.skipped == 1 and 'private-password' not in str(report.errors)
    assert raw_override()[0] == corrupt_domain
    report = import_domains_csv(1, data, mode='replace')
    assert report.updated == 1 and not report.errors
    assert storage.get_domain_override(1, 'example.com')['interval_minutes'] == 0


def test_recovery_is_not_confirmed_when_override_read_fails(monkeypatch):
    def unreadable(*args):
        raise sqlite3.OperationalError('private-database-details')

    monkeypatch.setattr(storage, 'get_domain_override', unreadable)
    assert not _is_fresh_ok_for_all(AppConfig(), 1, 'example.com', ['ping'], [
        CheckOutcome('ping', Status.OK, 'up', {}),
    ])
