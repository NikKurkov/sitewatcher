import asyncio
from contextlib import closing
import sqlite3
from types import SimpleNamespace

import pytest

from sitewatcher import storage
from sitewatcher.bot.handlers.history import cmd_history


def save(domain, check, status, message, *, owner=1):
    storage.save_history(owner, domain, check, status, message, {})


def command(*args):
    replies = []

    class Message:
        async def reply_html(self, text, **kwargs):
            replies.append(text)

    update = SimpleNamespace(effective_user=SimpleNamespace(id=1), effective_message=Message())
    asyncio.run(cmd_history(update, SimpleNamespace(args=list(args))))
    return '\n'.join(replies)


@pytest.mark.parametrize('status_filter', [[], ['crit']])
def test_changes_find_repeated_incident_after_recovery(status_filter):
    save('example.com', 'ping', 'CRIT', 'initial incident')
    save('example.com', 'ping', 'OK', 'intervening recovery')
    save('example.com', 'ping', 'CRIT', 'second incident')
    with closing(sqlite3.connect(storage.DEFAULT_DB)) as conn, conn:
        conn.execute("UPDATE history SET created_at='2026-10-21 12:00:00'")
    text = command('example.com', 'changes', *status_filter)
    assert 'second incident' in text
    assert 'initial incident' not in text and 'intervening recovery' not in text


@pytest.mark.parametrize('status_filter,expected', [('crit', 'onset'), ('ok', 'recovery')])
def test_changes_apply_onset_and_recovery_filters_after_transition_detection(status_filter, expected):
    save('example.com', 'ping', 'OK', 'initial baseline')
    save('example.com', 'ping', 'CRIT', 'onset')
    save('example.com', 'ping', 'OK', 'recovery')
    text = command('example.com', 'changes', status_filter)
    assert expected in text
    assert ('recovery' if expected == 'onset' else 'onset') not in text
    assert 'initial baseline' not in text


def interleaved_history():
    save('a.example', 'ping', 'OK', 'ping baseline')
    save('b.example', 'ping', 'CRIT', 'other domain baseline')
    save('a.example', 'tls_cert', 'OK', 'tls baseline')
    save('a.example', 'ping', 'CRIT', 'ping onset')
    save('b.example', 'ping', 'OK', 'other domain recovery')
    save('a.example', 'tls_cert', 'WARN', 'tls onset')
    save('private.example', 'ping', 'CRIT', 'private owner incident', owner=2)
    save('a.example', 'ping', 'OK', 'ping recovery')
    with closing(sqlite3.connect(storage.DEFAULT_DB)) as conn, conn:
        conn.execute("UPDATE history SET created_at='2026-10-21 12:00:00'")


def test_changes_keep_check_and_domain_sequences_separate_with_same_second_order():
    interleaved_history()
    text = command('changes')
    assert 'tls onset' in text and 'ping onset' in text
    assert text.index('tls onset') < text.index('ping onset')
    for omitted in ('baseline', 'recovery', 'private owner incident'):
        assert omitted not in text


def test_plain_history_same_second_limit_selects_newest_ids_first():
    interleaved_history()
    rows = list(storage.iter_history(1, limit=3))
    assert [row['message'] for row in rows] == [
        'ping recovery', 'tls onset', 'other domain recovery',
    ]
    assert [row['id'] for row in rows] == sorted((row['id'] for row in rows), reverse=True)
    text = command('ok', 'warn', 'crit', 'limit=3')
    assert text.index('ping recovery') < text.index('tls onset') < text.index('other domain recovery')
    assert 'private owner incident' not in text and 'ping onset' not in text
