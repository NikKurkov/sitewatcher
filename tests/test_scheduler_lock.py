"""Exclusive scheduler ownership uses OS descriptors, including after abrupt exits."""
import os
import selectors
import signal
import subprocess
import sys
import textwrap

import pytest


HOLDER = textwrap.dedent('''
    from pathlib import Path
    import sys
    from sitewatcher.scheduler_lock import acquire
    with acquire(Path(sys.argv[1])):
        print('LOCKED', flush=True)
        sys.stdin.read()
''')
CONTENDER = textwrap.dedent('''
    from pathlib import Path
    import sys
    from sitewatcher.scheduler_lock import acquire
    try:
        with acquire(Path(sys.argv[1])):
            print('ACQUIRED')
    except RuntimeError as exc:
        print(str(exc))
        sys.exit(23)
''')


def contender(path):
    return subprocess.run([sys.executable, '-c', CONTENDER, str(path)],
                          capture_output=True, text=True, timeout=5)


def holder(path):
    process = subprocess.Popen([sys.executable, '-c', HOLDER, str(path)],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    with selectors.DefaultSelector() as ready:
        ready.register(process.stdout, selectors.EVENT_READ)
        assert ready.select(timeout=5), 'Scheduler lock holder did not start promptly'
    line = process.stdout.readline()
    if line != 'LOCKED\n':
        process.kill()
        _, error = process.communicate(timeout=5)
        pytest.fail(f'Scheduler lock holder failed: {error}')
    return process


def stop(process):
    if process.poll() is None:
        process.kill()
    process.communicate(timeout=5)


def test_same_database_and_symlink_aliases_conflict_but_other_database_works(tmp_path):
    database = tmp_path / 'monitoring.db'
    database.touch()
    alias = tmp_path / 'alias.db'
    alias.symlink_to(database)
    directory_alias = tmp_path / 'directory-alias'
    directory_alias.symlink_to(tmp_path, target_is_directory=True)
    process = holder(database)
    try:
        for path in (database, alias, directory_alias / database.name):
            result = contender(path)
            assert result.returncode == 23, result.stderr
            assert 'already running' in result.stdout.lower()
        assert contender(tmp_path / 'other.db').returncode == 0
    finally:
        stop(process)


@pytest.mark.parametrize('exit_signal', [signal.SIGTERM, signal.SIGKILL])
def test_signal_releases_ownership_and_successor_keeps_lock_file(tmp_path, exit_signal):
    database = tmp_path / 'monitoring.db'
    first = holder(database)
    successor = None
    try:
        lock_files = set(tmp_path.iterdir())
        assert len(lock_files) == 1  # Locking must not create a monitoring database.
        lock_file = lock_files.pop()
        inode = lock_file.stat().st_ino
        os.kill(first.pid, exit_signal)
        first.communicate(timeout=5)
        successor = holder(database)
        assert lock_file.stat().st_ino == inode
        assert contender(database).returncode == 23
    finally:
        stop(first)
        if successor is not None:
            stop(successor)
    assert lock_file.stat().st_ino == inode
    assert contender(database).returncode == 0


def test_startup_failure_releases_descriptor(tmp_path):
    from sitewatcher.scheduler_lock import acquire

    database = tmp_path / 'monitoring.db'
    with pytest.raises(ValueError):
        with acquire(database):
            raise ValueError('startup failed')
    assert contender(database).returncode == 0


def test_busy_bot_fails_before_creating_request_clients(tmp_path, monkeypatch):
    from sitewatcher import storage
    from sitewatcher.bot import app
    from sitewatcher.config import AppConfig

    process = holder(storage.DEFAULT_DB)
    monkeypatch.setattr(app, 'get_bot_token_from_env', lambda: '123:offline')

    def unexpected_request(**kwargs):
        pytest.fail('Busy scheduler created an unclosable Telegram request client')

    monkeypatch.setattr(app, 'HTTPXRequest', unexpected_request)
    try:
        with pytest.raises(RuntimeError, match='already running'):
            app.run_bot(AppConfig())
    finally:
        stop(process)


def test_disabled_scheduler_bot_does_not_compete_for_ownership(tmp_path, monkeypatch):
    from telegram.ext import Application
    from sitewatcher import storage
    from sitewatcher.bot import app
    from sitewatcher.config import AppConfig

    process = holder(storage.DEFAULT_DB)
    monkeypatch.setattr(app, 'get_bot_token_from_env', lambda: '123:offline')
    polled = []
    monkeypatch.setattr(Application, 'run_polling', lambda self, **kwargs: polled.append(True))
    cfg = AppConfig()
    cfg.scheduler.enabled = False
    try:
        app.run_bot(cfg)
        assert polled == [True]
        assert contender(storage.DEFAULT_DB).returncode == 23
    finally:
        stop(process)


def test_bot_holds_lock_through_polling_and_releases_after_failure(monkeypatch):
    from telegram.ext import Application
    from sitewatcher import storage
    from sitewatcher.bot import app
    from sitewatcher.config import AppConfig

    monkeypatch.setattr(app, 'get_bot_token_from_env', lambda: '123:offline')

    def fail_polling(self, **kwargs):
        assert contender(storage.DEFAULT_DB).returncode == 23
        raise ValueError('polling startup failed')

    monkeypatch.setattr(Application, 'run_polling', fail_polling)
    with pytest.raises(ValueError, match='polling startup failed'):
        app.run_bot(AppConfig())
    assert contender(storage.DEFAULT_DB).returncode == 0
