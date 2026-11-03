"""Process-lifetime scheduler ownership for one canonical monitoring database."""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from collections.abc import Iterator


@contextmanager
def acquire(path: Path) -> Iterator[None]:
    """Hold a nonblocking OS lock; keep the lock file so contenders share one inode.

    Use around the entire bot/worker lifetime, not around individual ticks. Resolving
    the database first makes symlinked database and directory aliases contend too.
    The kernel releases ownership on descriptor close or process exit/crash.
    """
    try:
        import fcntl
    except ImportError as exc:
        raise RuntimeError('Scheduler ownership requires POSIX file locking (fcntl)') from exc

    database = Path(path).resolve()
    lock_path = database.with_name(database.name + '.scheduler.lock')
    with lock_path.open('a+b') as descriptor:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError(f'A scheduler is already running for database {database}') from exc
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
