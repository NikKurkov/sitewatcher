"""Bounded reads and atomic publication of private, mode-0600 configuration files."""
from __future__ import annotations

from collections.abc import Callable
import os
from pathlib import Path
import stat
import tempfile


def load_private_file(
    path: Path, validate: Callable[[str], str | None], read_limit: int, *,
    read_error: str, permissions_error: str | None = None, invalid_error: str | None = None,
) -> str | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    except OSError:
        raise ValueError(read_error) from None
    with os.fdopen(fd, encoding='utf-8') as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise ValueError(permissions_error or read_error)
        try:
            return validate(stream.read(read_limit))
        except (ValueError, UnicodeError):
            raise ValueError(invalid_error or read_error) from None


def save_private_file(path: Path, value: str, prefix: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=prefix, dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
