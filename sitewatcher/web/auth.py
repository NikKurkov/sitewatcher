"""Small authentication primitives for the single-owner web panel."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import secrets
import threading
import time
from collections import deque
from collections.abc import Callable, Mapping, MutableMapping
from dataclasses import dataclass, field


_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 5
_SCRYPT_PREFIX = f"scrypt:{_SCRYPT_N}:{_SCRYPT_R}:{_SCRYPT_P}"


def _decode_hash(encoded: str) -> tuple[bytes, bytes]:
    try:
        prefix, n, r, p, salt, digest = encoded.split(":")
        if (prefix, n, r, p) != ("scrypt", str(_SCRYPT_N), str(_SCRYPT_R), str(_SCRYPT_P)):
            raise ValueError("Unsupported scrypt parameters")
        salt_bytes = base64.b64decode(salt, validate=True)
        digest_bytes = base64.b64decode(digest, validate=True)
        if len(salt_bytes) < 16 or len(digest_bytes) != 32:
            raise ValueError("Invalid scrypt hash length")
        return salt_bytes, digest_bytes
    except (AttributeError, binascii.Error) as exc:
        raise ValueError("Invalid scrypt hash") from exc


def hash_password(password: str, *, salt: bytes | None = None) -> str:
    """Return a salted scrypt hash suitable for WEB_PASSWORD_HASH."""
    salt = secrets.token_bytes(16) if salt is None else salt
    if len(salt) < 16:
        raise ValueError("Salt must be at least 16 bytes")
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R,
        p=_SCRYPT_P, dklen=32, maxmem=64 * 1024 * 1024,
    )
    return f"{_SCRYPT_PREFIX}:{base64.b64encode(salt).decode()}:{base64.b64encode(digest).decode()}"


def verify_password(password: str, encoded: str) -> bool:
    """Verify a password without exposing digest comparison timing."""
    try:
        salt, expected = _decode_hash(encoded)
        actual = hashlib.scrypt(
            password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R,
            p=_SCRYPT_P, dklen=32, maxmem=64 * 1024 * 1024,
        )
        return hmac.compare_digest(actual, expected)
    except (TypeError, ValueError):
        return False


def password_fingerprint(encoded: str) -> str:
    """Identifier stored in sessions so replacing the hash logs out old sessions."""
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class WebSettings:
    owner_id: int
    password_hash: str
    session_secret: str
    cookie_secure: bool = False

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> WebSettings:
        env = os.environ if environ is None else environ
        try:
            owner_id = int(env["WEB_OWNER_ID"])
            if owner_id <= 0:
                raise ValueError
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("WEB_OWNER_ID must be a positive integer") from exc
        password_hash = env.get("WEB_PASSWORD_HASH", "")
        try:
            _decode_hash(password_hash)
        except ValueError as exc:
            raise ValueError("WEB_PASSWORD_HASH must be a valid scrypt hash") from exc
        session_secret = env.get("WEB_SESSION_SECRET", "")
        if len(session_secret) < 32:
            raise ValueError("WEB_SESSION_SECRET must be at least 32 characters")
        secure = env.get("WEB_COOKIE_SECURE", "false").lower()
        if secure not in ("true", "false", "1", "0"):
            raise ValueError("WEB_COOKIE_SECURE must be true or false")
        return cls(owner_id, password_hash, session_secret, secure in ("true", "1"))


def csrf_token(session: MutableMapping[str, object]) -> str:
    """Get or create the CSRF token held in a signed Starlette session."""
    existing = session.get("csrf_token")
    if isinstance(existing, str) and existing:
        return existing
    token = secrets.token_urlsafe(32)
    session["csrf_token"] = token
    return token


def verify_csrf(session: Mapping[str, object], supplied: str | None) -> bool:
    expected = session.get("csrf_token")
    return (
        isinstance(expected, str)
        and isinstance(supplied, str)
        and hmac.compare_digest(expected, supplied)
    )


@dataclass
class LoginRateLimiter:
    max_attempts: int = 5
    window_seconds: float = 300
    clock: Callable[[], float] = time.monotonic
    _failures: dict[str, deque[float]] = field(default_factory=dict, init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def _recent(self, key: str, now: float) -> deque[float]:
        failures = self._failures.get(key, deque())
        while failures and failures[0] <= now - self.window_seconds:
            failures.popleft()
        if not failures:
            self._failures.pop(key, None)
        return failures

    def allow(self, key: str) -> bool:
        with self._lock:
            return len(self._recent(key, self.clock())) < self.max_attempts

    def record_failure(self, key: str) -> None:
        with self._lock:
            now = self.clock()
            failures = self._recent(key, now)
            failures.append(now)
            self._failures[key] = failures

    def reset(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)
