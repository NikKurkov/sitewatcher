import base64

import pytest

from sitewatcher.web.auth import (
    LoginRateLimiter,
    WebSettings,
    csrf_token,
    hash_password,
    password_fingerprint,
    verify_csrf,
    verify_password,
)


HASH = "scrypt:16384:8:5:" + base64.b64encode(b"0" * 16).decode() + ":" + base64.b64encode(b"1" * 32).decode()


def valid_env(**changes):
    return {
        "WEB_OWNER_ID": "123",
        "WEB_PASSWORD_HASH": HASH,
        "WEB_SESSION_SECRET": "x" * 32,
        **changes,
    }


def test_web_settings_accepts_valid_environment_and_defaults_cookie_to_insecure():
    settings = WebSettings.from_env(valid_env())
    assert settings == WebSettings(123, HASH, "x" * 32, False)
    assert WebSettings.from_env(valid_env(WEB_COOKIE_SECURE="true")).cookie_secure is True


@pytest.mark.parametrize(
    "change",
    [
        {"WEB_OWNER_ID": ""},
        {"WEB_OWNER_ID": "0"},
        {"WEB_OWNER_ID": "-1"},
        {"WEB_OWNER_ID": "one"},
        {"WEB_PASSWORD_HASH": "plaintext"},
        {"WEB_PASSWORD_HASH": "scrypt:1:8:5:abc:def"},
        {"WEB_PASSWORD_HASH": "scrypt:16384:8:5:bad!:digest"},
        {"WEB_SESSION_SECRET": "short"},
        {"WEB_COOKIE_SECURE": "maybe"},
    ],
)
def test_web_settings_rejects_invalid_environment(change):
    with pytest.raises(ValueError):
        WebSettings.from_env(valid_env(**change))


def test_web_settings_requires_all_three_secrets():
    for key in ("WEB_OWNER_ID", "WEB_PASSWORD_HASH", "WEB_SESSION_SECRET"):
        env = valid_env()
        del env[key]
        with pytest.raises(ValueError):
            WebSettings.from_env(env)


def test_hash_password_uses_fixed_scrypt_parameters_and_verifies_password():
    encoded = hash_password("correct horse battery staple", salt=b"a" * 16)
    assert encoded.startswith("scrypt:16384:8:5:")
    assert verify_password("correct horse battery staple", encoded)
    assert not verify_password("wrong password", encoded)
    assert len(base64.b64decode(encoded.split(":")[-1])) == 32


def test_hash_password_uses_random_salt_and_rejects_bad_hashes():
    first = hash_password("same password")
    second = hash_password("same password")
    assert first != second
    assert verify_password("same password", first)
    assert not verify_password("same password", "invalid")
    assert not verify_password("same password", "scrypt:999999999:8:5:abc:def")


def test_password_fingerprint_changes_when_password_hash_changes():
    assert password_fingerprint("one") != password_fingerprint("two")
    assert len(password_fingerprint("one")) == 64


def test_csrf_token_is_session_bound_and_reused():
    session = {}
    token = csrf_token(session)
    assert token == csrf_token(session)
    assert verify_csrf(session, token)
    assert not verify_csrf({}, token)
    assert not verify_csrf(session, "wrong")
    assert not verify_csrf(session, None)


def test_login_rate_limiter_blocks_after_failures_and_recovers_after_window():
    now = [100.0]
    limiter = LoginRateLimiter(max_attempts=3, window_seconds=60, clock=lambda: now[0])
    for _ in range(3):
        assert limiter.allow("client")
        limiter.record_failure("client")
    assert not limiter.allow("client")
    assert limiter.allow("other")
    now[0] = 160.0
    assert limiter.allow("client")


def test_login_rate_limiter_reset_clears_failed_attempts():
    limiter = LoginRateLimiter(max_attempts=1)
    limiter.record_failure("client")
    assert not limiter.allow("client")
    limiter.reset("client")
    assert limiter.allow("client")
