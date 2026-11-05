"""Shared private-file I/O preserves each service's existing storage contract."""
import os

import pytest

from sitewatcher import telegram_connection, telegram_proxy, virustotal_settings


SERVICES = [
    (telegram_connection.token_path, telegram_connection.load_bot_token,
     telegram_connection.save_bot_token, '123:' + 'a' * 20, 'TELEGRAM_TOKEN',
     'Telegram token file could not be read securely.',
     'Telegram token file requires mode 0600 permissions.',
     'Telegram token file is invalid.'),
    (telegram_proxy.proxy_path, telegram_proxy.load_proxy,
     telegram_proxy.save_proxy, 'http://proxy.example:80', 'TELEGRAM_PROXY',
     'Telegram proxy file could not be read securely.',
     'Telegram proxy file requires mode 0600 permissions.',
     'Telegram proxy file is invalid. Save a new proxy or remove it.'),
    (virustotal_settings.key_path, virustotal_settings.load_api_key,
     virustotal_settings.save_api_key, 'synthetic-key', 'VIRUSTOTAL_API_KEY',
     *[virustotal_settings.KEY_FILE_ERROR] * 3),
]


@pytest.mark.parametrize('path,load,save,value,env,read_error,mode_error,invalid_error', SERVICES)
@pytest.mark.parametrize('kind', ['symlink', 'fifo', 'permissions', 'invalid', 'unicode'])
def test_service_file_errors_remain_exact(
    path, load, save, value, env, read_error, mode_error, invalid_error,
    kind, tmp_path, monkeypatch,
):
    monkeypatch.delenv(env, raising=False)
    secret = path()
    if kind == 'symlink':
        target = tmp_path / 'target'
        target.write_text(value)
        secret.symlink_to(target)
        expected = read_error
    elif kind == 'fifo':
        os.mkfifo(secret, 0o600)
        expected = mode_error
    else:
        secret.write_bytes(b'\xff' if kind == 'unicode' else b'\x00')
        secret.chmod(0o644 if kind == 'permissions' else 0o600)
        expected = mode_error if kind == 'permissions' else invalid_error
    with pytest.raises(ValueError) as error:
        load()
    assert str(error.value) == expected


@pytest.mark.parametrize('path,load,save,value,env,read_error,mode_error,invalid_error', SERVICES)
def test_failed_publication_preserves_existing_file_and_removes_temporary(
    path, load, save, value, env, read_error, mode_error, invalid_error, tmp_path, monkeypatch,
):
    from sitewatcher.utils import private_file

    monkeypatch.delenv(env, raising=False)
    save(value)
    def fail_replace(*args):
        raise OSError('synthetic replacement failure')
    monkeypatch.setattr(private_file.os, 'replace', fail_replace)
    with pytest.raises(OSError, match='synthetic replacement failure'):
        save(value)
    assert load() == value
    assert list(tmp_path.iterdir()) == [path()]


@pytest.mark.parametrize('module,value,limit,env', [
    (telegram_connection, '123:' + 'a' * 20, 256, 'TELEGRAM_TOKEN'),
    (telegram_proxy, 'http://proxy.example:80', 2049, 'TELEGRAM_PROXY'),
])
def test_telegram_read_limits_preserve_truncated_prefix_behavior(module, value, limit, env,
                                                              monkeypatch):
    monkeypatch.delenv(env, raising=False)
    path = module.token_path() if module is telegram_connection else module.proxy_path()
    load = module.load_bot_token if module is telegram_connection else module.load_proxy
    path.write_text(value.ljust(limit) + 'ignored suffix')
    path.chmod(0o600)
    assert load() == value


def test_virustotal_raw_proxy_limit_precedes_whitespace_normalization(monkeypatch):
    monkeypatch.delenv('VIRUSTOTAL_PROXY', raising=False)
    path = virustotal_settings.vt_proxy_path()
    path.write_text('http://proxy.example:80'.ljust(2049))
    path.chmod(0o600)
    with pytest.raises(ValueError) as error:
        virustotal_settings.load_vt_proxy()
    assert str(error.value) == virustotal_settings.KEY_FILE_ERROR
