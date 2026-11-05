"""VirusTotal secrets stay private and are refreshed for every passive probe."""
import asyncio
import os
import stat

import httpx
import pytest

from sitewatcher.checks.base import Status
from sitewatcher.checks.malware_scan import MalwareScanCheck, _VTConfig


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch):
    monkeypatch.delenv('VIRUSTOTAL_API_KEY', raising=False)


def test_key_storage_precedence_removal_and_atomic_permissions(tmp_path, monkeypatch):
    from sitewatcher.virustotal_settings import (
        key_path, load_api_key, remove_api_key, save_api_key,
    )
    assert load_api_key() is None
    save_api_key('private-test-key')
    assert load_api_key() == 'private-test-key'
    assert stat.S_IMODE(key_path().stat().st_mode) == 0o600
    assert load_api_key('configured-key') == 'configured-key'
    monkeypatch.setenv('VIRUSTOTAL_API_KEY', 'environment-key')
    assert load_api_key('configured-key') == 'environment-key'
    remove_api_key()
    assert not key_path().exists()
    assert load_api_key('configured-key') == 'environment-key'
    monkeypatch.delenv('VIRUSTOTAL_API_KEY')
    assert load_api_key() is None
    assert not list(tmp_path.glob('.virustotal-key-*'))


@pytest.mark.parametrize('kind', ['symlink', 'fifo', 'permissions', 'invalid'])
def test_untrusted_secret_files_fail_safely(tmp_path, kind):
    from sitewatcher.virustotal_settings import key_path, load_api_key
    path = key_path()
    if kind == 'symlink':
        target = tmp_path / 'target'
        target.write_text('private-test-key')
        path.symlink_to(target)
    elif kind == 'fifo':
        os.mkfifo(path, 0o600)
    else:
        path.write_text('private-test-key' if kind == 'permissions' else '\x00secret')
        path.chmod(0o644 if kind == 'permissions' else 0o600)
    with pytest.raises(ValueError) as error:
        load_api_key()
    assert 'private-test-key' not in str(error.value)
    assert '\x00secret' not in str(error.value)


def test_save_replaces_symlink_and_remove_never_changes_target(tmp_path):
    from sitewatcher.virustotal_settings import key_path, remove_api_key, save_api_key
    target = tmp_path / 'target'
    target.write_text('leave-target-alone')
    key_path().symlink_to(target)
    save_api_key('replacement')
    assert not key_path().is_symlink()
    assert target.read_text() == 'leave-target-alone'
    key_path().unlink()
    key_path().symlink_to(target)
    remove_api_key()
    assert target.read_text() == 'leave-target-alone'


def test_existing_probe_reloads_key_and_environment_without_restart(monkeypatch, expire_vt_report):
    from sitewatcher.virustotal_settings import remove_api_key, save_api_key
    seen = []
    def handler(request):
        assert request.method == 'GET'
        seen.append(request.headers['x-apikey'])
        return httpx.Response(200, json={'data': {'attributes': {'last_analysis_stats': {
            'malicious': 0, 'suspicious': 0, 'harmless': 1}}}})
    async def scenario():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            probe = MalwareScanCheck('example.test', client=client)
            assert (await probe.run()).message.endswith('API key is missing')
            save_api_key('saved-one')
            assert (await probe.run()).status is Status.OK
            expire_vt_report()
            save_api_key('saved-two')
            await probe.run()
            expire_vt_report()
            monkeypatch.setenv('VIRUSTOTAL_API_KEY', 'environment-key')
            await probe.run()
            expire_vt_report()
            remove_api_key()
            await probe.run()
            monkeypatch.delenv('VIRUSTOTAL_API_KEY')
            assert (await probe.run()).message.endswith('API key is missing')
    asyncio.run(scenario())
    assert seen == ['saved-one', 'saved-two', 'environment-key', 'environment-key']


def test_bad_setting_does_not_crash_probe_or_contact_provider(monkeypatch):
    monkeypatch.setenv('VIRUSTOTAL_API_KEY', 'invalid\nprivate-key')
    async def scenario():
        def unexpected(request):
            pytest.fail('invalid configuration must not contact VirusTotal')
        async with httpx.AsyncClient(transport=httpx.MockTransport(unexpected)) as client:
            result = await MalwareScanCheck('example.test', client=client).run()
            assert result.status is Status.UNKNOWN
            assert result.message == 'VirusTotal configuration could not be read securely'
    asyncio.run(scenario())


def test_provider_exception_logs_never_include_key(caplog):
    async def scenario():
        def failure(request):
            raise RuntimeError('private-test-key')
        async with httpx.AsyncClient(transport=httpx.MockTransport(failure)) as client:
            result = await MalwareScanCheck('example.test', client=client,
                                           vt_cfg=_VTConfig(api_key='private-test-key')).run()
            assert result.status is Status.UNKNOWN
            assert 'private-test-key' not in result.message
    asyncio.run(scenario())
    assert 'private-test-key' not in caplog.text
    assert all('private-test-key' not in str(record.__dict__) for record in caplog.records)


def test_oversized_saved_key_is_rejected_before_trimming():
    from sitewatcher.virustotal_settings import key_path, load_api_key
    key_path().write_text('x' * 2048 + '\nprivate-trailing-data')
    key_path().chmod(0o600)
    with pytest.raises(ValueError):
        load_api_key()


def test_key_loading_never_initializes_monitoring_database(monkeypatch):
    from sitewatcher import storage
    from sitewatcher.virustotal_settings import load_api_key, save_api_key
    def unexpected(*args, **kwargs):
        pytest.fail('secret loading must not initialize storage')
    monkeypatch.setattr(storage, '_ensure_initialized', unexpected)
    save_api_key('private-test-key')
    assert load_api_key() == 'private-test-key'


def test_atomic_concurrent_key_writes_keep_one_complete_key(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from sitewatcher.virustotal_settings import key_path, load_api_key, save_api_key
    keys = [f'private-concurrent-key-{index}' for index in range(12)]
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(save_api_key, keys))
    assert load_api_key() in keys
    assert stat.S_IMODE(key_path().stat().st_mode) == 0o600
    assert not list(tmp_path.glob('.virustotal-key-*'))


def test_bad_saved_key_keeps_probe_unknown_without_http():
    from sitewatcher.virustotal_settings import key_path
    key_path().write_text('saved-private-key')
    key_path().chmod(0o644)
    async def scenario():
        def unexpected(request):
            pytest.fail('an unsafe saved key must not contact VirusTotal')
        async with httpx.AsyncClient(transport=httpx.MockTransport(unexpected)) as client:
            result = await MalwareScanCheck('example.test', client=client).run()
            assert result.status is Status.UNKNOWN
            assert result.message == 'VirusTotal configuration could not be read securely'
    asyncio.run(scenario())
