import json
import subprocess
import sys
import textwrap

import pytest


def run_logging(script):
    return subprocess.run(
        [sys.executable, '-c', textwrap.dedent(script)],
        capture_output=True, text=True, timeout=10,
    )


@pytest.mark.parametrize('format_name', ['pretty', 'json'])
def test_logging_can_be_enabled_after_disabled_configuration(format_name):
    result = run_logging(f'''
        import logging
        from sitewatcher.config import LoggingConfig
        from sitewatcher.logging_setup import setup_logging

        logger = logging.getLogger('sitewatcher.test')
        setup_logging(LoggingConfig(enabled=False))
        logger.critical('disabled-message')
        setup_logging(LoggingConfig(format={format_name!r}))
        logger.info('enabled-message', extra={{'event': 'enabled', 'count': 2}})
        setup_logging(LoggingConfig(format={format_name!r}))
        logger.info('reconfigured-message')
    ''')
    assert result.returncode == 0, result.stderr
    assert result.stderr == ''
    assert 'disabled-message' not in result.stdout
    assert result.stdout.count('enabled-message') == 1
    assert result.stdout.count('reconfigured-message') == 1
    if format_name == 'json':
        rows = [json.loads(line) for line in result.stdout.splitlines()]
        event = next(row for row in rows if row['message'] == 'enabled-message')
        assert event['event'] == 'enabled' and event['count'] == 2
    else:
        assert 'INFO sitewatcher.test - enabled-message' in result.stdout
        assert '"event":"enabled","count":2' in result.stdout


@pytest.mark.parametrize(('level', 'library_level'), [('info', 'info'), (' debug ', ' warning ')])
def test_logging_normalizes_root_and_third_party_levels(level, library_level):
    result = run_logging(f'''
        import logging
        from sitewatcher.config import LoggingConfig
        from sitewatcher.logging_setup import setup_logging

        cfg = LoggingConfig(level={level!r}, third_party_levels={{'example.library': {library_level!r}}})
        setup_logging(cfg)
        logging.getLogger('sitewatcher.test').info('root-level-works')
        logging.getLogger('example.library').warning('library-level-works')
    ''')
    assert result.returncode == 0, result.stderr
    assert result.stderr == ''
    assert 'root-level-works' in result.stdout
    assert 'library-level-works' in result.stdout


def test_timed_file_rotation_normalizes_when_and_writes_json(tmp_path):
    log_path = tmp_path / 'nested' / 'monitor.log'
    result = run_logging(f'''
        import logging
        from sitewatcher.config import LoggingConfig, LoggingFileConfig
        from sitewatcher.logging_setup import setup_logging

        cfg = LoggingConfig(destination='file', format='json', file=LoggingFileConfig(
            path={str(log_path)!r}, rotate='time', when=' h ', interval=1,
        ))
        setup_logging(cfg)
        logging.getLogger('sitewatcher.test').info('file-message', extra={{'count': 3}})
        logging.shutdown()
    ''')
    assert result.returncode == 0, result.stderr
    assert result.stderr == ''
    record = json.loads(log_path.read_text().splitlines()[-1])
    assert record['message'] == 'file-message' and record['count'] == 3
