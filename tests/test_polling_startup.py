"""Start the real polling lifecycle with synthetic Telegram I/O, then stop early."""
import os
import subprocess
import sys
import textwrap


def test_bot_polling_starts_without_a_preexisting_event_loop(tmp_path):
    environment = os.environ.copy()
    environment.update(TELEGRAM_TOKEN='123:offline-only', TELEGRAM_ALLOWED_USER_IDS='7',
                       DATABASE_PATH=str(tmp_path / 'unused.sqlite'))
    environment.pop('TELEGRAM_PROXY', None)
    source = textwrap.dedent('''
        import httpx
        from telegram.ext import Application
        from telegram.request import HTTPXRequest
        from sitewatcher.bot import app
        from sitewatcher.config import AppConfig

        def respond(request):
            assert request.url.path.endswith('/getMe')
            return httpx.Response(200, json={'ok': True, 'result': {
                'id': 123, 'is_bot': True, 'first_name': 'Offline bot',
                'username': 'sitewatcher_offline_bot',
            }})

        def offline_request(**kwargs):
            kwargs['proxy'] = None
            kwargs['httpx_kwargs'] = {
                'transport': httpx.MockTransport(respond), 'trust_env': False,
            }
            return HTTPXRequest(**kwargs)

        async def stop_after_initialization(application):
            application.stop_running()

        real_polling = Application.run_polling
        def local_polling(application, **kwargs):
            application.post_init = stop_after_initialization
            real_polling(application, stop_signals=None, bootstrap_retries=0, **kwargs)

        app.HTTPXRequest = offline_request
        Application.run_polling = local_polling
        cfg = AppConfig()
        cfg.scheduler.enabled = False
        app.run_bot(cfg)
        print('POLLING_STARTUP_OK')
    ''')
    result = subprocess.run([sys.executable, '-c', source], cwd=tmp_path, env=environment,
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert 'POLLING_STARTUP_OK' in result.stdout
    assert not (tmp_path / 'unused.sqlite').exists()
