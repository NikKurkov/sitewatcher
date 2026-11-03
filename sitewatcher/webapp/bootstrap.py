"""Explicit startup and additive Django migrations on the monitoring database."""
from __future__ import annotations

import os
from pathlib import Path
import secrets
import stat
import tempfile

from sitewatcher import storage
from sitewatcher.config import AppConfig


def load_secret_key(database: Path) -> str:
    """Publish a complete mode-0600 key atomically without replacing another process's key."""
    explicit = os.getenv('SITEWATCHER_WEB_SECRET_KEY')
    if explicit:
        return explicit
    path = database.with_name(database.name + '.web-secret')
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        fd, temporary = tempfile.mkstemp(prefix='.web-secret-', dir=path.parent)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                stream.write(secrets.token_urlsafe(64))
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, path)
            except FileExistsError:
                pass
        finally:
            os.unlink(temporary)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, encoding='utf-8') as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise ValueError('Web secret file requires mode 0600 permissions')
        key = stream.read().strip()
    if not key:
        raise ValueError('Web secret file is empty')
    return key


def configure_web(cfg: AppConfig, *, read_only: bool = False) -> None:
    """Configure Django once per process before serving requests or running commands."""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'sitewatcher.webapp.settings')
    import django
    from django.conf import settings

    database = storage.DEFAULT_DB.resolve()
    settings.SECRET_KEY = load_secret_key(database)
    settings.DATABASES['default']['NAME'] = str(database)
    allowed_hosts = os.getenv('SITEWATCHER_WEB_ALLOWED_HOSTS', '127.0.0.1,localhost,[::1]')
    hosts = [host.strip() for host in allowed_hosts.split(',') if host.strip()]
    if not hosts or any('*' in host for host in hosts):
        raise ValueError('Explicit web hosts are required; wildcards are not allowed')
    settings.ALLOWED_HOSTS = hosts
    settings.SECURE_PROXY_SSL_HEADER = (
        ('HTTP_X_FORWARDED_PROTO', 'https')
        if os.getenv('SITEWATCHER_WEB_TRUST_PROXY') == '1' else None
    )
    https = os.getenv('SITEWATCHER_WEB_HTTPS') == '1'
    settings.SESSION_COOKIE_SECURE = https
    settings.CSRF_COOKIE_SECURE = https
    settings.SITEWATCHER_CONFIG = cfg
    settings.SITEWATCHER_READ_ONLY = read_only
    django.setup()


def migrate_web_database() -> None:
    """Create new framework tables without renaming or replacing monitoring tables."""
    from django.core.management import call_command

    storage._ensure_initialized()
    call_command('migrate', interactive=False, verbosity=0)


def run_asgi(cfg: AppConfig, *, port: int = 8080, read_only: bool = False,
             owner_id: int | None = None) -> None:
    """Serve one process; explicit container binding never changes authentication."""
    import signal
    import socket

    import uvicorn
    from django.core.asgi import get_asgi_application

    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError('Port must be an integer between 0 and 65535')
    bind = os.getenv('SITEWATCHER_WEB_BIND', '127.0.0.1')
    if bind not in {'127.0.0.1', '0.0.0.0'}:
        raise ValueError('Web bind must be 127.0.0.1 or 0.0.0.0')
    configure_web(cfg, read_only=read_only)
    migrate_web_database()
    if owner_id is not None:
        from .models import Workspace
        if (type(owner_id) is not int or not 0 < owner_id < 2**63
                or not Workspace.objects.filter(owner_id=owner_id).exists()):
            raise ValueError('Web owner does not match a configured workspace; run sitewatcher setup')
    application = get_asgi_application()
    previous_handler = signal.signal(signal.SIGTERM, signal.default_int_handler)
    try:
        with socket.create_server((bind, port)) as listener:
            print(f'http://{bind}:{listener.getsockname()[1]}', flush=True)
            uvicorn.run(application, fd=listener.fileno(), access_log=False, lifespan='off',
                        log_level='warning', proxy_headers=False)
    except KeyboardInterrupt:
        pass
    finally:
        signal.signal(signal.SIGTERM, previous_handler)
