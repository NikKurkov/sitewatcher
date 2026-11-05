"""Shared owner navigation without initializing or mutating monitoring storage."""
from django.conf import settings
from django.db import connection


def owner_toolbar(request):
    # Public status bypasses authentication middleware and redacts its bearer path.
    if request.path.startswith('/status/'):
        return {}
    user = getattr(request, 'user', None)
    workspace = getattr(request, 'workspace', None)
    if not user or not user.is_authenticated or workspace is None:
        return {}
    with connection.cursor() as cursor:
        cursor.execute('SELECT 1 FROM domains WHERE owner_id = %s LIMIT 1',
                       [workspace.owner_id])
        has_domains = cursor.fetchone() is not None
    return {
        'owner_toolbar': True,
        'toolbar_read_only': settings.SITEWATCHER_READ_ONLY,
        'toolbar_has_domains': has_domains,
        'toolbar_overview': request.path == '/',
        'settings_active': request.path.startswith(('/settings', '/workspace')),
    }
