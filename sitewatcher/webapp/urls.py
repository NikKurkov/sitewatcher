"""Explicit public health/assets and authenticated owner account routes."""
from importlib.resources import files

from django.http import Http404, HttpResponse, JsonResponse
from django.urls import path
from django.views.decorators.http import require_safe

from . import auth_views, domains, preferences, public
from .activity import activity
from .network_routes import route

ASSETS = {
    'workspace.css': 'text/css; charset=utf-8',
    'vt_proxy.js': 'application/javascript; charset=utf-8',
    'key_visibility.js': 'application/javascript; charset=utf-8',
    'activity.css': 'text/css; charset=utf-8',
    'domain_order.js': 'application/javascript; charset=utf-8',
    'route_view.js': 'application/javascript; charset=utf-8',
    'activity.js': 'application/javascript; charset=utf-8',
    'theme.js': 'application/javascript; charset=utf-8',
    'logo-light.svg': 'image/svg+xml',
    'logo-dark.svg': 'image/svg+xml',
    'favicon.svg': 'image/svg+xml',
    'favicon.ico': 'image/x-icon',
    'apple-touch-icon.png': 'image/png',
}


@require_safe
def health(request):
    import sqlite3
    from contextlib import closing
    from sitewatcher import storage

    try:
        # A read-only connection neither initializes storage nor recreates a lost database.
        with closing(sqlite3.connect(storage.DEFAULT_DB.resolve().as_uri() + '?mode=ro',
                                     uri=True, timeout=1)) as connection:
            for table, columns in (
                ('domains', 'owner_id,name,favorite'), ('history', 'source,metrics_json'),
                ('webapp_workspace', 'owner_id,public_enabled'),
                ('auth_user', 'password'), ('django_session', 'session_key'),
            ):
                connection.execute(f'SELECT {columns} FROM {table} LIMIT 0')
    except (sqlite3.Error, OSError):
        return JsonResponse({'status': 'unavailable'}, status=503)
    return JsonResponse({'status': 'ok'})


@require_safe
def asset(request, name):
    if name not in ASSETS:
        raise Http404
    body = files('sitewatcher.webapp').joinpath('static', 'sitewatcher', name).read_bytes()
    return HttpResponse(body, content_type=ASSETS[name])


urlpatterns = [
    path('', domains.dashboard, name='workspace'),
    path('api/status', domains.status, name='status'),
    path('api/activity', activity, name='activity'),
    path('domains/reorder', domains.reorder, name='reorder'),
    path('domains/route', route, name='route'),
    path('login/', auth_views.OwnerLoginView.as_view(), name='login'),
    path('logout/', auth_views.OwnerLogoutView.as_view(), name='logout'),
    path('password/', auth_views.OwnerPasswordChangeView.as_view(), name='password_change'),
    path('healthz', health, name='health'),
    path('settings/public', public.publication, name='public_settings'),
    path('assets/<str:name>', asset, name='asset'),
]

# Explicit owner routes and native POST actions.
urlpatterns += [
    path('domains/new', domains.management, {'view': 'add'}),
    path('domains/edit', domains.management, {'view': 'edit'}),
    path('domains/delete', domains.management, {'view': 'delete'}),
    path('domains/history', domains.management, {'view': 'history'}),
    path('workspace', preferences.preferences),
    path('settings', preferences.preferences, name='settings'),
    path('import', domains.management, {'view': 'import'}),
    path('export.csv', domains.export),
    path('theme', domains.theme),
]
urlpatterns += [path('domains/' + route, domains.action, {'operation': operation})
                for route, operation in [('add', 'add'), ('save', 'save'), ('pause', 'pause'),
                                         ('resume', 'resume'), ('reset', 'reset'), ('check', 'check'),
                                         ('favorite', 'favorite')]]
urlpatterns += [path('alerts', domains.action, {'operation': 'alerts'})]
