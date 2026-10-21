"""Explicit public health/assets and authenticated owner account routes."""
from importlib.resources import files

from django.http import Http404, HttpResponse, JsonResponse
from django.urls import path
from django.views.decorators.http import require_safe

from . import auth_views, domains, preferences

ASSETS = {
    'workspace.css': 'text/css; charset=utf-8',
    'theme.js': 'application/javascript; charset=utf-8',
}


@require_safe
def health(request):
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
    path('login/', auth_views.OwnerLoginView.as_view(), name='login'),
    path('logout/', auth_views.OwnerLogoutView.as_view(), name='logout'),
    path('password/', auth_views.OwnerPasswordChangeView.as_view(), name='password_change'),
    path('healthz', health, name='health'),
    path('assets/<str:name>', asset, name='asset'),
]

# Keep the transitional renderer's explicit POST actions inside the authenticated router.
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
    path('style.css', domains.legacy_asset, {'name': 'style.css'}),
    path('theme.js', domains.legacy_asset, {'name': 'theme.js'}),
]
urlpatterns += [path('domains/' + route, domains.action, {'operation': operation})
                for route, operation in [('add', 'add'), ('save', 'save'), ('pause', 'pause'),
                                         ('resume', 'resume'), ('reset', 'reset'), ('check', 'check')]]
urlpatterns += [path('alerts', domains.action, {'operation': 'alerts'})]
