"""Explicit public health/assets and authenticated owner account routes."""
from importlib.resources import files

from django.http import Http404, HttpResponse, JsonResponse
from django.urls import path
from django.views.decorators.http import require_safe

from . import auth_views

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
    path('', auth_views.workspace, name='workspace'),
    path('api/status', auth_views.status, name='status'),
    path('login/', auth_views.OwnerLoginView.as_view(), name='login'),
    path('logout/', auth_views.OwnerLogoutView.as_view(), name='logout'),
    path('password/', auth_views.OwnerPasswordChangeView.as_view(), name='password_change'),
    path('healthz', health, name='health'),
    path('assets/<str:name>', asset, name='asset'),
]
