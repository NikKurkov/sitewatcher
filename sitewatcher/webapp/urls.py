"""Only health and explicitly packaged assets are exposed before authentication exists."""
from importlib.resources import files

from django.http import Http404, HttpResponse, JsonResponse
from django.urls import path
from django.views.decorators.http import require_safe

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
    path('healthz', health, name='health'),
    path('assets/<str:name>', asset, name='asset'),
]
