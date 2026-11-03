"""Owner-only commands enqueue diagnostics; HTTP requests never run a traceroute."""
import sqlite3

from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.http import require_POST

from sitewatcher import network_routes
from sitewatcher.utils.domains import normalize_domain
from .accounts import owner_required


@owner_required(api=True)
@require_POST
def route(request):
    if settings.SITEWATCHER_READ_ONLY:
        return JsonResponse({'error': 'Read-only workspace'}, status=405)
    fields = dict(request.management_form)
    fields.pop('csrfmiddlewaretoken', None)
    if (request.GET or set(fields) != {'domain', 'action'}
            or fields['action'] not in {'refresh', 'disable'}):
        return JsonResponse({'error': 'Invalid request'}, status=400)
    domain = normalize_domain(fields['domain'])
    if not domain:
        return JsonResponse({'error': 'Invalid domain'}, status=400)
    try:
        network_routes.request_trace(request.workspace.owner_id, domain,
                                     enabled=fields['action'] == 'refresh')
    except ValueError:
        return JsonResponse({'error': 'Domain not found'}, status=404)
    except RuntimeError:
        return JsonResponse({'error': 'Route already queued or running'}, status=409)
    except (sqlite3.Error, OSError):
        return JsonResponse({'error': 'Route diagnostics unavailable'}, status=503)
    return JsonResponse({'saved': True})
