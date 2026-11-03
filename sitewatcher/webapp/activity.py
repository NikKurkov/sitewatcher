"""Read-only owner-scoped check activity; GET never initializes monitoring storage."""
from datetime import datetime, timezone
import sqlite3

from django.conf import settings
from django.http import JsonResponse
from django.utils.translation import gettext as _
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_safe

from sitewatcher import check_activity
from .accounts import owner_required
from .presentation import check_label, status_label


@never_cache
@owner_required(api=True)
@require_safe
def activity(request):
    if request.GET:
        return JsonResponse({'error': 'Invalid query'}, status=400)
    try:
        events = check_activity.recent(request.workspace.owner_id)
    except (sqlite3.Error, OSError):
        return JsonResponse({'error': 'Activity unavailable'}, status=503)
    timeout = settings.SITEWATCHER_CONFIG.scheduler.domain_timeout_s
    stale_after = timeout + 10 if isinstance(timeout, (int, float)) and timeout > 0 else None
    now = datetime.now(timezone.utc)
    for event in events:
        event['label'] = str(check_label(event['check_name']))
        if event['finished_at']:
            event['phase'] = 'finished'
            event['status_label'] = str(status_label(event['status']))
            continue
        interrupted = False
        if stale_after is not None:
            try:
                stamp = datetime.fromisoformat(event['started_at'])
                interrupted = (now - stamp).total_seconds() > stale_after
            except (TypeError, ValueError, OverflowError):
                interrupted = True
        event['status'] = 'UNKNOWN'
        event['phase'] = 'interrupted' if interrupted else 'running'
        event['status_label'] = str(_('Interrupted') if interrupted else _('Running'))
    response = JsonResponse({'events': events})
    response['Cache-Control'] = 'no-store'
    return response
