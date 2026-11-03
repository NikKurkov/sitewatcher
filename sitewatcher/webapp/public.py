"""Revocable public capabilities with narrow HTTP-only report and activity serializers."""
import hashlib
import logging
import secrets

from django.conf import settings
from django.utils import translation
from django.utils.crypto import salted_hmac
from django.utils.translation import gettext as _
from django.db import transaction
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render
from django.views.decorators.debug import sensitive_variables
from django.views.decorators.http import require_POST

from sitewatcher import check_activity, storage
from sitewatcher.reporting import build_snapshot
from . import analytics
from .accounts import owner_required
from .models import Workspace
from .presentation import check_label, local_time, report_context, status_label
from .activity import present_events


def _totals(value):
    result = {key: value[key] for key in ('successful', 'failed', 'unknown', 'sample_count',
                                        'success_percent')}
    known = result['successful'] + result['failed']
    result['failure_percent'] = result['failed'] / known * 100 if known else None
    return result


def public_report(workspace, *, days):
    """Project safe domain DTOs; never use the whole-owner overview totals/cache."""
    names = set(storage.list_domains(workspace.owner_id))
    snapshot = build_snapshot(settings.SITEWATCHER_CONFIG, workspace.owner_id)
    current = {row['name']: row for row in snapshot['domains']}
    reports = []
    for name in sorted(set(workspace.public_domains) & names):
        raw = analytics.domain_report(workspace.owner_id, name, days=days,
                                      timezone=workspace.timezone)
        report = {key: raw[key] for key in ('domain', 'days', 'timezone', 'window_start',
                   'window_end', 'bucket_seconds', 'latest_observed_at')}
        report['latest_availability'] = (raw['latest_availability'] if raw['latest_availability']
                                        in {'available', 'unavailable'} else 'unknown')
        row = current.get(name, {})
        http = next((check for check in row.get('checks', []) if check['name'] == 'http_basic'), {})
        report['last_checked_at'] = http.get('checked_at')
        # Current state follows the latest owned HTTP observation, not the chart window.
        latest = storage.latest_check_results(workspace.owner_id, name).get('http_basic')
        classification, _ = analytics._classification(latest['metrics_json'] if latest else None)
        availability = {'successful': 'available', 'failed': 'unavailable',
                        'unknown': 'unknown'}[classification]
        report['current_state'] = ('paused' if row.get('paused') else 'no_recent_data'
            if not http or http.get('stale') or http.get('missing') or row.get('error')
            or availability == 'unknown' else availability)
        report['totals'] = {**_totals(raw['totals']), 'latency_ms': raw['totals']['latency_ms']}
        report['buckets'] = [{**{key: point[key] for key in ('index', 'start_at', 'label',
                              'latency_ms')}, **_totals(point)} for point in raw['buckets']]
        reports.append(report)
    totals = {key: sum(item['totals'][key] for item in reports)
              for key in ('successful', 'failed', 'unknown', 'sample_count')}
    known = totals['successful'] + totals['failed']
    totals['success_percent'] = totals['successful'] / known * 100 if known else None
    return {'days': days, 'timezone': workspace.timezone, 'totals': _totals(totals),
            'domains': reports}


def public_activity(workspace):
    events, domains = check_activity.published_http(
        workspace.owner_id, sorted(set(workspace.public_domains)),
    )
    present_events(events)
    for event in events:
        # Opaque per-link identifiers do not reveal the owner's global probe counter.
        event['id'] = salted_hmac(
            'sitewatcher.public_activity', workspace.public_token_hash + ':' + str(event['id']),
            algorithm='sha256',
        ).hexdigest()[:24]
        event.pop('check_name')
    for domain in domains:
        domain['label'] = str(check_label('http_basic'))
        domain['status_label'] = str(status_label(domain['status']))
    return {'events': events, 'domains': domains}


@sensitive_variables('token')
def status(request, token, *, data=False, activity=False):
    """Called inside the early bearer-path boundary; no owner/session middleware runs."""
    if request.method not in {'GET', 'HEAD'}:
        return HttpResponse(_('Method not allowed'), status=405, headers={'Allow': 'GET, HEAD'})
    workspace = Workspace.objects.filter(public_enabled=True,
        public_token_hash=hashlib.sha256(token.encode()).hexdigest()).first()
    if workspace is None:
        return HttpResponse(_('Not found'), status=404)
    request.LANGUAGE_CODE = workspace.language
    with translation.override(workspace.language):
        if activity:
            response = (HttpResponse(_('Not found'), status=404) if request.GET
                        else JsonResponse(public_activity(workspace)))
        else:
            response = _status_page(request, workspace, data=data)
    response['Content-Language'] = workspace.language
    return response


def _status_page(request, workspace, *, data):
    query = request.GET
    try:
        if set(query) - {'days', 'mode'} or any(len(v) != 1 for _, v in query.lists()):
            raise ValueError
        days = int(query.get('days', '1'))
        if days not in {1, 7, 30}:
            raise ValueError
        if 'mode' in query:
            if data or query['mode'] not in {'light', 'dark'}:
                raise ValueError
            response = HttpResponse(status=303, headers={'Location': '?days=' + str(days)})
            response.set_cookie('sitewatcher_theme', query['mode'], max_age=31536000,
                                samesite='Strict', secure=settings.SESSION_COOKIE_SECURE)
            return response
    except ValueError:
        return HttpResponse(_('Not found'), status=404)
    report = public_report(workspace, days=days)
    if data:
        return JsonResponse(report)
    for item in report['domains']:
        report_context(item)
        item['observed'] = local_time(item['last_checked_at'], workspace.timezone)
        item['state'], item['state_label'] = {
            'available': ('ok', _('Available')), 'unavailable': ('crit', _('Unavailable')),
            'no_recent_data': ('unknown', _('No recent data')), 'paused': ('paused', _('Paused')),
        }[item['current_state']]
    available = sum(item['current_state'] == 'available' for item in report['domains'])
    unavailable = sum(item['current_state'] == 'unavailable' for item in report['domains'])
    last = max((item['last_checked_at'] for item in report['domains']
                if item['last_checked_at']), default=None)
    return render(request, 'sitewatcher/public.html', {
        'public_view': True, 'public_timezone': workspace.timezone, 'report': report,
        'available': available, 'unavailable': unavailable, 'observed': local_time(last, workspace.timezone),
    })


@owner_required
@require_POST
@sensitive_variables('token', 'link')
def publication(request):
    from .preferences import _render
    if settings.SITEWATCHER_READ_ONLY:
        return HttpResponse(_('Read-only workspace'), status=405, headers={'Allow': 'GET, HEAD'})
    fields = dict(request.management_form)
    fields.pop('csrfmiddlewaretoken', None)
    action = fields.get('action')
    owned = set(storage.list_domains(request.workspace.owner_id))
    selection = {key[7:]: value for key, value in fields.items() if key.startswith('domain.')}
    if (request.GET or set(fields) - {'action', 'domains', *('domain.' + n for n in owned)}
            or ('domains' in fields and selection) or any(v != 'on' for v in selection.values())
            or action not in {
            'enable', 'rotate', 'disable', 'selection'}):
        return HttpResponse(_('Invalid request'), status=400)
    names = sorted(set(fields['domains'].split()) if 'domains' in fields else selection)
    if not set(names) <= owned:
        return _render(request, error=_('Select only domains in your workspace.'), status=400)
    link = ''
    with transaction.atomic():
        workspace = Workspace.objects.get(pk=request.workspace.pk)
        if action in {'rotate', 'selection'} and not workspace.public_enabled:
            return HttpResponse(_('Enable public status first'), status=400)
        if action in {'enable', 'rotate'}:
            token = secrets.token_urlsafe(32)
            workspace.public_enabled = True
            workspace.public_token_hash = hashlib.sha256(token.encode()).hexdigest()
            link = request.build_absolute_uri('/status/' + token + '/')
        if action in {'enable', 'selection'}:
            workspace.public_domains = names
        if action == 'disable':
            workspace.public_enabled = False
            workspace.public_token_hash = ''
        workspace.save(update_fields=['public_enabled', 'public_token_hash', 'public_domains'])
    request.workspace = workspace
    try:
        return _render(request, notice=_('Public status updated.'), public_link=link)
    except Exception as error:
        # Rendering the one-time link must not put its context into exception reports.
        logging.getLogger(__name__).warning(
            'Public status settings unavailable (%s)', type(error).__name__)
        return HttpResponse(_('Public status settings temporarily unavailable; reload Settings.'), status=503)
