"""Authenticated owner management using existing monitoring operations and renderers."""
from __future__ import annotations

import asyncio
from importlib.resources import files
from threading import Lock
from urllib.parse import urlencode, urlsplit

from django.conf import settings
from django.http import Http404, HttpResponse, JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_http_methods, require_POST, require_safe

from sitewatcher import storage
from sitewatcher.config import AppConfig, ChecksModel
from sitewatcher.dashboard import FILTERS
from sitewatcher.dispatcher import Dispatcher
from sitewatcher.reporting import SnapshotError, build_snapshot
from sitewatcher.utils.domains import normalize_domain
from sitewatcher.utils.domains_csv import export_domains_csv, import_domains_csv
from sitewatcher.web_actions import (
    LIST_FIELDS, NUMERIC_FIELDS, act_on_domain, history_context, save_domain, settings_context,
)
from .accounts import owner_required
from .analytics import domain_report, overview_report
from .presentation import domain_form_context, local_time, report_context

# ponytail: one process-local manual run; run a single web process, use a job queue to scale.
_check_lock = Lock()


async def _check_domains(cfg: AppConfig, owner_id: int, names: list[str]) -> None:
    async with Dispatcher(cfg) as dispatcher:
        for name in names:
            if not storage.domain_exists(owner_id, name):
                continue
            async with asyncio.timeout(cfg.scheduler.domain_timeout_s or 120):
                results = await dispatcher.run_for(owner_id, name, use_cache=False)
            storage.save_histories(owner_id, name, results, create_missing=False, source="manual")


def run_manual_checks(cfg: AppConfig, owner_id: int, names: list[str]) -> None:
    """Run probes without alert delivery; concurrent deletion must never recreate a domain."""
    asyncio.run(_check_domains(cfg, owner_id, names))


def _private(response):
    response['Cache-Control'] = 'no-store'
    return response


def _render(request, template, context, *, status=200):
    context['read_only'] = settings.SITEWATCHER_READ_ONLY
    return _private(render(request, 'sitewatcher/' + template + '.html', context, status=status))


def _period(request):
    days = int(request.GET.get('days', '1'))
    if days not in {1, 7, 30}:
        raise ValueError('Invalid period')
    return days


def _query(request):
    if len(request.GET) > 20 or any(len(v) != 1 for _, v in request.GET.lists()):
        raise ValueError('Invalid query')
    return request.GET


def _existing(owner_id, raw):
    name = normalize_domain(raw)
    if not name or not storage.domain_exists(owner_id, name):
        raise Http404('Domain not found')
    return name


def _page(request, view, domain='', *, error='', values=None, status=200):
    owner_id = request.workspace.owner_id
    cfg = settings.SITEWATCHER_CONFIG
    context = {'domain': domain}
    if view in {'add', 'edit'}:
        try:
            context = settings_context(cfg, owner_id, domain if view == 'edit' else None)
        except ValueError:
            if view == 'edit' and not storage.domain_exists(owner_id, domain):
                raise Http404('Domain not found') from None
            return _private(HttpResponse('Settings unavailable; reload the page', status=400))
    elif view == 'history':
        try:
            report = domain_report(owner_id, domain, days=_period(request),
                                   timezone=request.workspace.timezone)
        except ValueError:
            if not storage.domain_exists(owner_id, domain):
                raise Http404('Domain not found') from None
            return _private(HttpResponse('Invalid request', status=400))
        snapshot = build_snapshot(cfg, owner_id)
        row = next((row for row in snapshot['domains'] if row['name'] == domain), None)
        if row is None:
            raise Http404('Domain not found')
        _row_context(row, request.workspace.timezone)
        try:
            history = history_context(owner_id, domain)
        except ValueError:
            raise Http404('Domain not found') from None
        for item in history:
            item['observed'] = local_time(item['created_at'], request.workspace.timezone)
        return _render(request, 'domain_detail', {'report': report_context(report), 'row': row,
                                                 'history': history})
    elif view == 'workspace':
        context['alerts_enabled'] = storage.is_user_alerts_enabled(owner_id)
    if view == 'add' and values is None:
        context['values'].update({
            f'check.{key}': 'on' if key in {'http_basic', 'tls_cert'} else 'off'
            for key in ChecksModel.model_fields})
    if values is not None:
        context['values'] = {**context.get('values', {}), **values, 'proxy': ''}
        context['domain'] = values.get('domain', domain)
        if 'revision' in values:
            context['revision'] = values['revision']
        if view == 'import':
            context['mode'] = values.get('mode', 'merge')
    context.update(view=view, error=error)
    if view in {'add', 'edit'}:
        domain_form_context(context, error)
    return _render(request, 'domain_form' if view in {'add', 'edit'} else 'management',
                   context, status=status)


def _row_context(row, zone):
    row['state'] = ('paused' if row['paused'] else row['overall'].lower())
    row['label'] = {'paused': 'Paused', 'crit': 'Critical', 'warn': 'Warning',
                    'ok': 'Healthy', 'unknown': 'No data'}[row['state']]
    row['observed'] = local_time(row['last_checked_at'], zone)
    for check in row['checks']:
        check['observed'] = local_time(check['checked_at'], zone)


@owner_required
@require_safe
def dashboard(request):
    try:
        query = _query(request)
        status = query.get('status', 'all')
        if status not in FILTERS:
            raise ValueError('Invalid filter')
        owner_id, zone = request.workspace.owner_id, request.workspace.timezone
        snapshot = build_snapshot(settings.SITEWATCHER_CONFIG, owner_id)
        report = overview_report(owner_id, days=_period(request), timezone=zone)
        reports = {item['domain']: report_context(item) for item in report['domains']}
        rows = snapshot['domains']
        attention = sum(row['overall'] in {'CRIT', 'WARN'} and not row['paused'] for row in rows)
        last = max((row['last_checked_at'] for row in rows if row['last_checked_at']), default=None)
        for row in rows:
            _row_context(row, zone)
            row['report'] = reports.get(row['name'])
        rows.sort(key=lambda row: ({'crit': 0, 'warn': 1, 'unknown': 2, 'ok': 3,
                                    'paused': 4}[row['state']], row['name']))
        search = query.get('q', '').strip()
        filtered = [row for row in rows if search.lower() in row['name'] and (
            status == 'all' or status == 'problems' and row['overall'] in {'CRIT', 'WARN'}
            or status in {'paused', 'stale'} and row[status]
            or row['overall'].lower() == status)]
        return _render(request, 'overview', {'rows': filtered, 'total': len(rows),
            'attention': attention, 'summary': snapshot['summary'], 'report': report,
            'healthy': sum(row['state'] == 'ok' for row in rows),
            'observed': local_time(last, zone), 'query': search, 'status': status,
            'filters': FILTERS.items(), 'notice': query.get('notice', '')})
    except ValueError:
        return _private(HttpResponse('Invalid request', status=400))
    except SnapshotError:
        return _private(HttpResponse('Monitoring unavailable', status=503))


@owner_required(api=True)
@require_safe
def status(request):
    try:
        _query(request)
        snapshot = build_snapshot(settings.SITEWATCHER_CONFIG, request.workspace.owner_id)
    except ValueError:
        return _private(JsonResponse({'error': 'Invalid request'}, status=400))
    except SnapshotError:
        return _private(JsonResponse({'error': 'Monitoring unavailable'}, status=503))
    return _private(JsonResponse({'owner_id': request.workspace.owner_id, **snapshot}))


def _redirect(notice):
    return _private(HttpResponse(status=303, headers={'Location': '/?' + urlencode({'notice': notice})}))


def _act(request, action, form):
    cfg, owner_id = settings.SITEWATCHER_CONFIG, request.workspace.owner_id
    if action in {'add', 'save'}:
        save_domain(cfg, owner_id, form, create=action == 'add')
        return _redirect('Domain saved')
    if action in {'delete', 'pause', 'resume', 'reset', 'check'}:
        domain = form.get('domain', '')
        if action != 'check' or domain != '*':
            domain = _existing(owner_id, domain)
        if action == 'delete' and form.get('confirm') != domain:
            raise ValueError('Confirm deletion first')
        if action == 'check':
            names = storage.list_domains(owner_id) if domain == '*' else [domain]
            if not names:
                raise ValueError('No domains to check')
            if not _check_lock.acquire(blocking=False):
                return _private(HttpResponse('Another manual check is running', status=409))
            try:
                run_manual_checks(cfg, owner_id, names)
            finally:
                _check_lock.release()
            return _redirect('Checks completed; results saved')
        act_on_domain(cfg, owner_id, action, domain)
        return _redirect('Domain updated')
    if action == 'alerts':
        if form.get('enabled') not in {'on', 'off'}:
            raise ValueError('Invalid alert setting')
        storage.set_user_alerts_enabled(owner_id, form['enabled'] == 'on')
        return _redirect('Notification preference saved')
    if action == 'import':
        if form.get('csv_file') and form.get('csv_text'):
            raise ValueError('Choose a file or pasted CSV, not both')
        text = form.get('csv_file') or form.get('csv_text') or ''
        report = import_domains_csv(owner_id, text.encode('utf-8'),
                                    mode=form.get('mode', 'merge'), cfg=cfg)
        notice = f'CSV: {report.added} added, {report.updated} updated, {report.skipped} skipped'
        if report.errors:
            return _page(request, 'import', error=notice + '. Some rows were not imported.',
                         values=form, status=400)
        return _redirect(notice)
    raise Http404


def _mutate(request, action):
    if settings.SITEWATCHER_READ_ONLY:
        return _private(HttpResponse('Read-only workspace', status=405, headers={'Allow': 'GET, HEAD'}))
    form = dict(request.management_form)
    form.pop('csrfmiddlewaretoken', None)
    allowed = {'domain'}
    if action in {'add', 'save'}:
        allowed.update((*NUMERIC_FIELDS, *LIST_FIELDS, 'revision', 'proxy_mode', 'proxy'))
        allowed.update(f'check.{name}' for name in ChecksModel.model_fields)
    elif action == 'delete':
        allowed.add('confirm')
    elif action == 'alerts':
        allowed = {'enabled'}
    elif action == 'import':
        allowed = {'csv_file', 'csv_text', 'mode'}
    if request.GET or set(form) - allowed:
        return _private(HttpResponse('Invalid request', status=400))
    if action == 'save':
        _existing(request.workspace.owner_id, form.get('domain', ''))
    try:
        return _act(request, action, form)
    except ValueError as error:
        view = {'add': 'add', 'save': 'edit', 'import': 'import'}.get(action)
        if view:
            return _page(request, view, form.get('domain', ''), error=str(error),
                         values=form, status=400)
        return _private(HttpResponse('Invalid action; reload the page', status=400))
    except Http404:
        raise
    except TimeoutError:
        return _private(HttpResponse('Checks timed out; inspect saved results before retrying', status=504))
    except Exception:
        return _private(HttpResponse('Operation failed; inspect saved state before retrying', status=503))


@owner_required
@require_http_methods(['GET', 'HEAD', 'POST'])
def management(request, view):
    if request.method == 'POST':
        if view == 'history':
            return _private(HttpResponse('Method not allowed', status=405,
                                         headers={'Allow': 'GET, HEAD'}))
        return _mutate(request, {'add': 'add', 'edit': 'save', 'delete': 'delete',
                                 'workspace': 'alerts', 'import': 'import'}[view])
    try:
        query = _query(request)
    except ValueError:
        return _private(HttpResponse('Invalid request', status=400))
    domain = ''
    if view in {'edit', 'delete', 'history'}:
        domain = _existing(request.workspace.owner_id, query.get('domain', ''))
    return _page(request, view, domain)


@owner_required
@require_POST
def action(request, operation):
    return _mutate(request, operation)


@owner_required
@require_safe
def export(request):
    try:
        _query(request)
    except ValueError:
        return _private(HttpResponse('Invalid request', status=400))
    return _private(HttpResponse(export_domains_csv(request.workspace.owner_id),
                                content_type='text/csv; charset=utf-8', headers={
                                    'Content-Disposition': 'attachment; filename="sitewatcher-domains.csv"',
                                }))


@require_safe
def legacy_asset(request, name):
    asset, mime = {'style.css': ('dashboard.css', 'text/css'),
                   'theme.js': ('theme.js', 'application/javascript')}[name]
    return HttpResponse(files('sitewatcher').joinpath('data', asset).read_bytes(),
                        content_type=mime + '; charset=utf-8')


@require_safe
def theme(request):
    try:
        query = _query(request)
        mode, target = query.get('mode', 'light'), query.get('next', '/')
        parsed = urlsplit(target)
        if (mode not in {'light', 'dark'} or parsed.scheme or parsed.netloc or parsed.fragment
                or parsed.path not in {'/', '/domains/new', '/domains/edit', '/domains/delete',
                                       '/domains/history', '/workspace', '/import', '/login/', '/password/'}
                or any(ord(char) < 32 or char == chr(92) for char in target)):
            raise ValueError('Invalid theme')
    except ValueError:
        return _private(HttpResponse('Invalid request', status=400))
    response = _private(HttpResponse(status=303, headers={'Location': target}))
    response.set_cookie('sitewatcher_theme', mode, max_age=31536000, samesite='Strict',
                        secure=settings.SESSION_COOKIE_SECURE)
    return response
