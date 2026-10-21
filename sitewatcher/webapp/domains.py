"""Authenticated owner management using existing monitoring operations and renderers."""
from __future__ import annotations

import asyncio
from importlib.resources import files
from threading import Lock
from urllib.parse import urlencode, urlsplit

from django.conf import settings
from django.http import Http404, HttpResponse, JsonResponse
from django.middleware.csrf import get_token
from django.views.decorators.http import require_http_methods, require_POST, require_safe

from sitewatcher import storage
from sitewatcher.config import AppConfig, ChecksModel
from sitewatcher.dashboard import FILTERS, render_dashboard
from sitewatcher.dispatcher import Dispatcher
from sitewatcher.management import render_management
from sitewatcher.reporting import SnapshotError, build_snapshot
from sitewatcher.utils.domains import normalize_domain
from sitewatcher.utils.domains_csv import export_domains_csv, import_domains_csv
from sitewatcher.web_actions import (
    LIST_FIELDS, NUMERIC_FIELDS, act_on_domain, history_context, save_domain, settings_context,
)
from .accounts import owner_required

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


def _html(request, page, *, status=200):
    # Transitional escaped renderer; every form uses Django's session-bound CSRF token.
    page = page.replace('name="csrf_token"', 'name="csrfmiddlewaretoken"')
    return _private(HttpResponse(page, status=status, content_type='text/html; charset=utf-8'))


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
    if view in {'add', 'edit'}:
        context = settings_context(cfg, owner_id, domain if view == 'edit' else None)
    elif view == 'history':
        context = {'domain': domain, 'rows': history_context(owner_id, domain)}
    elif view == 'workspace':
        context = {'alerts_enabled': storage.is_user_alerts_enabled(owner_id)}
    else:
        context = {'domain': domain}
    if values is not None:
        context['values'] = {**context.get('values', {}), **values, 'proxy': ''}
        context['domain'] = values.get('domain', domain)
        if 'revision' in values:
            context['revision'] = values['revision']
        if view == 'import':
            context['mode'] = values.get('mode', 'merge')
    return _html(request, render_management(view, context, get_token(request), error=error,
                                           theme=request.COOKIES.get('sitewatcher_theme', 'light')),
                 status=status)


@owner_required
@require_safe
def dashboard(request):
    try:
        query = _query(request)
        status = query.get('status', 'all')
        if status not in FILTERS:
            raise ValueError('Invalid filter')
        snapshot = build_snapshot(settings.SITEWATCHER_CONFIG, request.workspace.owner_id)
        return _html(request, render_dashboard(
            snapshot, query=query.get('q', ''), status=status,
            auto_refresh=query.get('refresh', 'on') != 'off',
            csrf_token=None if settings.SITEWATCHER_READ_ONLY else get_token(request),
            notice=query.get('notice', ''), theme=request.COOKIES.get('sitewatcher_theme', 'light'),
        ))
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


@owner_required
@require_safe
def theme(request):
    try:
        query = _query(request)
        mode, target = query.get('mode', 'light'), query.get('next', '/')
        parsed = urlsplit(target)
        if (mode not in {'light', 'dark'} or parsed.scheme or parsed.netloc or parsed.fragment
                or parsed.path not in {'/', '/domains/new', '/domains/edit', '/domains/delete',
                                       '/domains/history', '/workspace', '/import'}
                or any(ord(char) < 32 or char == chr(92) for char in target)):
            raise ValueError('Invalid theme')
    except ValueError:
        return _private(HttpResponse('Invalid request', status=400))
    response = _private(HttpResponse(status=303, headers={'Location': target}))
    response.set_cookie('sitewatcher_theme', mode, max_age=31536000, samesite='Strict',
                        secure=settings.SESSION_COOKIE_SECURE)
    return response
