"""Authenticated owner management using existing monitoring operations and renderers."""
from __future__ import annotations

import asyncio
import json
from threading import Lock
from urllib.parse import urlencode, urlsplit

from django.utils.translation import gettext_lazy as _, gettext_noop

from django.conf import settings
from django.http import Http404, HttpResponse, JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_http_methods, require_POST, require_safe

from sitewatcher import storage, domain_groups
from sitewatcher.config import AppConfig, ChecksModel
from sitewatcher.dispatcher import Dispatcher
from sitewatcher.reporting import SnapshotError, build_snapshot
from sitewatcher.utils.domains import normalize_domain
from sitewatcher.utils.domains_csv import export_domains_csv, import_domains_csv
from sitewatcher.utils.results import is_missing_malware_report, is_pending_malware_report
from sitewatcher.web_actions import (
    LIST_FIELDS, NUMERIC_FIELDS, act_on_domain, add_domains, history_context,
    save_domain, settings_context,
)
from .accounts import owner_required
from .check_presentation import prepare_check_list
from .models import Workspace
from .forms import HistoryFiltersForm
from .analytics import domain_report, overview_report
from .presentation import check_label, diagnostic_message, domain_form_context, local_time, report_context, status_label

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
    for name in ('error', 'notice'):
        if context.get(name):
            context[name] = _(context[name])
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
        reset_revision = storage.domain_reset_revision(owner_id, domain) if view == 'edit' else ''
        try:
            context = settings_context(cfg, owner_id, domain if view == 'edit' else None)
        except ValueError:
            if view == 'edit' and not storage.domain_exists(owner_id, domain):
                raise Http404('Domain not found') from None
            if view == 'edit':
                return _render(request, 'domain_recovery', {
                    'domain': domain, 'reset_revision': reset_revision,
                })
            return _private(HttpResponse(_('Settings unavailable; reload the page'), status=400))
        context['reset_revision'] = reset_revision
    elif view == 'history':
        try:
            report = domain_report(owner_id, domain, days=_period(request),
                                   timezone=request.workspace.timezone)
        except ValueError:
            if not storage.domain_exists(owner_id, domain):
                raise Http404('Domain not found') from None
            return _private(HttpResponse(_('Invalid request'), status=400))
        snapshot = build_snapshot(cfg, owner_id)
        row = next((row for row in snapshot['domains'] if row['name'] == domain), None)
        if row is None:
            raise Http404('Domain not found')
        _row_context(row, request.workspace.timezone)
        history_form = HistoryFiltersForm(request.GET, zone=request.workspace.timezone)
        filters_valid = history_form.is_valid()
        filters = history_form.cleaned_data
        try:
            history = history_context(
                owner_id, domain, check=filters.get('history_check'),
                status=filters.get('history_status'), since=filters.get('since'),
                until=filters.get('until'),
            ) if filters_valid else []
        except ValueError:
            raise Http404('Domain not found') from None
        for item in history:
            item['check_label'] = check_label(item['check_name'])
            item['message'] = diagnostic_message(item['message'])
            item['status_label'] = status_label(item['status'])
            item['observed'] = local_time(item['created_at'], request.workspace.timezone)
        return _render(request, 'domain_detail', {'report': report_context(report), 'row': row,
                                                 'history': history, 'history_form': history_form,
                                                 'history_query': urlencode({
                                                     name: request.GET[name] for name in history_form.fields
                                                     if request.GET.get(name)}),
                                                 'history_filtered': any(request.GET.get(name)
                                                     for name in history_form.fields)},
                       status=200 if filters_valid else 400)
    if view == 'add' and values is None:
        context['values']['interval_minutes'] = str(context['defaults']['interval_minutes'])
    if values is not None:
        context['values'] = {**context.get('values', {}), **values, 'proxy': ''}
        context['domain'] = values.get('original_domain', values.get('domain', domain))
        if 'revision' in values:
            context['revision'] = values['revision']
        if view == 'import':
            context['mode'] = values.get('mode', 'merge')
    context.update(view=view, error=error)
    if view in {'add', 'edit'}:
        context['groups'] = domain_groups.list_groups(owner_id)
        domain_form_context(context, error)
    return _render(request, 'domain_form' if view in {'add', 'edit'} else 'management',
                   context, status=status)


def _row_context(row, zone):
    row['http_enabled'] = any(check['name'] == 'http_basic' for check in row['checks'])
    row['state'] = ('paused' if row['paused'] else row['overall'].lower())
    row['label'] = {'paused': _('Paused'), 'crit': _('Critical'), 'warn': _('Warning'),
                    'ok': _('Healthy'), 'unknown': _('No data')}[row['state']]
    if row['error']:
        row['state'], row['label'] = 'warn', _('Settings error')
    row['observed'] = local_time(row['last_checked_at'], zone)
    for check in row['checks']:
        neutral = is_missing_malware_report(check['name'], check['status'], check['message'])
        check['pending'] = is_pending_malware_report(check['name'], check['status'], check['message'])
        check['attention'] = not neutral and (check['status'] != 'OK' or check['stale'])
        check['label'] = check_label(check['name'])
        check['message'] = diagnostic_message(check['message'])
        check['status_label'] = (_('Analysis pending') if check['pending']
                                 else status_label(check['status']))
        check['observed'] = local_time(check['checked_at'], zone)
    row['problems'] = sorted(
        (check for check in row['checks'] if check['attention']),
        key=lambda check: {'CRIT': 0, 'WARN': 1}.get(check['status'], 2),
    )
    row['checks'].sort(key=lambda check: (
        not check['attention'], {'CRIT': 0, 'WARN': 1}.get(check['status'], 2), check['name']))
    row['checks_common_observed'] = prepare_check_list(row['checks'])


FILTERS = {
    "all": _("All domains"), "problems": _("Problems"), "ok": _("Healthy"), "warn": _("Warnings"),
    "crit": _("Critical"), "unknown": _("No data"), "paused": _("Paused"), "stale": _("Overdue"),
}

def _sort_domains(rows, saved_order):
    ranks = {name: rank for rank, name in enumerate(saved_order)}
    rows.sort(key=lambda row: (row.get('group_id', 0), not row['favorite'], row['name'] not in ranks,
        ranks.get(row['name'], 0),
        {'crit': 0, 'warn': 1, 'unknown': 2, 'ok': 3, 'paused': 4}[row['state']], row['name']))


@owner_required(api=True)
@require_POST
def reorder(request):
    if settings.SITEWATCHER_READ_ONLY:
        return JsonResponse({'error': 'Read-only workspace'}, status=405)
    form = dict(request.management_form)
    form.pop('csrfmiddlewaretoken', None)
    if request.GET or set(form) != {'order'}:
        return JsonResponse({'error': 'Invalid request'}, status=400)
    try:
        order = json.loads(form['order'])
        if (not isinstance(order, list) or len(order) < 2
                or any(not isinstance(name, str) for name in order)
                or len(set(order)) != len(order)):
            raise ValueError('Invalid order')
        rows = build_snapshot(settings.SITEWATCHER_CONFIG, request.workspace.owner_id)['domains']
        for row in rows:
            _row_context(row, request.workspace.timezone)
        _sort_domains(rows, request.workspace.domain_order)
        favorites = {row['name']: row['favorite'] for row in rows}
        groups = {row['name']: row.get('group_id', 0) for row in rows}
        if any(name not in favorites for name in order):
            return JsonResponse({'error': 'Domain not found'}, status=404)
        positions = [(groups[name], not favorites[name]) for name in order]
        if positions != sorted(positions):
            raise ValueError('Move domains within their group; favorites stay first')
        # Replace only visible slots: filtered-out domains retain their relative positions.
        selected = set(order)
        replacement = iter(order)
        merged = [next(replacement) if row['name'] in selected else row['name'] for row in rows]
        updated = Workspace.objects.filter(
            pk=request.workspace.pk, domain_order=request.workspace.domain_order,
        ).update(domain_order=merged)
        if not updated:
            return JsonResponse({'error': 'Order changed; reload the page'}, status=409)
    except (ValueError, TypeError, RecursionError):
        return JsonResponse({'error': 'Invalid order'}, status=400)
    except SnapshotError:
        return JsonResponse({'error': 'Monitoring unavailable'}, status=503)
    return JsonResponse({'saved': True})


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
        attention = sum(bool(row['error']) or (row['overall'] in {'CRIT', 'WARN'}
                                              and not row['paused']) for row in rows)
        last = max((row['last_checked_at'] for row in rows if row['last_checked_at']), default=None)
        for row in rows:
            _row_context(row, zone)
            row['report'] = reports.get(row['name'])
        _sort_domains(rows, request.workspace.domain_order)
        search = query.get('q', '').strip()
        filtered = [row for row in rows if search.lower() in row['name'] and (
            status == 'all' or status == 'problems' and (row['error'] or row['overall'] in {'CRIT', 'WARN'})
            or status in {'paused', 'stale'} and row[status]
            or row['overall'].lower() == status)]
        groups = []
        for group in snapshot['groups']:
            members = [row for row in rows if row.get('group_id', 0) == group['id']]
            visible = [row for row in filtered if row.get('group_id', 0) == group['id']]
            if (search or status != 'all') and not visible:
                continue
            groups.append({**group, 'label': _('Main') if group['is_default'] else group['name'],
                           'rows': visible, 'total': len(members),
                           'attention': sum(bool(row['error']) or (
                               row['overall'] in {'CRIT', 'WARN'} and not row['paused'])
                               for row in members)})
        return _render(request, 'overview', {'rows': filtered, 'total': len(rows),
            'groups': groups, 'group_choices': snapshot['groups'],
            'group_filtered': bool(search or status != 'all'),
            'attention': attention, 'summary': snapshot['summary'], 'report': report,
            'healthy': sum(row['state'] == 'ok' for row in rows),
            'observed': local_time(last, zone), 'query': search, 'status': status,
            'filters': FILTERS.items(), 'notice': query.get('notice', '')})
    except ValueError:
        return _private(HttpResponse(_('Invalid request'), status=400))
    except SnapshotError:
        return _private(HttpResponse(_('Monitoring unavailable'), status=503))


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


def _redirect(notice, filters=None):
    return _private(HttpResponse(status=303, headers={
        'Location': '/?' + urlencode({'notice': notice, **(filters or {})}),
    }))


def _list_filters(form):
    days, status = form.get('days', '1'), form.get('status', 'all')
    if days not in {'1', '7', '30'} or status not in FILTERS:
        raise ValueError('Invalid list filters')
    return {'days': days, 'status': status, 'q': form.get('q', '')}


def _act(request, action, form):
    cfg, owner_id = settings.SITEWATCHER_CONFIG, request.workspace.owner_id
    filters = (_list_filters(form) if action in {'check', 'pause', 'resume'}
               and any(key in form for key in ('q', 'status', 'days')) else {})
    if action == 'favorite':
        state = form.get('favorite')
        filters = _list_filters(form)
        if state not in {'on', 'off'}:
            raise ValueError('Invalid favorite setting')
        domain = _existing(owner_id, form.get('domain', ''))
        if not storage.set_domain_favorite(owner_id, domain, state == 'on'):
            raise Http404('Domain not found')
        query = urlencode(filters)
        return _private(HttpResponse(status=303, headers={'Location': '/?' + query}))
    if action == 'add':
        count = add_domains(cfg, owner_id, form)
        return _redirect(_('Domains added: %(count)s') % {'count': count})
    if action == 'save':
        save_domain(cfg, owner_id, form)
        return _redirect(_('Domain saved'))
    if action in {'delete', 'pause', 'resume', 'reset', 'check'}:
        domain = form.get('domain', '')
        if action != 'check' or domain != '*':
            domain = _existing(owner_id, domain)
        if action == 'delete' and form.get('confirm') != domain:
            raise ValueError(gettext_noop('Confirm deletion first'))
        if action == 'check':
            names = storage.list_domains(owner_id) if domain == '*' else [domain]
            if not names:
                raise ValueError(gettext_noop('No domains to check'))
            if not _check_lock.acquire(blocking=False):
                return _private(HttpResponse(_('Another manual check is running'), status=409))
            try:
                run_manual_checks(cfg, owner_id, names)
            finally:
                _check_lock.release()
            return _redirect(_('Checks completed; results saved'), filters)
        if action == 'reset' and not form.get('revision'):
            raise ValueError('Reset requires the current settings revision')
        act_on_domain(cfg, owner_id, action, domain, revision=form.get('revision'))
        return _redirect(_('Domain updated'), filters)
    if action == 'alerts':
        if form.get('enabled') not in {'on', 'off'}:
            raise ValueError('Invalid alert setting')
        storage.set_user_alerts_enabled(owner_id, form['enabled'] == 'on')
        return _redirect(_('Notification preference saved'))
    if action == 'import':
        if form.get('csv_file') and form.get('csv_text'):
            raise ValueError(gettext_noop('Choose a file or pasted CSV, not both'))
        text = form.get('csv_file') or form.get('csv_text') or ''
        report = import_domains_csv(owner_id, text.encode('utf-8'),
                                    mode=form.get('mode', 'merge'), cfg=cfg)
        notice = _('CSV: %(added)s added, %(updated)s updated, %(skipped)s skipped') % {
            'added': report.added, 'updated': report.updated, 'skipped': report.skipped}
        if report.errors:
            return _page(request, 'import', error=notice + _('. Some rows were not imported.'),
                         values=form, status=400)
        return _redirect(notice)
    raise Http404


def _mutate(request, action):
    if settings.SITEWATCHER_READ_ONLY:
        return _private(HttpResponse(_('Read-only workspace'), status=405, headers={'Allow': 'GET, HEAD'}))
    form = dict(request.management_form)
    form.pop('csrfmiddlewaretoken', None)
    allowed = {'domain'}
    if action in {'add', 'save'}:
        allowed.update((*NUMERIC_FIELDS, *LIST_FIELDS, 'http_url', 'http_scheme', 'original_domain', 'revision', 'proxy_mode', 'proxy', 'group_id', 'original_group_id'))
        allowed.update(f'check.{name}' for name in ChecksModel.model_fields)
    elif action == 'favorite':
        allowed.update({'favorite', 'q', 'status', 'days'})
    elif action in {'check', 'pause', 'resume'}:
        allowed.update({'q', 'status', 'days'})
    elif action == 'delete':
        allowed.add('confirm')
    elif action == 'reset':
        allowed.add('revision')
    elif action == 'alerts':
        allowed = {'enabled'}
    elif action == 'import':
        allowed = {'csv_file', 'csv_text', 'mode'}
    if request.GET or set(form) - allowed:
        return _private(HttpResponse(_('Invalid request'), status=400))
    if action == 'save':
        _existing(request.workspace.owner_id, form.get('original_domain', form.get('domain', '')))
    try:
        return _act(request, action, form)
    except ValueError as error:
        if action == 'reset' and str(error) == 'Settings changed; reload this page before saving':
            return _private(HttpResponse(_('Settings changed; reload the domain before resetting'),
                                         status=409))
        view = {'add': 'add', 'save': 'edit', 'import': 'import'}.get(action)
        if view:
            return _page(request, view, form.get('original_domain', form.get('domain', '')), error=str(error),
                         values=form, status=400)
        return _private(HttpResponse(_('Invalid action; reload the page'), status=400))
    except Http404:
        raise
    except TimeoutError:
        return _private(HttpResponse(_('Checks timed out; inspect saved results before retrying'), status=504))
    except Exception:
        return _private(HttpResponse(_('Operation failed; inspect saved state before retrying'), status=503))


@owner_required
@require_http_methods(['GET', 'HEAD', 'POST'])
def management(request, view):
    if request.method == 'POST':
        if view == 'history':
            return _private(HttpResponse(_('Method not allowed'), status=405,
                                         headers={'Allow': 'GET, HEAD'}))
        return _mutate(request, {'add': 'add', 'edit': 'save', 'delete': 'delete',
                                 'import': 'import'}[view])
    try:
        query = _query(request)
    except ValueError:
        return _private(HttpResponse(_('Invalid request'), status=400))
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
        return _private(HttpResponse(_('Invalid request'), status=400))
    return _private(HttpResponse(export_domains_csv(request.workspace.owner_id),
                                content_type='text/csv; charset=utf-8', headers={
                                    'Content-Disposition': 'attachment; filename="sitewatcher-domains.csv"',
                                }))


@require_safe
def theme(request):
    try:
        query = _query(request)
        mode, target = query.get('mode', 'light'), query.get('next', '/')
        parsed = urlsplit(target)
        if (mode not in {'light', 'dark'} or parsed.scheme or parsed.netloc or parsed.fragment
                or parsed.path not in {'/', '/domains/new', '/domains/edit', '/domains/delete',
                                       '/domains/history', '/workspace', '/settings', '/import', '/login/', '/password/'}
                or any(ord(char) < 32 or char == chr(92) for char in target)):
            raise ValueError('Invalid theme')
    except ValueError:
        return _private(HttpResponse(_('Invalid request'), status=400))
    response = _private(HttpResponse(status=303, headers={'Location': target}))
    response.set_cookie('sitewatcher_theme', mode, max_age=31536000, samesite='Strict',
                        secure=settings.SESSION_COOKIE_SECURE)
    return response
