"""Owner-only native group forms; memberships never alter monitoring settings."""
import json

from django.conf import settings
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render
from django.template.loader import render_to_string
from django.utils.translation import gettext as _
from django.views.decorators.http import require_http_methods

from sitewatcher import domain_groups
from .accounts import owner_required


@owner_required
@require_http_methods(['GET', 'HEAD', 'POST'])
def management(request):
    error = ''
    status = 200
    owner_id = request.workspace.owner_id
    if request.method == 'POST':
        if settings.SITEWATCHER_READ_ONLY:
            return HttpResponse(_('Read-only workspace'), status=405)
        fields = dict(request.management_form)
        fields.pop('csrfmiddlewaretoken', None)
        operation = fields.get('operation')
        original = fields.pop('original_group_id', None) if operation == 'move' else None
        allowed = {'create': {'operation', 'name'},
                   'rename': {'operation', 'group_id', 'name'},
                   'delete': {'operation', 'group_id', 'confirm'},
                   'move': {'operation', 'group_id', 'domains'}}
        try:
            if request.GET or operation not in allowed or set(fields) != allowed[operation]:
                raise ValueError('Invalid request')
            if operation == 'create':
                domain_groups.create_group(owner_id, fields['name'])
            else:
                raw = fields['group_id']
                if not raw.isascii() or not raw.isdigit() or len(raw) > 18:
                    raise ValueError('Invalid group')
                group_id = int(raw)
                if operation == 'rename':
                    domain_groups.rename_group(owner_id, group_id, fields['name'])
                elif operation == 'delete':
                    if fields['confirm'] != 'on':
                        raise ValueError('Confirm moving sites to Main before deleting this group')
                    domain_groups.delete_group(owner_id, group_id)
                else:
                    names = json.loads(fields['domains'])
                    if (not isinstance(names, list) or not 1 <= len(names) <= 1000
                            or any(not isinstance(name, str) for name in names)
                            or len(set(names)) != len(names)):
                        raise ValueError('Select between 1 and 1000 sites')
                    if original is not None and (
                            not original.isascii() or not original.isdigit() or len(original) > 18):
                        raise ValueError('Invalid group')
                    domain_groups.move_domains(owner_id, names, group_id,
                        expected_group_id=int(original) if original is not None else None)
            if operation == 'move' and request.headers.get('Accept') == 'application/json':
                return _move_snapshot(request)
            return HttpResponse(status=303, headers={'Location': (
                '/' if operation == 'move' else '/settings/groups')})
        except domain_groups.GroupChangedError:
            return JsonResponse({'saved': False}, status=409)
        except (ValueError, TypeError, OverflowError, RecursionError) as exception:
            error, status = _(str(exception)), 400
    if request.method in {'GET', 'HEAD'} and request.headers.get('Accept') == 'application/json':
        return _move_snapshot(request)
    groups = domain_groups.list_groups(owner_id)
    # One membership read for the whole owner rather than one query per domain.
    from sitewatcher.reporting import SnapshotError, build_snapshot
    try:
        rows = build_snapshot(settings.SITEWATCHER_CONFIG, owner_id)['domains']
    except SnapshotError:
        return HttpResponse(_('Monitoring unavailable'), status=503)
    counts = {}
    for row in rows:
        key = row.get('group_id', 0)
        counts[key] = counts.get(key, 0) + 1
    for group in groups:
        group['count'] = counts.get(group['id'], 0)
    return render(request, 'sitewatcher/groups.html', {
        'groups': groups, 'error': error, 'read_only': settings.SITEWATCHER_READ_ONLY,
    }, status=status)


def _move_snapshot(request):
    """Owner-only, authoritative membership and localized headings, without check metrics."""
    from sitewatcher.reporting import SnapshotError, build_snapshot
    from .domains import _sort_domains
    from .presentation import domain_state, group_presentation
    try:
        snapshot = build_snapshot(settings.SITEWATCHER_CONFIG, request.workspace.owner_id)
    except SnapshotError:
        return JsonResponse({'saved': False}, status=503)
    rows = snapshot['domains']
    for row in rows:
        row['state'] = domain_state(row)
    _sort_domains(rows, request.workspace.domain_order)
    groups = []
    for group in snapshot['groups']:
        summary = group_presentation(group, [row for row in rows
                                            if row.get('group_id', 0) == group['id']])
        groups.append({'id': group['id'], 'total': summary['total'],
            'heading': render_to_string('sitewatcher/partials/group_heading.html', {'group': summary}),
            'empty': render_to_string('sitewatcher/partials/group_empty.html', {'group': summary})})
    return JsonResponse({'saved': True, 'groups': groups,
                         'order': [row['name'] for row in rows],
                         'membership': {row['name']: row.get('group_id', 0) for row in rows}})
