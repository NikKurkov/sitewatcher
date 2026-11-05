"""Owner-scoped status-page configuration and one-time private links."""
import hashlib
import logging
import re
import secrets

from django import forms
from django.conf import settings
from django.db import IntegrityError, transaction
from django.http import Http404, HttpResponse
from django.shortcuts import render
from django.utils import timezone
from django.utils.text import slugify
from django.utils.translation import gettext_lazy as _
from django.views.decorators.debug import sensitive_variables
from django.views.decorators.http import require_http_methods, require_safe

from sitewatcher import storage
from .accounts import owner_required
from .models import StatusPage, Workspace
from .public import RESERVED_PUBLIC_SLUGS


class StatusPageForm(forms.Form):
    title = forms.CharField(label=_('Title'), max_length=120)
    access_mode = forms.ChoiceField(label=_('Access'), choices=[
        ('public', _('Public')), ('private', _('Private link'))])
    public_slug = forms.CharField(label=_('Page address'), max_length=64, required=False,
        help_text=_('Lowercase Latin letters, numbers, hyphens and underscores. Changing the address disables the old link.'))
    enabled = forms.BooleanField(label=_('Page enabled'), required=False, initial=True)
    revision = forms.CharField(required=False, widget=forms.HiddenInput)

    def __init__(self, *args, page=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.page = page

    def clean_public_slug(self):
        slug = self.cleaned_data['public_slug'].strip('/')
        if self.cleaned_data.get('access_mode') != 'public' or not slug:
            return ''
        pages = StatusPage.objects.filter(public_slug=slug)
        workspaces = Workspace.objects.filter(public_slug=slug)
        if self.page:
            pages = pages.exclude(pk=self.page.pk)
            if self.page.legacy_primary:
                workspaces = workspaces.exclude(pk=self.page.workspace_id)
        if (not re.fullmatch(r'[a-z][a-z0-9_-]{0,63}', slug)
                or slug in RESERVED_PUBLIC_SLUGS or pages.exists() or workspaces.exists()):
            raise forms.ValidationError(_('Choose an unused page address using lowercase letters, numbers, hyphens or underscores.'))
        return slug


def _new_slug(title):
    base = slugify(title)[:40].strip('-')
    if not base or not base[0].isalpha() or base in RESERVED_PUBLIC_SLUGS:
        base = 'status-page'
    candidate = base
    while (StatusPage.objects.filter(public_slug=candidate).exists()
           or Workspace.objects.filter(public_slug=candidate).exists()):
        candidate = base + '-' + secrets.token_hex(4)
    return candidate


def sync_legacy_page(page, *, deleted=False):
    """Retain the old publication API/export fields during the transition."""
    if page.legacy_primary:
        Workspace.objects.filter(pk=page.workspace_id).update(
            public_enabled=False if deleted else page.public_enabled,
            public_token_hash='' if deleted else page.public_token_hash,
            public_domains=[] if deleted else page.public_domains,
            public_slug=page.public_slug,
        )


@owner_required
@require_safe
def listing(request):
    if request.GET and (set(request.GET) != {'saved'} or request.GET.getlist('saved') != ['1']):
        return HttpResponse(_('Invalid request'), status=400)
    return render(request, 'sitewatcher/status_pages.html', {
        'pages': StatusPage.objects.filter(workspace=request.workspace),
        'read_only': settings.SITEWATCHER_READ_ONLY,
        'notice': _('Status page saved.') if request.GET.get('saved') else '',
    })


@sensitive_variables('private_link')
def _editor(request, page, form=None, *, selected=None, error='', status=200, private_link=''):
    if form is None:
        form = StatusPageForm(initial={
            'title': (page.title or _('Service status')) if page else '',
            'access_mode': page.access_mode if page else 'public',
            'public_slug': page.public_slug if page else '',
            'enabled': page.public_enabled if page else True,
            'revision': page.updated_at.isoformat() if page else '',
        }, page=page)
    selected = set(page.public_domains if page else []) if selected is None else set(selected)
    try:
        return render(request, 'sitewatcher/status_page_form.html', {
            'page': page, 'form': form, 'error': error,
            'private_link': private_link, 'read_only': settings.SITEWATCHER_READ_ONLY,
            'domains': [{'name': name, 'selected': name in selected}
                        for name in storage.list_domains(request.workspace.owner_id)],
        }, status=status)
    except Exception as error:
        # A template failure must never put a one-time bearer URL into an exception report.
        logging.getLogger(__name__).warning('Status page editor unavailable (%s)', type(error).__name__)
        return HttpResponse(_('Status page settings temporarily unavailable.'), status=503)


@owner_required
@require_http_methods(['GET', 'HEAD', 'POST'])
@sensitive_variables('token', 'private_link', 'values')
def editor(request, page_id=None):
    page = (StatusPage.objects.filter(pk=page_id, workspace=request.workspace).first()
            if page_id is not None else None)
    if page_id is not None and page is None:
        raise Http404
    if request.GET:
        return HttpResponse(_('Invalid request'), status=400)
    if request.method != 'POST':
        return _editor(request, page)
    if settings.SITEWATCHER_READ_ONLY:
        return HttpResponse(_('Read-only workspace'), status=405, headers={'Allow': 'GET, HEAD'})
    values = dict(request.management_form)
    values.pop('csrfmiddlewaretoken', None)
    action = values.pop('action', 'save')
    owned = set(storage.list_domains(request.workspace.owner_id))
    selection = {name[7:]: value for name, value in values.items() if name.startswith('domain.')}
    allowed = set(StatusPageForm.base_fields) | {'domain.' + name for name in owned}
    if (action not in {'save', 'rotate', 'delete'} or set(values) - allowed
            or not set(selection) <= owned or any(value != 'on' for value in selection.values())):
        return HttpResponse(_('Invalid request'), status=400)
    form = StatusPageForm({key: value for key, value in values.items()
                           if key in StatusPageForm.base_fields}, page=page)
    if not form.is_valid():
        return _editor(request, page, form, selected=selection, status=400)
    if page and form.cleaned_data['revision'] != page.updated_at.isoformat():
        return _editor(request, page, form, selected=selection,
                       error=_('This page changed. Reload before saving.'), status=409)
    if not page and action != 'save':
        return HttpResponse(_('Invalid request'), status=400)
    private_link = ''
    try:
        with transaction.atomic():
            if action == 'delete':
                deleted, _delete_counts = StatusPage.objects.filter(pk=page.pk,
                    workspace=request.workspace, updated_at=page.updated_at).delete()
                if not deleted:
                    return _editor(request, page, form, selected=selection,
                       error=_('This page changed. Reload before saving.'), status=409)
                sync_legacy_page(page, deleted=True)
                return HttpResponse(status=303, headers={'Location': '/settings/status-pages'})
            if action == 'rotate':
                if page.access_mode != 'private' or not page.public_enabled:
                    return HttpResponse(_('Enable a private page before reissuing its link.'), status=400)
                update = {}
            else:
                update = {'title': form.cleaned_data['title'],
                          'access_mode': form.cleaned_data['access_mode'],
                          'public_enabled': form.cleaned_data['enabled'],
                          'public_domains': sorted(selection)}
                if form.cleaned_data['access_mode'] == 'public' and form.cleaned_data['public_slug']:
                    update['public_slug'] = form.cleaned_data['public_slug']
            enabled = update.get('public_enabled', page.public_enabled if page else True)
            mode = update.get('access_mode', page.access_mode if page else 'public')
            if enabled and mode == 'private' and (not page or action == 'rotate'
                    or page.access_mode != 'private' or not page.public_token_hash):
                token = secrets.token_urlsafe(32)
                update['public_token_hash'] = hashlib.sha256(token.encode()).hexdigest()
                private_link = request.build_absolute_uri('/status/' + token + '/')
            elif not enabled or page and page.access_mode == 'private' and mode == 'public':
                update['public_token_hash'] = ''
            if page:
                updated = StatusPage.objects.filter(pk=page.pk, workspace=request.workspace,
                    updated_at=page.updated_at).update(**update, updated_at=timezone.now())
                if not updated:
                    return _editor(request, page, form, selected=selection,
                       error=_('This page changed. Reload before saving.'), status=409)
                page.refresh_from_db()
            else:
                if 'public_slug' not in update:
                    update['public_slug'] = _new_slug(update['title'])
                page = StatusPage.objects.create(workspace=request.workspace, **update)
            sync_legacy_page(page)
    except IntegrityError:
        return _editor(request, page, form, selected=selection,
                       error=_('The page could not be saved. Reload and try again.'), status=409)
    if private_link:
        return _editor(request, page, private_link=private_link)
    return HttpResponse(status=303, headers={'Location': '/settings/status-pages?saved=1'})
