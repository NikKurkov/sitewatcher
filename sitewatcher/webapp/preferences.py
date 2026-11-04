"""Owner settings share the existing delivery preferences and UTC monitoring data."""
import asyncio
import os

from django.utils.translation import gettext as _

from django.conf import settings
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render
from django.views.decorators.debug import sensitive_post_parameters, sensitive_variables
from django.views.decorators.http import require_http_methods

from sitewatcher import storage
from sitewatcher.bot.utils import _resolve_alert_chat_id
from sitewatcher.telegram_connection import (
    find_chats, load_bot_token, save_bot_token, send_test_notification,
)
from sitewatcher.telegram_proxy import load_proxy, save_proxy, remove_proxy
from sitewatcher.virustotal_settings import (
    load_api_key, save_api_key, remove_api_key, load_vt_proxy, save_vt_proxy, remove_vt_proxy,
)
from .accounts import owner_required
from .forms import WorkspacePreferencesForm


def _destination(cfg, owner_id):
    chat_id = _resolve_alert_chat_id(None, None, cfg, owner_id)
    configured = getattr(cfg.alerts, 'chat_id', None)
    if isinstance(configured, int) and configured:
        source = 'installation'
    elif storage.get_user_alert_chat_id(owner_id):
        source = 'workspace'
    elif chat_id:
        source = 'environment'
    else:
        source = 'missing'
    return chat_id, source


@sensitive_variables('token', 'proxy', 'api_key', 'configured_key', 'configured_proxy', 'vt_proxy', 'form')
def _render(request, form=None, *, error='', notice='', chats=None, status=200, public_link=''):
    owner_id = request.workspace.owner_id
    destination, source = _destination(settings.SITEWATCHER_CONFIG, owner_id)
    if form is None:
        form = WorkspacePreferencesForm(initial={
            'language': request.workspace.language,
            'timezone': request.workspace.timezone,
            'enabled': 'on' if storage.is_user_alerts_enabled(owner_id) else 'off',
            'chat_id': storage.get_user_alert_chat_id(owner_id),
        })
    try:
        token = load_bot_token()
        token_present = bool(token)
    except (OSError, ValueError):
        token_present = False
        error = error or _('The saved Telegram connection could not be read. Save a new bot token.')
    try:
        proxy = load_proxy()
        proxy_present = bool(proxy)
    except (OSError, ValueError):
        proxy_present = False
        error = error or _('The Telegram proxy could not be read. Save a new proxy or remove it.')
    configured_key = settings.SITEWATCHER_CONFIG.malware.vt_api_key
    try:
        api_key = load_api_key(configured_key)
        virustotal_present = bool(api_key)
    except (OSError, ValueError):
        virustotal_present = False
        error = error or _('The VirusTotal key could not be read. Save a new key or remove it.')
    configured_proxy = settings.SITEWATCHER_CONFIG.malware.vt_proxy
    try:
        vt_proxy = load_vt_proxy(configured_proxy)
        virustotal_proxy_present = bool(vt_proxy)
    except (OSError, ValueError):
        virustotal_proxy_present = False
        error = error or _('The VirusTotal proxy could not be read. Save a new proxy or remove it.')
    response = render(request, 'sitewatcher/preferences.html', {
        'form': form, 'read_only': settings.SITEWATCHER_READ_ONLY,
        'token_present': token_present, 'environment_override': bool(os.getenv('TELEGRAM_TOKEN', '').strip()),
        'virustotal_present': virustotal_present,
        'virustotal_environment_override': bool(os.getenv('VIRUSTOTAL_API_KEY', '').strip()),
        'virustotal_config_override': bool(configured_key),
        'virustotal_proxy_present': virustotal_proxy_present,
        'virustotal_proxy_environment_override': bool(os.getenv('VIRUSTOTAL_PROXY', '').strip()),
        'virustotal_proxy_config_override': bool(configured_proxy),
        'proxy_present': proxy_present,
        'proxy_environment_override': bool(os.getenv('TELEGRAM_PROXY', '').strip()),
        'destination': destination, 'destination_source': source,
        'alerts_enabled': storage.is_user_alerts_enabled(owner_id),
        'error': error, 'notice': notice, 'chats': chats or [],
        'public_link': public_link,
        'publication_domains': [{'name': name, 'selected': name in request.workspace.public_domains}
                                for name in storage.list_domains(owner_id)],
    }, status=status)
    response['Cache-Control'] = 'no-store'
    return response


@owner_required
@require_http_methods(['GET', 'HEAD', 'POST'])
@sensitive_post_parameters('bot_token', 'telegram_proxy', 'virustotal_api_key', 'virustotal_proxy')
@sensitive_variables('token', 'fields', 'form', 'api_key')
def preferences(request):
    if request.method != 'POST':
        if set(request.GET) - {'saved'} or any(len(v) != 1 for _, v in request.GET.lists()):
            return HttpResponse(_('Invalid request'), status=400)
        return _render(request, notice=_('Settings saved.') if request.GET.get('saved') == '1' else '')
    if settings.SITEWATCHER_READ_ONLY:
        return HttpResponse(_('Read-only workspace'), status=405, headers={'Allow': 'GET, HEAD'})
    fields = dict(request.management_form)
    fields.pop('csrfmiddlewaretoken', None)
    action = fields.pop('action', 'save')
    if (request.GET or set(fields) - set(WorkspacePreferencesForm.base_fields)
            or action not in {'save', 'test', 'find_chats', 'reveal_virustotal_key'} or action != 'save' and fields):
        return HttpResponse(_('Invalid request'), status=400)
    if action == 'reveal_virustotal_key':
        try:
            api_key = load_api_key(settings.SITEWATCHER_CONFIG.malware.vt_api_key)
        except (OSError, ValueError):
            return JsonResponse({'error': 'Key unavailable'}, status=503,
                                headers={'Cache-Control': 'no-store'})
        return JsonResponse({'key': api_key or ''}, headers={'Cache-Control': 'no-store'})
    if action == 'save':
        form = WorkspacePreferencesForm(fields)
        if not form.is_valid():
            return _render(request, form, status=400)
        try:
            # Empty connection fields retain the existing configuration.
            if form.cleaned_data['remove_virustotal_api_key']:
                remove_api_key()
            elif form.cleaned_data['virustotal_api_key']:
                save_api_key(form.cleaned_data['virustotal_api_key'])
            if form.cleaned_data['remove_virustotal_proxy']:
                remove_vt_proxy()
            elif form.cleaned_data['virustotal_proxy']:
                save_vt_proxy(form.cleaned_data['virustotal_proxy'])
            if form.cleaned_data['remove_telegram_proxy']:
                remove_proxy()
            elif form.cleaned_data['telegram_proxy']:
                save_proxy(form.cleaned_data['telegram_proxy'])
            if form.cleaned_data['bot_token']:
                save_bot_token(form.cleaned_data['bot_token'])
            if 'enabled' in fields:
                storage.set_user_alerts_enabled(request.workspace.owner_id,
                                                form.cleaned_data['enabled'] == 'on')
            if form.cleaned_data['chat_id'] is not None:
                storage.set_user_alert_chat_id(request.workspace.owner_id,
                                               form.cleaned_data['chat_id'])
            if 'timezone' in fields:
                request.workspace.timezone = form.cleaned_data['timezone']
                request.workspace.save(update_fields=['timezone'])
            if 'language' in fields:
                request.workspace.language = form.cleaned_data['language']
                request.workspace.save(update_fields=['language'])
        except Exception:
            return _render(request, form, error=_('Settings could not be saved. Reload and check before retrying.'),
                           status=503)
        response = HttpResponse(status=303, headers={'Location': '/settings?saved=1'})
        if 'language' in fields:
            response.set_cookie(settings.LANGUAGE_COOKIE_NAME, request.workspace.language,
                                max_age=31536000, httponly=True, samesite='Lax',
                                secure=settings.SESSION_COOKIE_SECURE)
        return response
    try:
        token = load_bot_token()
    except (OSError, ValueError):
        return _render(request, error=_('The saved Telegram connection could not be read. Save a new bot token.'),
                       status=400)
    if not token:
        return _render(request, error=_('Add a bot token before connecting to Telegram.'), status=400)
    try:
        if action == 'find_chats':
            chats = asyncio.run(find_chats(token))
            notice = (_('Choose a chat below, then save it as your destination.') if chats else
                      _('No chats found. Send /start to your bot and try again, or enter a chat ID in Advanced.'))
            return _render(request, chats=chats, notice=notice)
        destination = _destination(settings.SITEWATCHER_CONFIG, request.workspace.owner_id)[0]
        if destination is None:
            return _render(request, error=_('Choose a chat destination before sending a test.'), status=400)
        asyncio.run(send_test_notification(token, destination))
        return _render(request, notice=_('Test notification sent to the effective destination shown below.'))
    except Exception:
        # Never echo an exception: client errors can contain the credential-bearing URL.
        return _render(request, error=(
            _('Telegram could not complete the request. Check the token and destination. '
            'If finding chats, another process may be polling or a webhook may be enabled; '
            'enter a chat ID in Advanced, or stop polling before trying again.')), status=400)
