"""Django authentication with one generic rejection for every account state."""
from datetime import datetime, time, timedelta, timezone
from email import policy
from email.parser import BytesParser
from urllib.parse import parse_qs
from zoneinfo import ZoneInfo, available_timezones

from django import forms
from django.contrib.auth.forms import AuthenticationForm
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from .accounts import AUTH_ERROR
from .models import Workspace


class OwnerAuthenticationForm(AuthenticationForm):
    remember_me = forms.BooleanField(label=_('Remember me for 30 days'), required=False)

    error_messages = {'invalid_login': AUTH_ERROR, 'inactive': AUTH_ERROR}

    def confirm_login_allowed(self, user):
        super().confirm_login_allowed(user)
        if not Workspace.objects.filter(user=user).exists():
            raise ValidationError(AUTH_ERROR, code='invalid_login')


def parse_management_form(content_type: str, body: bytes, *, max_fields=40) -> dict[str, str]:
    """Decode a bounded native form; ambiguous fields are never silently accepted."""
    if content_type.split(';', 1)[0].strip().lower() == 'application/x-www-form-urlencoded':
        values = parse_qs(body.decode('utf-8'), keep_blank_values=True, max_num_fields=max_fields,
                          encoding='utf-8', errors='strict')
        if any(len(value) != 1 for value in values.values()):
            raise ValueError('Duplicate fields')
        return {key: value[0] for key, value in values.items()}
    if not content_type.lower().startswith('multipart/form-data;'):
        raise ValueError('Unsupported form encoding')
    message = BytesParser(policy=policy.default).parsebytes(
        b'Content-Type: ' + content_type.encode('ascii') + b'\r\nMIME-Version: 1.0\r\n\r\n' + body,
    )
    if not message.is_multipart() or message.defects:
        raise ValueError('Invalid multipart form')
    values = {}
    for part in message.iter_parts():
        name = part.get_param('name', header='content-disposition')
        if (not name or name in values or len(values) >= max_fields or part.is_multipart()
                or part.get_content_disposition() != 'form-data' or part.defects):
            raise ValueError('Invalid form field')
        values[name] = (part.get_payload(decode=True) or b'').decode('utf-8-sig')
    return values


class ProxyAddressInput(forms.PasswordInput):
    """Show proxy URLs; the owner settings view opts in to prefilling saved values."""
    input_type = 'text'


class WorkspacePreferencesForm(forms.Form):
    """Validate optional patches so a timezone save never resets Telegram settings."""
    language = forms.ChoiceField(label=_('Language'), required=False,
                                 choices=[('en', 'English'), ('ru', 'Русский')],
                                 help_text=_('Choose the language of your workspace.'))
    timezone = forms.CharField(label=_('Timezone'), max_length=64, required=False,
                               help_text=_('Dates and times use your selected timezone.'),
                               widget=forms.Select(choices=[
                                   (zone, zone.replace('_', ' ').replace('/', ' / '))
                                   for zone in sorted(available_timezones())
                                   if not zone.startswith(('posix/', 'right/'))]))
    enabled = forms.ChoiceField(label=_('Telegram notifications'), required=False,
                               choices=[('on', _('Enabled')), ('off', _('Disabled'))])
    chat_id = forms.IntegerField(label=_('Chat ID'), required=False,
                                 min_value=-(2**63) + 1, max_value=2**63 - 1,
                                 widget=forms.TextInput(attrs={'inputmode': 'numeric'}))
    bot_token = forms.CharField(label=_('New bot token'), required=False, max_length=224,
                                widget=forms.PasswordInput(render_value=False, attrs={
                                    'autocomplete': 'new-password', 'spellcheck': 'false',
                                }))

    telegram_proxy = forms.CharField(label=_('New Telegram proxy'), required=False, max_length=2048,
                                    widget=forms.PasswordInput(render_value=False, attrs={
                                        'autocomplete': 'new-password', 'spellcheck': 'false',
                                    }))
    remove_telegram_proxy = forms.BooleanField(label=_('Remove saved Telegram proxy'), required=False)

    virustotal_api_key = forms.CharField(
        label=_('VirusTotal API key'), required=False, max_length=2048,
        widget=forms.PasswordInput(render_value=False, attrs={
            'autocomplete': 'new-password', 'spellcheck': 'false',
        }))
    remove_virustotal_api_key = forms.BooleanField(
        label=_('Remove saved VirusTotal API key'), required=False)

    virustotal_proxy_settings = forms.ChoiceField(
        required=False, choices=[('1', '1')], initial='1', widget=forms.HiddenInput)
    virustotal_proxy_enabled = forms.BooleanField(
        label=_('Use a proxy for VirusTotal'), required=False,
        widget=forms.CheckboxInput(attrs={
            'data-vt-proxy-toggle': '', 'aria-controls': 'virustotal-proxy-fields',
        }))
    virustotal_proxy = forms.CharField(
        label=_('VirusTotal proxy'), required=False, max_length=2048,
        widget=ProxyAddressInput(render_value=False, attrs={
            'autocomplete': 'off', 'spellcheck': 'false',
        }))
    remove_virustotal_proxy = forms.BooleanField(
        label=_('Remove saved VirusTotal proxy'), required=False)

    def clean_virustotal_proxy(self):
        from sitewatcher.virustotal_settings import validate_vt_proxy
        value = self.cleaned_data['virustotal_proxy']
        if value:
            try:
                return validate_vt_proxy(value)
            except ValueError as error:
                raise ValidationError(_(str(error))) from None
        return ''

    def clean_virustotal_api_key(self):
        from sitewatcher.virustotal_settings import validate_api_key
        value = self.cleaned_data['virustotal_api_key']
        if value:
            try:
                return validate_api_key(value)
            except ValueError as error:
                raise ValidationError(_(str(error))) from None
        return ''

    def clean_telegram_proxy(self):
        from sitewatcher.telegram_proxy import normalize_proxy
        value = self.cleaned_data['telegram_proxy']
        if value:
            try:
                return normalize_proxy(value)
            except ValueError as error:
                raise ValidationError(_(str(error))) from None
        return ''

    def clean(self):
        data = super().clean()
        if data.get('telegram_proxy') and data.get('remove_telegram_proxy'):
            self.add_error('telegram_proxy', _('Choose a new proxy or remove the saved proxy.'))
        if data.get('virustotal_api_key') and data.get('remove_virustotal_api_key'):
            self.add_error('virustotal_api_key',
                           _('Choose a new VirusTotal key or remove the saved key.'))
        return data

    def clean_timezone(self):
        from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
        value = self.cleaned_data['timezone']
        if 'timezone' in self.data:
            try:
                ZoneInfo(value)
            except (ValueError, ZoneInfoNotFoundError):
                raise ValidationError(_('Choose a valid timezone from the list.')) from None
        return value

    def clean_language(self):
        value = self.cleaned_data['language']
        if 'language' in self.data and not value:
            raise ValidationError(_('Choose English or Russian.'))
        return value

    def clean_enabled(self):
        value = self.cleaned_data['enabled']
        if 'enabled' in self.data and not value:
            raise ValidationError(_('Choose Enabled or Disabled.'))
        return value

    def clean_chat_id(self):
        value = self.cleaned_data['chat_id']
        if value == 0:
            raise ValidationError(_('Enter a nonzero numeric Telegram chat ID.'))
        return value

    def clean_bot_token(self):
        from sitewatcher.telegram_connection import validate_bot_token
        value = self.cleaned_data['bot_token']
        if value:
            try:
                return validate_bot_token(value)
            except ValueError as error:
                raise ValidationError(str(error)) from None
        return ''


class HistoryFiltersForm(forms.Form):
    """Date inputs describe inclusive calendar days in the workspace timezone."""
    history_from = forms.DateField(label=_('From date'), required=False,
        input_formats=['%Y-%m-%d'],
        widget=forms.DateInput(format='%Y-%m-%d', attrs={'type': 'date'}))
    history_to = forms.DateField(label=_('To date'), required=False,
        input_formats=['%Y-%m-%d'],
        widget=forms.DateInput(format='%Y-%m-%d', attrs={'type': 'date'}))
    history_check = forms.ChoiceField(label=_('Check'), required=False)
    history_status = forms.ChoiceField(label=_('State'), required=False)

    def __init__(self, *args, zone: str, **kwargs):
        super().__init__(*args, **kwargs)
        from sitewatcher.config import ChecksModel
        from .presentation import check_label, status_label
        self.zone = ZoneInfo(zone)
        self.fields['history_check'].choices = [('', _('All checks'))] + [
            (name, check_label(name)) for name in [*ChecksModel.model_fields, 'rkn_block']]
        self.fields['history_status'].choices = [('', _('All states'))] + [
            (name, status_label(name)) for name in ('OK', 'WARN', 'CRIT', 'UNKNOWN')]

    def clean(self):
        data = super().clean()
        start, end = data.get('history_from'), data.get('history_to')
        if start and end and start > end:
            raise ValidationError(_('The end date must not be before the start date.'))
        try:
            data['since'] = (datetime.combine(start, time.min, self.zone).astimezone(timezone.utc)
                             if start else None)
            data['until'] = ((datetime.combine(end, time.min, self.zone) + timedelta(days=1))
                             .astimezone(timezone.utc) if end else None)
        except (ValueError, OverflowError):
            raise ValidationError(_('Date range is out of bounds.')) from None
        return data
