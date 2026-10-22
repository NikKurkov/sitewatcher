"""Django authentication with one generic rejection for every account state."""
from email import policy
from email.parser import BytesParser
from urllib.parse import parse_qs
from zoneinfo import available_timezones

from django import forms
from django.contrib.auth.forms import AuthenticationForm
from django.core.exceptions import ValidationError

from .accounts import AUTH_ERROR
from .models import Workspace


class OwnerAuthenticationForm(AuthenticationForm):
    error_messages = {'invalid_login': AUTH_ERROR, 'inactive': AUTH_ERROR}

    def confirm_login_allowed(self, user):
        super().confirm_login_allowed(user)
        if not Workspace.objects.filter(user=user).exists():
            raise ValidationError(AUTH_ERROR, code='invalid_login')


def parse_management_form(content_type: str, body: bytes) -> dict[str, str]:
    """Decode a bounded native form; ambiguous fields are never silently accepted."""
    if content_type.split(';', 1)[0].strip().lower() == 'application/x-www-form-urlencoded':
        values = parse_qs(body.decode('utf-8'), keep_blank_values=True, max_num_fields=40,
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
        if (not name or name in values or len(values) >= 40 or part.is_multipart()
                or part.get_content_disposition() != 'form-data' or part.defects):
            raise ValueError('Invalid form field')
        values[name] = (part.get_payload(decode=True) or b'').decode('utf-8-sig')
    return values


class WorkspacePreferencesForm(forms.Form):
    """Validate optional patches so a timezone save never resets Telegram settings."""
    timezone = forms.CharField(label='Timezone', max_length=64, required=False,
                               help_text='Dates and times use your selected timezone.',
                               widget=forms.Select(choices=[
                                   (zone, zone.replace('_', ' ').replace('/', ' / '))
                                   for zone in sorted(available_timezones())
                                   if not zone.startswith(('posix/', 'right/'))]))
    enabled = forms.ChoiceField(label='Telegram notifications', required=False,
                               choices=[('on', 'Enabled'), ('off', 'Disabled')])
    chat_id = forms.IntegerField(label='Chat ID', required=False,
                                 min_value=-(2**63) + 1, max_value=2**63 - 1,
                                 widget=forms.TextInput(attrs={'inputmode': 'numeric'}))
    bot_token = forms.CharField(label='New bot token', required=False, max_length=224,
                                widget=forms.PasswordInput(render_value=False, attrs={
                                    'autocomplete': 'new-password', 'spellcheck': 'false',
                                }))

    def clean_timezone(self):
        from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
        value = self.cleaned_data['timezone']
        if 'timezone' in self.data:
            try:
                ZoneInfo(value)
            except (ValueError, ZoneInfoNotFoundError):
                raise ValidationError('Choose a valid timezone from the list.') from None
        return value

    def clean_enabled(self):
        value = self.cleaned_data['enabled']
        if 'enabled' in self.data and not value:
            raise ValidationError('Choose Enabled or Disabled.')
        return value

    def clean_chat_id(self):
        value = self.cleaned_data['chat_id']
        if value == 0:
            raise ValidationError('Enter a nonzero numeric Telegram chat ID.')
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
