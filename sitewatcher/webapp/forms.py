"""Django authentication with one generic rejection for every account state."""
from email import policy
from email.parser import BytesParser
from urllib.parse import parse_qs

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
