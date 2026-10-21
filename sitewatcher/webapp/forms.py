"""Django authentication with one generic rejection for every account state."""
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
