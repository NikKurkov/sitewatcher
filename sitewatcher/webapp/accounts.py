"""Local-only account administration and request authority boundaries."""
from functools import wraps
import getpass
import secrets
import warnings

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.views import redirect_to_login
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import connection, transaction
from django.http import HttpResponse, JsonResponse
from django.views.decorators.debug import sensitive_variables
from django.utils.translation import gettext_lazy as _

from sitewatcher import storage
from .models import Workspace

AUTH_ERROR = _('Unable to sign in with these credentials.')


def require_workspace(request) -> Workspace:
    """Never accept owner identity from a URL, form, header or legacy Telegram row."""
    if not request.user.is_authenticated:
        raise PermissionDenied('Authentication required')
    try:
        return Workspace.objects.select_related('user').get(user=request.user)
    except Workspace.DoesNotExist:
        raise PermissionDenied('Workspace unavailable') from None


def owner_required(view=None, *, api=False):
    """Guard owner views before they read monitoring data."""
    def decorate(handler):
        @wraps(handler)
        def guarded(request, *args, **kwargs):
            if not request.user.is_authenticated:
                if api:
                    return JsonResponse({'error': 'Authentication required'}, status=401)
                return redirect_to_login(request.get_full_path(), settings.LOGIN_URL)
            try:
                request.workspace = require_workspace(request)
            except PermissionDenied:
                if api:
                    return JsonResponse({'error': 'Workspace unavailable'}, status=403)
                raise
            return handler(request, *args, **kwargs)
        return guarded
    return decorate(view) if view is not None else decorate


def locked_out(request, credentials=None, **kwargs):
    # No username/IP echo, permissive CORS, or submitted credentials in the response.
    return HttpResponse(AUTH_ERROR, status=429, content_type='text/plain; charset=utf-8')


@sensitive_variables('password', 'confirmation')
def _read_password(user):
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            password = getpass.getpass('Password: ')
            confirmation = getpass.getpass('Confirm password: ')
    except getpass.GetPassWarning:
        raise ValueError('Hidden password entry requires a terminal') from None
    if password != confirmation:
        raise ValueError('The password confirmation does not match')
    try:
        validate_password(password, user)
    except ValidationError:
        raise ValueError('The password does not meet the password requirements '
                         '(at least 12 characters; avoid common, numeric or personal values)') from None
    return password


@sensitive_variables('password')
def setup_owner(*, owner_id: int | None = None) -> None:
    """Create the sole local owner; existing histories require explicit --owner selection."""
    if owner_id is not None and not 0 < owner_id < 2**63:
        raise ValueError('Owner ID must be a positive SQLite integer')
    if Workspace.objects.exists():
        raise ValueError('An owner is already configured; use sitewatcher password')
    username = input('Username: ').strip()
    user = get_user_model()(username=username)
    try:
        user.full_clean(exclude=['password'])
    except ValidationError:
        raise ValueError('Username is invalid or already exists') from None
    password = _read_password(user)
    # Fresh setup must not silently select a Telegram user's monitoring history.
    if owner_id is None:
        existing = set(storage.list_users())
        while owner_id is None or owner_id in existing:
            owner_id = secrets.randbelow(2**62 - 1) + 1
    with transaction.atomic():
        if Workspace.objects.exists():
            raise ValueError('An owner is already configured; use sitewatcher password')
        user.set_password(password)
        user.save()
        # The fixed initial PK also makes competing first-setup writes fail closed.
        Workspace.objects.create(pk=1, user=user, owner_id=owner_id)
        # Same transaction/connection as the new account: never leave a partial binding.
        with connection.cursor() as cursor:
            cursor.execute('INSERT INTO users(telegram_id) VALUES (%s) '
                           'ON CONFLICT(telegram_id) DO NOTHING', [owner_id])
    print('Owner configured. Sign in at /login/.')


@sensitive_variables('password')
def reset_password() -> None:
    """Filesystem-admin recovery, independent of browser sessions and login throttling."""
    from axes.utils import reset

    try:
        workspace = Workspace.objects.select_related('user').get()
    except (Workspace.DoesNotExist, Workspace.MultipleObjectsReturned):
        raise ValueError('Exactly one configured owner is required; run sitewatcher setup') from None
    user = workspace.user
    password = _read_password(user)
    with transaction.atomic():
        user.set_password(password)
        user.save(update_fields=['password'])
        reset(username=user.username)
    print('Password updated and login lockout cleared. Sign in again.')
