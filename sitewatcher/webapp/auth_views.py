"""Framework-native owner account views."""
from django.contrib.auth.views import LoginView, LogoutView, PasswordChangeView
from django.urls import reverse_lazy
from django.utils.decorators import method_decorator

from .accounts import owner_required
from .forms import OwnerAuthenticationForm


class OwnerLoginView(LoginView):
    template_name = 'sitewatcher/login.html'
    authentication_form = OwnerAuthenticationForm


class OwnerLogoutView(LogoutView):
    next_page = reverse_lazy('login')


@method_decorator(owner_required, name='dispatch')
class OwnerPasswordChangeView(PasswordChangeView):
    template_name = 'sitewatcher/password.html'
    success_url = reverse_lazy('workspace')
