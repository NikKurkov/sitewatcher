"""Framework-native account views and a protected shell for the owner workspace."""
from django.contrib.auth.views import LoginView, LogoutView, PasswordChangeView
from django.http import JsonResponse
from django.shortcuts import render
from django.urls import reverse_lazy
from django.utils.decorators import method_decorator
from django.views.decorators.http import require_safe

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


@owner_required
@require_safe
def workspace(request):
    return render(request, 'sitewatcher/workspace.html')


@owner_required(api=True)
@require_safe
def status(request):
    return JsonResponse({'owner_id': request.workspace.owner_id})
