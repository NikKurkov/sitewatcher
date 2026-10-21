class SecurityHeadersMiddleware:
    """Apply a local-assets-only policy to successful and error responses alike."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response['Cache-Control'] = 'no-store'
        response['Content-Security-Policy'] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; object-src 'none'; base-uri 'self'; "
            "frame-ancestors 'none'; form-action 'self'"
        )
        return response


class ManagementBodyMiddleware:
    """Bound native monitoring forms before CSRF's multipart parser consumes uploads."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        from django.core.exceptions import RequestDataTooBig
        from django.http import HttpResponse
        from .forms import parse_management_form

        if request.method == 'POST' and request.path in {
            '/domains/new', '/domains/edit', '/domains/add', '/domains/save',
            '/domains/delete', '/domains/pause', '/domains/resume', '/domains/reset',
            '/domains/check', '/workspace', '/settings', '/alerts', '/import',
        }:
            try:
                length = request.META.get('CONTENT_LENGTH', '')
                if not length.isascii() or not length.isdigit():
                    raise ValueError('Invalid length')
                if int(length) > 1024 * 1024:
                    return HttpResponse('Form too large', status=413)
                body = request.body
                if len(body) > 1024 * 1024:
                    return HttpResponse('Form too large', status=413)
                request.management_form = parse_management_form(
                    request.META.get('CONTENT_TYPE', ''), body,
                )
            except RequestDataTooBig:
                return HttpResponse('Form too large', status=413)
            except (ValueError, UnicodeError, RecursionError):
                return HttpResponse('Invalid request', status=400)
        return self.get_response(request)
