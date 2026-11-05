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

        status_page_form = request.path.startswith('/settings/status-pages')
        if request.method == 'POST' and (status_page_form or request.path in {
            '/domains/new', '/domains/edit', '/domains/add', '/domains/save',
            '/domains/delete', '/domains/pause', '/domains/resume', '/domains/reset',
            '/domains/check', '/domains/favorite', '/domains/reorder', '/domains/route', '/workspace', '/settings', '/settings/public', '/settings/groups', '/alerts', '/import',
        }):
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
                    max_fields=1000 if status_page_form else 40,
                )
            except RequestDataTooBig:
                return HttpResponse('Form too large', status=413)
            except (ValueError, UnicodeError, RecursionError):
                return HttpResponse('Invalid request', status=400)
        return self.get_response(request)


class PublicStatusMiddleware:
    """Handle bearer URLs before sessions, CSRF and Django exception/path logging.

    Retain the original path only long enough to extract the capability, then redact
    request metadata before any application work. This deliberately bypasses owner
    middleware: public GET/HEAD must never create sessions or mutate monitoring data.
    Bootstrap disables Uvicorn access logs; an upstream proxy needs the same policy.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        import re
        from .public import RESERVED_PUBLIC_SLUGS
        alias = re.fullmatch(r'/([a-z][a-z0-9_-]{0,63})(?:/(data|activity)?)?', request.path_info)
        alias = alias if alias and alias[1] not in RESERVED_PUBLIC_SLUGS else None
        if not request.path_info.startswith('/status/') and not alias:
            return self.get_response(request)
        from django.core.exceptions import DisallowedHost, TooManyFieldsSent
        from django.http import HttpResponse, QueryDict
        from .public import status

        query_string = request.META.get('QUERY_STRING', '')
        match = re.fullmatch(r'/status/([A-Za-z0-9_-]{43})/(data|activity)?', request.path_info)
        request.public_alias = alias is not None
        request.path = request.path_info = '/status/[redacted]/'
        for key in ('PATH_INFO', 'RAW_URI', 'REQUEST_URI', 'QUERY_STRING', 'HTTP_REFERER'):
            request.META.pop(key, None)
        # ASGI exception reporters can include the raw scope; never retain bearer paths there.
        if hasattr(request, 'scope'):
            request.scope = {**request.scope, 'path': request.path,
                             'raw_path': request.path.encode(), 'query_string': b''}
        try:
            request.get_host()  # The owner CommonMiddleware is intentionally bypassed.
            request.GET = QueryDict(query_string, encoding=request.encoding)
            if alias:
                response = status(request, public_slug=alias[1], data=alias[2] == 'data',
                                  activity=alias[2] == 'activity')
            else:
                response = status(request, match[1], data=match[2] == 'data',
                                  activity=match[2] == 'activity') if match else HttpResponse(
                    'Not found', status=404)
        except DisallowedHost:
            response = HttpResponse('Invalid host', status=400)
        except TooManyFieldsSent:
            response = HttpResponse('Not found', status=404)
        except Exception as error:
            import logging
            logging.getLogger(__name__).warning('Public status unavailable (%s)', type(error).__name__)
            # No traceback or exception text: dependencies can include a bearer URL in errors.
            response = HttpResponse('Public status temporarily unavailable', status=503)
        response['Cache-Control'] = 'no-store'
        response['Referrer-Policy'] = 'no-referrer'
        response['X-Robots-Tag'] = 'noindex, nofollow, noarchive'
        response['X-Frame-Options'] = 'DENY'
        return response


class WorkspaceLanguageMiddleware:
    """Activate an explicit account preference; browser headers never change the default."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        from django.conf import settings
        from django.utils import translation
        from django.utils.cache import patch_vary_headers
        from .models import Workspace

        language = request.COOKIES.get(settings.LANGUAGE_COOKIE_NAME, 'en')
        if request.user.is_authenticated:
            language = Workspace.objects.filter(user_id=request.user.pk).values_list(
                'language', flat=True).first() or 'en'
        if language not in {'en', 'ru'}:
            language = 'en'
        request.LANGUAGE_CODE = language
        with translation.override(language):
            response = self.get_response(request)
        response['Content-Language'] = language
        patch_vary_headers(response, ('Cookie',))
        return response
