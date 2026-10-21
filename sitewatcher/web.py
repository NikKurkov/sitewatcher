"""Loopback-only monitoring dashboard and owner-scoped management forms."""
from __future__ import annotations

import asyncio
from email import policy
from email.parser import BytesParser
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
import json
import secrets
from threading import Lock
from urllib.parse import parse_qs, urlencode, urlsplit

from . import storage
from .config import AppConfig
from .dispatcher import Dispatcher

_VIEW_STATUSES = {'all', 'problems', 'ok', 'warn', 'crit', 'unknown', 'paused', 'stale'}
_THEMES = {'light', 'dark'}
_PAGES = {'/domains/new': 'add', '/domains/edit': 'edit', '/domains/delete': 'delete',
          '/domains/history': 'history', '/workspace': 'workspace', '/import': 'import'}
_MAX_FORM_BYTES = 1024 * 1024
_CSP = ("default-src 'none'; style-src 'self'; form-action 'self'; "
        "script-src 'self'; base-uri 'none'; frame-ancestors 'none'")


def _parse_form(content_type: str, body: bytes) -> dict[str, str]:
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


async def _check_domains(cfg: AppConfig, owner_id: int, names: list[str]) -> None:
    """Use the existing probe path; the web process never sends Telegram messages."""
    async with Dispatcher(cfg) as dispatcher:
        for name in names:
            if not storage.domain_exists(owner_id, name):
                continue
            async with asyncio.timeout(cfg.scheduler.domain_timeout_s or 120):
                results = await dispatcher.run_for(owner_id, name, use_cache=False)
            storage.save_histories(owner_id, name, results, create_missing=False)


def create_server(cfg: AppConfig, owner_id: int, *, port: int = 8080,
                  read_only: bool = False) -> ThreadingHTTPServer:
    """Legacy test hook only; production run_web uses authenticated Django ASGI."""
    if type(owner_id) is not int or owner_id <= 0:
        raise ValueError('A positive integer owner is required')
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError('Port must be an integer between 0 and 65535')
    csrf_token = secrets.token_urlsafe(32) if not read_only else None
    check_lock = Lock()

    class Handler(BaseHTTPRequestHandler):
        server_version = 'SiteWatcher'
        sys_version = ''

        def log_message(self, format, *args):
            # Access paths and queries may contain private monitoring information.
            pass

        def _send(self, code, body, content_type='text/plain; charset=utf-8', *, headers=None):
            self.send_response(code)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Security-Policy', _CSP)
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header('Referrer-Policy', 'same-origin')
            if code == 405:
                self.send_header('Allow', 'GET, HEAD' if read_only else 'GET, HEAD, POST')
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            if self.command != 'HEAD':
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        def send_error(self, code, message=None, explain=None):
            self.close_connection = True
            self._send(code, b'Invalid request\n')

        def _trusted_request(self):
            hosts = self.headers.get_all('Host', [])
            expected = {f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'}
            if self.server.server_port == 80:
                expected.update({'127.0.0.1', 'localhost'})
            origins = self.headers.get_all('Origin', [])
            if (len(hosts) != 1 or hosts[0].lower() not in expected
                    or origins and (len(origins) != 1 or origins[0] != f'http://{hosts[0].lower()}')):
                self._send(403, b'Forbidden\n')
                return False
            return True

        def _route(self):
            parsed = urlsplit(self.path)
            if parsed.scheme or parsed.netloc or parsed.fragment:
                raise ValueError('Invalid path')
            query = parse_qs(parsed.query, max_num_fields=20, keep_blank_values=True)
            if any(len(value) != 1 for value in query.values()):
                raise ValueError('Duplicate query field')
            return parsed.path, {key: value[0] for key, value in query.items()}

        def _theme(self):
            try:
                cookie = SimpleCookie(self.headers.get('Cookie', ''))
                value = cookie['sitewatcher_theme'].value if 'sitewatcher_theme' in cookie else 'light'
                return value if value in _THEMES else 'light'
            except CookieError:
                return 'light'

        def _redirect(self, notice='', *, location=None, headers=None):
            target = location or '/?' + urlencode({'notice': notice})
            self._send(303, b'', headers={'Location': target, **(headers or {})})

        def _page(self, view, domain='', *, error='', values=None, code=200):
            from .management import render_management
            from .web_actions import history_context, settings_context

            if view in {'add', 'edit'}:
                context = settings_context(cfg, owner_id, domain if view == 'edit' else None)
            elif view == 'history':
                context = {'domain': domain, 'rows': history_context(owner_id, domain)}
            elif view == 'workspace':
                context = {'alerts_enabled': storage.is_user_alerts_enabled(owner_id)}
            else:
                context = {'domain': domain}
            if values is not None:
                context['values'] = {**context.get('values', {}), **values, 'proxy': '', 'csrf_token': ''}
                context['domain'] = values.get('domain', domain)
                if 'revision' in values:
                    context['revision'] = values['revision']
                if view == 'import':
                    context['mode'] = values.get('mode', 'merge')
            page = render_management(view, context, csrf_token, error=error, theme=self._theme())
            self._send(code, page.encode('utf-8'), 'text/html; charset=utf-8')

        def _read(self):
            if not self._trusted_request():
                return
            try:
                path, query = self._route()
                status = query.get('status', 'all')
                if status not in _VIEW_STATUSES:
                    raise ValueError('Invalid status')
                if path == '/theme':
                    theme = query.get('mode', 'light')
                    target = query.get('next', '/')
                    parsed = urlsplit(target)
                    if (theme not in _THEMES or parsed.scheme or parsed.netloc or parsed.fragment
                            or parsed.path not in {'/', *_PAGES}
                            or any(ord(char) < 32 or char == '\\' for char in target)):
                        raise ValueError('Invalid theme')
                    self._redirect(location=target, headers={'Set-Cookie':
                        f'sitewatcher_theme={theme}; Path=/; Max-Age=31536000; SameSite=Strict'})
                    return
                if path in _PAGES and not read_only:
                    domain = query.get('domain', '')
                    if path.startswith('/domains/') and path != '/domains/new':
                        from .utils.domains import normalize_domain
                        domain = normalize_domain(domain)
                        if not domain or not storage.domain_exists(owner_id, domain):
                            self._send(404, b'Domain not found\n')
                            return
                    self._page(_PAGES[path], domain)
                    return
                if path == '/export.csv' and not read_only:
                    from .utils.domains_csv import export_domains_csv
                    self._send(200, export_domains_csv(owner_id), 'text/csv; charset=utf-8',
                               headers={'Content-Disposition': 'attachment; filename="sitewatcher-domains.csv"'})
                    return
                if path in {'/style.css', '/theme.js'}:
                    asset, mime = ('dashboard.css', 'text/css') if path == '/style.css' else (
                        'theme.js', 'text/javascript')
                    self._send(200, files('sitewatcher').joinpath('data/' + asset).read_bytes(),
                               mime + '; charset=utf-8')
                    return
                if path not in {'/', '/api/status', '/healthz'}:
                    self._send(404, b'Not found\n')
                    return
                from .reporting import build_snapshot
                snapshot = build_snapshot(cfg, owner_id)
                if path == '/api/status':
                    self._send(200, json.dumps(snapshot, ensure_ascii=False).encode('utf-8'),
                               'application/json; charset=utf-8')
                elif path == '/healthz':
                    self._send(200, b'{"ok":true}', 'application/json; charset=utf-8')
                else:
                    from .dashboard import render_dashboard
                    page = render_dashboard(snapshot, query=query.get('q', ''), status=status,
                                            auto_refresh=query.get('refresh', 'on') != 'off',
                                            csrf_token=csrf_token, notice=query.get('notice', ''),
                                            theme=self._theme())
                    self._send(200, page.encode('utf-8'), 'text/html; charset=utf-8')
            except ValueError:
                self._send(400, b'Invalid request\n')
            except Exception:
                self._send(503, b'Service unavailable\n')

        do_GET = _read
        do_HEAD = _read

        def do_POST(self):
            if not self._trusted_request():
                return
            if read_only:
                self._send(405, b'Method not allowed\n')
                return
            if len(self.headers.get_all('Origin', [])) != 1:
                self._send(403, b'Forbidden\n')
                return
            form = {}
            path = ''
            try:
                path, query = self._route()
                if query or self.headers.get_all('Transfer-Encoding'):
                    raise ValueError('Invalid request')
                lengths = self.headers.get_all('Content-Length', [])
                if len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit():
                    raise ValueError('Invalid length')
                length = int(lengths[0])
                if length > _MAX_FORM_BYTES:
                    self._send(413, b'Form too large\n')
                    return
                types = self.headers.get_all('Content-Type', [])
                if len(types) != 1:
                    raise ValueError('Invalid content type')
                self.connection.settimeout(10)
                body = self.rfile.read(length)
                if len(body) != length:
                    raise ValueError('Incomplete request')
                form = _parse_form(types[0], body)
                provided = form.pop('csrf_token', '')
                if not secrets.compare_digest(provided.encode('utf-8'), csrf_token.encode('ascii')):
                    self._send(403, b'Forbidden\n')
                    return
            except (ValueError, UnicodeError, RecursionError):
                self._send(400, b'Invalid request\n')
                return
            except TimeoutError:
                self._send(408, b'Request timed out\n')
                return
            try:
                self._act(path, form)
            except ValueError as error:
                # Action helpers only expose static or sanitized validation diagnostics.
                view = {'/domains/add': 'add', '/domains/save': 'edit', '/import': 'import'}.get(path)
                if view:
                    try:
                        self._page(view, form.get('domain', ''), error=str(error), values=form, code=400)
                    except Exception:
                        self._send(400, b'Invalid settings; reload the form\n')
                else:
                    self._send(400, b'Invalid action; reload the page\n')
            except TimeoutError:
                self._send(504, b'Checks timed out; inspect saved results before retrying\n')
            except Exception:
                self._send(503, b'Operation failed; inspect saved state before retrying\n')

        def _act(self, path, form):
            from .web_actions import LIST_FIELDS, NUMERIC_FIELDS, act_on_domain, save_domain
            from .config import ChecksModel

            allowed = {'domain'}
            if path in {'/domains/add', '/domains/save'}:
                allowed.update((*NUMERIC_FIELDS, *LIST_FIELDS, 'revision', 'proxy_mode', 'proxy'))
                allowed.update(f'check.{name}' for name in ChecksModel.model_fields)
            elif path == '/domains/delete':
                allowed.add('confirm')
            elif path == '/alerts':
                allowed = {'enabled'}
            elif path == '/import':
                allowed = {'csv_file', 'csv_text', 'mode'}
            if set(form) - allowed:
                raise ValueError('Unexpected form fields')
            if path in {'/domains/add', '/domains/save'}:
                save_domain(cfg, owner_id, form, create=path == '/domains/add')
                self._redirect('Domain saved')
            elif path in {'/domains/pause', '/domains/resume', '/domains/reset', '/domains/delete'}:
                domain = form.get('domain', '')
                if path == '/domains/delete' and form.get('confirm') != domain:
                    raise ValueError('Confirm deletion first')
                act_on_domain(cfg, owner_id, path.rsplit('/', 1)[-1], domain)
                self._redirect('Domain updated')
            elif path == '/domains/check':
                domain = form.get('domain', '')
                if domain != '*' and not storage.domain_exists(owner_id, domain):
                    self._send(404, b'Domain not found\n')
                    return
                names = storage.list_domains(owner_id) if domain == '*' else [domain]
                if not names:
                    raise ValueError('No domains to check')
                if not check_lock.acquire(blocking=False):
                    self._send(409, b'Another manual check is running; reload the dashboard shortly\n')
                    return
                try:
                    asyncio.run(_check_domains(cfg, owner_id, names))
                finally:
                    check_lock.release()
                self._redirect('Checks completed; results saved')
            elif path == '/alerts':
                if form.get('enabled') not in {'on', 'off'}:
                    raise ValueError('Invalid alert setting')
                storage.set_user_alerts_enabled(owner_id, form['enabled'] == 'on')
                self._redirect('Notification preference saved')
            elif path == '/import':
                from .utils.domains_csv import import_domains_csv
                if form.get('csv_file') and form.get('csv_text'):
                    raise ValueError('Choose a file or pasted CSV, not both')
                text = form.get('csv_file') or form.get('csv_text') or ''
                report = import_domains_csv(owner_id, text.encode('utf-8'),
                                            mode=form.get('mode', 'merge'), cfg=cfg)
                notice = f'CSV: {report.added} added, {report.updated} updated, {report.skipped} skipped'
                if report.errors:
                    self._page('import', error=notice + '. Some rows were not imported; check the CSV.',
                               values=form, code=400)
                else:
                    self._redirect(notice)
            else:
                self._send(404, b'Not found\n')

        def _unsupported(self):
            if self._trusted_request():
                self._send(405, b'Method not allowed\n')

        def __getattr__(self, name):
            if name.startswith('do_'):
                return self._unsupported
            raise AttributeError(name)

    return ThreadingHTTPServer(('127.0.0.1', port), Handler)


def run_web(cfg: AppConfig, owner_id: int | None = None, port: int = 8080, *,
            read_only: bool = False) -> None:
    """Production web entry: legacy create_server remains test-only until Task 10 removal."""
    from .webapp.bootstrap import run_asgi

    run_asgi(cfg, port=port, read_only=read_only, owner_id=owner_id)
