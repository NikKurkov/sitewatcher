"""Loopback-only, read-only HTTP view of saved monitoring results."""
from __future__ import annotations

import json
import signal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from urllib.parse import parse_qs, urlsplit

from .config import AppConfig

_VIEW_STATUSES = {'all', 'problems', 'ok', 'warn', 'crit', 'unknown', 'paused', 'stale'}
_CSP = ("default-src 'none'; style-src 'self'; form-action 'self'; "
        "base-uri 'none'; frame-ancestors 'none'")


def create_server(cfg: AppConfig, owner_id: int, *, port: int = 8080) -> ThreadingHTTPServer:
    """Bind IPv4 loopback; the owner is fixed for this server's entire lifetime."""
    if type(owner_id) is not int or owner_id <= 0:
        raise ValueError('A positive integer owner is required')
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError('Port must be an integer between 0 and 65535')

    class Handler(BaseHTTPRequestHandler):
        server_version = 'SiteWatcher'
        sys_version = ''

        def log_message(self, format, *args):
            # Access paths and queries may include private monitoring information.
            pass

        def _send(self, code: int, body: bytes, content_type: str = 'text/plain; charset=utf-8'):
            self.send_response(code)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Security-Policy', _CSP)
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'DENY')
            if code == 405:
                self.send_header('Allow', 'GET, HEAD')
            self.end_headers()
            if self.command != 'HEAD':
                self.wfile.write(body)

        def send_error(self, code, message=None, explain=None):
            # The stdlib parser can reject a request before dispatching a route.
            self.close_connection = True
            self._send(code, b'Invalid request\n')

        def _trusted_request(self) -> bool:
            hosts = self.headers.get_all('Host', [])
            expected = {f'127.0.0.1:{self.server.server_port}',
                        f'localhost:{self.server.server_port}'}
            if self.server.server_port == 80:
                expected.update({'127.0.0.1', 'localhost'})
            if len(hosts) != 1 or hosts[0].lower() not in expected:
                self._send(403, b'Forbidden\n')
                return False
            origins = self.headers.get_all('Origin', [])
            if origins and (len(origins) != 1 or origins[0] != f'http://{hosts[0].lower()}'):
                self._send(403, b'Forbidden\n')
                return False
            return True

        def _read(self):
            if not self._trusted_request():
                return
            try:
                parsed = urlsplit(self.path)
                query = parse_qs(parsed.query, max_num_fields=20)
                if parsed.scheme or parsed.netloc or parsed.fragment:
                    raise ValueError
            except ValueError:
                self._send(400, b'Invalid request\n')
                return
            if parsed.path not in {'/', '/api/status', '/healthz', '/style.css'}:
                self._send(404, b'Not found\n')
                return
            view_status = query.get('status', ['all'])[0]
            if view_status not in _VIEW_STATUSES:
                self._send(400, b'Invalid status filter\n')
                return
            try:
                if parsed.path == '/style.css':
                    body = files('sitewatcher').joinpath('data/dashboard.css').read_bytes()
                    content_type = 'text/css; charset=utf-8'
                else:
                    # Imports stay local: the standalone server constructor performs no reads.
                    from .reporting import build_snapshot
                    snapshot = build_snapshot(cfg, owner_id)
                    if parsed.path == '/api/status':
                        body = json.dumps(snapshot, ensure_ascii=False).encode('utf-8')
                        content_type = 'application/json; charset=utf-8'
                    elif parsed.path == '/healthz':
                        body = b'{"ok":true}'
                        content_type = 'application/json; charset=utf-8'
                    else:
                        from .dashboard import render_dashboard
                        body = render_dashboard(snapshot, query=query.get('q', [''])[0],
                                                status=view_status,
                                                auto_refresh=query.get('refresh', ['on'])[0] != 'off',
                                                ).encode('utf-8')
                        content_type = 'text/html; charset=utf-8'
            except Exception:
                # No exception text, paths, configuration values or private rows cross HTTP.
                self._send(503, b'Service unavailable\n')
                return
            self._send(200, body, content_type)

        do_GET = _read
        do_HEAD = _read

        def _unsupported(self):
            if self._trusted_request():
                self._send(405, b'Method not allowed\n')

        def __getattr__(self, name):
            # BaseHTTPRequestHandler otherwise returns 501 for arbitrary method tokens.
            if name.startswith('do_'):
                return self._unsupported
            raise AttributeError(name)

    return ThreadingHTTPServer(('127.0.0.1', port), Handler)


def run_web(cfg: AppConfig, owner_id: int, port: int = 8080) -> None:
    """Serve until interrupted and always close the listening socket."""
    server = create_server(cfg, owner_id, port=port)
    previous_handler = signal.signal(signal.SIGTERM, signal.default_int_handler)
    try:
        print(f'http://127.0.0.1:{server.server_port}', flush=True)
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        signal.signal(signal.SIGTERM, previous_handler)
