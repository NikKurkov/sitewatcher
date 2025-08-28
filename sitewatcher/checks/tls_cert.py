from __future__ import annotations

import asyncio
import ssl
import contextlib
import traceback
import datetime as dt
from typing import Optional

from .base import BaseCheck, CheckOutcome, Status

DEFAULT_TLS_TIMEOUT_S = 10.0  # Single source of truth for this check


class TlsCertCheck(BaseCheck):
    """Fetch peer certificate via TLS and report time-to-expiry."""

    name = "tls_cert"

    def __init__(self, domain: str, warn_days: int = 14, timeout_s: float = DEFAULT_TLS_TIMEOUT_S) -> None:
        super().__init__(domain)
        self.warn_days = int(warn_days)
        self.timeout_s = float(timeout_s)

    async def run(self) -> CheckOutcome:
        try:
            cert = await self._fetch_peer_cert()
            if not cert or not isinstance(cert, dict):
                return CheckOutcome(self.name, Status.UNKNOWN, "no certificate", {
                    "module": __name__,
                    "file": __file__,
                    "cert_type": type(cert).__name__ if cert is not None else None,
                })

            # Например: 'Apr 10 12:00:00 2026 GMT' или 'Jun  9 12:00:00 2026 GMT'
            not_after = cert.get("notAfter")
            if not not_after:
                return CheckOutcome(self.name, Status.UNKNOWN, "no notAfter in certificate", {
                    "module": __name__,
                    "file": __file__,
                    "cert_keys": list(cert.keys()),
                })

            expires_at = self._parse_openssl_gmt(not_after)
            if not expires_at:
                return CheckOutcome(self.name, Status.UNKNOWN, "bad notAfter format", {
                    "module": __name__,
                    "file": __file__,
                    "not_after_raw": not_after,
                })

            now = dt.datetime.now(dt.timezone.utc)
            days_left = int((expires_at - now).total_seconds() // 86400)
            date_str = expires_at.strftime("%Y-%m-%d")

            if days_left < 0:
                status = Status.CRIT
                msg = f"expired {-days_left}d ago ({date_str} UTC)"
            elif days_left <= self.warn_days:
                status = Status.WARN
                msg = f"expires in {days_left}d ({date_str} UTC)"
            else:
                status = Status.OK
                msg = f"expires in {days_left}d ({date_str} UTC)"

            return CheckOutcome(
                check=self.name,
                status=status,
                message=msg,
                metrics={
                    "expires_at": expires_at.isoformat(),
                    "days_left": days_left,
                    "not_after_raw": not_after,
                },
            )

        except asyncio.TimeoutError:
            return CheckOutcome(self.name, Status.UNKNOWN, "connect timeout", {
                "module": __name__, "file": __file__
            })
        except (ConnectionError, OSError) as e:
            # Port closed, network unreachable, DNS errors, etc.
            return CheckOutcome(self.name, Status.UNKNOWN, f"network error: {type(e).__name__}: {e}", {
                "module": __name__, "file": __file__
            })
        except ssl.SSLError as e:
            # Handshake/cert validation problems
            return CheckOutcome(self.name, Status.CRIT, f"tls handshake error: {type(e).__name__}: {e}", {
                "module": __name__,
                "file": __file__,
                "trace": "\n".join(traceback.format_exc().splitlines()[-8:]),
            })
        except Exception as e:
            # Любые неожиданные ошибки — как UNKNOWN, плюс подробности для отладки
            return CheckOutcome(self.name, Status.UNKNOWN, f"tls error: {type(e).__name__}: {e}", {
                "module": __name__,
                "file": __file__,
                "trace": "\n".join(traceback.format_exc().splitlines()[-8:]),
            })

    # ------------------------------ internals ------------------------------

    async def _fetch_peer_cert(self) -> Optional[dict]:
        """
        Open a TLS connection (with SNI), return getpeercert() dict or None.

        Нормируем поведение разных платформ:
        - пробуем get_extra_info('peercert') (может вернуть dict или callbable),
        - фоллбэк через ssl_object.getpeercert().
        """
        ssl_ctx = ssl.create_default_context()  # CERT_REQUIRED + hostname check
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.domain, 443, ssl=ssl_ctx, server_hostname=self.domain),
                timeout=self.timeout_s,
            )

            cert = None

            info = writer.get_extra_info("peercert")
            if callable(info):
                with contextlib.suppress(Exception):
                    cert = info()
            elif info:
                cert = info

            if not cert:
                sslobj = writer.get_extra_info("ssl_object")
                if sslobj:
                    with contextlib.suppress(Exception):
                        cert = sslobj.getpeercert()

            return cert
        finally:
            if writer is not None:
                with contextlib.suppress(Exception):
                    writer.close()
                wc = getattr(writer, "wait_closed", None)
                if callable(wc):
                    with contextlib.suppress(Exception):
                        await wc()

    @staticmethod
    def _parse_openssl_gmt(val: str) -> Optional[dt.datetime]:
        """Parse OpenSSL 'notAfter' like 'Jun  9 12:00:00 2026 GMT' → aware UTC datetime."""
        try:
            # %d «пережёвывает» ведущий пробел для дней 1–9 (двойной пробел после месяца — ок)
            naive = dt.datetime.strptime(val, "%b %d %H:%M:%S %Y %Z")
            return naive.replace(tzinfo=dt.timezone.utc)
        except Exception:
            return None
