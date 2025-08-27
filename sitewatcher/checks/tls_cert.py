from __future__ import annotations

import asyncio
import ssl
from datetime import datetime, timezone
from typing import Optional, Tuple

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
            if not cert:
                return CheckOutcome(self.name, Status.UNKNOWN, "no certificate", {})

            not_after = cert.get("notAfter")  # e.g. 'Apr 10 12:00:00 2026 GMT'
            if not not_after:
                return CheckOutcome(self.name, Status.UNKNOWN, "no notAfter in certificate", {})

            expires_at = self._parse_openssl_gmt(not_after)
            if not expires_at:
                return CheckOutcome(self.name, Status.UNKNOWN, "bad notAfter format", {"not_after_raw": not_after})

            now = datetime.now(timezone.utc)
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
                    "days_left": days_left,
                    "expires_at": expires_at.isoformat(),
                    "not_after_raw": not_after,
                },
            )

        # Map common transient issues to UNKNOWN (reachability), and TLS issues to CRIT.
        except asyncio.TimeoutError:
            return CheckOutcome(self.name, Status.UNKNOWN, "connect timeout", {})
        except (ConnectionError, OSError) as e:
            # Port closed, network unreachable, DNS hiccup, etc.
            return CheckOutcome(self.name, Status.UNKNOWN, f"network error: {e.__class__.__name__}", {})
        except ssl.SSLError as e:
            # Handshake/cert validation problems are relevant to this check.
            return CheckOutcome(self.name, Status.CRIT, f"tls handshake error: {e.__class__.__name__}", {})
        except Exception as e:
            # Keep it simple: unexpected failures are UNKNOWN here.
            return CheckOutcome(self.name, Status.UNKNOWN, f"tls error: {e.__class__.__name__}", {})

    # ------------------------------ internals ------------------------------

    async def _fetch_peer_cert(self) -> Optional[dict]:
        """Open a TLS connection (with SNI), return `getpeercert()` dict or None."""
        ssl_ctx = ssl.create_default_context()
        # We only need the handshake to complete. No data transfer required.
        reader = None
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.domain, 443, ssl=ssl_ctx, server_hostname=self.domain),
                timeout=self.timeout_s,
            )
            sslobj: Optional[ssl.SSLObject] = writer.get_extra_info("ssl_object")
            return sslobj.getpeercert() if sslobj else None
        finally:
            if writer is not None:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()

    @staticmethod
    def _parse_openssl_gmt(val: str) -> Optional[datetime]:
        """Parse OpenSSL-style 'notAfter' format like 'Apr 10 12:00:00 2026 GMT' to aware UTC datetime."""
        try:
            dt = datetime.strptime(val, "%b %d %H:%M:%S %Y %Z")
            return dt.replace(tzinfo=timezone.utc)
        except Exception:
            return None
