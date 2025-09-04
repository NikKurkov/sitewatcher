# sitewatcher/checks/tls_cert.py
from __future__ import annotations

import asyncio
import logging
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from .base import BaseCheck, CheckOutcome, Status

# Module-level logger for structured events
log = logging.getLogger(__name__)


@dataclass(frozen=True)
class _TlsResult:
    """Container with raw peer certificate and timestamps."""
    cert: dict[str, Any]
    fetched_at: datetime


def _flatten_x509_name(seq: Any) -> list[tuple[str, str]]:
    """
    Flatten OpenSSL subject/issuer representation from ssl.getpeercert() into [(key, value), ...].

    ssl.getpeercert() returns e.g.:
        subject = ((('countryName', 'US'),), (('commonName', 'example.com'),))
        issuer  = ((('organizationName', "Let's Encrypt"),), (('commonName', 'R3'),))
    """
    out: list[tuple[str, str]] = []
    if not isinstance(seq, (list, tuple)):
        return out
    for rdn in seq:
        if not isinstance(rdn, (list, tuple)):
            continue
        for pair in rdn:
            if isinstance(pair, (list, tuple)) and len(pair) >= 2:
                k, v = pair[0], pair[1]
                try:
                    out.append((str(k), str(v)))
                except Exception:
                    # Be tolerant to odd shapes/values
                    continue
    return out


def _extract_san_dns(cert: Optional[dict[str, Any]]) -> list[str]:
    """Extract DNS names from subjectAltName; robust to odd shapes."""
    if not cert:
        return []
    san = cert.get("subjectAltName") or []
    out: list[str] = []
    if isinstance(san, (list, tuple)):
        for entry in san:
            # Expected: ('DNS', 'example.com'), but tolerate weird entries
            if isinstance(entry, (list, tuple)) and len(entry) >= 2:
                kind, value = entry[0], entry[1]
                if isinstance(kind, str) and kind.upper() == "DNS" and isinstance(value, str):
                    out.append(value.strip())
            elif isinstance(entry, str):
                # Rare: SAN as plain string
                out.append(entry.strip())
    return out


def _parse_not_after(cert: dict[str, Any]) -> Optional[datetime]:
    """
    Parse 'notAfter' from ssl.getpeercert() dict into an aware datetime (UTC).

    Common formats observed:
      - 'Jun 10 12:00:00 2025 GMT'         (OpenSSL default)
      - ISO variants with 'Z' or '+00:00'  (rare)
    """
    raw = cert.get("notAfter")
    if not raw:
        return None
    s = str(raw).strip()

    # OpenSSL default: e.g. 'Jun 10 12:00:00 2025 GMT'
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT"):
        try:
            dt = datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            pass

    # ISO-ish fallbacks
    if s.endswith("Z"):
        try:
            return datetime.fromisoformat(s[:-1] + "+00:00")
        except Exception:
            pass
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return None


def _hostname_matches(hostname: str, san_dns: Iterable[str]) -> bool:
    """
    Check whether hostname matches any SAN DNS entry.
    Wildcards: only left-most label ('*.example.com') semantics are supported.
    """
    hn = (hostname or "").strip().lower().rstrip(".")
    for pattern in san_dns:
        p = (pattern or "").lower().rstrip(".")
        if not p:
            continue
        if p == hn:
            return True
        if p.startswith("*."):
            # Match single-label wildcard: sub.example.com matches, example.com doesn't
            suffix = p[1:]  # "*.example.com" -> ".example.com"
            if hn.endswith(suffix) and hn.count(".") >= p.count("."):
                return True
    return False


class TlsCertCheck(BaseCheck):
    """TLS certificate expiry and hostname/SAN validation."""
    name = "tls_cert"

    def __init__(
        self,
        domain: str,
        *,
        warn_days: int = 30,
        port: int = 443,
        timeout_s: float = 10.0,
    ) -> None:
        """
        Args:
            domain: Hostname to connect to.
            warn_days: Warning threshold for days until expiry.
            port: TLS port (default 443).
            timeout_s: Overall connection handshake timeout.
        """
        super().__init__(domain)
        self.warn_days = int(warn_days)
        self.port = int(port)
        self.timeout_s = float(timeout_s)

    async def run(self) -> CheckOutcome:
        """Open a TLS connection, parse the leaf certificate and classify status."""
        # Start event for diagnostics
        log.debug(
            "tls_cert.start",
            extra={
                "event": "tls_cert.start",
                "domain": self.domain,
                "port": self.port,
                "timeout_s": self.timeout_s,
                "warn_days": self.warn_days,
            },
        )
        try:
            res = await asyncio.wait_for(
                self._fetch_peer_cert(self.domain, self.port),
                timeout=self.timeout_s,
            )
        except asyncio.TimeoutError:
            log.warning(
                "tls_cert.timeout",
                extra={
                    "event": "tls_cert.timeout",
                    "domain": self.domain,
                    "port": self.port,
                    "timeout_s": self.timeout_s,
                },
            )
            return CheckOutcome(self.name, Status.UNKNOWN, "tls timeout", {"timeout_s": self.timeout_s})
        except ssl.SSLError as e:
            # SSL-level failures (handshake issues, protocol mismatch, etc.)
            log.error(
                "tls_cert.ssl_error",
                extra={
                    "event": "tls_cert.ssl_error",
                    "domain": self.domain,
                    "port": self.port,
                    "error": f"{e.__class__.__name__}: {e}",
                },
            )
            return CheckOutcome(self.name, Status.UNKNOWN, f"tls error: {e.__class__.__name__}: {e}", {})
        except OSError as e:
            # DNS/socket-level failures
            log.error(
                "tls_cert.socket_error",
                extra={
                    "event": "tls_cert.socket_error",
                    "domain": self.domain,
                    "port": self.port,
                    "error": f"{e.__class__.__name__}: {e}",
                },
            )
            return CheckOutcome(self.name, Status.UNKNOWN, f"socket error: {e.__class__.__name__}: {e}", {})
        except Exception as e:
            # Defensive default
            log.exception(
                "tls_cert.unexpected_error",
                extra={
                    "event": "tls_cert.unexpected_error",
                    "domain": self.domain,
                    "port": self.port,
                },
            )
            return CheckOutcome(self.name, Status.UNKNOWN, f"tls error: {e.__class__.__name__}: {e}", {})

        cert = res.cert or {}
        not_after = _parse_not_after(cert)
        if not not_after:
            log.warning(
                "tls_cert.no_not_after",
                extra={
                    "event": "tls_cert.no_not_after",
                    "domain": self.domain,
                    "port": self.port,
                    "subject": cert.get("subject"),
                },
            )
            return CheckOutcome(
                self.name,
                Status.UNKNOWN,
                "no notAfter in certificate",
                {"subject": cert.get("subject")},
            )

        now = datetime.now(timezone.utc)
        days_left = int((not_after - now).total_seconds() // 86400)

        # Expiry classification
        if days_left < 0:
            status = Status.CRIT
            msg_exp = f"expired {-days_left}d ago ({not_after.date()} UTC)"
        elif days_left <= 3:
            status = Status.CRIT
            msg_exp = f"expires in {days_left}d ({not_after.date()} UTC)"
        elif days_left <= self.warn_days:
            status = Status.WARN
            msg_exp = f"expires in {days_left}d ({not_after.date()} UTC)"
        else:
            status = Status.OK
            msg_exp = f"expires in {days_left}d ({not_after.date()} UTC)"

        # Hostname vs SAN validation
        san_dns = _extract_san_dns(cert)
        host_matches = _hostname_matches(self.domain, san_dns) if san_dns else False
        if san_dns and not host_matches:
            # Don't escalate to CRIT by default (endpoints may terminate for other hostnames);
            # but still surface a WARN.
            log.warning(
                "tls_cert.hostname_mismatch",
                extra={
                    "event": "tls_cert.hostname_mismatch",
                    "domain": self.domain,
                    "port": self.port,
                    "san_count": len(san_dns),
                    "example_san": san_dns[0] if san_dns else None,
                },
            )
            status = Status.WARN if status == Status.OK else status

        # Subject CN (robust)
        subject_pairs = _flatten_x509_name(cert.get("subject"))
        common_name = next((v for k, v in subject_pairs if k in ("commonName", "CN")), None)

        # Human-friendly message
        details = [msg_exp]
        if san_dns:
            details.append("hostname match" if host_matches else "hostname mismatch")
        else:
            details.append("no SAN")
        msg = "; ".join(details)

        metrics = {
            "not_after_raw": cert.get("notAfter"),
            "expires_at": not_after.isoformat(),
            "days_left": days_left,
            "issuer": cert.get("issuer"),
            "subject": cert.get("subject"),
            "san": cert.get("subjectAltName"),
            "san_dns": san_dns,
            "san_present": bool(san_dns),
            "host_matches": host_matches,
            "common_name": common_name,
            "port": self.port,
            "fetched_at": res.fetched_at.isoformat(),
        }

        # Final event
        log.info(
            "tls_cert.done",
            extra={
                "event": "tls_cert.done",
                "domain": self.domain,
                "port": self.port,
                "status": status.name,
                "days_left": days_left,
                "expires_at": not_after.date().isoformat(),
                "san_present": bool(san_dns),
                "host_matches": host_matches,
                "common_name": common_name,
            },
        )

        return CheckOutcome(self.name, status, msg, metrics)

    # ------------------------------- IO helpers -------------------------------

    async def _fetch_peer_cert(self, host: str, port: int) -> _TlsResult:
        """
        Open a TLS connection to host:port and return the peer certificate dict.

        We request SNI using server_hostname=host. We set check_hostname=False in the
        SSL context to always obtain the certificate even if it doesn't match.
        """
        # Create a standard client context but do not enforce host verification here.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        # Verify certificates against system CAs (validates the chain), but hostname
        # mismatch will not prevent retrieval.
        ctx.verify_mode = ssl.CERT_REQUIRED

        reader: asyncio.StreamReader
        writer: asyncio.StreamWriter
        reader, writer = await asyncio.open_connection(
            host=host,
            port=port,
            ssl=ctx,
            server_hostname=host,
        )
        try:
            # StreamWriter.get_extra_info proxies transport.get_extra_info(...)
            ssl_obj = None
            try:
                ssl_obj = writer.get_extra_info("ssl_object")  # type: ignore[attr-defined]
            except Exception:
                ssl_obj = None
            if ssl_obj is None:
                # Fallback: try reader transport
                try:
                    ssl_obj = getattr(getattr(reader, "_transport", None), "get_extra_info", lambda *_: None)("ssl_object")  # type: ignore[attr-defined]
                except Exception:
                    ssl_obj = None

            cert: dict[str, Any] = ssl_obj.getpeercert() if ssl_obj is not None else {}
            res = _TlsResult(cert=cert or {}, fetched_at=datetime.now(timezone.utc))
            log.debug(
                "tls_cert.peer_cert_fetched",
                extra={
                    "event": "tls_cert.peer_cert_fetched",
                    "domain": host,
                    "port": port,
                    "has_cert": bool(cert),
                    "fetched_at": res.fetched_at.isoformat(),
                },
            )
            return res
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except asyncio.CancelledError:
                # allow clean task cancellation during shutdown
                pass
            except Exception:
                pass
