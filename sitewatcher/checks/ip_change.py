from __future__ import annotations

import asyncio
import json
import logging
import socket
import sqlite3
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, List, Optional, Tuple

from .base import BaseCheck, CheckOutcome, Status
from .. import storage

# Module-level logger for structured events
log = logging.getLogger(__name__)


@dataclass(frozen=True)
class _Row:
    """Cached DNS snapshot row."""
    domain: str
    snapshot_json: str
    fetched_at: datetime


class IpChangeCheck(BaseCheck):
    """Detects IP (A/AAAA) changes for a domain with lightweight local caching."""

    name = "ip_change"

    def __init__(self, domain: str, *, cfg: Any, owner_id: int | None = None) -> None:
        """
        Args:
            domain: Target domain to resolve.
            owner_id: Monitoring owner; 0 isolates ephemeral scans; None retains legacy caching.
            cfg: ip_change config section with fields (optional):
                 - include_ipv6: bool (default False)
                 - refresh_hours: float (default 24)
                 - db_path: path to sqlite file (default storage.DEFAULT_DB)
        """
        super().__init__(domain)
        if owner_id is not None and (type(owner_id) is not int or owner_id < 0):
            raise ValueError("owner_id must be a nonnegative integer or None")
        self._owner_id = owner_id
        self.cfg = cfg
        self._db_path = Path(getattr(cfg, "db_path", None) or storage.DEFAULT_DB)

        # Normalize basic options
        self.cfg.include_ipv6 = bool(getattr(cfg, "include_ipv6", False))
        self.cfg.refresh_hours = float(getattr(cfg, "refresh_hours", 24))

    # ------------------------------------------------------------------ public

    async def run(self) -> CheckOutcome:
        """Resolve current IPs, compare to stored snapshot, and classify."""
        prev = self._db_get()
        now = datetime.now(timezone.utc)

        # Decide whether to refresh the stored snapshot due to TTL
        must_refresh = True
        if prev:
            age_h = (now - prev.fetched_at).total_seconds() / 3600.0
            must_refresh = age_h >= float(self.cfg.refresh_hours)

        log.debug(
            "ipchange.start",
            extra={
                "event": "ipchange.start",
                "domain": self.domain,
                "include_ipv6": bool(self.cfg.include_ipv6),
                "refresh_hours": float(self.cfg.refresh_hours),
                "has_prev": bool(prev),
                "must_refresh": must_refresh,
            },
        )

        # Always resolve fresh IPs; cheap and reliable vs. DNS cache.
        try:
            ips_v4, ips_v6 = await self._resolve_ips()
        except OSError as error:
            log.warning(
                "ipchange.resolve_failed",
                extra={"event": "ipchange.resolve_failed", "domain": self.domain,
                       "error": error.__class__.__name__},
            )
            return CheckOutcome(
                self.name, Status.UNKNOWN, f"DNS lookup failed: {error.__class__.__name__}",
                {"error": error.__class__.__name__, "baseline_preserved": prev is not None},
            )
        log.info(
            "ipchange.resolved",
            extra={
                "event": "ipchange.resolved",
                "domain": self.domain,
                "ips_v4_count": len(ips_v4),
                "ips_v6_count": len(ips_v6),
            },
        )

        # If no records at all — treat as CRIT and persist the snapshot.
        if not ips_v4 and (not self.cfg.include_ipv6 or not ips_v6):
            log.warning("ipchange.no_records", extra={"event": "ipchange.no_records", "domain": self.domain})
            self._maybe_upsert(ips_v4, ips_v6, now, prev, must_refresh)
            return CheckOutcome(
                self.name,
                Status.CRIT,
                "no A/AAAA records",
                {"ips_v4": [], "ips_v6": []},
            )

        # Compare with previous snapshot (if any)
        status = Status.OK
        changes_msg = ""
        added_v4: List[str] = []
        removed_v4: List[str] = []
        added_v6: List[str] = []
        removed_v6: List[str] = []

        if prev:
            try:
                old = json.loads(prev.snapshot_json)
            except Exception:
                old = {}

            old_v4 = set(old.get("ips_v4") or [])
            cur_v4 = set(ips_v4)
            added_v4 = sorted(list(cur_v4 - old_v4))
            removed_v4 = sorted(list(old_v4 - cur_v4))

            parts: List[str] = []
            if added_v4 or removed_v4:
                parts.append(f"v4 +{len(added_v4)} -{len(removed_v4)}")

            if self.cfg.include_ipv6:
                old_v6 = set(old.get("ips_v6") or [])
                cur_v6 = set(ips_v6)
                added_v6 = sorted(list(cur_v6 - old_v6))
                removed_v6 = sorted(list(old_v6 - cur_v6))
                if added_v6 or removed_v6:
                    parts.append(f"v6 +{len(added_v6)} -{len(removed_v6)}")

            if parts:
                status = Status.WARN
                changes_msg = "; ".join(parts)
                log.info(
                    "ipchange.changed",
                    extra={
                        "event": "ipchange.changed",
                        "domain": self.domain,
                        "v4_added": len(added_v4),
                        "v4_removed": len(removed_v4),
                        "v6_added": len(added_v6) if self.cfg.include_ipv6 else 0,
                        "v6_removed": len(removed_v6) if self.cfg.include_ipv6 else 0,
                    },
                )

        # Human-facing message
        if status is Status.WARN:
            msg = f"ip changed: {changes_msg}"
        else:
            # Show current IPs for quick visibility
            ip_list = ips_v4 + (ips_v6 if (self.cfg.include_ipv6 and ips_v6) else [])
            msg = f"no change ({','.join(ip_list)})"
            log.info(
                "ipchange.no_change",
                extra={
                    "event": "ipchange.no_change",
                    "domain": self.domain,
                    "ips_v4_count": len(ips_v4),
                    "ips_v6_count": len(ips_v6) if self.cfg.include_ipv6 else 0,
                },
            )

        # Persist snapshot if needed (first run, TTL, or set actually changed)
        self._maybe_upsert(ips_v4, ips_v6, now, prev, must_refresh)

        return CheckOutcome(
            check=self.name,
            status=status,
            message=msg,
            metrics={
                "ips_v4": ips_v4,
                "ips_v6": ips_v6,
                "fetched_at": now.isoformat(),
                "include_ipv6": bool(self.cfg.include_ipv6),
            },
        )

    # -------------------------------------------------------------- internals

    async def _resolve_ips(self) -> Tuple[List[str], List[str]]:
        """Resolve both A and AAAA using getaddrinfo and split by address family."""
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(self.domain, 80, type=socket.SOCK_STREAM)
        except socket.gaierror as error:
            if error.errno not in {socket.EAI_NONAME, getattr(socket, "EAI_NODATA", None)}:
                raise
            infos = []

        v4: set[str] = set()
        v6: set[str] = set()
        for family, *_rest, sockaddr in infos:
            host = sockaddr[0]
            if family == socket.AF_INET:
                v4.add(host)
            elif family == socket.AF_INET6:
                v6.add(host)

        return sorted(v4), sorted(v6)

    def _connect(self) -> sqlite3.Connection:
        """Open a connection to the sqlite database."""
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        storage._ensure_initialized(self._db_path)
        return sqlite3.connect(str(self._db_path))

    def _db_get(self) -> Optional[_Row]:
        """Load a scoped snapshot, bootstrapping from the untouched legacy cache once."""
        conn = self._connect()
        try:
            if self._owner_id is None:
                row = conn.execute(
                    "SELECT snapshot_json, fetched_at FROM dns_state WHERE domain=?",
                    (self.domain.lower(),),
                ).fetchone()
            else:
                query = "SELECT snapshot_json, fetched_at FROM owner_dns_state WHERE owner_id=? AND domain=?"
                params = (self._owner_id, self.domain.lower())
                row = conn.execute(query, params).fetchone()
                if row is None:
                    # Copy once, even when unchanged: later scans must not consume this baseline.
                    conn.execute(
                        "INSERT OR IGNORE INTO owner_dns_state(owner_id,domain,snapshot_json,fetched_at) "
                        "SELECT ?,domain,snapshot_json,fetched_at FROM dns_state WHERE domain=?", params,
                    )
                    conn.commit()
                    row = conn.execute(query, params).fetchone()
            if not row:
                return None
            snap_json, fetched_at = row
            try:
                dt = datetime.fromisoformat(str(fetched_at))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                else:
                    dt = dt.astimezone(timezone.utc)
            except Exception:
                dt = datetime.now(timezone.utc)
            return _Row(domain=self.domain.lower(), snapshot_json=str(snap_json), fetched_at=dt)
        finally:
            conn.close()

    def _maybe_upsert(
        self,
        ips_v4: List[str],
        ips_v6: List[str],
        now: datetime,
        prev: Optional[_Row],
        must_refresh: bool,
    ) -> None:
        """
        Save snapshot if it doesn't exist, TTL has expired, or the set actually changed.
        Avoids unnecessary writes.
        """
        reason: Optional[str] = None
        if not prev:
            reason = "no_prev"
        elif must_refresh:
            reason = "ttl_expired"
        else:
            try:
                old = json.loads(prev.snapshot_json)
            except Exception:
                old = {}
            if set(old.get("ips_v4") or []) != set(ips_v4):
                reason = "v4_changed"
            elif self.cfg.include_ipv6 and set(old.get("ips_v6") or []) != set(ips_v6):
                reason = "v6_changed"

        if not reason:
            log.debug("ipchange.db.skip", extra={"event": "ipchange.db.skip", "domain": self.domain})
            return

        conn = self._connect()
        try:
            table = "dns_state" if self._owner_id is None else "owner_dns_state"
            owner_column = "" if self._owner_id is None else "owner_id,"
            params = (
                self.domain.lower(),
                json.dumps({"ips_v4": ips_v4, "ips_v6": ips_v6}, ensure_ascii=False),
                now.isoformat(),
            )
            if self._owner_id is not None:
                params = (self._owner_id, *params)
            conn.execute(
                f"INSERT INTO {table}({owner_column}domain,snapshot_json,fetched_at) "
                f"VALUES({','.join('?' for _ in params)}) "
                f"ON CONFLICT({owner_column}domain) DO UPDATE SET "
                "snapshot_json=excluded.snapshot_json,fetched_at=excluded.fetched_at,"
                "updated_at=CURRENT_TIMESTAMP", params,
            )
            conn.commit()
            log.debug(
                "ipchange.db.upsert",
                extra={"event": "ipchange.db.upsert", "domain": self.domain, "reason": reason},
            )
        finally:
            conn.close()
