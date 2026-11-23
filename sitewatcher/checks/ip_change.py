from __future__ import annotations

import asyncio
import json
import logging
import socket
import sqlite3
from contextlib import closing
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, List, Optional, Tuple

from ..check_context import CheckContext
from .base import BaseCheck, CheckOutcome, Status
from .. import storage

# Module-level logger for structured events
log = logging.getLogger(__name__)
_RECENT_ADDRESS_SETS = 8


@dataclass(frozen=True)
class _Row:
    """Cached DNS snapshot row."""
    domain: str
    snapshot_json: str
    fetched_at: datetime


class IpChangeCheck(BaseCheck):
    """Detects IP (A/AAAA) changes for a domain with lightweight local caching."""

    name = "ip_change"

    def __init__(
        self, domain: str, *, cfg: Any, owner_id: int | None = None,
        cycle_context: CheckContext | None = None,
    ) -> None:
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
        self.cycle_context = cycle_context
        self.cfg = cfg
        self._db_path = Path(getattr(cfg, "db_path", None) or storage.DEFAULT_DB)

        # Normalize basic options
        self.cfg.include_ipv6 = bool(getattr(cfg, "include_ipv6", False))
        self.cfg.refresh_hours = float(getattr(cfg, "refresh_hours", 24))

    # ------------------------------------------------------------------ public

    async def run(self) -> CheckOutcome:
        """Resolve current IPs and confirm a novel set on consecutive observations."""
        prev = self._db_get()
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

        with closing(self._connect()) as conn, conn:
            # Manual and scheduled probes can finish DNS concurrently.
            conn.execute("BEGIN IMMEDIATE")
            prev = self._db_read(conn)
            now = datetime.now(timezone.utc)
            return self._record_resolution(conn, ips_v4, ips_v6, now, prev)

    def _record_resolution(
        self, conn: sqlite3.Connection, ips_v4: list[str], ips_v6: list[str],
        now: datetime, prev: _Row | None,
    ) -> CheckOutcome:
        include_ipv6 = self.cfg.include_ipv6
        old = self._load_snapshot(prev.snapshot_json) if prev else {}
        must_refresh = (prev is None or
                        (now - prev.fetched_at).total_seconds() >= self.cfg.refresh_hours * 3600)
        if not ips_v4 and not (include_ipv6 and ips_v6):
            log.warning("ipchange.no_records", extra={"event": "ipchange.no_records", "domain": self.domain})
            snapshot = {"ips_v4": [], "ips_v6": []}
            if must_refresh or snapshot != old:
                self._db_upsert(conn, snapshot, now)
            return CheckOutcome(self.name, Status.CRIT, "no A/AAAA records",
                                {"ips_v4": [], "ips_v6": []})

        current = [ips_v4, ips_v6 if include_ipv6 else []]
        previous = [sorted(old.get("ips_v4") or []),
                    sorted(old.get("ips_v6") or []) if include_ipv6 else []]
        same_mode = old.get("include_ipv6", include_ipv6) == include_ipv6
        recent = (old.get("recent_sets") or []) if same_mode else []
        pending = old.get("pending_change") if same_mode else None

        status = Status.OK
        ip_list = ",".join(current[0] + current[1])
        message = f"no change ({ip_list})"
        if current != previous and any(previous):
            if current in recent:
                pending = None
                message = f"known DNS address set ({ip_list})"
            else:
                parts = []
                for family, before, after in zip(("v4", "v6"), previous, current, strict=True):
                    added = set(after) - set(before)
                    removed = set(before) - set(after)
                    if added or removed:
                        parts.append(f"{family} +{len(added)} -{len(removed)}")
                pending = "; ".join(parts)
                message = f"new DNS address set, awaiting confirmation ({ip_list})"
            recent = [addresses for addresses in recent if addresses != current]
            recent = (recent + [previous])[-_RECENT_ADDRESS_SETS:]
        elif current == previous and pending:
            status = Status.WARN
            message = f"ip changed: {pending}"
            pending = None
        elif must_refresh:
            # A set unchanged through the refresh window becomes the new baseline.
            recent = []

        snapshot = {"ips_v4": ips_v4, "ips_v6": ips_v6}
        if recent or pending:
            snapshot.update(recent_sets=recent, pending_change=pending, include_ipv6=include_ipv6)
        if must_refresh or snapshot != old:
            self._db_upsert(conn, snapshot, now)

        return CheckOutcome(self.name, status, message, {
            "ips_v4": ips_v4,
            "ips_v6": ips_v6,
            "fetched_at": now.isoformat(),
            "include_ipv6": include_ipv6,
        })

    @staticmethod
    def _load_snapshot(snapshot: str) -> dict:
        try:
            value = json.loads(snapshot)
            return value if isinstance(value, dict) else {}
        except ValueError:
            return {}

    # -------------------------------------------------------------- internals

    async def _resolve_ips(self) -> Tuple[List[str], List[str]]:
        """Resolve both A and AAAA using getaddrinfo and split by address family."""
        loop = asyncio.get_running_loop()
        try:
            if self.cycle_context is not None:
                family = socket.AF_UNSPEC if self.cfg.include_ipv6 else socket.AF_INET
                infos = await self.cycle_context.resolve(self.domain, family=family)
            else:
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
        with closing(self._connect()) as conn, conn:
            row = self._db_read(conn)
            if row is not None or self._owner_id is None:
                return row
            domain = self.domain.lower()
            legacy = conn.execute(
                "SELECT snapshot_json, fetched_at FROM dns_state WHERE domain=?", (domain,),
            ).fetchone()
            if legacy is None:
                return None
            raw, fetched_at = legacy
            snapshot = self._load_snapshot(raw)
            if "recent_sets" in snapshot:
                # Owners start with legacy address facts and learn their own rotation history.
                raw = json.dumps({key: snapshot[key] for key in ("ips_v4", "ips_v6")})
            conn.execute(
                "INSERT OR IGNORE INTO owner_dns_state(owner_id,domain,snapshot_json,fetched_at) "
                "VALUES(?,?,?,?)", (self._owner_id, domain, raw, fetched_at),
            )
            return self._db_read(conn)

    def _db_read(self, conn: sqlite3.Connection) -> Optional[_Row]:
        domain = self.domain.lower()
        if self._owner_id is None:
            row = conn.execute(
                "SELECT snapshot_json, fetched_at FROM dns_state WHERE domain=?", (domain,),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT snapshot_json, fetched_at FROM owner_dns_state WHERE owner_id=? AND domain=?",
                (self._owner_id, domain),
            ).fetchone()
        if row is None:
            return None
        snapshot, fetched_at = row
        try:
            date = datetime.fromisoformat(str(fetched_at))
            date = date.astimezone(timezone.utc) if date.tzinfo else date.replace(tzinfo=timezone.utc)
        except ValueError:
            date = datetime.now(timezone.utc)
        return _Row(domain=domain, snapshot_json=str(snapshot), fetched_at=date)

    def _db_upsert(self, conn: sqlite3.Connection, snapshot: dict, now: datetime) -> None:
        table = "dns_state" if self._owner_id is None else "owner_dns_state"
        owner_column = "" if self._owner_id is None else "owner_id,"
        params = (self.domain.lower(), json.dumps(snapshot, ensure_ascii=False), now.isoformat())
        if self._owner_id is not None:
            params = (self._owner_id, *params)
        conn.execute(
            f"INSERT INTO {table}({owner_column}domain,snapshot_json,fetched_at) "
            f"VALUES({','.join('?' for _ in params)}) "
            f"ON CONFLICT({owner_column}domain) DO UPDATE SET "
            "snapshot_json=excluded.snapshot_json,fetched_at=excluded.fetched_at,"
            "updated_at=CURRENT_TIMESTAMP", params,
        )
