# /checks/ip_change.py
from __future__ import annotations

import asyncio
import json
import socket
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from .base import BaseCheck, CheckOutcome, Status
from ..config import IpChangeConfig
from .. import storage  # single source of truth for DB path


@dataclass
class _Row:
    snapshot_json: str
    fetched_at: datetime


class IpChangeCheck(BaseCheck):
    """
    Tracks current DNS A/AAAA set and compares it with the last snapshot stored in SQLite.

    Status rules:
      - CRIT: no A/AAAA records
      - WARN: the set of IPs changed (added/removed)
      - OK: no changes
    """

    name = "ip_change"

    def __init__(self, domain: str, cfg: IpChangeConfig) -> None:
        super().__init__(domain)
        self.cfg = cfg
        # Use storage.DEFAULT_DB directly (SSOT). It already respects DATABASE_PATH env.
        self.db_path = str(storage.DEFAULT_DB)

    async def run(self) -> CheckOutcome:
        prev = self._db_get()
        now = datetime.now(timezone.utc)

        must_refresh = True
        if prev:
            age_h = (now - prev.fetched_at).total_seconds() / 3600.0
            must_refresh = age_h >= float(self.cfg.refresh_hours)

        # Always resolve the fresh set of IPs; cheap and reliable.
        ips_v4, ips_v6 = await self._resolve_ips()

        if not ips_v4 and (not self.cfg.include_ipv6 or not ips_v6):
            # No address at all → CRIT. Still persist the snapshot so we have history.
            self._maybe_upsert(ips_v4, ips_v6, now, prev, must_refresh)
            return CheckOutcome(
                self.name,
                Status.CRIT,
                "no A/AAAA records",
                {"ips_v4": [], "ips_v6": []},
            )

        # Compare with previous snapshot if present.
        status = Status.OK
        changes_msg = ""
        if prev:
            old = json.loads(prev.snapshot_json)
            old_v4 = set(old.get("ips_v4") or [])
            old_v6 = set(old.get("ips_v6") or [])

            new_v4 = set(ips_v4)
            # If IPv6 tracking is disabled, treat new_v6 as old_v6 to suppress v6 diffs.
            new_v6 = set(ips_v6) if self.cfg.include_ipv6 else old_v6

            added_v4 = sorted(new_v4 - old_v4)
            removed_v4 = sorted(old_v4 - new_v4)
            added_v6 = sorted(new_v6 - old_v6)
            removed_v6 = sorted(old_v6 - new_v6)

            parts: List[str] = []
            if added_v4:
                parts.append(f"v4+:{','.join(added_v4)}")
            if removed_v4:
                parts.append(f"v4-:{','.join(removed_v4)}")
            if self.cfg.include_ipv6:
                if added_v6:
                    parts.append(f"v6+:{','.join(added_v6)}")
                if removed_v6:
                    parts.append(f"v6-:{','.join(removed_v6)}")

            if parts:
                status = Status.WARN
                changes_msg = "; ".join(parts)

        # Human-facing message.
        if status is Status.WARN:
            msg = f"ip changed: {changes_msg}"
        else:
            # Show current IPs for quick visibility.
            ip_list = ips_v4 + (ips_v6 if (self.cfg.include_ipv6 and ips_v6) else [])
            msg = f"no change ({','.join(ip_list)})"

        # Persist snapshot when needed.
        self._maybe_upsert(ips_v4, ips_v6, now, prev, must_refresh)

        return CheckOutcome(
            check=self.name,
            status=status,
            message=msg,
            metrics={"ips_v4": ips_v4, "ips_v6": ips_v6, "fetched_at": now.isoformat()},
        )

    # ---------- DNS resolve ----------

    async def _resolve_ips(self) -> Tuple[List[str], List[str]]:
        """Resolve both A and AAAA using getaddrinfo and split by address family."""
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(self.domain, 80, type=socket.SOCK_STREAM)
        except Exception:
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

    # ---------- SQLite I/O ----------

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def _db_get(self) -> Optional[_Row]:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT snapshot_json, fetched_at FROM dns_state WHERE domain = ?",
                (self.domain.lower(),),
            ).fetchone()
            if not row:
                return None
            try:
                fetched_at = datetime.fromisoformat(row[1])
            except Exception:
                fetched_at = datetime.now(timezone.utc)
            return _Row(snapshot_json=row[0], fetched_at=fetched_at)
        except sqlite3.OperationalError:
            # Table is not created yet — treat as no snapshot.
            return None
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
        should_update = False
        if not prev or must_refresh:
            should_update = True
        else:
            old = json.loads(prev.snapshot_json)
            if set(old.get("ips_v4") or []) != set(ips_v4):
                should_update = True
            elif self.cfg.include_ipv6 and set(old.get("ips_v6") or []) != set(ips_v6):
                should_update = True

        if not should_update:
            return

        conn = self._connect()
        try:
            conn.execute(
                """
                INSERT INTO dns_state(domain, snapshot_json, fetched_at)
                VALUES(?,?,?)
                ON CONFLICT(domain) DO UPDATE SET
                    snapshot_json=excluded.snapshot_json,
                    fetched_at=excluded.fetched_at,
                    updated_at=CURRENT_TIMESTAMP
                """,
                (
                    self.domain.lower(),
                    json.dumps({"ips_v4": ips_v4, "ips_v6": ips_v6}, ensure_ascii=False),
                    now.isoformat(),
                ),
            )
            conn.commit()
        finally:
            conn.close()
