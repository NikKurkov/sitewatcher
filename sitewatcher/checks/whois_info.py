# sitewatcher/checks/whois_info.py
from __future__ import annotations

import asyncio
import contextlib
import json
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import httpx
import tldextract

from .base import BaseCheck, CheckOutcome, Status
from ..config import WhoisConfig
from ..utils.http_retry import get_with_retries
from .. import storage


WHOIS_PORT = 43  # single source of truth for raw WHOIS


# ----------------------------- RDAP parsing utils -----------------------------
def registrable_domain(hostname: str) -> str:
    """Return eTLD+1 (registrable domain) for a given hostname.

    Examples:
      - "www.example.com"   -> "example.com"
      - "api.service.co.uk" -> "service.co.uk"
      - "example.biz"       -> "example.biz"
    """
    hn = (hostname or "").strip().rstrip(".").lower()
    ext = tldextract.extract(hn)
    if not ext.domain or not ext.suffix:
        # Fallback to original if parsing fails
        return hn
    return f"{ext.domain}.{ext.suffix}"


def _get_event_date(obj: Dict[str, Any], action: str) -> Optional[datetime]:
    """Return timezone-aware datetime for RDAP 'events' by action."""
    for ev in obj.get("events", []) or []:
        if (ev.get("eventAction") or "").lower() == action.lower() and "eventDate" in ev:
            try:
                # Normalize trailing Z to +00:00 then parse to aware datetime
                return datetime.fromisoformat(str(ev["eventDate"]).replace("Z", "+00:00")).astimezone(
                    timezone.utc
                )
            except Exception:
                continue
    return None


def _get_entities(obj: Dict[str, Any], role: str) -> List[Dict[str, Any]]:
    """Return entities matching requested RDAP role."""
    role = role.lower()
    out: List[Dict[str, Any]] = []
    for e in (obj.get("entities") or []):
        roles = [str(r).lower() for r in (e.get("roles") or [])]
        if role in roles:
            out.append(e)
    return out


def _vcard_get(entity: Dict[str, Any], key: str) -> Optional[str]:
    """Safe extractor for vCard fields (fn/org/etc) from RDAP entity."""
    v = entity.get("vcardArray")
    if not isinstance(v, list) or len(v) < 2 or not isinstance(v[1], list):
        return None
    for item in v[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == key:
            val = item[3]
            if isinstance(val, list):  # e.g., org can be a list
                return " ".join([str(x) for x in val if x])
            return str(val)
    return None


def _extract_snapshot(rdap: Dict[str, Any]) -> Dict[str, Any]:
    """Build a normalized, comparable snapshot dict from raw RDAP JSON."""
    # Registrar
    registrar_name = None
    for ent in _get_entities(rdap, "registrar"):
        registrar_name = _vcard_get(ent, "fn") or _vcard_get(ent, "org")
        if registrar_name:
            break

    # Registrant
    registrant = None
    for ent in _get_entities(rdap, "registrant"):
        registrant = _vcard_get(ent, "fn") or _vcard_get(ent, "org")
        if registrant:
            break

    # Nameservers
    ns: List[str] = []
    for n in (rdap.get("nameservers") or []):
        name = n.get("ldhName") or n.get("unicodeName")
        if name:
            ns.append(str(name).lower().rstrip("."))

    # Status codes
    status = sorted([str(s).lower() for s in (rdap.get("status") or [])])

    # Dates
    expires = _get_event_date(rdap, "expiration")
    created = _get_event_date(rdap, "registration")
    updated = _get_event_date(rdap, "last changed") or _get_event_date(
        rdap, "last update of rdap database"
    )

    return {
        "registrar": registrar_name or "",
        "registrant": registrant or "",
        "nameservers": sorted(set(ns)),
        "status": status,
        "expires_at": expires.isoformat() if expires else None,
        "created_at": created.isoformat() if created else None,
        "updated_at": updated.isoformat() if updated else None,
        "rdap_source": rdap.get("port43") or "rdap",  # best effort hint
    }


# --------------------------------- Data model ---------------------------------
@dataclass
class _WhoisRow:
    snapshot_json: str
    fetched_at: datetime


# --------------------------------- Main check ---------------------------------
class WhoisInfoCheck(BaseCheck):
    """WHOIS/RDAP change & expiry check with local SQLite snapshot cache."""
    name = "whois"

    def __init__(self, domain: str, client: httpx.AsyncClient, cfg: WhoisConfig) -> None:
        super().__init__(domain)
        self.client = client
        self.cfg = cfg
        # SSOT: rely on storage.DEFAULT_DB, not env lookups here.
        self.db_path = storage.DEFAULT_DB

    async def run(self) -> CheckOutcome:
        """Run the check: fetch snapshot (with cache), diff, and expiry status."""
        prev = self._db_get()
        now = datetime.now(timezone.utc)

        # Cache policy: refresh if data is older than refresh_hours
        must_refresh = True
        if prev:
            age_hours = (now - prev.fetched_at).total_seconds() / 3600.0
            must_refresh = age_hours >= float(getattr(self.cfg, "refresh_hours", 24) or 24)

        # Always define rx_metrics so except-paths can safely reference it
        rx_metrics: Dict[str, Any] = {}

        try:
            if must_refresh or not prev:
                snap, fetched_at, rx_metrics = await self._fetch_snapshot(self.domain)
                self._db_upsert(snap, fetched_at)
            else:
                snap = json.loads(prev.snapshot_json)
                fetched_at = prev.fetched_at

        except httpx.HTTPStatusError as e:
            code = e.response.status_code if e.response is not None else None
            url = str(e.request.url) if e.request is not None else None
            base = {"url": url, "status_code": code, **rx_metrics}
            if code == 429:
                ra = e.response.headers.get("Retry-After") if e.response is not None else None
                base["retry_after"] = ra
                return CheckOutcome(self.name, Status.UNKNOWN, "RDAP rate-limited", base)
            return CheckOutcome(
                self.name,
                Status.CRIT,
                f"RDAP HTTP {code}" if code is not None else "RDAP HTTP error",
                base,
            )

        except httpx.RequestError as e:
            url = str(e.request.url) if getattr(e, "request", None) else None
            return CheckOutcome(
                self.name,
                Status.UNKNOWN,
                f"RDAP request error: {e.__class__.__name__}",
                {"url": url, "error": str(e), **rx_metrics},
            )

        except Exception as e:
            return CheckOutcome(
                self.name,
                Status.UNKNOWN,
                f"whois/rdap error: {e.__class__.__name__}: {e}",
                {"error": str(e), **rx_metrics},
            )

        # 1) Expiry assessment
        expires_at = snap.get("expires_at")
        expiry_status, expiry_msg, days_left = self._expiry_status(expires_at)

        # 2) Diff the key fields against previous snapshot
        changes_msg = ""
        if prev:
            before = json.loads(prev.snapshot_json)
            track_keys = getattr(
                self.cfg,
                "track_fields",
                ["registrar", "registrant", "nameservers", "status"],
            )
            diff = self._diff_snapshots(before, snap, track_keys)
            if diff:
                parts: List[str] = []
                for k, (old, new) in diff.items():
                    if isinstance(old, list) or isinstance(new, list):
                        old_list = old or []
                        new_list = new or []
                        added = sorted(set(new_list) - set(old_list))
                        removed = sorted(set(old_list) - set(new_list))
                        if added:
                            parts.append(f"{k}+:{','.join(added)}")
                        if removed:
                            parts.append(f"{k}-:{','.join(removed)}")
                    else:
                        parts.append(f"{k}:{(old or '-')}\u2192{(new or '-')}")
                changes_msg = "; ".join(parts)

        # 3) Final status
        if expiry_status == Status.CRIT:
            status = Status.CRIT
        elif changes_msg:
            status = Status.WARN
        else:
            status = expiry_status  # OK or WARN (close to expiry)

        # 4) Message
        msg_parts: List[str] = []
        if expiry_msg:
            msg_parts.append(expiry_msg)
        if changes_msg:
            msg_parts.append(f"changed: {changes_msg}")
        if not msg_parts:
            msg_parts.append("no changes")
        message = "; ".join(msg_parts)

        metrics = {
            "expires_at": expires_at,
            "days_left": days_left,
            "registrar": snap.get("registrar"),
            "registrant": snap.get("registrant"),
            "nameservers": snap.get("nameservers"),
            "status_list": snap.get("status"),
            "fetched_at": fetched_at.isoformat(),
            **rx_metrics,
        }
        return CheckOutcome(self.name, status, message, metrics)

    # ------------------------------- Fetch helpers ------------------------------
    async def _fetch_snapshot(self, domain: str) -> Tuple[Dict[str, Any], datetime, Dict[str, Any]]:
        """Fetch snapshot for domain via RDAP or raw WHOIS override.

        Returns:
            (snapshot_dict, fetched_at_utc, metrics_dict)
        """
        reg_domain = registrable_domain(domain)  # normalize to eTLD+1 for WHOIS/RDAP
        tld = reg_domain.split(".")[-1].lower()

        # Optional TLD-specific override (e.g., RU/SU via whois.tcinet.ru)
        override = getattr(self.cfg, "tld_overrides", {}).get(tld)
        if isinstance(override, dict) and str(override.get("method", "")).lower() == "whois":
            host = str(override.get("host", "")).strip() or "whois.tcinet.ru"
            start = time.perf_counter()
            text = await self._whois_query(host, reg_domain)
            elapsed_ms = int((time.perf_counter() - start) * 1000)

            # Currently only specialized parser we provide is for tcinet
            if "tcinet" in host or host.endswith("tcinet.ru"):
                snap = self._parse_tcinet_ru(text, host)
            else:
                # Generic fallback: keep minimal snapshot; expiry unknown
                snap = {
                    "registrar": "",
                    "registrant": "",
                    "nameservers": [],
                    "status": [],
                    "expires_at": None,
                    "created_at": None,
                    "updated_at": None,
                    "rdap_source": host,
                }

            return snap, datetime.now(timezone.utc), {
                "whois_latency_ms": elapsed_ms,
                "whois_host": host,
            }

        # Default: RDAP path
        rdap, rdap_ms = await self._fetch_rdap(reg_domain)
        snap = _extract_snapshot(rdap)
        return snap, datetime.now(timezone.utc), {
            "rdap_latency_ms": rdap_ms,
            "rdap_url": str(getattr(self.cfg, "rdap_endpoint", "https://rdap.org/domain/{domain}")).format(
                domain=reg_domain
            ),
        }

    async def _fetch_rdap(self, domain: str) -> Tuple[Dict[str, Any], int]:
        """Perform RDAP query with retry policy; returns (json, latency_ms)."""
        url = str(getattr(self.cfg, "rdap_endpoint", "https://rdap.org/domain/{domain}")).format(
            domain=domain
        )
        start = time.perf_counter()
        r = await get_with_retries(
            self.client,
            url,
            timeout_s=float(getattr(self.cfg, "timeout_s", 30.0) or 30.0),
            retries=2,
            backoff_s=0.3,
            follow_redirects=True,
            headers={
                "User-Agent": "sitewatcher/0.1 (+https://github.com/NikKurkov/sitewatcher)"
            },
        )
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        r.raise_for_status()
        return r.json(), elapsed_ms

    # ------------------------------ Raw WHOIS (43) ------------------------------
    async def _whois_query(self, host: str, query: str) -> str:
        """Minimalistic port-43 WHOIS query (RFC 3912)."""
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host=host, port=WHOIS_PORT),
            timeout=15.0,
        )
        try:
            writer.write((query + "\r\n").encode("utf-8", "ignore"))
            await writer.drain()
            chunks: List[bytes] = []
            while True:
                try:
                    data = await asyncio.wait_for(reader.read(4096), timeout=10.0)
                except asyncio.TimeoutError:
                    break
                if not data:
                    break
                chunks.append(data)
            return b"".join(chunks).decode("utf-8", "ignore")
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    def _parse_tcinet_ru(self, text: str, whois_host: str) -> Dict[str, Any]:
        """Parse whois.tcinet.ru (RU/РФ/SU) flat text into a normalized snapshot."""
        lines = [l.strip() for l in text.splitlines()]
        kv: List[Tuple[str, str]] = []
        for ln in lines:
            if not ln or ln.startswith("%"):
                continue
            if ":" in ln:
                k, v = ln.split(":", 1)
                kv.append((k.strip().lower(), v.strip()))

        def first(key: str) -> Optional[str]:
            for k, v in kv:
                if k == key:
                    return v
            return None

        registrar = first("registrar")
        org = first("org")
        person = first("person")
        registrant = org or person or ""

        # nserver: ns.example.ru. 1.2.3.4
        ns: List[str] = []
        for k, v in kv:
            if k == "nserver":
                name = v.split()[0].rstrip(".").lower()
                ns.append(name)
        nameservers = sorted(set(ns))

        # state: REGISTERED, DELEGATED, VERIFIED
        state = first("state") or ""
        statuses = [s.strip().lower() for s in state.split(",") if s.strip()]

        def parse_dt(val: Optional[str]) -> Optional[str]:
            if not val:
                return None
            s = val.strip()
            for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
                try:
                    dt = datetime.strptime(s, fmt)
                    # If date only, assume 00:00:00 UTC
                    if fmt == "%Y-%m-%d":
                        dt = dt.replace(hour=0, minute=0, second=0, tzinfo=timezone.utc)
                    else:
                        dt = dt.replace(tzinfo=timezone.utc)
                    return dt.isoformat()
                except ValueError:
                    continue
            # Fallback: ISO with trailing Z normalization
            try:
                return datetime.fromisoformat(s.replace("Z", "+00:00")).isoformat()
            except Exception:
                return None

        created = parse_dt(first("created"))
        paid_till = parse_dt(first("paid-till"))

        return {
            "registrar": registrar or "",
            "registrant": registrant,
            "nameservers": nameservers,
            "status": statuses,
            "expires_at": paid_till,
            "created_at": created,
            "updated_at": None,
            "rdap_source": whois_host,
        }

    # ------------------------------- Diff & expiry ------------------------------
    def _expiry_status(self, expires_at_iso: Optional[str]) -> Tuple[Status, str, Optional[int]]:
        """Classify domain expiry proximity into Status + human message."""
        if not expires_at_iso:
            return Status.UNKNOWN, "no expiry in rdap", None
        try:
            exp = datetime.fromisoformat(expires_at_iso)
        except Exception:
            try:
                exp = datetime.fromisoformat(expires_at_iso + "+00:00")
            except Exception:
                return Status.UNKNOWN, "bad expiry format", None

        now = datetime.now(timezone.utc)
        days_left = int((exp - now).total_seconds() // 86400)

        if days_left < 0:
            return Status.CRIT, f"domain expired {-days_left}d ago ({exp.date()} UTC)", days_left
        if days_left <= int(getattr(self.cfg, "expiry_crit_days", 7) or 7):
            return Status.CRIT, f"expires in {days_left}d ({exp.date()} UTC)", days_left
        if days_left <= int(getattr(self.cfg, "expiry_warn_days", 30) or 30):
            return Status.WARN, f"expires in {days_left}d ({exp.date()} UTC)", days_left
        return Status.OK, f"expires in {days_left}d ({exp.date()} UTC)", days_left

    def _diff_snapshots(
        self, old: Dict[str, Any], new: Dict[str, Any], keys: List[str]
    ) -> Dict[str, Tuple[Any, Any]]:
        """Return a dict of {key: (old, new)} for changed tracked fields."""
        diff: Dict[str, Tuple[Any, Any]] = {}
        for k in keys:
            ov = old.get(k)
            nv = new.get(k)
            # Normalize lists for deterministic comparison
            if isinstance(ov, list):
                ov = sorted(ov)
            if isinstance(nv, list):
                nv = sorted(nv)
            if ov != nv:
                diff[k] = (ov, nv)
        return diff

    # --------------------------------- SQLite IO --------------------------------
    def _connect(self) -> sqlite3.Connection:
        """Open a connection to the snapshot DB."""
        return sqlite3.connect(str(self.db_path))

    def _db_get(self) -> Optional[_WhoisRow]:
        """Load previous snapshot row for domain, if any."""
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT snapshot_json, fetched_at FROM whois_state WHERE domain = ?",
                (self.domain.lower(),),
            ).fetchone()
            if not row:
                return None
            snap_json = row[0]
            try:
                fetched_at = datetime.fromisoformat(row[1])
                if fetched_at.tzinfo is None:
                    fetched_at = fetched_at.replace(tzinfo=timezone.utc)
            except Exception:
                fetched_at = datetime.now(timezone.utc)
            return _WhoisRow(snapshot_json=snap_json, fetched_at=fetched_at)
        finally:
            conn.close()

    def _db_upsert(self, snapshot: Dict[str, Any], fetched_at: datetime) -> None:
        """Upsert current snapshot for domain into SQLite cache."""
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO whois_state(domain, snapshot_json, fetched_at) VALUES(?,?,?) "
                "ON CONFLICT(domain) DO UPDATE SET snapshot_json=excluded.snapshot_json, "
                "fetched_at=excluded.fetched_at, updated_at=CURRENT_TIMESTAMP",
                (self.domain.lower(), json.dumps(snapshot, ensure_ascii=False), fetched_at.isoformat()),
            )
            conn.commit()
        finally:
            conn.close()
