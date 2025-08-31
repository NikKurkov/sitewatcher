# sitewatcher/utils/domains_csv.py
from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from .. import storage

# Fixed CSV header (semicolon separated), first row must be exported as headers.
HEADERS: Tuple[str, ...] = (
    "domain",
    "checks.http_basic",
    "checks.tls_cert",
    "checks.ping",
    "checks.keywords",
    "checks.rkn_block",
    "checks.whois",
    "checks.ip_blacklist",
    "checks.ip_change",
    "checks.ports",
    "keywords",
    "ports",
    "http_timeout_s",
    "latency_warn_ms",
    "latency_crit_ms",
    "tls_warn_days",
    "proxy",
    "interval_minutes",
)

# Simple (permissive) domain pattern
_DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$")


@dataclass
class RowResult:
    domain: str
    status: str  # "added" | "updated" | "skipped"
    error: Optional[str] = None


@dataclass
class ImportReport:
    added: int = 0
    updated: int = 0
    skipped: int = 0
    errors: List[str] = None
    details: List[RowResult] = None

    def __post_init__(self) -> None:
        if self.errors is None:
            self.errors = []
        if self.details is None:
            self.details = []


# ------------------------ parsing & normalization helpers ------------------------

def _is_truthy(s: str) -> Optional[bool]:
    """Parse common boolean representations; return None if empty/unknown."""
    if s is None:
        return None
    t = s.strip().lower()
    if t == "":
        return None
    if t in {"1", "true", "yes", "on"}:
        return True
    if t in {"0", "false", "no", "off"}:
        return False
    return None


def _parse_int(s: str, *, min_value: Optional[int] = None, max_value: Optional[int] = None) -> Optional[int]:
    """Parse integer or return None on empty; raise ValueError on invalid."""
    if s is None:
        return None
    t = s.strip()
    if t == "":
        return None
    v = int(t)
    if min_value is not None and v < min_value:
        raise ValueError(f"value {v} < {min_value}")
    if max_value is not None and v > max_value:
        raise ValueError(f"value {v} > {max_value}")
    return v


def _parse_list_str(s: str) -> Optional[List[str]]:
    """Parse comma-separated list of strings; None means 'not provided'."""
    if s is None:
        return None
    t = s.strip()
    if t == "":
        return []
    return [x.strip() for x in t.split(",") if x.strip()]


def _parse_list_ports(s: str) -> Optional[List[int]]:
    """Parse comma-separated list of ports; None means 'not provided'."""
    if s is None:
        return None
    t = s.strip()
    if t == "":
        return []
    out: List[int] = []
    for part in t.split(","):
        p = int(part.strip())
        if not (1 <= p <= 65535):
            raise ValueError(f"port {p} out of range")
        out.append(p)
    return out


def _normalize_domain(name: str) -> str:
    """Normalize domain to lower-case and strip trailing dot."""
    dn = (name or "").strip().lower().rstrip(".")
    if not dn or not _DOMAIN_RE.match(dn):
        raise ValueError("invalid domain format")
    return dn


def _flatten_for_export(override: Dict) -> Dict[str, str]:
    """Flatten override dict to CSV string values (booleans -> 'true'/'false')."""
    checks = (override or {}).get("checks") or {}
    def b(v):  # bool to 'true'/'false'
        return "" if v is None else ("true" if bool(v) else "false")
    def join(xs):
        if xs is None:
            return ""
        if isinstance(xs, list):
            return ",".join(str(x) for x in xs)
        return str(xs)

    return {
        "checks.http_basic": b(checks.get("http_basic")),
        "checks.tls_cert":   b(checks.get("tls_cert")),
        "checks.ping":       b(checks.get("ping")),
        "checks.keywords":   b(checks.get("keywords")),
        "checks.rkn_block":  b(checks.get("rkn_block")),
        "checks.whois":      b(checks.get("whois")),
        "checks.ip_blacklist": b(checks.get("ip_blacklist")),
        "checks.ip_change":  b(checks.get("ip_change")),
        "checks.ports":      b(checks.get("ports")),
        "keywords": join(override.get("keywords")),
        "ports": join(override.get("ports")),
        "http_timeout_s": str(override.get("http_timeout_s") or "") if override.get("http_timeout_s") is not None else "",
        "latency_warn_ms": str(override.get("latency_warn_ms") or "") if override.get("latency_warn_ms") is not None else "",
        "latency_crit_ms": str(override.get("latency_crit_ms") or "") if override.get("latency_crit_ms") is not None else "",
        "tls_warn_days": str(override.get("tls_warn_days") or "") if override.get("tls_warn_days") is not None else "",
        "proxy": (override.get("proxy") or "") if override.get("proxy") is not None else "",
        "interval_minutes": str(override.get("interval_minutes") or "") if override.get("interval_minutes") is not None else "",
    }


def export_domains_csv(owner_id: int) -> bytes:
    """Export domains and their overrides to CSV bytes (UTF-8-SIG, ';' delimiter)."""
    domains = storage.list_domains(owner_id)
    domains_sorted = sorted(domains)
    # Prepare rows
    rows: List[List[str]] = []
    for dn in domains_sorted:
        ov = storage.get_domain_override(owner_id, dn) or {}
        flat = _flatten_for_export(ov)
        row = [dn] + [flat[col] for col in HEADERS[1:]]
        rows.append(row)

    sio = io.StringIO(newline="")
    writer = csv.writer(sio, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_MINIMAL)
    writer.writerow(HEADERS)
    writer.writerows(rows)
    # UTF-8-SIG for Excel friendliness
    data = sio.getvalue().encode("utf-8-sig")
    return data


def _build_override_from_row(row: Dict[str, str], *, mode: str) -> Dict:
    """Build an override dict from a parsed CSV row; honor merge/replace semantics."""
    # Parse booleans (None means 'not provided')
    def pb(name: str) -> Optional[bool]:
        return _is_truthy(row.get(name, ""))

    checks: Dict[str, bool] = {}
    for key in (
        "checks.http_basic", "checks.tls_cert", "checks.ping", "checks.keywords",
        "checks.rkn_block", "checks.whois", "checks.ip_blacklist", "checks.ip_change", "checks.ports"
    ):
        val = pb(key)
        if val is not None:
            checks[key.split(".", 1)[1]] = val

    # Parse lists (None -> not provided; [] -> explicitly empty (replace mode))
    kws = _parse_list_str(row.get("keywords", ""))
    ports = _parse_list_ports(row.get("ports", ""))
    # Parse ints
    http_timeout_s = _parse_int(row.get("http_timeout_s", ""), min_value=1) if row.get("http_timeout_s", "").strip() != "" else None
    latency_warn_ms = _parse_int(row.get("latency_warn_ms", ""), min_value=0) if row.get("latency_warn_ms", "").strip() != "" else None
    latency_crit_ms = _parse_int(row.get("latency_crit_ms", ""), min_value=0) if row.get("latency_crit_ms", "").strip() != "" else None
    tls_warn_days = _parse_int(row.get("tls_warn_days", ""), min_value=0) if row.get("tls_warn_days", "").strip() != "" else None
    interval_minutes = _parse_int(row.get("interval_minutes", ""), min_value=0) if row.get("interval_minutes", "").strip() != "" else None

    # proxy: '', '-', 'none', 'null', 'off' -> None
    proxy_raw = (row.get("proxy") or "").strip()
    proxy: Optional[str]
    if proxy_raw == "":
        proxy = None if mode == "replace" else None  # keep None; merge mode will ignore if not present below
    elif proxy_raw.lower() in {"-", "none", "null", "off"}:
        proxy = None
    else:
        proxy = proxy_raw

    # Assemble override; include only provided values in merge mode
    ov: Dict = {}
    if checks:
        ov["checks"] = checks
    if mode == "replace":
        ov["keywords"] = kws if kws is not None else []
        ov["ports"] = ports if ports is not None else []
        ov["proxy"] = proxy  # may be None to clear
        if http_timeout_s is not None:
            ov["http_timeout_s"] = http_timeout_s
        if latency_warn_ms is not None:
            ov["latency_warn_ms"] = latency_warn_ms
        if latency_crit_ms is not None:
            ov["latency_crit_ms"] = latency_crit_ms
        if tls_warn_days is not None:
            ov["tls_warn_days"] = tls_warn_days
        if interval_minutes is not None:
            ov["interval_minutes"] = interval_minutes
    else:
        # merge: only include fields explicitly provided and non-empty
        if kws is not None and len(kws) > 0:
            ov["keywords"] = kws
        if ports is not None and len(ports) > 0:
            ov["ports"] = ports
        if proxy_raw != "":
            ov["proxy"] = proxy
        if http_timeout_s is not None:
            ov["http_timeout_s"] = http_timeout_s
        if latency_warn_ms is not None:
            ov["latency_warn_ms"] = latency_warn_ms
        if latency_crit_ms is not None:
            ov["latency_crit_ms"] = latency_crit_ms
        if tls_warn_days is not None:
            ov["tls_warn_days"] = tls_warn_days
        if interval_minutes is not None:
            ov["interval_minutes"] = interval_minutes

    return ov


def import_domains_csv(owner_id: int, data: bytes, *, mode: str = "merge") -> ImportReport:
    """Import domains and overrides from CSV bytes. Mode: 'merge' or 'replace'."""
    if mode not in {"merge", "replace"}:
        raise ValueError("mode must be 'merge' or 'replace'")

    # Decode with UTF-8-SIG to strip BOM if present.
    text = data.decode("utf-8-sig", errors="strict")
    f = io.StringIO(text)
    reader = csv.reader(f, delimiter=";")

    # Read first row: skip if header
    try:
        first = next(reader)
    except StopIteration:
        return ImportReport(added=0, updated=0, skipped=0, errors=["empty CSV"])

    # If first cell equals 'domain' and headers length matches — skip as header.
    if len(first) >= 1 and first[0] == "domain":
        header = first
        if tuple(header[:len(HEADERS)]) != HEADERS:
            # Enforce exact header match to avoid accidental misalignment
            return ImportReport(errors=["invalid header; expected exact predefined header"], added=0, updated=0, skipped=0)
    else:
        # No header line; rewind to process this row as data.
        f.seek(0)
        reader = csv.reader(f, delimiter=";")

    report = ImportReport()

    line_no = 1  # data line counter (after header decision)
    for row in reader:
        line_no += 1
        # Skip empty lines
        if not row or (len(row) == 1 and (row[0] or "").strip() == ""):
            continue
        if len(row) < len(HEADERS):
            report.skipped += 1
            report.details.append(RowResult(domain="", status="skipped", error=f"line {line_no}: not enough columns"))
            report.errors.append(f"line {line_no}: not enough columns")
            continue

        # Map columns by fixed positions
        data_map = {HEADERS[i]: (row[i] if i < len(row) else "") for i in range(len(HEADERS))}
        raw_domain = data_map["domain"]
        try:
            domain = _normalize_domain(raw_domain)
        except Exception as e:
            report.skipped += 1
            report.details.append(RowResult(domain=raw_domain, status="skipped", error=f"line {line_no}: {e}"))
            report.errors.append(f"line {line_no}: domain '{raw_domain}': {e}")
            continue

        # Build override, with field-level validation
        try:
            override = _build_override_from_row(data_map, mode=mode)
        except ValueError as e:
            report.skipped += 1
            report.details.append(RowResult(domain=domain, status="skipped", error=f"line {line_no}: {e}"))
            report.errors.append(f"line {line_no}: {domain}: {e}")
            continue

        # Apply to storage
        existed = storage.domain_exists(owner_id, domain)
        if not existed:
            storage.add_domain(owner_id, domain)

        if mode == "replace":
            # Clear previous override, then set new override (possibly empty)
            storage.unset_domain_override(owner_id, domain, None)
            if override:
                storage.set_domain_override(owner_id, domain, override)
        else:
            # merge
            if override:
                storage.set_domain_override(owner_id, domain, override)

        if not existed:
            report.added += 1
            report.details.append(RowResult(domain=domain, status="added"))
        else:
            # Consider 'updated' only when we had something to change
            if override:
                report.updated += 1
                report.details.append(RowResult(domain=domain, status="updated"))
            else:
                report.details.append(RowResult(domain=domain, status="updated"))  # no-op but processed

    return report
