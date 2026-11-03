# sitewatcher/utils/domains_csv.py
from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .. import storage
from ..config import AppConfig, ChecksModel, validate_domain_override, validation_message
from .domains import normalize_domain

__all__ = ["HEADERS", "RowResult", "ImportReport", "export_domains_csv", "import_domains_csv"]

# Fixed CSV header (semicolon separated), first row must be exported as headers.
HEADERS: Tuple[str, ...] = (
    "domain",
    "checks.http_basic",
    "checks.tls_cert",
    "checks.ping",
    "checks.keywords",
    "checks.deface",
    "checks.rkn_block",
    "checks.whois",
    "checks.ip_blacklist",
    "checks.ip_change",
    "checks.malware",
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
LEGACY_HEADERS = HEADERS
HEADERS = (*HEADERS, 'checks.rkn_domain', 'checks.rkn_ip')


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
    """Parse lossless JSON lists or legacy comma-separated keywords."""
    if s is None:
        return None
    t = s.strip()
    if t == "":
        return []
    if t.startswith("["):
        try:
            values = json.loads(t)
        except json.JSONDecodeError:
            pass  # A legacy keyword can start with a literal bracket.
        else:
            return values
    return [x.strip() for x in t.split(",") if x.strip()]


def _parse_list_ports(s: str) -> Optional[List[int]]:
    """Parse comma-separated list of ports; None means 'not provided'."""
    if s is None:
        return None
    t = s.strip()
    if t == "":
        return []
    if t.startswith("["):
        values = json.loads(t)
        if not isinstance(values, list):
            raise ValueError("ports must be a list")
        return values
    out: List[int] = []
    for part in t.split(","):
        p = int(part.strip())
        if not (1 <= p <= 65535):
            raise ValueError(f"port {p} out of range")
        out.append(p)
    return out


def _normalize_domain(name: str) -> str:
    domain = normalize_domain(name)
    if domain is None:
        raise ValueError("invalid domain format")
    return domain


def _flatten_for_export(override: Dict) -> Dict[str, str]:
    """Flatten override dict to CSV string values (booleans -> 'true'/'false')."""
    checks = (override or {}).get("checks") or {}

    def b(v):  # bool to 'true'/'false'
        return "" if v is None else ("true" if bool(v) else "false")

    return {
        "checks.http_basic": b(checks.get("http_basic")),
        "checks.tls_cert": b(checks.get("tls_cert")),
        "checks.ping": b(checks.get("ping")),
        "checks.keywords": b(checks.get("keywords")),
        "checks.deface": b(checks.get("deface")),
        "checks.rkn_block": b(checks.get("rkn_block")),
        "checks.rkn_domain": b(checks.get("rkn_domain")),
        "checks.rkn_ip": b(checks.get("rkn_ip")),
        "checks.whois": b(checks.get("whois")),
        "checks.ip_blacklist": b(checks.get("ip_blacklist")),
        "checks.ip_change": b(checks.get("ip_change")),
        "checks.malware": b(checks.get("malware")),
        "checks.ports": b(checks.get("ports")),
        "keywords": (json.dumps(override["keywords"], ensure_ascii=False)
                     if override.get("keywords") is not None else ""),
        "ports": (json.dumps(override["ports"], ensure_ascii=False)
                  if override.get("ports") is not None else ""),
        "http_timeout_s": str(override["http_timeout_s"]) if override.get("http_timeout_s") is not None else "",
        "latency_warn_ms": str(override["latency_warn_ms"]) if override.get("latency_warn_ms") is not None else "",
        "latency_crit_ms": str(override["latency_crit_ms"]) if override.get("latency_crit_ms") is not None else "",
        "tls_warn_days": str(override["tls_warn_days"]) if override.get("tls_warn_days") is not None else "",
        "proxy": (override["proxy"] if override["proxy"] is not None else "off") if "proxy" in override else "",
        "interval_minutes": str(override["interval_minutes"]) if override.get("interval_minutes") is not None else "",
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
        raw = row.get(name, "")
        value = _is_truthy(raw)
        if raw.strip() and value is None:
            raise ValueError("Invalid check flag")
        return value

    checks: Dict[str, bool] = {}
    for key in (
        "checks.http_basic", "checks.tls_cert", "checks.ping", "checks.keywords",
        "checks.deface",
        "checks.rkn_block", "checks.rkn_domain", "checks.rkn_ip",
        "checks.whois", "checks.ip_blacklist", "checks.ip_change",
        "checks.malware",
        "checks.ports"
    ):
        val = pb(key)
        if val is not None:
            # store as inner key without "checks."
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
        proxy = None  # merge mode: ignored below; replace mode: will clear if included
    elif proxy_raw.lower() in {"-", "none", "null", "off"}:
        proxy = None
    else:
        proxy = proxy_raw

    # Assemble override; include only provided values in merge mode
    ov: Dict = {}
    if checks:
        ov["checks"] = ChecksModel.model_validate(checks).model_dump(exclude_unset=True)
    if mode == "replace":
        ov["keywords"] = kws if kws is not None else []
        ov["ports"] = ports if ports is not None else []
        ov["proxy"] = proxy  # may be None to clear
    else:
        # merge: only include fields explicitly provided and non-empty
        if kws is not None and (len(kws) > 0 or row.get("keywords", "").strip() == "[]"):
            ov["keywords"] = kws
        if ports is not None and (len(ports) > 0 or row.get("ports", "").strip() == "[]"):
            ov["ports"] = ports
        if proxy_raw != "":
            ov["proxy"] = proxy

    for key, value in {
        "http_timeout_s": http_timeout_s,
        "latency_warn_ms": latency_warn_ms,
        "latency_crit_ms": latency_crit_ms,
        "tls_warn_days": tls_warn_days,
        "interval_minutes": interval_minutes,
    }.items():
        if value is not None:
            ov[key] = value
    return ov


def import_domains_csv(owner_id: int, data: bytes, *, mode: str = "merge", cfg: AppConfig | None = None) -> ImportReport:
    """Import domains and overrides from CSV bytes. Mode: 'merge' or 'replace'."""
    if mode not in {"merge", "replace"}:
        raise ValueError("mode must be 'merge' or 'replace'")

    # Decode with UTF-8-SIG to strip BOM if present.
    text = data.decode("utf-8-sig", errors="strict")
    f = io.StringIO(text)
    reader = csv.reader(f, delimiter=";")

    # Read first row: detect header
    try:
        first = next(reader)
    except StopIteration:
        return ImportReport(added=0, updated=0, skipped=0, errors=["empty CSV"])

    has_header = len(first) >= 1 and first[0] == "domain"
    if has_header:
        header = first
        if tuple(header) not in (HEADERS, LEGACY_HEADERS):
            # Enforce exact header match to avoid accidental misalignment
            return ImportReport(errors=["invalid header; expected exact predefined header"], added=0, updated=0, skipped=0)
    else:
        # No header line; rewind to process this row as data.
        f.seek(0)
        reader = csv.reader(f, delimiter=";")

    report = ImportReport()

    # Enumerate with correct line numbers (1-based; header is line 1 if present)
    start_line = 2 if has_header else 1
    for line_no, row in enumerate(reader, start=start_line):
        # Skip empty lines
        if not row or (len(row) == 1 and (row[0] or "").strip() == ""):
            continue
        columns = tuple(header) if has_header else (
            HEADERS if len(row) >= len(HEADERS) else LEGACY_HEADERS)
        if len(row) < len(columns):
            report.skipped += 1
            msg = f"line {line_no}: not enough columns"
            report.details.append(RowResult(domain="", status="skipped", error=msg))
            report.errors.append(msg)
            continue

        # Map columns by fixed positions
        data_map = dict(zip(columns, row, strict=False))
        raw_domain = data_map["domain"]
        try:
            domain = _normalize_domain(raw_domain)
        except Exception as e:
            report.skipped += 1
            msg = f"line {line_no}: domain '{raw_domain}': {e}"
            report.details.append(RowResult(domain=raw_domain, status="skipped", error=msg))
            report.errors.append(msg)
            continue

        # Validate against the same revision that will be written atomically.
        try:
            existed = storage.domain_exists(owner_id, domain)
            current = storage.get_domain_override(owner_id, domain) if mode == "merge" and existed else None
            override = _build_override_from_row(data_map, mode=mode)
            validate_domain_override(
                cfg if cfg is not None else AppConfig(), domain, override, current,
            )
            if override:
                storage.set_domain_override(
                    owner_id, domain, override, replace=(mode == "replace"), create_missing=True,
                    create_only=not existed,
                    expected_revision=storage.domain_override_revision(current)
                    if mode == "merge" and existed else None,
                )
            elif not existed:
                storage.add_domain(owner_id, domain)
        except ValueError as e:
            report.skipped += 1
            msg = f"line {line_no}: {domain}: {validation_message(e)}"
            report.details.append(RowResult(domain=domain, status="skipped", error=msg))
            report.errors.append(msg)
            continue

        if not existed:
            report.added += 1
            report.details.append(RowResult(domain=domain, status="added"))
        else:
            if override:
                report.updated += 1
                report.details.append(RowResult(domain=domain, status="updated"))
            else:
                # No changes were provided for this existing domain
                report.skipped += 1
                report.details.append(RowResult(domain=domain, status="skipped", error="no changes"))
                report.errors.append(f"line {line_no}: {domain}: no changes")

    return report
