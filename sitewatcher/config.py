# sitewatcher/config.py
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Literal, Union

import yaml
from pydantic import BaseModel, Field


# -------------------------- Checks & Schedules --------------------------

class ChecksModel(BaseModel):
    """Feature flags for individual checks."""
    http_basic: bool = True
    tls_cert: bool = True
    keywords: bool = False
    deface: bool = False
    ping: bool = True
    rkn_block: bool = False
    ports: bool = False
    whois: bool = True
    ip_blacklist: bool = False
    ip_change: bool = True


class CheckSchedule(BaseModel):
    """
    Scheduler policy for a single check.

    interval_minutes: how often background runner should execute the check
    cache_ttl_minutes: how long manual runs (/check) may serve cached results (0 = disabled)
    """
    interval_minutes: int
    cache_ttl_minutes: int = 0


class SchedulesConfig(BaseModel):
    # Default intervals (tweak in YAML if needed)
    http_basic:   CheckSchedule = CheckSchedule(interval_minutes=5,  cache_ttl_minutes=2)
    tls_cert:     CheckSchedule = CheckSchedule(interval_minutes=60, cache_ttl_minutes=30)
    keywords:     CheckSchedule = CheckSchedule(interval_minutes=10, cache_ttl_minutes=5)
    deface:       CheckSchedule = CheckSchedule(interval_minutes=15, cache_ttl_minutes=5)
    ping:         CheckSchedule = CheckSchedule(interval_minutes=5,  cache_ttl_minutes=0)
    rkn_block:    CheckSchedule = CheckSchedule(interval_minutes=30, cache_ttl_minutes=10)
    ports:        CheckSchedule = CheckSchedule(interval_minutes=15, cache_ttl_minutes=0)
    whois:        CheckSchedule = CheckSchedule(interval_minutes=360, cache_ttl_minutes=60)
    ip_blacklist: CheckSchedule = CheckSchedule(interval_minutes=60, cache_ttl_minutes=30)
    ip_change:    CheckSchedule = CheckSchedule(interval_minutes=60, cache_ttl_minutes=30)


class SchedulerConfig(BaseModel):
    """
    Global scheduler settings.
    - domains_concurrency: max in-flight domains for background runs
    - per_domain_concurrency: concurrent checks per single domain
    - domain_timeout_s: optional overall timeout per domain execution
    """
    enabled: bool = True
    interval_minutes: int = 10
    jitter_seconds: int = 30
    run_on_startup: bool = True
    domains_concurrency: int = 5
    per_domain_concurrency: int = 4
    domain_timeout_s: float | None = None


class AlertsConfig(BaseModel):
    """Alerting policy and routing."""
    enabled: bool = True
    policy: Literal["overall_change", "worsen_only", "all"] = "overall_change"
    # Support both names; alerts code already checks cooldown_sec/debounce_sec
    debounce_sec: int | None = 300
    cooldown_sec: int | None = None
    chat_id: Optional[int] = None


class IpChangeConfig(BaseModel):
    """IP change tracking options used by checks/ip_change.py."""
    refresh_hours: int = 24          # how long to keep last IPs before considering change
    include_ipv6: bool = False       # also track IPv6 addresses


class PortSpec(BaseModel):
    """A single TCP port target entry."""
    port: int
    tls: bool = False
    timeout_s: Optional[float] = None
    read_bytes: Optional[int] = None


class PortsConfig(BaseModel):
    """TCP ports probing defaults and targets."""
    connect_timeout_s: float = 3.0
    read_timeout_s: float = 2.0
    read_bytes: int = 128
    targets: List[PortSpec] = Field(
        default_factory=lambda: [
            PortSpec(port=80),
            PortSpec(port=443, tls=True),
            PortSpec(port=22),
            PortSpec(port=25),
        ]
    )


class RknConfig(BaseModel):
    """RKN (zapret-info) source configuration."""
    source: Literal["z-i"] = "z-i"
    # Local SQLite index path; if None -> <package data>/z_i_index.db
    index_db_path: Optional[str] = None
    # Upstream dump URL (csv or csv.gz)
    z_i_url: str = "https://raw.githubusercontent.com/zapret-info/z-i/master/dump.csv.gz"
    # Refresh policy
    cache_ttl_hours: int = 12
    match_subdomains: bool = True
    check_ip: bool = True


class WhoisConfig(BaseModel):
    """WHOIS/RDAP configuration."""
    rdap_endpoint: str = "https://rdap.org/domain/{domain}"
    timeout_s: float = 30.0
    refresh_hours: int = 24
    expiry_warn_days: int = 30
    expiry_crit_days: int = 7
    # Raw WHOIS overrides for specific TLDs (e.g., {"ru": {"method": "whois", "host": "whois.tcinet.ru"}})
    tld_overrides: Dict[str, Dict[str, str]] = Field(default_factory=dict)


class HttpClientConfig(BaseModel):
    """Optional HTTP client tuning for httpx.AsyncClient."""
    connect_timeout: float = 5.0
    read_timeout: float = 10.0
    write_timeout: float = 10.0
    pool_timeout: float = 5.0
    max_connections: int = 100
    max_keepalive_connections: int = 20
    proxy: Optional[str] = None
    # optional mapping support; Dispatcher умеет работать с `proxies` как mounts
    proxies: Optional[Dict[str, str]] = None


class Defaults(BaseModel):
    """Global defaults for checks."""
    http_timeout_s: int = 10
    latency_warn_ms: int = 800
    latency_crit_ms: int = 2000
    tls_warn_days: int = 30
    proxy: Optional[str] = None
    keywords: List[str] = Field(default_factory=list)
    checks: ChecksModel = ChecksModel()


class DomainConfig(BaseModel):
    """Per-domain overrides."""
    name: str
    latency_warn_ms: Optional[int] = None
    latency_crit_ms: Optional[int] = None
    tls_warn_days: Optional[int] = None
    proxy: Optional[str] = None
    keywords: Optional[List[str]] = None
    checks: Optional[ChecksModel] = None
    ports: Optional[List[PortSpec]] = None


class IpBlConfig(BaseModel):
    """DNSBL/RBL config."""
    zones: List[str] = Field(default_factory=list)
    dns_servers: Optional[List[str]] = None
    timeout_s: float = 2.0
    concurrency: int = 50
    check_ipv6: bool = False


class AppConfig(BaseModel):
    """Top-level application configuration."""
    defaults: Defaults = Defaults()
    schedules: SchedulesConfig = SchedulesConfig()
    scheduler: SchedulerConfig = SchedulerConfig()
    alerts: AlertsConfig = AlertsConfig()
    ipchange: IpChangeConfig = IpChangeConfig()
    ipbl: IpBlConfig = Field(default_factory=lambda: IpBlConfig())
    ports: PortsConfig = PortsConfig()
    whois: WhoisConfig = WhoisConfig()
    rkn: RknConfig = RknConfig()
    http: Optional[HttpClientConfig] = None
    # simple container for deface config
    deface: "DefaceConfig" = Field(default_factory=lambda: DefaceConfig())
    domains: List[DomainConfig] = Field(default_factory=list)


class DefaceConfig(BaseModel):
    phrases_path: Optional[str] = None  # e.g., "sitewatcher/data/deface_markers.txt"


# -------------------------- Load/resolve helpers --------------------------

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent / "data" / "config.yaml"


def load_config(path: Optional[Union[str, os.PathLike, Path]] = None) -> AppConfig:
    """
    Load YAML config from a given path or the package default.
    Raises FileNotFoundError if the file does not exist.
    """
    cfg_path = Path(path) if path is not None else DEFAULT_CONFIG_PATH
    if not cfg_path.exists():
        raise FileNotFoundError(f"Config not found: {cfg_path}")
    with open(cfg_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return AppConfig.model_validate(data)


@dataclass
class ResolvedSettings:
    """
    Minimal resolved view consumed by checks/dispatcher.
    """
    name: str
    http_timeout_s: int
    latency_warn_ms: int
    latency_crit_ms: int
    tls_warn_days: int
    proxy: Optional[str]
    keywords: List[str]
    checks: ChecksModel
    ports: Optional[List[PortSpec]]


def resolve_settings(cfg: AppConfig, domain: str) -> ResolvedSettings:
    """
    Merge global defaults with per-domain overrides for a given domain.
    Only the fields used by checks are resolved here.
    """
    dom = next((d for d in cfg.domains if d.name.lower() == domain.lower()), None)
    defaults = cfg.defaults

    return ResolvedSettings(
        name=domain,
        http_timeout_s=defaults.http_timeout_s,
        latency_warn_ms=dom.latency_warn_ms if dom and dom.latency_warn_ms is not None else defaults.latency_warn_ms,
        latency_crit_ms=dom.latency_crit_ms if dom and dom.latency_crit_ms is not None else defaults.latency_crit_ms,
        tls_warn_days=dom.tls_warn_days if dom and dom.tls_warn_days is not None else defaults.tls_warn_days,
        proxy=(dom.proxy if dom and dom.proxy is not None else defaults.proxy),
        keywords=(dom.keywords if dom and dom.keywords is not None else defaults.keywords),
        checks=(dom.checks if dom and dom.checks is not None else defaults.checks),
        ports=(dom.ports if dom and dom.ports is not None else None),
    )


def get_bot_token_from_env() -> Optional[str]:
    """Best-effort Telegram token reader (returns None if unset)."""
    return os.getenv("TELEGRAM_TOKEN")


# -------------------------- Validation helpers --------------------------

def validate_config(cfg: AppConfig) -> None:
    """Validate runtime-critical config invariants. Raise ValueError with a summary on failure."""
    errors: list[str] = []

    # Scheduler
    if cfg.scheduler.interval_minutes <= 0:
        errors.append("scheduler.interval_minutes must be > 0")
    if cfg.scheduler.domains_concurrency < 1:
        errors.append("scheduler.domains_concurrency must be >= 1")
    if cfg.scheduler.per_domain_concurrency < 1:
        errors.append("scheduler.per_domain_concurrency must be >= 1")
    if cfg.scheduler.domain_timeout_s is not None and cfg.scheduler.domain_timeout_s <= 0:
        errors.append("scheduler.domain_timeout_s must be > 0 or null")
    if cfg.scheduler.jitter_seconds < 0:
        errors.append("scheduler.jitter_seconds must be >= 0")

    # Alerts
    if cfg.alerts.debounce_sec is not None and cfg.alerts.debounce_sec < 0:
        errors.append("alerts.debounce_sec must be >= 0")
    if cfg.alerts.cooldown_sec is not None and cfg.alerts.cooldown_sec < 0:
        errors.append("alerts.cooldown_sec must be >= 0")

    # Defaults sanity
    if cfg.defaults.http_timeout_s <= 0:
        errors.append("defaults.http_timeout_s must be > 0")
    if cfg.defaults.latency_warn_ms <= 0:
        errors.append("defaults.latency_warn_ms must be > 0")
    if cfg.defaults.latency_crit_ms <= 0:
        errors.append("defaults.latency_crit_ms must be > 0")
    if cfg.defaults.latency_crit_ms < cfg.defaults.latency_warn_ms:
        errors.append("defaults.latency_crit_ms must be >= defaults.latency_warn_ms")
    if cfg.defaults.tls_warn_days < 0:
        errors.append("defaults.tls_warn_days must be >= 0")

    # Schedules (all checks)
    schedules = cfg.schedules.model_dump()
    for name, sch in schedules.items():
        iv = int(sch.get("interval_minutes", 0) or 0)
        ttl = int(sch.get("cache_ttl_minutes", 0) or 0)
        if iv <= 0:
            errors.append(f"schedules.{name}.interval_minutes must be > 0")
        if ttl < 0:
            errors.append(f"schedules.{name}.cache_ttl_minutes must be >= 0")

    # Ports defaults and targets
    if cfg.ports.connect_timeout_s <= 0:
        errors.append("ports.connect_timeout_s must be > 0")
    if cfg.ports.read_timeout_s <= 0:
        errors.append("ports.read_timeout_s must be > 0")
    if cfg.ports.read_bytes <= 0:
        errors.append("ports.read_bytes must be > 0")
    for i, tgt in enumerate(cfg.ports.targets):
        p = int(getattr(tgt, "port", 0) or 0)
        if not (1 <= p <= 65535):
            errors.append(f"ports.targets[{i}] port must be in 1..65535")
        ts = getattr(tgt, "timeout_s", None)
        if ts is not None and ts <= 0:
            errors.append(f"ports.targets[{i}].timeout_s must be > 0 if set")

    # IpBL
    if cfg.ipbl.timeout_s <= 0:
        errors.append("ipbl.timeout_s must be > 0")
    if cfg.ipbl.concurrency < 1:
        errors.append("ipbl.concurrency must be >= 1")
    if cfg.ipbl.dns_servers is not None:
        for i, s in enumerate(cfg.ipbl.dns_servers):
            if not str(s).strip():
                errors.append(f"ipbl.dns_servers[{i}] must be a non-empty string")

    # Whois
    if cfg.whois.refresh_hours <= 0:
        errors.append("whois.refresh_hours must be > 0")
    if cfg.whois.expiry_warn_days < 0:
        errors.append("whois.expiry_warn_days must be >= 0")
    if cfg.whois.expiry_crit_days < 0:
        errors.append("whois.expiry_crit_days must be >= 0")
    if cfg.whois.expiry_crit_days > cfg.whois.expiry_warn_days:
        errors.append("whois.expiry_crit_days must be <= whois.expiry_warn_days")

    # HTTP client tuning (if present)
    if cfg.http is not None:
        if cfg.http.connect_timeout <= 0:
            errors.append("http.connect_timeout must be > 0")
        if cfg.http.read_timeout <= 0:
            errors.append("http.read_timeout must be > 0")
        if cfg.http.write_timeout <= 0:
            errors.append("http.write_timeout must be > 0")
        if cfg.http.pool_timeout <= 0:
            errors.append("http.pool_timeout must be > 0")
        if cfg.http.max_connections < 1:
            errors.append("http.max_connections must be >= 1")
        if cfg.http.max_keepalive_connections < 0:
            errors.append("http.max_keepalive_connections must be >= 0")

    # Deface markers file (optional)
    if getattr(cfg.deface, "phrases_path", None):
        p = Path(cfg.deface.phrases_path)
        if not p.exists():
            errors.append(f"deface.phrases_path does not exist: {p}")
        elif not p.is_file():
            errors.append(f"deface.phrases_path must be a file: {p}")

    # Per-domain overrides (ports sanity)
    for i, dom in enumerate(cfg.domains):
        if not dom.name or not str(dom.name).strip():
            errors.append(f"domains[{i}].name must be a non-empty string")
        if getattr(dom, "ports", None):
            for j, tgt in enumerate(dom.ports):
                p = int(getattr(tgt, "port", 0) or 0)
                if not (1 <= p <= 65535):
                    errors.append(f"domains[{i}].ports[{j}] port must be in 1..65535")
                ts = getattr(tgt, "timeout_s", None)
                if ts is not None and ts <= 0:
                    errors.append(f"domains[{i}].ports[{j}].timeout_s must be > 0 if set")

    if errors:
        lines = "\n  - " + "\n  - ".join(errors)
        raise ValueError(f"Invalid configuration:{lines}")
