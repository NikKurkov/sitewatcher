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
    ping: bool = True
    rkn_block: bool = True
    ports: bool = False
    whois: bool = True
    ip_blacklist: bool = False
    ip_change: bool = True


class CheckSchedule(BaseModel):
    """
    Scheduler policy for a single check.

    interval_minutes: how often background runner should execute the check
    cache_ttl_minutes: how long manual runs (/check_*) may serve cached results (0 = disabled)
    """
    interval_minutes: int
    cache_ttl_minutes: int = 0


class SchedulesConfig(BaseModel):
    # Use keyword args for Pydantic v2 compatibility
    http_basic:   CheckSchedule = Field(default_factory=lambda: CheckSchedule(interval_minutes=5,    cache_ttl_minutes=0))
    tls_cert:     CheckSchedule = Field(default_factory=lambda: CheckSchedule(interval_minutes=1440, cache_ttl_minutes=1440))
    keywords:     CheckSchedule = Field(default_factory=lambda: CheckSchedule(interval_minutes=60,   cache_ttl_minutes=0))
    ping:         CheckSchedule = Field(default_factory=lambda: CheckSchedule(interval_minutes=5,    cache_ttl_minutes=0))
    rkn_block:    CheckSchedule = Field(default_factory=lambda: CheckSchedule(interval_minutes=1440, cache_ttl_minutes=1440))
    ports:        CheckSchedule = Field(default_factory=lambda: CheckSchedule(interval_minutes=1440, cache_ttl_minutes=1440))
    whois:        CheckSchedule = Field(default_factory=lambda: CheckSchedule(interval_minutes=1440, cache_ttl_minutes=1440))
    ip_blacklist: CheckSchedule = Field(default_factory=lambda: CheckSchedule(interval_minutes=1440, cache_ttl_minutes=1440))
    ip_change:    CheckSchedule = Field(default_factory=lambda: CheckSchedule(interval_minutes=1440, cache_ttl_minutes=0))


# -------------------------- Runtime knobs --------------------------

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
    debounce_sec: int = 300
    chat_id: Optional[int] = None


class IpChangeConfig(BaseModel):
    """IP change tracking cache policy."""
    refresh_hours: int = 6
    include_ipv6: bool = True


class IpBLConfig(BaseModel):
    """DNSBL lookup settings."""
    zones: List[str] = Field(
        default_factory=lambda: [
            "zen.spamhaus.org",
            "dnsbl.dronebl.org",
            "rbl.efnetrbl.org",
        ]
    )
    dns_servers: Optional[List[str]] = None
    timeout_s: int = 3
    concurrency: int = 8
    check_ipv6: bool = False


class WhoisConfig(BaseModel):
    """RDAP/WHOIS resolution settings."""
    rdap_endpoint: str = "https://rdap.org/domain/{domain}"
    refresh_hours: int = 12
    expiry_warn_days: int = 30
    expiry_crit_days: int = 0
    track_fields: List[str] = Field(default_factory=lambda: ["registrar", "registrant", "nameservers", "status"])
    tld_overrides: Dict[str, Dict[str, str]] = Field(
        default_factory=lambda: {
            "ru": {"method": "whois", "host": "whois.tcinet.ru"},
            "xn--p1ai": {"method": "whois", "host": "whois.tcinet.ru"},  # .рф
            "su": {"method": "whois", "host": "whois.tcinet.ru"},
        }
    )


class PortSpec(BaseModel):
    """Single target specification for the ports check."""
    port: int
    host: Optional[str] = None
    tls: bool = False
    send: Optional[str] = None
    expect: Optional[str] = None
    timeout_s: Optional[int] = None


class PortsConfig(BaseModel):
    """Defaults for the ports check."""
    connect_timeout_s: int = 3
    read_timeout_s: int = 2
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
    z_i_url: str = "https://raw.githubusercontent.com/zapret-info/z-i/master/dump.csv.gz"
    cache_ttl_hours: int = 12
    index_db_path: str | None = None
    match_subdomains: bool = True
    check_ip: bool = True
    dns_timeout_s: int = 3


class HttpClientConfig(BaseModel):
    """
    Optional HTTP client tuning used by Dispatcher.
    Matches the fields Dispatcher reads; safe to omit entirely.
    """
    connect_timeout: float = 5.0
    read_timeout: float = 10.0
    write_timeout: float = 10.0
    pool_timeout: float = 5.0
    max_connections: int = 100
    max_keepalive_connections: int = 20
    proxy: Optional[str] = None  # currently unused in client ctor, kept for future


# -------------------------- Defaults, domains, root config --------------------------

class DefaultsModel(BaseModel):
    """Per-domain defaults applied unless overridden by a specific domain."""
    http_timeout_s: int = 5
    latency_warn_ms: int = 1000
    latency_crit_ms: int = 3000
    tls_warn_days: int = 14
    proxy: Optional[str] = None
    keywords: List[str] = Field(default_factory=list)
    checks: ChecksModel = Field(default_factory=ChecksModel)


class DomainModel(BaseModel):
    """Optional overrides for a specific domain."""
    name: str
    checks: Optional[ChecksModel] = None
    keywords: Optional[List[str]] = None
    latency_warn_ms: Optional[int] = None
    latency_crit_ms: Optional[int] = None
    tls_warn_days: Optional[int] = None
    proxy: Optional[str] = None
    ports: Optional[List[PortSpec]] = None


class AppConfig(BaseModel):
    """Top-level application config."""
    version: int = 1
    defaults: DefaultsModel = Field(default_factory=DefaultsModel)
    scheduler: SchedulerConfig = Field(default_factory=SchedulerConfig)  # single, not duplicated
    domains: List[DomainModel] = Field(default_factory=list)
    rkn: RknConfig = Field(default_factory=RknConfig)
    ports: PortsConfig = Field(default_factory=PortsConfig)
    whois: WhoisConfig = Field(default_factory=WhoisConfig)
    ipbl: IpBLConfig = Field(default_factory=IpBLConfig)
    ipchange: IpChangeConfig = Field(default_factory=IpChangeConfig)
    alerts: AlertsConfig = Field(default_factory=AlertsConfig)
    schedules: SchedulesConfig = Field(default_factory=SchedulesConfig)
    http: Optional[HttpClientConfig] = None  # optional client tuning


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
    Flattened domain settings consumed by checks/dispatcher.
    Keep only fields that are actually used at runtime.
    """
    name: str
    http_timeout_s: int
    latency_warn_ms: int
    latency_crit_ms: int
    tls_warn_days: int
    proxy: Optional[str]
    keywords: List[str]
    checks: ChecksModel
    ports: Optional[List[PortSpec]]  # include so dispatcher can read settings.ports safely


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
