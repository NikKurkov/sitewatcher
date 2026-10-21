# sitewatcher/config.py
from __future__ import annotations

import os
import logging
import re
from copy import deepcopy
from dataclasses import dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import Dict, List, Optional, Literal, Union

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator
from urllib.parse import urlsplit

from .utils.domains import normalize_domain


# -------------------------- Checks & Schedules --------------------------

class ConfigModel(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True, allow_inf_nan=False)


class ConfigurationError(ValueError):
    """Actionable configuration errors containing only application-defined messages."""


def _validate_proxy(value: str | None) -> str | None:
    if value is None:
        return value
    try:
        parsed = urlsplit(value)
        if (parsed.scheme not in {"http", "https", "socks5", "socks5h"}
                or not parsed.hostname or any(char.isspace() for char in value)):
            raise ValueError
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError
    except ValueError:
        raise ValueError("proxy must be a supported URL with a host") from None
    return value


class ChecksModel(ConfigModel):
    model_config = ConfigDict(strict=True)
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
    malware: bool = False


class CheckSchedule(ConfigModel):
    """
    Scheduler policy for a single check.

    interval_minutes: how often background runner should execute the check
    cache_ttl_minutes: how long manual runs (/check) may serve cached results (0 = disabled)
    cache_unknown: optional, when True cached UNKNOWN may be served (default False)
    """
    interval_minutes: int
    cache_ttl_minutes: int = 0
    cache_unknown: bool = False


class SchedulesConfig(ConfigModel):
    # Default intervals (tweak in YAML if needed)
    http_basic:   CheckSchedule = CheckSchedule(interval_minutes=5,   cache_ttl_minutes=2)
    tls_cert:     CheckSchedule = CheckSchedule(interval_minutes=1440,  cache_ttl_minutes=1440)
    keywords:     CheckSchedule = CheckSchedule(interval_minutes=10,  cache_ttl_minutes=5)
    deface:       CheckSchedule = CheckSchedule(interval_minutes=15,  cache_ttl_minutes=5)
    ping:         CheckSchedule = CheckSchedule(interval_minutes=5,   cache_ttl_minutes=0)
    rkn_block:    CheckSchedule = CheckSchedule(interval_minutes=1440,  cache_ttl_minutes=1440)
    ports:        CheckSchedule = CheckSchedule(interval_minutes=60,  cache_ttl_minutes=0)
    # For whois we explicitly keep cache_unknown=False to avoid sticking on "no expiry info"
    whois:        CheckSchedule = CheckSchedule(interval_minutes=1440, cache_ttl_minutes=1440, cache_unknown=False)
    ip_blacklist: CheckSchedule = CheckSchedule(interval_minutes=1440,  cache_ttl_minutes=1440)
    ip_change:    CheckSchedule = CheckSchedule(interval_minutes=120,  cache_ttl_minutes=120)
    malware:      CheckSchedule = CheckSchedule(interval_minutes=1440,  cache_ttl_minutes=1440)


class SchedulerConfig(ConfigModel):
    """
    Global scheduler settings.
    - domains_concurrency: max in-flight domains for background runs
    - per_domain_concurrency: concurrent checks per single domain
    - domain_timeout_s: optional overall timeout per domain execution
    """
    enabled: bool = True
    interval_minutes: int = 1
    jitter_seconds: int = 30
    run_on_startup: bool = True
    domains_concurrency: int = 5
    per_domain_concurrency: int = 4
    domain_timeout_s: float | None = None


class AlertsConfig(ConfigModel):
    """Alerting policy and routing."""
    enabled: bool = True
    policy: Literal["overall_change", "worsen_only", "all"] = "overall_change"
    # Support both names; alerts code already checks cooldown_sec/debounce_sec
    debounce_sec: int | None = 300
    cooldown_sec: int | None = None
    chat_id: Optional[int] = None


    @property
    def effective_cooldown(self) -> int:
        """Explicit cooldown (including zero) takes precedence over the legacy name."""
        value = self.cooldown_sec if self.cooldown_sec is not None else self.debounce_sec
        return value if value is not None else 0


class IpChangeConfig(ConfigModel):
    """IP change tracking options used by checks/ip_change.py."""
    refresh_hours: int = Field(24, gt=0)          # how long to keep last IPs before considering change
    include_ipv6: bool = False       # also track IPv6 addresses
    db_path: Optional[str] = None    # optional custom sqlite path (default inside check)


class PortSpec(ConfigModel):
    """A single TCP port target entry."""
    port: int = Field(ge=1, le=65535)
    host: Optional[str] = None
    tls: bool = False
    send: Optional[str] = None
    expect: Optional[str] = None
    timeout_s: Optional[float] = Field(None, gt=0)
    read_bytes: Optional[int] = Field(None, gt=0)

    @field_validator("expect")
    @classmethod
    def valid_expectation(cls, value):
        if value:
            try:
                re.compile(value, flags=re.IGNORECASE | re.MULTILINE)
            except re.error:
                raise ValueError("expect must be a valid regular expression") from None
        return value


class PortsConfig(ConfigModel):
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


class RknConfig(ConfigModel):
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


class WhoisConfig(ConfigModel):
    """WHOIS/RDAP configuration."""
    rdap_endpoint: str = "https://rdap.org/domain/{domain}"
    timeout_s: float = 30.0
    refresh_hours: int = 24
    # New field used by checks/whois_info: primary threshold for WARN
    warn_days: int = 30
    # Backward-compat: keep old fields; not required by the new check but validated below
    expiry_warn_days: int = 30
    expiry_crit_days: int = 7
    # Raw WHOIS overrides for specific TLDs (e.g., {"ru": {"method": "whois", "host": "whois.tcinet.ru"}})
    tld_overrides: Dict[str, Dict[str, str]] = Field(default_factory=dict)
    # Optional sqlite cache path (used by the check if provided)
    db_path: Optional[str] = None
    # If RDAP lacks expiry (common for .RU/.SU/.РФ), fallback to WHOIS tcinet.ru
    fallback_whois_if_missing_expiry: bool = True


class HttpClientConfig(ConfigModel):
    """Optional HTTP client tuning for httpx.AsyncClient."""
    max_response_bytes: int = Field(8 * 1024 * 1024, gt=0)
    connect_timeout: float = 5.0
    read_timeout: float = 10.0
    write_timeout: float = 10.0
    pool_timeout: float = 5.0
    max_connections: int = 100
    max_keepalive_connections: int = 20
    proxy: Optional[str] = None
    # optional mapping support; Dispatcher умеет работать с `proxies` как mounts
    proxies: Optional[Dict[str, str]] = None

    _proxy = field_validator("proxy")(_validate_proxy)

    @field_validator("proxies")
    @classmethod
    def validate_proxy_mapping(cls, value):
        for scheme, proxy in (value or {}).items():
            if scheme.removesuffix("://") not in {"http", "https", "all"}:
                raise ValueError("proxy mappings must use http, https or all schemes")
            _validate_proxy(proxy)
        return value


class Defaults(ConfigModel):
    """Global defaults for checks."""
    http_timeout_s: int = Field(10, gt=0)
    latency_warn_ms: int = Field(800, ge=0)
    latency_crit_ms: int = Field(2000, ge=0)
    tls_warn_days: int = Field(30, ge=0)
    proxy: Optional[str] = None
    keywords: List[str] = Field(default_factory=list)
    checks: ChecksModel = ChecksModel()


    _proxy = field_validator("proxy")(_validate_proxy)

    @model_validator(mode="after")
    def check_latency_thresholds(self):
        if self.latency_crit_ms < self.latency_warn_ms:
            raise ValueError("latency_crit_ms must be >= latency_warn_ms")
        return self


class DomainOverride(ConfigModel):
    """Validated partial settings; missing fields inherit their configured value."""
    http_timeout_s: Optional[int] = Field(None, gt=0)
    interval_minutes: Optional[int] = Field(None, ge=0)
    latency_warn_ms: Optional[int] = Field(None, ge=0)
    latency_crit_ms: Optional[int] = Field(None, ge=0)
    tls_warn_days: Optional[int] = Field(None, ge=0)
    proxy: Optional[str] = None
    keywords: Optional[List[str]] = None
    checks: Optional[ChecksModel] = None
    ports: Optional[List[PortSpec]] = None

    _proxy = field_validator("proxy")(_validate_proxy)

    @field_validator("ports", mode="before")
    @classmethod
    def normalize_ports(cls, value):
        if isinstance(value, list):
            return [{"port": item} if isinstance(item, (int, str)) else item for item in value]
        return value


class DomainConfig(DomainOverride):
    name: str

    @field_validator("name")
    @classmethod
    def normalize_name(cls, value):
        name = normalize_domain(value)
        if not name:
            raise ValueError("Invalid domain")
        return name


class IpBlConfig(ConfigModel):
    """DNSBL/RBL config."""
    zones: List[str] = Field(default_factory=list)
    dns_servers: Optional[List[str]] = None
    timeout_s: float = 2.0
    concurrency: int = 50
    check_ipv6: bool = False


@dataclass
class LoggingFileConfig:
    __pydantic_config__ = ConfigDict(extra="forbid", hide_input_in_errors=True)
    path: str = "./logs/sitewatcher.log"
    rotate: Literal["size", "time"] = "size"         # "size" | "time"
    max_bytes: int = 10_000_000
    backup_count: int = 5
    when: str = "midnight"       # for time-based rotation
    interval: int = 1            # for time-based rotation
    utc: bool = True


@dataclass
class LoggingPrettyConfig:
    __pydantic_config__ = ConfigDict(extra="forbid", hide_input_in_errors=True)
    use_rich: bool = False
    show_path: bool = False
    show_time: bool = True


@dataclass
class LoggingJsonConfig:
    __pydantic_config__ = ConfigDict(extra="forbid", hide_input_in_errors=True)
    ensure_ascii: bool = False
    include_fields: List[str] = field(default_factory=lambda: [
        "timestamp", "level", "logger", "message",
        "module", "line", "pid", "thread",
        "owner", "domain", "check", "run_id", "status",
    ])


@dataclass
class LoggingConfig:
    __pydantic_config__ = ConfigDict(extra="forbid", hide_input_in_errors=True)
    enabled: bool = True
    level: str = "INFO"             # DEBUG|INFO|WARNING|ERROR
    destination: Literal["console", "file"] = "console"    # console|file
    format: Literal["pretty", "json"] = "pretty"          # pretty|json
    file: LoggingFileConfig = field(default_factory=LoggingFileConfig)
    pretty: LoggingPrettyConfig = field(default_factory=LoggingPrettyConfig)
    json: LoggingJsonConfig = field(default_factory=LoggingJsonConfig)
    third_party_levels: Dict[str, str] = field(default_factory=lambda: {
        "httpx": "WARNING",
        "apscheduler": "INFO",
        "telegram": "WARNING",
    })


class VTLimits(ConfigModel):
    """Rate limits for VirusTotal Free tier."""
    per_minute: int = 4
    per_day: int = 500
    per_month: int = 15500
    # How long we can wait in-place for the nearest window to free a slot.
    # If > 0, the checker may sleep briefly; if 0 -> return UNKNOWN immediately.
    max_wait_s: float = 2.0


class MalwareConfig(ConfigModel):
    """Malware reputation check (MVP: VirusTotal passive lookup)."""
    vt_api_key: Optional[str] = None  # VirusTotal API key (if unset -> provider unavailable)
    timeout_s: float = Field(10.0, gt=0)           # per-provider timeout
    follow_redirects: bool = True     # reserved for future URL resolution step
    vt_limits: VTLimits = VTLimits()  # strict rate limits for VT Free


class HistoryConfig(ConfigModel):
    """Retention and cleanup policy for history tables."""
    retention_days: int = 30          # keep last N days in history
    cleanup_time: str = "03:30"       # HH:MM UTC for daily cleanup job
    vacuum_weekly: bool = True        # run VACUUM/PRAGMA optimize weekly (Sunday)


class AppConfig(ConfigModel):
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
    deface: "DefaceConfig" = Field(default_factory=lambda: DefaceConfig())
    domains: List[DomainConfig] = Field(default_factory=list)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    malware: MalwareConfig = Field(default_factory=MalwareConfig)
    history: HistoryConfig = Field(default_factory=HistoryConfig)


class DefaceConfig(ConfigModel):
    phrases_path: Optional[str] = None  # e.g., "sitewatcher/data/deface_markers.txt"


# -------------------------- Load/resolve helpers --------------------------

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent / "data" / "config.yaml"


def load_config(path: Optional[Union[str, os.PathLike, Path]] = None) -> AppConfig:
    """
    Load YAML config from a given path or the package default.
    An absent default file means built-in defaults. An explicit path must exist.
    """
    cfg_path = Path(path) if path is not None else DEFAULT_CONFIG_PATH
    if not cfg_path.exists() and path is None:
        return AppConfig()
    if not cfg_path.exists():
        raise FileNotFoundError(f"Config not found: {cfg_path}")
    with open(cfg_path, "r", encoding="utf-8") as f:
        try:
            data = yaml.safe_load(f) or {}
        except yaml.YAMLError:
            raise ValueError("Invalid YAML configuration") from None
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
    interval_minutes: int | None = None


def resolve_settings(cfg: AppConfig, domain: str, override: Optional[dict] = None) -> ResolvedSettings:
    """
    Merge global defaults with per-domain overrides for a given domain.
    Only the fields used by checks are resolved here.
    """
    normalized = normalize_domain(domain)
    if not normalized:
        raise ValueError("Invalid domain")
    dom = next((d for d in cfg.domains if d.name == normalized), None)
    values = cfg.defaults.model_dump()
    ports = None
    interval = None
    if dom:
        domain_values = dom.model_dump(exclude_unset=True, exclude={"name"})
        domain_values = {key: value for key, value in domain_values.items() if value is not None}
        checks = domain_values.pop("checks", {})
        values["checks"].update(checks)
        values.update(domain_values)
    if override is not None:
        validated = DomainOverride.model_validate(override).model_dump(exclude_unset=True)
        validated = {
            key: value for key, value in validated.items() if value is not None or key == "proxy"
        }
        checks = validated.pop("checks", None)
        if checks is not None:
            values["checks"].update(checks)
        values.update(validated)
    ports = values.pop("ports", ports)
    interval = values.pop("interval_minutes", interval)
    validated_defaults = Defaults.model_validate(values)
    return ResolvedSettings(
        name=normalized,
        **validated_defaults.model_dump(exclude={"checks"}),
        checks=validated_defaults.checks,
        ports=[PortSpec.model_validate(port) for port in ports] if ports is not None else None,
        interval_minutes=interval,
    )


def validate_domain_override(
    cfg: AppConfig, domain: str, patch: dict, current: dict | None = None,
) -> dict:
    """Validate a merged patch while preserving its storage-compatible representation."""
    merged = deepcopy(current) if current is not None else {}
    if not isinstance(merged, dict) or not isinstance(patch, dict):
        raise ValueError("Domain override must be an object")
    for key, value in patch.items():
        if key == "checks" and isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key].update(deepcopy(value))
        else:
            merged[key] = deepcopy(value)
    resolve_settings(cfg, domain, merged)
    return merged


def validation_message(error: Exception) -> str:
    """Render validation diagnostics without raw values, credentials, or unknown field names."""
    if isinstance(error, ConfigurationError):
        return str(error)
    if isinstance(error, ValidationError):
        known_fields = set()
        for model in globals().values():
            if isinstance(model, type) and issubclass(model, ConfigModel):
                known_fields.update(model.model_fields)
            elif isinstance(model, type) and is_dataclass(model):
                known_fields.update(item.name for item in fields(model))
        messages = []
        for item in error.errors(include_input=False):
            location = ".".join(
                str(part) if isinstance(part, int) or part in known_fields else "<field>"
                for part in item["loc"]
            )
            messages.append(f"{location or '<settings>'}: {item['type']}")
        return "Invalid settings: " + "; ".join(
            dict.fromkeys(messages)
        )
    return "Invalid settings"


def get_bot_token_from_env() -> Optional[str]:
    """Best-effort Telegram token reader (returns None if unset)."""
    return os.getenv("TELEGRAM_TOKEN")


# -------------------------- Validation helpers --------------------------

def validate_config(cfg: AppConfig) -> None:
    """Validate runtime-critical config invariants. Raise ValueError with a summary on failure."""
    errors: list[str] = []

    # Rebuilding/removing the RKN index must never destroy persistent monitoring/cache state.
    from .checks.rkn_block_sqlite import rkn_index_path
    try:
        index_path = rkn_index_path(cfg.rkn).resolve()
        if any(path and index_path == Path(path).resolve()
               for path in (cfg.whois.db_path, cfg.ipchange.db_path)):
            raise ValueError
    except (OSError, ValueError):
        errors.append("rkn.index_db_path must be separate from monitoring, WHOIS and IP-change databases")

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
    if cfg.defaults.latency_warn_ms < 0:
        errors.append("defaults.latency_warn_ms must be >= 0")
    if cfg.defaults.latency_crit_ms < 0:
        errors.append("defaults.latency_crit_ms must be >= 0")
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
        # cache_unknown is optional bool; no strict validation needed

    # History / retention
    if cfg.history.retention_days < 0:
        errors.append("history.retention_days must be >= 0")

    # cleanup_time must be HH:MM within 24h
    ct = str(getattr(cfg.history, "cleanup_time", "03:30")).strip()
    try:
        hh, mm = [int(x) for x in ct.split(":", 1)]
        if not (0 <= hh <= 23 and 0 <= mm <= 59):
            raise ValueError
    except Exception:
        errors.append("history.cleanup_time must be in HH:MM format (00:00..23:59)")

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
    if cfg.whois.warn_days < 0:
        errors.append("whois.warn_days must be >= 0")
    # Back-compat validation (kept harmless even if unused by the check)
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

    # Malware / VT limits sanity
    try:
        lim = cfg.malware.vt_limits
        if lim.per_minute <= 0:
            errors.append("malware.vt_limits.per_minute must be > 0")
        if lim.per_day <= 0:
            errors.append("malware.vt_limits.per_day must be > 0")
        if lim.per_month <= 0:
            errors.append("malware.vt_limits.per_month must be > 0")
        if lim.per_month < lim.per_day:
            errors.append("malware.vt_limits.per_month must be >= per_day")
        if lim.max_wait_s < 0:
            errors.append("malware.vt_limits.max_wait_s must be >= 0")
    except Exception:
        errors.append("malware.vt_limits is invalid or missing")

    if cfg.ipchange.refresh_hours <= 0:
        errors.append("ipchange.refresh_hours must be > 0")
    if cfg.malware.timeout_s <= 0:
        errors.append("malware.timeout_s must be > 0")
    if cfg.logging.destination not in {"console", "file"}:
        errors.append("logging.destination must be console or file")
    levels = [cfg.logging.level, *cfg.logging.third_party_levels.values()]
    if any(not isinstance(level, str) or level.strip().upper() not in logging.getLevelNamesMapping()
           for level in levels):
        errors.append("logging levels must be standard names such as DEBUG, INFO or WARNING")
    if cfg.logging.file.interval <= 0:
        errors.append("logging.file.interval must be > 0")
    if cfg.logging.file.max_bytes < 0:
        errors.append("logging.file.max_bytes must be >= 0")
    if cfg.logging.file.backup_count < 0:
        errors.append("logging.file.backup_count must be >= 0")
    if cfg.logging.file.rotate == "time" and cfg.logging.file.when.strip().upper() not in {
        "S", "M", "H", "D", "MIDNIGHT", *(f"W{day}" for day in range(7)),
    }:
        errors.append("logging.file.when must be S, M, H, D, MIDNIGHT or W0..W6")
    if cfg.logging.destination == "file" and not cfg.logging.file.path.strip():
        errors.append("logging.file.path must be nonempty")

    # Deface markers file (optional)
    if getattr(cfg.deface, "phrases_path", None):
        p = Path(cfg.deface.phrases_path)
        if not p.exists():
            errors.append("deface.phrases_path does not exist")
        elif not p.is_file():
            errors.append("deface.phrases_path must be a file")

    # Per-domain overrides (ports sanity)
    for i, dom in enumerate(cfg.domains):
        try:
            resolve_settings(cfg, dom.name)
        except ValueError as error:
            errors.append(f"domains[{i}]: {validation_message(error)}")
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
        raise ConfigurationError(f"Invalid configuration:{lines}")
