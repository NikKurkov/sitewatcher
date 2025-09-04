# sitewatcher/logging_setup.py
from __future__ import annotations

import logging
import logging.config
import os
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Mapping, Optional


# -------- Helpers: formatters & filters --------

class UTCFormatter(logging.Formatter):
    """Formatter that emits UTC ISO-8601 timestamps with milliseconds."""
    default_msec_format = "%s.%03d"

    def formatTime(self, record: logging.LogRecord, datefmt: Optional[str] = None) -> str:
        dt = datetime.fromtimestamp(record.created, tz=timezone.utc)
        if datefmt:
            return dt.strftime(datefmt)
        # Example: 2025-09-03T10:15:30.123Z
        return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


class JsonFormatter(logging.Formatter):
    """Lightweight JSON formatter without external deps."""
    _STD_KEYS = {
        "name", "msg", "args", "levelname", "levelno", "pathname",
        "filename", "module", "exc_info", "exc_text", "stack_info",
        "lineno", "funcName", "created", "msecs", "relativeCreated",
        "thread", "threadName", "processName", "process",
    }

    def __init__(self, *, ensure_ascii: bool = False, include_fields: Optional[Iterable[str]] = None):
        super().__init__()
        import json  # local import to avoid global dependency if unused
        self._json = json
        self.ensure_ascii = ensure_ascii
        self.include_fields = list(include_fields or [])

    def format(self, record: logging.LogRecord) -> str:
        # Base fields
        payload: Dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc)
                                 .isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "line": record.lineno,
            "pid": os.getpid(),
            "thread": record.thread,
        }

        # Custom extras passed via `extra=...`
        for k, v in record.__dict__.items():
            if k not in self._STD_KEYS and k not in payload and not k.startswith("_"):
                payload[k] = v

        # Exceptions
        if record.exc_info:
            # Render exception as single string (type: message\nstack)
            payload["exception"] = self.formatException(record.exc_info)

        # Order output fields if include_fields specified
        if self.include_fields:
            ordered: Dict[str, Any] = {}
            for key in self.include_fields:
                if key in payload:
                    ordered[key] = payload[key]
            # Append leftovers to preserve data
            for k, v in payload.items():
                if k not in ordered:
                    ordered[k] = v
            payload = ordered

        return self._json.dumps(payload, ensure_ascii=self.ensure_ascii, separators=(",", ":"))


class StructExtraFilter(logging.Filter):
    """Derive a compact one-line JSON tail with structured extras for pretty output.

    - Collects non-standard LogRecord attributes (i.e., those passed via `extra=`).
    - Stores them in `record._extra_dict` (internal) and renders `record.extra_tail`
      as a space-prefixed JSON string (or empty string if no extras).
    - This keeps pretty logs readable, while JSON logs use JsonFormatter above.
    """

    _STD_KEYS = set(vars(logging.LogRecord("", 0, "", 0, "", (), None)).keys()) | {
        "msg", "args", "exc_info", "exc_text", "stack_info"
    }

    def __init__(self, pretty_mode: bool = True) -> None:
        super().__init__()
        self.pretty_mode = pretty_mode
        try:
            import json
        except Exception:  # pragma: no cover
            json = None  # type: ignore
        self._json = json

    def filter(self, record: logging.LogRecord) -> bool:
        extras: Dict[str, Any] = {}
        for k, v in record.__dict__.items():
            if k in self._STD_KEYS or k.startswith("_"):
                continue
            # Skip attributes that are typically in base/formatters
            if k in {"levelname", "levelno", "name", "pathname", "filename", "module",
                     "lineno", "funcName", "created", "msecs", "relativeCreated",
                     "thread", "threadName", "processName", "process"}:
                continue
            extras[k] = v
        setattr(record, "_extra_dict", extras)
        if self.pretty_mode and self._json:
            tail = (" " + self._json.dumps(extras, ensure_ascii=False, separators=(",", ":"))) if extras else ""
        else:
            tail = ""
        # Always set attribute to avoid KeyError in format strings
        setattr(record, "extra_tail", tail)
        return True


# -------- Public API --------

def setup_logging(logging_cfg: Any | None) -> None:
    """
    Initialize logging using dictConfig based on provided config object/dict.
    Safe to call multiple times; reconfigures logging in-place.
    """
    cfg = _normalize_cfg(logging_cfg)

    if not cfg["enabled"]:
        # Disable all logging if explicitly turned off
        logging.disable(logging.CRITICAL)
        return

    # Create log directory if file destination selected
    if cfg["destination"] == "file":
        log_path = cfg["file"]["path"]
        if log_path:
            os.makedirs(os.path.dirname(os.path.abspath(log_path)), exist_ok=True)

    dict_cfg = _build_dict_config(cfg)
    logging.config.dictConfig(dict_cfg)

    # Lower verbosity of noisy third-party loggers
    for logger_name, level in cfg.get("third_party_levels", {}).items():
        if not logger_name:
            continue
        logging.getLogger(logger_name).setLevel(level)

    # Self-check line to confirm configuration at startup
    logging.getLogger("sitewatcher.logging").info(
        "logging.configured",
        extra={
            "event": "logging.configured",
            "destination": cfg["destination"],
            "format": cfg["format"],
            "level": cfg["level"],
            "file_path": cfg["file"]["path"] if cfg["destination"] == "file" else None,
            "pretty_rich": bool(cfg["pretty"]["use_rich"]) if cfg["format"] == "pretty" else None,
        },
    )


# -------- Internal: config building --------

def _normalize_cfg(logging_cfg: Any | None) -> Dict[str, Any]:
    """Accept dataclass, mapping or None. Fill in safe defaults."""
    default = {
        "enabled": True,
        "level": "INFO",                     # DEBUG|INFO|WARNING|ERROR
        "destination": "console",            # console|file
        "format": "pretty",                  # pretty|json
        "file": {
            "path": "./logs/sitewatcher.log",
            "rotate": "size",                # size|time
            "max_bytes": 10_000_000,
            "backup_count": 5,
            "when": "midnight",
            "interval": 1,
            "utc": True,
        },
        "pretty": {
            "use_rich": False,
            "show_path": False,
            "show_time": True,
        },
        "json": {
            "ensure_ascii": False,
            "include_fields": [
                "timestamp", "level", "logger", "message",
                "module", "line", "pid", "thread",
                "owner", "domain", "check", "run_id", "status",
            ],
        },
        "third_party_levels": {
            "httpx": "WARNING",
            "apscheduler": "INFO",
            "telegram": "WARNING",
        },
    }

    if logging_cfg is None:
        return default
    if is_dataclass(logging_cfg):
        return _deep_merge(default, asdict(logging_cfg))
    if isinstance(logging_cfg, Mapping):
        return _deep_merge(default, dict(logging_cfg))
    # Fallback: unexpected type
    return default


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base)
    for k, v in override.items():
        if isinstance(v, Mapping) and isinstance(out.get(k), Mapping):
            out[k] = _deep_merge(dict(out[k]), dict(v))
        else:
            out[k] = v
    return out


def _build_dict_config(cfg: Dict[str, Any]) -> Dict[str, Any]:
    level = cfg["level"].upper()
    destination = cfg["destination"]
    fmt = cfg["format"]

    # Formatters
    fmt_pretty = "%(asctime)s %(levelname)s %(name)s - %(message)s%(extra_tail)s"
    if cfg["pretty"]["show_path"]:
        fmt_pretty = "%(asctime)s %(levelname)s %(name)s [%(module)s:%(lineno)d] - %(message)s%(extra_tail)s"

    formatters: Dict[str, Any] = {
        "pretty": {
            "()": "sitewatcher.logging_setup.UTCFormatter",
            "format": fmt_pretty,
        },
        "pretty_rich": {
            # Rich prints time/level/path itself; append extras tail only
            "format": "%(message)s%(extra_tail)s",
        },
        "json": {
            "()": "sitewatcher.logging_setup.JsonFormatter",
            "ensure_ascii": cfg["json"]["ensure_ascii"],
            "include_fields": cfg["json"]["include_fields"],
        },
    }

    # Filters (inject extra_tail for pretty output)
    filters: Dict[str, Any] = {
        "struct": {
            "()": "sitewatcher.logging_setup.StructExtraFilter",
            "pretty_mode": (fmt == "pretty"),
        }
    }

    # Handlers
    handlers: Dict[str, Any] = {}

    # Console handler (Stream or Rich)
    use_rich = bool(cfg["pretty"]["use_rich"])
    rich_available = False
    if use_rich:
        try:
            import rich  # noqa: F401
            rich_available = True
        except Exception:
            rich_available = False

    if destination == "console":
        if use_rich and rich_available and fmt == "pretty":
            handlers["console"] = {
                "class": "rich.logging.RichHandler",
                "level": level,
                "formatter": "pretty_rich",
                "filters": ["struct"],
                "rich_tracebacks": True,
                "markup": False,
                "show_time": bool(cfg["pretty"]["show_time"]),
                "show_path": bool(cfg["pretty"]["show_path"]),
                "log_time_format": "[%Y-%m-%d %H:%M:%S]",
            }
        else:
            handlers["console"] = {
                "class": "logging.StreamHandler",
                "level": level,
                "formatter": "json" if fmt == "json" else "pretty",
                "filters": ["struct"],
                "stream": "ext://sys.stdout",
            }

    # File handler (Rotating/TimedRotating)
    if destination == "file":
        rotate = cfg["file"]["rotate"]
        filename = cfg["file"]["path"]
        if rotate == "time":
            handlers["file"] = {
                "class": "logging.handlers.TimedRotatingFileHandler",
                "level": level,
                "formatter": "json" if fmt == "json" else "pretty",
                "filters": ["struct"],
                "filename": filename,
                "when": cfg["file"]["when"],
                "interval": int(cfg["file"]["interval"]),
                "backupCount": int(cfg["file"]["backup_count"]),
                "utc": bool(cfg["file"]["utc"]),
                "encoding": "utf-8",
            }
        else:
            handlers["file"] = {
                "class": "logging.handlers.RotatingFileHandler",
                "level": level,
                "formatter": "json" if fmt == "json" else "pretty",
                "filters": ["struct"],
                "filename": filename,
                "maxBytes": int(cfg["file"]["max_bytes"]),
                "backupCount": int(cfg["file"]["backup_count"]),
                "encoding": "utf-8",
            }

    # Root logger targets
    root_handlers = ["console"] if destination == "console" else ["file"]

    dict_cfg = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": formatters,
        "filters": filters,
        "handlers": handlers,
        "root": {
            "level": level,
            "handlers": root_handlers,
        },
    }
    return dict_cfg
