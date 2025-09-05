# sitewatcher/checks/base.py
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional

# Public API surface
__all__ = ["Status", "CheckOutcome", "BaseCheck", "Metrics"]

# Convenient alias for metrics payloads
Metrics = Dict[str, Any]


class Status(str, Enum):
    """Normalized check status values."""
    OK = "OK"
    WARN = "WARN"
    CRIT = "CRIT"
    UNKNOWN = "UNKNOWN"

    def weight(self) -> int:
        """Numeric severity for easy comparisons/sorting (CRIT=2, WARN/UNKNOWN=1, OK=0)."""
        if self is Status.CRIT:
            return 2
        if self in (Status.WARN, Status.UNKNOWN):
            return 1
        return 0


@dataclass(slots=True)
class CheckOutcome:
    """Result of a single check run."""
    check: str
    status: Status
    message: str
    metrics: Metrics = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Be tolerant: allow status to be passed as a plain string (e.g. when loading from DB).
        if isinstance(self.status, str):
            try:
                self.status = Status(self.status)
            except ValueError:
                self.status = Status.UNKNOWN
        # Normalize message to str and guard against None/invalid metrics.
        self.message = "" if self.message is None else str(self.message)
        if not isinstance(self.metrics, dict):
            self.metrics = {}

    def as_dict(self) -> Dict[str, Any]:
        """Lossless dict representation (useful for JSON logging/serialization)."""
        return {
            "check": self.check,
            "status": str(self.status),
            "message": self.message,
            "metrics": self.metrics,
        }


class BaseCheck:
    """Base class for all checks. Subclasses must set `name` and implement `run()`."""
    name: str = "base"

    def __init__(self, domain: str, **kwargs: Any) -> None:
        self.domain = domain
        # Keep optional constructor kwargs for subclasses that want to access extras.
        self.kwargs = kwargs
        # Per-check logger with a consistent namespace.
        self.log = logging.getLogger(f"sitewatcher.check.{self.name}")

    @property
    def run_id(self) -> Optional[str]:
        """Optional correlation id (if Dispatcher provided it)."""
        rid = self.kwargs.get("run_id")
        return str(rid) if rid is not None else None

    async def run(self) -> CheckOutcome:
        """Execute the check and return a normalized CheckOutcome."""
        raise NotImplementedError
