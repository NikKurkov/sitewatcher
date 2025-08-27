# /checks/base.py
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional

__all__ = ["Status", "CheckOutcome", "BaseCheck"]


class Status(str, Enum):
    """Normalized check status values."""
    OK = "OK"
    WARN = "WARN"
    CRIT = "CRIT"
    UNKNOWN = "UNKNOWN"


@dataclass(slots=True)
class CheckOutcome:
    """Result of a single check run."""
    check: str
    status: Status
    message: str
    metrics: Dict[str, Any]

    def __post_init__(self) -> None:
        # Be tolerant: allow status to be passed as a plain string (e.g. when loading from DB).
        if isinstance(self.status, str):
            try:
                self.status = Status(self.status)
            except ValueError:
                self.status = Status.UNKNOWN
        # Guard against None/invalid metrics.
        if not isinstance(self.metrics, dict):
            self.metrics = {}


class BaseCheck:
    """Base class for all checks. Subclasses must set `name` and implement `run()`."""
    name: str = "base"

    def __init__(self, domain: str, **kwargs: Any) -> None:
        self.domain = domain
        # Keep optional constructor kwargs for subclasses that want to access extras.
        self.kwargs = kwargs

    async def run(self) -> CheckOutcome:
        """Execute the check and return a normalized CheckOutcome."""
        raise NotImplementedError
