from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

    @property
    def rank(self) -> int:
        """Higher = more severe. Used for sorting."""
        return _RANK[self]

    @property
    def weight(self) -> int:
        """Score penalty per finding (see core/scoring.py)."""
        return _WEIGHT[self]

    @property
    def color(self) -> str:
        """rich color name."""
        return _COLOR[self]

    @classmethod
    def parse(cls, value: str) -> "Severity":
        for s in cls:
            if s.value.lower() == value.strip().lower():
                return s
        raise ValueError(f"unknown severity: {value!r}")


_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}
_WEIGHT = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 12,
    Severity.MEDIUM: 6,
    Severity.LOW: 2,
    Severity.INFO: 0,
}
_COLOR = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}
