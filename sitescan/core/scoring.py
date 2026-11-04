"""Weighted 0-100 posture score.

Each severity has a per-finding penalty (Severity.weight) and a cap on the
total penalty that severity can contribute, so fifty Low findings can't
outweigh one Critical:

    severity   per-finding   cap
    Critical        25        60
    High            12        45
    Medium           6        30
    Low              2        12
    Info             0         0

score = max(0, 100 - sum(min(cap, count * weight)))

Grade: A >= 90, B >= 80, C >= 70, D >= 60, else F.
Any Critical finding caps the grade at D; any High caps it at C.
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Iterable

from .finding import Finding
from .severity import Severity

CAPS = {
    Severity.CRITICAL: 60,
    Severity.HIGH: 45,
    Severity.MEDIUM: 30,
    Severity.LOW: 12,
    Severity.INFO: 0,
}
GRADES = [(90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F")]
_ORDER = "ABCDF"


def severity_counts(findings: Iterable[Finding]) -> dict[Severity, int]:
    c = Counter(f.severity for f in findings)
    return {s: c.get(s, 0) for s in Severity}


def score(findings: Iterable[Finding]) -> int:
    counts = severity_counts(findings)
    penalty = sum(min(CAPS[s], n * s.weight) for s, n in counts.items())
    return max(0, 100 - penalty)


def grade(findings: Iterable[Finding]) -> str:
    findings = list(findings)
    s = score(findings)
    letter = next(g for floor, g in GRADES if s >= floor)
    counts = severity_counts(findings)
    if counts[Severity.CRITICAL]:
        letter = _worse(letter, "D")
    elif counts[Severity.HIGH]:
        letter = _worse(letter, "C")
    return letter


def _worse(a: str, b: str) -> str:
    return a if _ORDER.index(a) > _ORDER.index(b) else b
