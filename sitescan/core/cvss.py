"""Minimal CVSS v3.x base-score calculator (FIRST spec, section 7)."""
from __future__ import annotations

import math

from .severity import Severity

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def base_score(vector: str) -> float | None:
    try:
        parts = dict(p.split(":", 1) for p in vector.split("/")[1:])
        s = parts["S"]
        iss = 1 - (1 - _W["CIA"][parts["C"]]) * (1 - _W["CIA"][parts["I"]]) * (1 - _W["CIA"][parts["A"]])
        impact = 6.42 * iss if s == "U" else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        expl = 8.22 * _W["AV"][parts["AV"]] * _W["AC"][parts["AC"]] * _PR[s][parts["PR"]] * _W["UI"][parts["UI"]]
    except (KeyError, ValueError, IndexError):
        return None
    if impact <= 0:
        return 0.0
    total = impact + expl if s == "U" else 1.08 * (impact + expl)
    return _roundup(min(total, 10.0))


def severity_for(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO
