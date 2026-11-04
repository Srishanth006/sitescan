"""Async orchestrator: runs every registered scanner concurrently, contains
failures, and assembles a ScanResult."""
from __future__ import annotations

import asyncio
import time
import traceback
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx

from .. import USER_AGENT, __version__
from .finding import Finding
from .http import HttpClient
from .ratelimit import RateLimiter
from .scanner import ScanConfig, ScanContext, Scanner, discover
from .scoring import grade, score, severity_counts
from .severity import Severity
from .target import Target


@dataclass
class ScannerRun:
    name: str
    status: str  # ok | error | timeout
    duration: float
    findings: int
    error: str | None = None


@dataclass
class ScanResult:
    target: Target
    started: datetime
    finished: datetime
    findings: list[Finding]
    runs: list[ScannerRun]
    requests: int
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def score(self) -> int:
        return score(self.findings)

    @property
    def grade(self) -> str:
        return grade(self.findings)

    @property
    def counts(self) -> dict[Severity, int]:
        return severity_counts(self.findings)

    @property
    def has_high_or_critical(self) -> bool:
        c = self.counts
        return bool(c[Severity.CRITICAL] or c[Severity.HIGH])

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": {"name": "sitescan", "version": __version__},
            "target": self.target.url,
            "host": self.target.host,
            "started": self.started.isoformat(),
            "finished": self.finished.isoformat(),
            "duration_seconds": round((self.finished - self.started).total_seconds(), 2),
            "requests_sent": self.requests,
            "score": self.score,
            "grade": self.grade,
            "severity_counts": {s.value: n for s, n in self.counts.items()},
            "findings": [f.to_dict() for f in self.findings],
            "scanners": [r.__dict__ for r in self.runs],
            "errors": self.errors,
            "notes": self.notes,
        }


def _sort_key(f: Finding):
    return (-f.severity.rank, f.scanner, f.id)


async def run_scan(
    target: Target,
    config: ScanConfig | None = None,
    *,
    only: Iterable[str] | None = None,
    skip: Iterable[str] | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> ScanResult:
    config = config or ScanConfig()
    config.user_agent = config.user_agent or USER_AGENT
    scanners = discover()
    if only:
        wanted = set(only)
        unknown = wanted - scanners.keys()
        if unknown:
            raise ValueError(f"unknown scanner(s): {', '.join(sorted(unknown))}")
        scanners = {k: v for k, v in scanners.items() if k in wanted}
    for name in skip or ():
        scanners.pop(name, None)

    limiter = RateLimiter(config.rate)
    http = HttpClient(
        limiter,
        config.user_agent,
        timeout=config.timeout,
        transport=transport,
    )
    ctx = ScanContext(target, config, limiter, http)
    started = datetime.now(timezone.utc)
    try:
        results = await asyncio.gather(
            *(_run_one(cls(), ctx) for cls in scanners.values())
        )
    finally:
        await http.aclose()
    finished = datetime.now(timezone.utc)

    findings: list[Finding] = []
    runs: list[ScannerRun] = []
    for run, fs in results:
        runs.append(run)
        findings.extend(fs)
    findings = _dedupe(findings)
    findings.sort(key=_sort_key)
    runs.sort(key=lambda r: r.name)
    return ScanResult(
        target=target,
        started=started,
        finished=finished,
        findings=findings,
        runs=runs,
        requests=limiter.total,
        errors=list(http.errors),
        notes=list(ctx.notes),
    )


async def _run_one(scanner: Scanner, ctx: ScanContext) -> tuple[ScannerRun, list[Finding]]:
    """Run one scanner; any exception or timeout becomes a status, never a crash."""
    t0 = time.monotonic()
    try:
        fs = await asyncio.wait_for(scanner.run(ctx), ctx.config.scanner_timeout)
        fs = list(fs or [])
        for f in fs:
            f.scanner = scanner.name
        return ScannerRun(scanner.name, "ok", round(time.monotonic() - t0, 2), len(fs)), fs
    except asyncio.TimeoutError:
        err = f"scanner exceeded {ctx.config.scanner_timeout}s"
        status = "timeout"
    except Exception as e:
        err = f"{type(e).__name__}: {e}"
        status = "error"
        ctx.notes.append(f"[{scanner.name}] " + traceback.format_exc(limit=3).strip())
    return ScannerRun(scanner.name, status, round(time.monotonic() - t0, 2), 0, err), []


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str]] = set()
    out = []
    for f in findings:
        key = (f.id, f.evidence)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out
