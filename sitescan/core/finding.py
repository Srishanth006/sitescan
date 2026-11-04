from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .severity import Severity

# OWASP Top 10 2021 categories, referenced by id from scanners.
OWASP = {
    "A01": "A01:2021-Broken Access Control",
    "A02": "A02:2021-Cryptographic Failures",
    "A03": "A03:2021-Injection",
    "A04": "A04:2021-Insecure Design",
    "A05": "A05:2021-Security Misconfiguration",
    "A06": "A06:2021-Vulnerable and Outdated Components",
    "A07": "A07:2021-Identification and Authentication Failures",
    "A08": "A08:2021-Software and Data Integrity Failures",
    "A09": "A09:2021-Security Logging and Monitoring Failures",
    "A10": "A10:2021-Server-Side Request Forgery",
}


@dataclass
class Finding:
    """A single observation produced by a scanner.

    ``id`` is a stable, dotted identifier (``headers.csp.unsafe-inline``)
    so CI pipelines can allow-list or track specific findings over time.
    """

    id: str
    title: str
    severity: Severity
    evidence: str
    remediation: str
    owasp: str | None = None  # key into OWASP, e.g. "A05"
    cwe: int | None = None
    cvss: str | None = None  # CVSS:3.1 vector string where meaningful
    scanner: str = ""  # filled in by the orchestrator
    references: list[str] = field(default_factory=list)

    @property
    def owasp_label(self) -> str | None:
        return OWASP.get(self.owasp, self.owasp) if self.owasp else None

    @property
    def cwe_label(self) -> str | None:
        return f"CWE-{self.cwe}" if self.cwe else None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["owasp"] = self.owasp_label
        d["cwe"] = self.cwe_label
        return d
