from __future__ import annotations

from collections import Counter
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .. import __version__
from ..core import OWASP, Severity
from ..core.cvss import base_score
from ..core.orchestrator import ScanResult

_TEMPLATES = Path(__file__).parent / "templates"


def _env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES)),
        autoescape=select_autoescape(["html", "j2"]),  # all evidence is attacker-influenced
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["cvss_score"] = lambda v: base_score(v) if v else None
    return env


def render_html(result: ScanResult) -> str:
    counts = result.counts
    max_count = max(counts.values()) or 1
    owasp_counts = Counter(f.owasp for f in result.findings if f.owasp and f.severity is not Severity.INFO)
    actionable = [f for f in result.findings if f.severity is not Severity.INFO]
    return _env().get_template("report.html.j2").render(
        r=result,
        version=__version__,
        severities=list(Severity),
        counts=counts,
        max_count=max_count,
        top=[f for f in actionable if f.severity.rank >= Severity.HIGH.rank][:5] or actionable[:3],
        owasp_rows=sorted(((OWASP[k], n) for k, n in owasp_counts.items()), key=lambda x: x[0]),
        actionable=len(actionable),
    )
