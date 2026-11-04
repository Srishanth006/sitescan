from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..core import Severity
from ..core.orchestrator import ScanResult

GRADE_STYLE = {"A": "bold green", "B": "green", "C": "yellow", "D": "bold red", "F": "bold white on red"}


def render_terminal(result: ScanResult, console: Console | None = None, show_info: bool = True) -> None:
    console = console or Console()
    counts = result.counts
    summary = Text.assemble(
        ("Target  ", "dim"), (result.target.url, "bold"), "\n",
        ("Score   ", "dim"), (f"{result.score}/100  ", "bold"),
        ("Grade ", "dim"), (f" {result.grade} ", GRADE_STYLE.get(result.grade, "bold")), "\n",
        ("Found   ", "dim"),
        *[
            part
            for s in Severity
            for part in ((f"{s.value} {counts[s]}", s.color if counts[s] else "dim"), "  ")
        ],
        "\n",
        ("Requests ", "dim"), str(result.requests),
        ("   Duration ", "dim"), f"{(result.finished - result.started).total_seconds():.1f}s",
    )
    console.print(Panel(summary, title="sitescan report", border_style="blue", expand=False))

    wide = console.width >= 120
    table = Table(box=box.SIMPLE_HEAVY, show_lines=False, expand=True)
    table.add_column("Severity", no_wrap=True)
    if wide:
        table.add_column("ID", style="dim", no_wrap=True, overflow="fold")
    table.add_column("Finding", ratio=2)
    table.add_column("Evidence", ratio=3, overflow="fold")
    if wide:
        table.add_column("OWASP / CWE", no_wrap=True)
    shown = [f for f in result.findings if show_info or f.severity is not Severity.INFO]
    for f in shown:
        ev = f.evidence if len(f.evidence) <= 160 else f.evidence[:159] + "…"
        sev = Text(f.severity.value, style=f.severity.color)
        if wide:
            owasp_cwe = "\n".join(x for x in (f.owasp or "", f.cwe_label or "") if x)
            table.add_row(sev, f.id, f.title, ev, owasp_cwe)
        else:
            table.add_row(sev, f.title, ev)
    if shown:
        console.print(table)
    else:
        console.print("[green]No findings.[/green]")

    failed = [r for r in result.runs if r.status != "ok"]
    if failed:
        t = Table(title="Scanner problems", box=box.MINIMAL)
        t.add_column("Scanner")
        t.add_column("Status")
        t.add_column("Error", overflow="fold")
        for r in failed:
            t.add_row(r.name, r.status, r.error or "")
        console.print(t)
    if result.errors:
        console.print(f"[dim]{len(result.errors)} request(s) failed (timeouts/connection errors); see JSON log.[/dim]")
