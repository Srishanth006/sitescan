"""sitescan command-line entrypoint.

Exit codes:
  0  scan completed, nothing at/above the --fail-on threshold (default: High)
  1  scan completed and found High/Critical (or >= --fail-on) issues  -> CI gate
  2  usage error (argparse)
  3  refused: authorization gate / denylist
  4  fatal error
"""
from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console

from . import USER_AGENT, __version__
from .core import ScanConfig, Severity, Target, discover
from .core.gate import AuthorizationError, check_authorization
from .core.orchestrator import ScanResult, run_scan
from .report import render_html, render_json, render_terminal

EXIT_OK, EXIT_FINDINGS, EXIT_REFUSED, EXIT_ERROR = 0, 1, 3, 4


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sitescan",
        description="Passive, non-destructive web security posture assessment. "
        "Only scan systems you own or are explicitly authorized to test.",
    )
    p.add_argument("target", nargs="?", help="target URL, e.g. https://example.com")
    p.add_argument("--i-am-authorized", action="store_true", dest="authorized",
                   help="assert you have permission to test the target (required)")
    p.add_argument("--confirm-host", metavar="HOST",
                   help="non-interactive hostname confirmation (for CI); must equal the target host")
    p.add_argument("--rate", type=float, default=5.0, help="max requests/second to the target (default 5)")
    p.add_argument("--timeout", type=float, default=10.0, help="per-request timeout seconds (default 10)")
    p.add_argument("--only", metavar="A,B", help="run only these scanners (comma-separated)")
    p.add_argument("--skip", metavar="A,B", help="skip these scanners (comma-separated)")
    p.add_argument("--json", metavar="PATH", help="write JSON report to PATH ('-' for stdout)")
    p.add_argument("--html", metavar="PATH", help="write self-contained HTML report to PATH")
    p.add_argument("--scans-dir", default="scans", help="directory for the per-scan audit log (default ./scans)")
    p.add_argument("--fail-on", default="High", choices=[s.value for s in Severity if s is not Severity.INFO],
                   help="minimum severity that causes exit code 1 (default High)")
    p.add_argument("--no-info", action="store_true", help="hide Info findings in the terminal table")
    p.add_argument("--ca-bundle", help="extra CA bundle to trust when validating the TLS chain")
    p.add_argument("--http-url", help="override the plain-HTTP URL used for the redirect check")
    p.add_argument("--dns-domain", help="domain for DNS/email checks (default: target host minus www.)")
    p.add_argument("--no-osv", action="store_true", help="don't query OSV.dev for library vulnerabilities")
    p.add_argument("--list-scanners", action="store_true", help="list available scanners and exit")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--version", action="version", version=f"sitescan {__version__}")
    return p


def _csv(v: str | None) -> list[str] | None:
    return [x.strip() for x in v.split(",") if x.strip()] if v else None


def write_scan_log(result: ScanResult, scans_dir: str | Path, argv: list[str]) -> Path:
    d = Path(scans_dir)
    d.mkdir(parents=True, exist_ok=True)
    stamp = result.started.strftime("%Y%m%dT%H%M%SZ")
    safe_host = re.sub(r"[^A-Za-z0-9._-]", "_", result.target.host)
    path = d / f"{stamp}-{safe_host}.json"
    try:
        operator = getpass.getuser()
    except Exception:
        operator = "unknown"
    data = result.to_dict()
    data["audit"] = {
        "operator": operator,
        "argv": argv,
        "authorized_flag": True,
        "hostname_confirmed": True,
        "user_agent": USER_AGENT,
        "logged_at": datetime.now(timezone.utc).isoformat(),
    }
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    args = build_parser().parse_args(argv)
    err = Console(stderr=True)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING)

    if args.list_scanners:
        for name, cls in sorted(discover().items()):
            print(f"{name:18} {cls.description}")
        return EXIT_OK
    if not args.target:
        err.print("[red]error:[/red] target URL is required")
        return 2
    if args.rate <= 0 or args.rate > 50:
        err.print("[red]error:[/red] --rate must be between 0 and 50 req/s")
        return 2

    try:
        target = Target.parse(args.target)
    except ValueError as e:
        err.print(f"[red]error:[/red] {e}")
        return 2

    try:
        check_authorization(
            target,
            authorized_flag=args.authorized,
            confirm_host=args.confirm_host,
            prompt=lambda msg: err.input(f"[bold yellow]{msg}[/bold yellow]"),
            interactive=sys.stdin.isatty(),
        )
    except AuthorizationError as e:
        err.print(f"[bold red]{e}[/bold red]")
        return EXIT_REFUSED
    except (EOFError, KeyboardInterrupt):
        err.print("[bold red]confirmation aborted[/bold red]")
        return EXIT_REFUSED

    config = ScanConfig(
        rate=args.rate,
        timeout=args.timeout,
        user_agent=USER_AGENT,
        ca_bundle=args.ca_bundle,
        http_url=args.http_url,
        dns_domain=args.dns_domain,
        osv_enabled=not args.no_osv,
    )
    err.print(f"[dim]scanning {target.url} at <= {args.rate:g} req/s as '{USER_AGENT}'[/dim]")
    try:
        result = asyncio.run(run_scan(target, config, only=_csv(args.only), skip=_csv(args.skip)))
    except ValueError as e:
        err.print(f"[red]error:[/red] {e}")
        return 2
    except KeyboardInterrupt:
        err.print("[red]interrupted[/red]")
        return EXIT_ERROR
    except Exception as e:  # pragma: no cover - last-resort guard
        err.print(f"[red]fatal:[/red] {type(e).__name__}: {e}")
        return EXIT_ERROR

    log_path = write_scan_log(result, args.scans_dir, argv)

    json_to_stdout = args.json == "-"
    if json_to_stdout:
        print(render_json(result))
    else:
        render_terminal(result, Console(), show_info=not args.no_info)
    if args.json and not json_to_stdout:
        Path(args.json).write_text(render_json(result), encoding="utf-8")
        err.print(f"JSON report: {args.json}")
    if args.html:
        Path(args.html).write_text(render_html(result), encoding="utf-8")
        err.print(f"HTML report: {args.html}")
    err.print(f"[dim]scan log: {log_path}[/dim]")

    threshold = Severity.parse(args.fail_on).rank
    return EXIT_FINDINGS if any(f.severity.rank >= threshold for f in result.findings) else EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
