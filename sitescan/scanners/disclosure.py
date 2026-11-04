"""Information disclosure: version banners, verbose error pages, directory listing."""
from __future__ import annotations

import re

from ..core import Finding, ScanContext, Scanner, Severity, register
from ._common import CVSS_INFO_LEAK_LOW, clip, random_path

BANNER_HEADERS = [
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-generator", "x-runtime", "x-version", "x-backend-server",
]
VERSION_RE = re.compile(r"\d+\.\d+")

ERROR_SIGNATURES = [
    ("Python traceback", re.compile(r"Traceback \(most recent call last\)")),
    ("Django debug page", re.compile(r"You're seeing this error because you have <code>DEBUG = True")),
    ("Debug mode flag", re.compile(r"DEBUG\s*=\s*True")),
    ("Werkzeug debugger", re.compile(r"Werkzeug Debugger|The debugger caught an exception")),
    ("Java stack trace", re.compile(r"\bat (?:java|javax|org\.apache|org\.springframework)\.[\w.$]+\(")),
    ("Spring Whitelabel error", re.compile(r"Whitelabel Error Page")),
    (".NET error page", re.compile(r"Server Error in '/' Application|ASP\.NET is configured to show verbose")),
    ("PHP error", re.compile(r"<b>(?:Fatal error|Warning|Parse error|Notice)</b>:.*? on line <b>\d+")),
    ("Ruby on Rails error", re.compile(r"ActionController::RoutingError|Rails\.root:")),
    ("Node.js stack trace", re.compile(r"at [\w.<>]+ \((?:/|[A-Z]:\\)[^)]+\.js:\d+:\d+\)")),
    ("SQL error", re.compile(r"SQLSTATE\[|You have an error in your SQL syntax|ORA-\d{5}|psql: error")),
]

LISTING_DIRS = [
    "/uploads/", "/images/", "/img/", "/static/", "/assets/", "/files/",
    "/backup/", "/backups/", "/media/", "/js/", "/css/", "/logs/", "/tmp/",
]
LISTING_RE = re.compile(
    r"<title>\s*Index of /|<h1>\s*Index of /|Directory listing for /|\[To Parent Directory\]",
    re.I,
)


@register
class DisclosureScanner(Scanner):
    name = "disclosure"
    description = "Version banners, verbose error pages, directory listing"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        out: list[Finding] = []
        root = await ctx.root()
        if root is None:
            return out  # unreachable; headers scanner already reports it
        for h in BANNER_HEADERS:
            for v in root.header_list(h):
                if h == "server" and not VERSION_RE.search(v):
                    continue  # "nginx" alone is fine
                out.append(Finding(
                    id=f"disclosure.banner.{h}",
                    title=f"{h.title()} header discloses software/version",
                    severity=Severity.LOW,
                    evidence=f"{h.title()}: {v}",
                    remediation=(
                        f"Remove or genericise the {h.title()} header (e.g. nginx `server_tokens off;`, "
                        "Apache `ServerTokens Prod` + `ServerSignature Off`, PHP `expose_php = Off`). "
                        "Version strings let attackers map you to known CVEs instantly."
                    ),
                    owasp="A05", cwe=200, cvss=CVSS_INFO_LEAK_LOW,
                ))

        # Verbose errors: request a path that should not exist.
        probe = await ctx.http.get(ctx.target.join(random_path()), cache=False)
        if probe is not None:
            hits = [label for label, rx in ERROR_SIGNATURES if rx.search(probe.text)]
            if hits:
                m = next(rx.search(probe.text) for label, rx in ERROR_SIGNATURES if label == hits[0])
                snippet = probe.text[max(0, m.start() - 40): m.end() + 80]
                out.append(Finding(
                    id="disclosure.verbose-errors",
                    title="Error pages expose debug information / stack traces",
                    severity=Severity.MEDIUM,
                    evidence=f"GET {probe.url} -> {probe.status}; signatures: {', '.join(hits)}; snippet: {clip(snippet, 200)}",
                    remediation=(
                        "Disable debug mode in production and serve generic error pages; log the details "
                        "server-side instead. Stack traces reveal paths, frameworks and code structure."
                    ),
                    owasp="A05", cwe=209, cvss=CVSS_INFO_LEAK_LOW,
                ))

        # Directory listing on common paths.
        for d in LISTING_DIRS:
            r = await ctx.http.get(ctx.target.join(d), follow=False, cache=False)
            if r is not None and r.status == 200 and LISTING_RE.search(r.text[:4096]):
                out.append(Finding(
                    id="disclosure.directory-listing",
                    title=f"Directory listing enabled at {d}",
                    severity=Severity.MEDIUM,
                    evidence=f"GET {r.url} -> 200, body contains an auto-generated index",
                    remediation=(
                        "Disable automatic indexes (nginx `autoindex off;`, Apache `Options -Indexes`, "
                        "IIS directoryBrowse enabled=false)."
                    ),
                    owasp="A01", cwe=548, cvss=CVSS_INFO_LEAK_LOW,
                ))
        return out
