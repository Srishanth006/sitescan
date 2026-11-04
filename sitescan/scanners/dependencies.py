"""Dependency surface: fingerprint front-end libraries and look them up in OSV.dev.

Only same-origin scripts are fetched (never third-party CDNs); CDN-hosted
libraries are identified from their URL alone. OSV.dev is the one external
service contacted, and only with {package, version} - never target data.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import httpx

from ..core import Finding, ScanContext, Scanner, Severity, register
from ..core.cvss import base_score, severity_for

V = r"(\d+\.\d+\.\d+)"


@dataclass(frozen=True)
class Lib:
    display: str
    npm: str  # OSV package name (npm ecosystem)
    url_patterns: tuple[str, ...]
    banner_patterns: tuple[str, ...]


LIBS = [
    Lib("jQuery", "jquery",
        (rf"jquery[.-]{V}(?:\.slim)?(?:\.min)?\.js", rf"/jquery/{V}/", rf"jquery@{V}"),
        (rf"jQuery (?:JavaScript Library )?v{V}", rf"jQuery v{V}")),
    Lib("jQuery UI", "jquery-ui",
        (rf"jquery-ui[.-]{V}", rf"/jqueryui/{V}/", rf"jquery-ui@{V}"),
        (rf"jQuery UI - v{V}",)),
    Lib("Bootstrap", "bootstrap",
        (rf"bootstrap[@/-]{V}", rf"/bootstrap/{V}/", rf"twitter-bootstrap/{V}/"),
        (rf"Bootstrap v{V}",)),
    Lib("AngularJS", "angular",
        (rf"angular(?:\.js)?[@/-]({V[1:-1]})(?=[/.])", rf"/angularjs/{V}/", rf"angular\.js/{V}/"),
        (rf"AngularJS v{V}",)),
    Lib("Lodash", "lodash", (rf"lodash[@/.-]{V}", rf"/lodash\.js/{V}/"), (rf"Lodash <https://lodash\.com/>[\s\S]{{0,200}}?VERSION\s*=\s*['\"]{V}",)),
    Lib("Moment.js", "moment", (rf"moment[@/.-]{V}", rf"/moment\.js/{V}/"), (rf"//! moment\.js\s*//! version : {V}",)),
    Lib("Vue", "vue", (rf"vue@{V}", rf"/vue/{V}/"), (rf"Vue\.js v{V}",)),
    Lib("React", "react", (rf"react@{V}", rf"/react/{V}/"), (rf"@license React v{V}", rf"React v{V}")),
    Lib("Handlebars", "handlebars", (rf"handlebars[@/.-]v?{V}",), (rf"Handlebars\.js v{V}", rf"handlebars v{V}")),
    Lib("DOMPurify", "dompurify", (rf"dompurify@{V}", rf"/dompurify/{V}/"), (rf"DOMPurify {V}",)),
    Lib("Underscore", "underscore", (rf"underscore[@/.-]{V}",), (rf"Underscore\.js {V}",)),
]
MAX_SCRIPTS = 15
OSV_SEV = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MODERATE": Severity.MEDIUM,
           "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}


class _AssetParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.scripts: list[str] = []
        self.links: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "script" and a.get("src"):
            self.scripts.append(a["src"])
        elif tag == "link" and a.get("href"):
            self.links.append(a["href"])


def detect_in_url(url: str) -> list[tuple[Lib, str]]:
    hits = []
    for lib in LIBS:
        for pat in lib.url_patterns:
            m = re.search(pat, url, re.I)
            if m:
                hits.append((lib, m.group(1)))
                break
    return hits


def detect_in_text(text: str) -> list[tuple[Lib, str]]:
    head = text[:20000]  # banners live at the top; bundles may embed several
    hits = []
    for lib in LIBS:
        for pat in lib.banner_patterns:
            m = re.search(pat, head)
            if m:
                hits.append((lib, m.group(1)))
                break
    return hits


def vuln_severity(v: dict) -> tuple[Severity, str | None, float | None]:
    vector, score = None, None
    for s in v.get("severity") or []:
        if str(s.get("type", "")).startswith("CVSS_V3"):
            vector = s.get("score")
            score = base_score(vector) if vector else None
            break
    label = str((v.get("database_specific") or {}).get("severity", "")).upper()
    if label in OSV_SEV:
        return OSV_SEV[label], vector, score
    if score is not None:
        return severity_for(score), vector, score
    return Severity.MEDIUM, vector, score  # known vuln, unknown severity


async def query_osv(ctx: ScanContext, client: httpx.AsyncClient, lib: Lib, version: str) -> list[dict] | None:
    try:
        r = await client.post(
            ctx.config.osv_url,
            json={"package": {"name": lib.npm, "ecosystem": "npm"}, "version": version},
        )
        r.raise_for_status()
        return r.json().get("vulns", [])
    except (httpx.HTTPError, ValueError) as e:
        ctx.notes.append(f"[dependencies] OSV query for {lib.npm}@{version} failed: {e}")
        return None


@register
class DependencyScanner(Scanner):
    name = "dependencies"
    description = "Front-end library fingerprinting + OSV.dev vulnerability lookup"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        root = await ctx.root()
        if root is None:
            return []
        parser = _AssetParser()
        try:
            parser.feed(root.text)
        except Exception:
            pass

        detected: dict[tuple[str, str], tuple[Lib, str, str]] = {}  # (npm, ver) -> (lib, ver, where)

        def add(hits, where):
            for lib, ver in hits:
                detected.setdefault((lib.npm, ver), (lib, ver, where))

        add(detect_in_text(root.text), "inline HTML")
        origin = urlsplit(root.url).netloc
        same_origin: list[str] = []
        for src in parser.scripts + parser.links:
            absolute = urljoin(root.url, src)
            add(detect_in_url(absolute), absolute)
            if src in parser.scripts and urlsplit(absolute).netloc == origin and absolute not in same_origin:
                same_origin.append(absolute)

        for url in same_origin[:MAX_SCRIPTS]:
            r = await ctx.http.get(url)
            if r is not None and r.status == 200:
                add(detect_in_text(r.text), url)

        if not detected:
            return []

        out: list[Finding] = []
        if not ctx.config.osv_enabled:
            for lib, ver, where in detected.values():
                out.append(self._detected(lib, ver, where, "OSV lookup disabled (--no-osv)"))
            return out

        async with httpx.AsyncClient(
            timeout=ctx.config.timeout,
            transport=ctx.config.osv_transport,
            headers={"User-Agent": ctx.config.user_agent},
        ) as client:
            for lib, ver, where in detected.values():
                vulns = await query_osv(ctx, client, lib, ver)
                if vulns is None:
                    out.append(self._detected(lib, ver, where, "OSV lookup failed; vulnerability status unknown"))
                elif not vulns:
                    out.append(self._detected(lib, ver, where, "no known vulnerabilities in OSV.dev"))
                else:
                    out.append(self._vulnerable(lib, ver, where, vulns))
        return out

    @staticmethod
    def _detected(lib: Lib, ver: str, where: str, status: str) -> Finding:
        return Finding(
            id=f"deps.{lib.npm}.detected", title=f"{lib.display} {ver} detected",
            severity=Severity.INFO, evidence=f"{lib.display} {ver} at {where}; {status}",
            remediation="Keep third-party libraries on supported, current releases.",
            owasp="A06",
        )

    @staticmethod
    def _vulnerable(lib: Lib, ver: str, where: str, vulns: list[dict]) -> Finding:
        rated = []
        for v in vulns:
            sev, vector, score = vuln_severity(v)
            cves = [a for a in v.get("aliases", []) if a.startswith("CVE-")]
            rated.append((sev, vector, score, v.get("id", "?"), cves, v.get("summary", "")))
        rated.sort(key=lambda x: (-x[0].rank, -(x[2] or 0)))
        worst_sev, worst_vec = rated[0][0], rated[0][1]
        lines = [
            f"{vid}{' (' + ', '.join(c) + ')' if c else ''} [{s.value}{f' {sc}' if sc is not None else ''}]: {summ}"
            for s, _, sc, vid, c, summ in rated
        ]
        return Finding(
            id=f"deps.{lib.npm}.vulnerable",
            title=f"{lib.display} {ver} has {len(vulns)} known vulnerabilit{'y' if len(vulns) == 1 else 'ies'}",
            severity=worst_sev,
            evidence=f"{lib.display} {ver} at {where}. " + " | ".join(lines),
            remediation=(
                f"Upgrade {lib.display} to the latest release (check each advisory's fixed version on "
                f"https://osv.dev/list?ecosystem=npm&q={lib.npm}) and remove unused copies. Consider "
                "Subresource Integrity for CDN-hosted files."
            ),
            owasp="A06", cwe=1104, cvss=worst_vec,
            references=[f"https://osv.dev/vulnerability/{r[3]}" for r in rated],
        )
