"""robots.txt, sitemap.xml and security.txt (RFC 9116)."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

from ..core import Finding, ScanContext, Scanner, Severity, register
from ..core.http import Response

INTERESTING = re.compile(
    r"admin|backup|private|secret|internal|config|staging|dev\b|test|\.git|\.env|debug|old|tmp|dump|sql",
    re.I,
)


def _is_text(r: Response | None) -> bool:
    """A real text file - not a soft-404 HTML page."""
    if r is None or r.status != 200:
        return False
    ct = r.headers.get("content-type", "").lower()
    head = r.text.lstrip()[:200].lower()
    return not ct.startswith("text/html") and not head.startswith(("<!doctype", "<html"))


def parse_robots(text: str) -> tuple[list[str], list[str]]:
    disallow, sitemaps = [], []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        k, _, v = line.partition(":")
        k, v = k.strip().lower(), v.strip()
        if k == "disallow" and v:
            disallow.append(v)
        elif k == "sitemap" and v:
            sitemaps.append(v)
    return disallow, sitemaps


def parse_security_txt(text: str) -> dict[str, list[str]]:
    fields: dict[str, list[str]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-----"):
            continue
        k, sep, v = line.partition(":")
        if sep:
            fields.setdefault(k.strip().lower(), []).append(v.strip())
    return fields


def analyze_security_txt(text: str, url: str, now: datetime | None = None) -> list[Finding]:
    now = now or datetime.now(timezone.utc)
    f = parse_security_txt(text)
    out: list[Finding] = []
    base = dict(owasp="A09", cwe=1059)
    if not f.get("contact"):
        out.append(Finding(
            id="wellknown.security-txt.no-contact", title="security.txt has no Contact field",
            severity=Severity.LOW, evidence=url,
            remediation="RFC 9116 requires at least one `Contact:` (mailto: or https: URI).", **base,
        ))
    exp = f.get("expires")
    if not exp:
        out.append(Finding(
            id="wellknown.security-txt.no-expires", title="security.txt has no Expires field",
            severity=Severity.LOW, evidence=url,
            remediation="RFC 9116 requires exactly one `Expires:` (ISO 8601, < 1 year ahead).", **base,
        ))
    else:
        try:
            when = datetime.fromisoformat(exp[0].replace("Z", "+00:00"))
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            if when < now:
                out.append(Finding(
                    id="wellknown.security-txt.expired", title="security.txt has expired",
                    severity=Severity.LOW, evidence=f"Expires: {exp[0]}",
                    remediation="Update Expires (and the contacts) - researchers treat stale files as abandoned.",
                    **base,
                ))
        except ValueError:
            out.append(Finding(
                id="wellknown.security-txt.bad-expires", title="security.txt Expires is not a valid date",
                severity=Severity.LOW, evidence=f"Expires: {exp[0]}",
                remediation="Use RFC 3339 format, e.g. 2027-01-01T00:00:00Z.", **base,
            ))
    if not out:
        out.append(Finding(
            id="wellknown.security-txt.ok", title="security.txt present and valid", severity=Severity.INFO,
            evidence=f"{url}: Contact={', '.join(f['contact'])}", remediation="No action required.",
        ))
    return out


@register
class WellKnownScanner(Scanner):
    name = "wellknown"
    description = "robots.txt, sitemap.xml and security.txt (RFC 9116)"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        t = ctx.target
        out: list[Finding] = []

        # robots.txt ------------------------------------------------------------
        robots = await ctx.http.get(t.join("/robots.txt"))
        sitemaps: list[str] = []
        if _is_text(robots):
            disallow, sitemaps = parse_robots(robots.text)
            juicy = [d for d in disallow if INTERESTING.search(d)]
            out.append(Finding(
                id="wellknown.robots.present", title=f"robots.txt: {len(disallow)} Disallow rule(s)",
                severity=Severity.INFO,
                evidence=f"Disallow: {', '.join(disallow[:20]) or '(none)'}; Sitemap: {', '.join(sitemaps) or '(none)'}",
                remediation="Informational.",
            ))
            if juicy:
                out.append(Finding(
                    id="wellknown.robots.sensitive-paths",
                    title="robots.txt advertises potentially sensitive paths",
                    severity=Severity.LOW, evidence="Disallow: " + ", ".join(juicy[:20]),
                    remediation=(
                        "robots.txt is public and is a roadmap for attackers. Protect sensitive areas with "
                        "authentication instead of hiding them, and drop them from robots.txt."
                    ),
                    owasp="A01", cwe=200,
                ))
        else:
            out.append(Finding(
                id="wellknown.robots.missing", title="No robots.txt", severity=Severity.INFO,
                evidence=f"{t.join('/robots.txt')} -> {robots.status if robots else 'no response'}",
                remediation="Informational (not a vulnerability).",
            ))

        # sitemap.xml -----------------------------------------------------------
        sm_urls = [urljoin(t.url, s) for s in sitemaps] or [t.join("/sitemap.xml")]
        sm_urls = [u for u in sm_urls if urlsplit(u).netloc == urlsplit(t.url).netloc][:3]
        found_sitemap = False
        for u in sm_urls:
            r = await ctx.http.get(u)
            if r is None or r.status != 200:
                continue
            try:
                root = ET.fromstring(r.text.encode("utf-8"))
            except ET.ParseError:
                continue
            locs = [e.text for e in root.iter() if e.tag.endswith("loc") and e.text]
            found_sitemap = True
            out.append(Finding(
                id="wellknown.sitemap.present", title=f"sitemap: {len(locs)} URL(s) listed",
                severity=Severity.INFO, evidence=f"{u}: " + ", ".join(locs[:5]) + (" ..." if len(locs) > 5 else ""),
                remediation="Informational. Make sure no internal/admin URLs are listed.",
            ))
        if not found_sitemap:
            out.append(Finding(
                id="wellknown.sitemap.missing", title="No sitemap.xml", severity=Severity.INFO,
                evidence=", ".join(sm_urls), remediation="Informational.",
            ))

        # security.txt (RFC 9116) ----------------------------------------------
        st_url = t.join("/.well-known/security.txt")
        st = await ctx.http.get(st_url)
        if _is_text(st):
            out += analyze_security_txt(st.text, st_url)
            if not st_url.startswith("https://"):
                out.append(Finding(
                    id="wellknown.security-txt.not-https", title="security.txt served over plain HTTP",
                    severity=Severity.LOW, evidence=st_url,
                    remediation="RFC 9116 requires security.txt to be served over HTTPS.",
                    owasp="A02", cwe=319,
                ))
        else:
            legacy = await ctx.http.get(t.join("/security.txt"))
            if _is_text(legacy):
                out.append(Finding(
                    id="wellknown.security-txt.legacy-location",
                    title="security.txt only at legacy /security.txt location",
                    severity=Severity.LOW, evidence=t.join("/security.txt"),
                    remediation="Move it to /.well-known/security.txt (RFC 9116 section 3).",
                    owasp="A09", cwe=1059,
                ))
            else:
                out.append(Finding(
                    id="wellknown.security-txt.missing", title="No security.txt (RFC 9116)",
                    severity=Severity.LOW,
                    evidence=f"{st_url} -> {st.status if st else 'no response'}",
                    remediation=(
                        "Publish /.well-known/security.txt with `Contact:` and `Expires:` so researchers can "
                        "report vulnerabilities to you (generator: https://securitytxt.org)."
                    ),
                    owasp="A09", cwe=1059,
                ))
        return out
