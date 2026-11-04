"""Transport hygiene: HTTP->HTTPS redirect, mixed content, HSTS preload eligibility."""
from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urlsplit

from ..core import Finding, ScanContext, Scanner, Severity, register
from ..core.http import Response
from ._common import CVSS_MITM_ACTIVE, CVSS_MITM_PASSIVE

PRELOAD_MIN_AGE = 31_536_000

# (tag, attribute) -> active?  Active mixed content is blocked by browsers but
# signals a page that breaks or silently downgrades; passive content can be
# tampered with / observed by a network attacker.
MIXED_ATTRS = {
    ("script", "src"): True,
    ("iframe", "src"): True,
    ("frame", "src"): True,
    ("object", "data"): True,
    ("embed", "src"): True,
    ("form", "action"): True,
    ("link", "href"): True,  # only for stylesheets / preload / icons - filtered below
    ("img", "src"): False,
    ("audio", "src"): False,
    ("video", "src"): False,
    ("source", "src"): False,
    ("track", "src"): False,
}
LINK_RELS = {"stylesheet", "preload", "modulepreload", "icon", "manifest", "prefetch"}


class _MixedParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hits: list[tuple[str, str, bool]] = []  # (tag, url, active)

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        for (t, attr), active in MIXED_ATTRS.items():
            if t != tag or attr not in a:
                continue
            url = a[attr].strip()
            if not url.lower().startswith("http://"):
                continue
            if tag == "link" and not (set(a.get("rel", "").lower().split()) & LINK_RELS):
                continue
            self.hits.append((tag, url, active))


def find_mixed_content(html: str) -> list[tuple[str, str, bool]]:
    p = _MixedParser()
    try:
        p.feed(html)
    except Exception:  # malformed HTML must never break the scan
        pass
    return p.hits


def preload_problems(hsts: str | None, redirects_to_https: bool) -> list[str]:
    """Requirements from https://hstspreload.org/#submission-requirements."""
    if not hsts:
        return ["no Strict-Transport-Security header"]
    probs = []
    m = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.I)
    if not m or int(m.group(1)) < PRELOAD_MIN_AGE:
        probs.append(f"max-age must be >= {PRELOAD_MIN_AGE} (1 year)")
    directives = {d.strip().lower() for d in hsts.split(";")}
    if "includesubdomains" not in directives:
        probs.append("missing includeSubDomains")
    if "preload" not in directives:
        probs.append("missing preload directive")
    if not redirects_to_https:
        probs.append("HTTP does not redirect to HTTPS on the same host")
    return probs


def _first_hop_https_same_host(resp: Response | None, host: str) -> tuple[bool, str]:
    if resp is None:
        return False, "no response"
    if not resp.history:
        return False, f"HTTP {resp.status} served without redirect"
    first = resp.history[0]
    dest = urlsplit(resp.history[0].location or "")
    # relative Location -> same scheme (http)
    if dest.scheme != "https":
        return False, f"first redirect ({first.status}) goes to {first.location!r}, not HTTPS"
    if (dest.hostname or "").lower() != host:
        return False, f"first redirect goes to a different host ({dest.hostname})"
    return True, f"{first.status} -> {first.location}"


@register
class TransportScanner(Scanner):
    name = "transport"
    description = "HTTP->HTTPS redirect, mixed content, HSTS preload eligibility"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        t = ctx.target
        out: list[Finding] = []

        if not t.is_https:
            https_url = f"https://{t.host}/" if not t.is_ip or ":" not in t.host else f"https://[{t.host}]/"
            https_resp = await ctx.http.get(https_url, follow=False)
            if https_resp is None:
                out.append(Finding(
                    id="transport.no-https", title="Site is not available over HTTPS",
                    severity=Severity.HIGH,
                    evidence=f"{t.url} is plain HTTP and {https_url} did not respond",
                    remediation=(
                        "Serve the site over HTTPS (free certificates via ACME/Let's Encrypt), redirect all "
                        "HTTP traffic with 301, then enable HSTS."
                    ),
                    owasp="A02", cwe=319, cvss=CVSS_MITM_ACTIVE,
                ))
            else:
                out.append(Finding(
                    id="transport.https-available", title="HTTPS is available; scan the HTTPS URL",
                    severity=Severity.INFO, evidence=f"{https_url} -> {https_resp.status}",
                    remediation=f"Re-run sitescan against {https_url} for TLS and header checks.",
                ))
            http_resp = await ctx.root()
            ok, detail = _first_hop_https_same_host(http_resp, t.host)
            if http_resp is not None and not ok:
                out.append(self._no_redirect(t.url, detail))
            return out

        # --- HTTPS target ------------------------------------------------------
        http_url = ctx.config.http_url or f"http://{t.host}/"
        http_resp = await ctx.http.get(http_url, follow=True)
        redirect_ok, detail = _first_hop_https_same_host(http_resp, t.host)
        if http_resp is None:
            out.append(Finding(
                id="transport.http-closed", title="Plain HTTP endpoint not reachable",
                severity=Severity.INFO, evidence=f"{http_url}: no response",
                remediation=(
                    "Fine if intentional, but users typing the bare domain get an error; consider a "
                    "port-80 listener that only issues 301 redirects to HTTPS."
                ),
            ))
        elif not redirect_ok:
            out.append(self._no_redirect(http_url, detail))
        elif http_resp.history[0].status in (302, 303, 307):
            out.append(Finding(
                id="transport.redirect-temporary", title="HTTP->HTTPS redirect is temporary",
                severity=Severity.LOW, evidence=detail,
                remediation="Use a permanent redirect (301 or 308) so clients and caches remember it.",
                owasp="A05", cwe=319,
            ))

        root = await ctx.root()
        if root is not None and root.url.startswith("https://"):
            hits = find_mixed_content(root.text)
            active = [h for h in hits if h[2]]
            passive = [h for h in hits if not h[2]]
            if active:
                out.append(Finding(
                    id="transport.mixed-content.active",
                    title=f"Active mixed content: {len(active)} HTTP resource(s) on HTTPS page",
                    severity=Severity.MEDIUM,
                    evidence="; ".join(f"<{tag}> {url}" for tag, url, _ in active[:10]),
                    remediation=(
                        "Load every script, stylesheet, frame and form target over HTTPS. As a safety net "
                        "add `Content-Security-Policy: upgrade-insecure-requests`."
                    ),
                    owasp="A02", cwe=319, cvss=CVSS_MITM_ACTIVE,
                ))
            if passive:
                out.append(Finding(
                    id="transport.mixed-content.passive",
                    title=f"Passive mixed content: {len(passive)} HTTP media resource(s)",
                    severity=Severity.LOW,
                    evidence="; ".join(f"<{tag}> {url}" for tag, url, _ in passive[:10]),
                    remediation="Serve images/media over HTTPS or use protocol-relative/HTTPS URLs.",
                    owasp="A02", cwe=319, cvss=CVSS_MITM_PASSIVE,
                ))

            hsts = root.headers.get("strict-transport-security")
            probs = preload_problems(hsts, redirect_ok)
            if not probs:
                out.append(Finding(
                    id="transport.hsts.preload-eligible", title="HSTS preload requirements met",
                    severity=Severity.INFO, evidence=f"Strict-Transport-Security: {hsts}",
                    remediation="Submit the apex domain at https://hstspreload.org if not already listed.",
                ))
            elif hsts and "preload" in hsts.lower():
                out.append(Finding(
                    id="transport.hsts.preload-invalid",
                    title="HSTS 'preload' set but preload requirements not met",
                    severity=Severity.LOW, evidence=f"{hsts} -> {'; '.join(probs)}",
                    remediation="Fix: " + "; ".join(probs) + ". Otherwise the preload submission will be rejected.",
                    owasp="A05", cwe=319,
                ))
            else:
                out.append(Finding(
                    id="transport.hsts.not-preload-eligible", title="Not eligible for the HSTS preload list",
                    severity=Severity.INFO, evidence="; ".join(probs),
                    remediation=(
                        "Preloading protects first visits. Requirements: valid cert, HTTP->HTTPS redirect, "
                        "HSTS max-age >= 1 year with includeSubDomains and preload."
                    ),
                ))
        return out

    @staticmethod
    def _no_redirect(url: str, detail: str) -> Finding:
        return Finding(
            id="transport.no-https-redirect", title="HTTP does not redirect to HTTPS",
            severity=Severity.MEDIUM, evidence=f"{url}: {detail}",
            remediation=(
                "Answer every plain-HTTP request with a 301 to the same host over https://. "
                "Redirecting to a different host first breaks HSTS preload eligibility."
            ),
            owasp="A02", cwe=319, cvss=CVSS_MITM_PASSIVE,
        )
