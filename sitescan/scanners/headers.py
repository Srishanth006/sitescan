"""HTTP security response headers, including a CSP parser."""
from __future__ import annotations

import re

from ..core import Finding, ScanContext, Scanner, Severity, register
from ._common import CVSS_CLICKJACK, CVSS_MITM_PASSIVE, CVSS_XSS_MITIGATION, clip

HSTS_MIN_AGE = 15_768_000  # 6 months
SCRIPT_FALLBACK = ("script-src-elem", "script-src", "default-src")
UNSAFE_REFERRER = {"unsafe-url", "no-referrer-when-downgrade"}
WILDCARD_SOURCES = {"*", "http:", "https:", "data:", "blob:"}


def parse_csp(value: str) -> dict[str, list[str]]:
    """Parse a CSP header into {directive: [sources]}. First occurrence wins (per spec)."""
    policy: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if not tokens:
            continue
        name = tokens[0].lower()
        if name not in policy:
            policy[name] = [t for t in tokens[1:]]
    return policy


def effective(policy: dict[str, list[str]], chain: tuple[str, ...]) -> tuple[str | None, list[str] | None]:
    for d in chain:
        if d in policy:
            return d, policy[d]
    return None, None


def analyze_csp(value: str) -> list[Finding]:
    policy = parse_csp(value)
    out: list[Finding] = []
    directive, sources = effective(policy, SCRIPT_FALLBACK)
    if sources is None:
        out.append(Finding(
            id="headers.csp.no-script-restriction",
            title="CSP does not restrict script sources",
            severity=Severity.MEDIUM,
            evidence=f"Content-Security-Policy: {clip(value)}",
            remediation=(
                "Add a `script-src` (or at least `default-src`) directive. A strong "
                "baseline is `default-src 'self'; script-src 'self' 'nonce-<random>'; "
                "object-src 'none'; base-uri 'self'`."
            ),
            owasp="A05", cwe=693, cvss=CVSS_XSS_MITIGATION,
        ))
        return out + _csp_misc(policy, value)

    lowered = [s.lower() for s in sources]
    has_nonce_or_hash = any(
        s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in lowered
    )
    if "'unsafe-inline'" in lowered and not has_nonce_or_hash:
        out.append(Finding(
            id="headers.csp.unsafe-inline",
            title=f"CSP allows 'unsafe-inline' scripts ({directive})",
            severity=Severity.MEDIUM,
            evidence=f"{directive} {' '.join(sources)}",
            remediation=(
                "Remove 'unsafe-inline' from script sources. Move inline scripts to "
                "external files, or authorise them with per-response nonces or hashes "
                "(browsers that support nonces ignore 'unsafe-inline' when one is present)."
            ),
            owasp="A05", cwe=79, cvss=CVSS_XSS_MITIGATION,
        ))
    if "'unsafe-eval'" in lowered:
        out.append(Finding(
            id="headers.csp.unsafe-eval",
            title=f"CSP allows 'unsafe-eval' ({directive})",
            severity=Severity.MEDIUM,
            evidence=f"{directive} {' '.join(sources)}",
            remediation=(
                "Remove 'unsafe-eval'. Refactor code that uses eval(), new Function(), "
                "or string arguments to setTimeout/setInterval."
            ),
            owasp="A05", cwe=95, cvss=CVSS_XSS_MITIGATION,
        ))
    wild = sorted(s for s in set(lowered) if s in WILDCARD_SOURCES)
    if wild and "'strict-dynamic'" not in lowered:
        out.append(Finding(
            id="headers.csp.wildcard-source",
            title=f"CSP script sources include wildcard/scheme sources ({directive})",
            severity=Severity.MEDIUM,
            evidence=f"{directive} {' '.join(sources)}  (wildcards: {', '.join(wild)})",
            remediation=(
                "Replace wildcard and bare-scheme sources (`*`, `https:`, `data:`) with "
                "an explicit allow-list of origins, or adopt a nonce + 'strict-dynamic' policy."
            ),
            owasp="A05", cwe=693, cvss=CVSS_XSS_MITIGATION,
        ))
    return out + _csp_misc(policy, value)


def _csp_misc(policy: dict[str, list[str]], raw: str) -> list[Finding]:
    out: list[Finding] = []
    od, osrc = effective(policy, ("object-src", "default-src"))
    if osrc is None or any(s.lower() in WILDCARD_SOURCES for s in osrc):
        out.append(Finding(
            id="headers.csp.object-src",
            title="CSP does not lock down plugin content (object-src)",
            severity=Severity.LOW,
            evidence=f"effective object-src: {' '.join(osrc) if osrc else '(none)'}",
            remediation="Add `object-src 'none'` to block legacy plugin-based script execution.",
            owasp="A05", cwe=693,
        ))
    if "base-uri" not in policy:
        out.append(Finding(
            id="headers.csp.base-uri",
            title="CSP missing base-uri directive",
            severity=Severity.LOW,
            evidence=f"Content-Security-Policy: {clip(raw)}",
            remediation=(
                "Add `base-uri 'self'` (or 'none'). base-uri does not fall back to "
                "default-src, so an injected <base> tag can redirect relative script URLs."
            ),
            owasp="A05", cwe=693,
        ))
    return out


@register
class HeadersScanner(Scanner):
    name = "headers"
    description = "HTTP security headers (CSP, HSTS, XFO, XCTO, Referrer-Policy, Permissions-Policy)"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        resp = await ctx.root()
        if resp is None:
            return [Finding(
                id="headers.unreachable",
                title="Could not fetch target to inspect headers",
                severity=Severity.INFO,
                evidence="; ".join(ctx.http.errors[-1:]) or "no response",
                remediation="Verify the target URL is reachable from the scanning host.",
            )]
        h = resp.headers
        https = resp.url.startswith("https://")
        out: list[Finding] = []

        # --- CSP -----------------------------------------------------------
        csp = h.get("content-security-policy")
        csp_ro = h.get("content-security-policy-report-only")
        if csp:
            out += analyze_csp(csp)
        elif csp_ro:
            out.append(Finding(
                id="headers.csp.report-only",
                title="CSP is in report-only mode (not enforced)",
                severity=Severity.LOW,
                evidence=f"Content-Security-Policy-Report-Only: {clip(csp_ro)}",
                remediation="Once violation reports are clean, ship the policy as an enforcing Content-Security-Policy header.",
                owasp="A05", cwe=693, cvss=CVSS_XSS_MITIGATION,
            ))
        else:
            out.append(Finding(
                id="headers.csp.missing",
                title="Content-Security-Policy header missing",
                severity=Severity.MEDIUM,
                evidence="no Content-Security-Policy header in response",
                remediation=(
                    "Define a Content-Security-Policy. Start with "
                    "`default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'` "
                    "in report-only mode, then tighten and enforce."
                ),
                owasp="A05", cwe=693, cvss=CVSS_XSS_MITIGATION,
            ))

        # --- HSTS ----------------------------------------------------------
        hsts = h.get("strict-transport-security")
        if https:
            if not hsts:
                out.append(Finding(
                    id="headers.hsts.missing",
                    title="Strict-Transport-Security header missing",
                    severity=Severity.MEDIUM,
                    evidence="no Strict-Transport-Security header on HTTPS response",
                    remediation=(
                        "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` "
                        "on every HTTPS response so browsers refuse to downgrade to HTTP."
                    ),
                    owasp="A02", cwe=319, cvss=CVSS_MITM_PASSIVE,
                ))
            else:
                m = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.I)
                if not m:
                    out.append(Finding(
                        id="headers.hsts.invalid",
                        title="Strict-Transport-Security header has no valid max-age",
                        severity=Severity.MEDIUM,
                        evidence=f"Strict-Transport-Security: {hsts}",
                        remediation="Use `max-age=<seconds>`; without it browsers ignore the header.",
                        owasp="A02", cwe=319, cvss=CVSS_MITM_PASSIVE,
                    ))
                elif int(m.group(1)) < HSTS_MIN_AGE:
                    out.append(Finding(
                        id="headers.hsts.short-max-age",
                        title="HSTS max-age is shorter than 6 months",
                        severity=Severity.LOW,
                        evidence=f"Strict-Transport-Security: {hsts}",
                        remediation="Raise max-age to at least 31536000 (1 year) once HTTPS is stable.",
                        owasp="A02", cwe=319, cvss=CVSS_MITM_PASSIVE,
                    ))

        # --- Framing ---------------------------------------------------------
        xfo = h.get("x-frame-options")
        has_fa = bool(csp and "frame-ancestors" in parse_csp(csp))
        if not xfo and not has_fa:
            out.append(Finding(
                id="headers.xfo.missing",
                title="No clickjacking protection (X-Frame-Options / frame-ancestors)",
                severity=Severity.MEDIUM,
                evidence="neither X-Frame-Options nor CSP frame-ancestors present",
                remediation=(
                    "Send `Content-Security-Policy: frame-ancestors 'self'` (preferred) and/or "
                    "`X-Frame-Options: DENY` / `SAMEORIGIN`."
                ),
                owasp="A05", cwe=1021, cvss=CVSS_CLICKJACK,
            ))
        elif xfo and xfo.strip().upper() not in ("DENY", "SAMEORIGIN") and not has_fa:
            out.append(Finding(
                id="headers.xfo.invalid",
                title="X-Frame-Options has an unsupported value",
                severity=Severity.LOW,
                evidence=f"X-Frame-Options: {xfo}",
                remediation="Use DENY or SAMEORIGIN (ALLOW-FROM is obsolete); prefer CSP frame-ancestors.",
                owasp="A05", cwe=1021, cvss=CVSS_CLICKJACK,
            ))

        # --- X-Content-Type-Options -----------------------------------------
        xcto = h.get("x-content-type-options")
        if (xcto or "").strip().lower() != "nosniff":
            out.append(Finding(
                id="headers.xcto.missing",
                title="X-Content-Type-Options: nosniff not set",
                severity=Severity.LOW,
                evidence=f"X-Content-Type-Options: {xcto}" if xcto else "header absent",
                remediation="Send `X-Content-Type-Options: nosniff` to stop MIME-type sniffing.",
                owasp="A05", cwe=693,
            ))

        # --- Referrer-Policy -------------------------------------------------
        rp = h.get("referrer-policy")
        if not rp:
            out.append(Finding(
                id="headers.referrer-policy.missing",
                title="Referrer-Policy header missing",
                severity=Severity.LOW,
                evidence="header absent (browser default applies)",
                remediation="Send `Referrer-Policy: strict-origin-when-cross-origin` or stricter.",
                owasp="A05", cwe=200,
            ))
        else:
            # the last recognised token wins in browsers
            tokens = [t.strip().lower() for t in rp.split(",") if t.strip()]
            if tokens and tokens[-1] in UNSAFE_REFERRER:
                out.append(Finding(
                    id="headers.referrer-policy.unsafe",
                    title="Referrer-Policy leaks full URLs cross-origin",
                    severity=Severity.LOW,
                    evidence=f"Referrer-Policy: {rp}",
                    remediation=(
                        "Use `strict-origin-when-cross-origin`, `same-origin` or `no-referrer`; "
                        "`unsafe-url` sends paths and query strings (which may hold tokens) to third parties."
                    ),
                    owasp="A05", cwe=200,
                ))

        # --- Permissions-Policy ---------------------------------------------
        if not h.get("permissions-policy"):
            out.append(Finding(
                id="headers.permissions-policy.missing",
                title="Permissions-Policy header missing",
                severity=Severity.LOW,
                evidence="header absent" + (" (legacy Feature-Policy present)" if h.get("feature-policy") else ""),
                remediation=(
                    "Disable powerful features you don't use, e.g. "
                    "`Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()`."
                ),
                owasp="A05", cwe=693,
            ))
        return out
