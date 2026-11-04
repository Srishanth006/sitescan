"""Cookie security attributes on every Set-Cookie header."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..core import Finding, ScanContext, Scanner, Severity, register
from ._common import CVSS_COOKIE_THEFT

SENSITIVE_NAME = re.compile(
    r"(sess|sid|auth|token|jwt|login|remember|phpsessid|jsessionid|asp\.net_sessionid|connect\.sid)",
    re.I,
)


@dataclass
class Cookie:
    name: str
    raw: str
    attrs: dict[str, str] = field(default_factory=dict)

    @property
    def redacted(self) -> str:
        """Header with the cookie value hidden - never echo secrets into reports."""
        rest = self.raw.split(";", 1)[1] if ";" in self.raw else ""
        return f"{self.name}=<redacted>" + (f";{rest}" if rest else "")


def parse_set_cookie(header: str) -> Cookie | None:
    parts = [p.strip() for p in header.split(";")]
    if not parts or "=" not in parts[0]:
        return None
    name = parts[0].split("=", 1)[0].strip()
    attrs: dict[str, str] = {}
    for p in parts[1:]:
        if not p:
            continue
        k, _, v = p.partition("=")
        attrs[k.strip().lower()] = v.strip()
    return Cookie(name=name, raw=header, attrs=attrs)


def analyze_cookie(c: Cookie, https: bool) -> list[Finding]:
    out: list[Finding] = []
    sensitive = bool(SENSITIVE_NAME.search(c.name)) or c.name.startswith(("__Host-", "__Secure-"))
    samesite = c.attrs.get("samesite", "").lower()

    if "secure" not in c.attrs:
        out.append(Finding(
            id="cookies.missing-secure",
            title=f"Cookie '{c.name}' lacks the Secure flag",
            severity=Severity.MEDIUM if (sensitive or https) else Severity.LOW,
            evidence=f"Set-Cookie: {c.redacted}",
            remediation=(
                "Add `Secure` so the cookie is never sent over plain HTTP. For session cookies, "
                "prefer the `__Host-` prefix (requires Secure, Path=/, no Domain)."
            ),
            owasp="A02", cwe=614, cvss=CVSS_COOKIE_THEFT,
        ))
    if "httponly" not in c.attrs:
        out.append(Finding(
            id="cookies.missing-httponly",
            title=f"Cookie '{c.name}' lacks the HttpOnly flag",
            severity=Severity.MEDIUM if sensitive else Severity.LOW,
            evidence=f"Set-Cookie: {c.redacted}",
            remediation=(
                "Add `HttpOnly` so JavaScript (and therefore XSS payloads) cannot read the cookie. "
                "Only omit it for cookies the front-end genuinely needs to read."
            ),
            owasp="A05", cwe=1004, cvss=CVSS_COOKIE_THEFT,
        ))
    if not samesite:
        out.append(Finding(
            id="cookies.missing-samesite",
            title=f"Cookie '{c.name}' has no SameSite attribute",
            severity=Severity.LOW,
            evidence=f"Set-Cookie: {c.redacted}",
            remediation=(
                "Set `SameSite=Lax` (or `Strict` for session cookies that never need cross-site "
                "navigation). Relying on browser defaults is inconsistent across clients."
            ),
            owasp="A01", cwe=1275,
        ))
    elif samesite == "none" and "secure" not in c.attrs:
        out.append(Finding(
            id="cookies.samesite-none-insecure",
            title=f"Cookie '{c.name}' uses SameSite=None without Secure",
            severity=Severity.MEDIUM,
            evidence=f"Set-Cookie: {c.redacted}",
            remediation="SameSite=None requires Secure; modern browsers reject the cookie otherwise.",
            owasp="A01", cwe=1275,
        ))
    elif samesite not in ("lax", "strict", "none"):
        out.append(Finding(
            id="cookies.samesite-invalid",
            title=f"Cookie '{c.name}' has an invalid SameSite value",
            severity=Severity.LOW,
            evidence=f"Set-Cookie: {c.redacted}",
            remediation="Use SameSite=Lax, Strict or None.",
            owasp="A01", cwe=1275,
        ))
    return out


@register
class CookieScanner(Scanner):
    name = "cookies"
    description = "Secure / HttpOnly / SameSite flags on every Set-Cookie"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        resp = await ctx.root()
        if resp is None:
            return []
        https = resp.url.startswith("https://")
        out: list[Finding] = []
        cookies = [c for c in map(parse_set_cookie, resp.header_list("set-cookie")) if c]
        for c in cookies:
            out += analyze_cookie(c, https)
        if cookies and not out:
            out.append(Finding(
                id="cookies.ok", title=f"{len(cookies)} cookie(s) set with secure attributes",
                severity=Severity.INFO, evidence=", ".join(c.name for c in cookies),
                remediation="No action required.",
            ))
        return out
