"""DNS & email posture: SPF, DKIM, DMARC, CAA, zone transfer (AXFR)."""
from __future__ import annotations

import asyncio
import re
from typing import Protocol

from ..core import Finding, ScanContext, Scanner, Severity, register
from ._common import CVSS_INFO_LEAK_LOW, CVSS_SPOOFING

DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "k2", "mail", "dkim",
    "s1", "s2", "smtp", "mandrill", "mxvault", "everlytickey1", "zoho", "protonmail",
]


class DnsBackend(Protocol):
    async def txt(self, name: str) -> list[str]: ...
    async def caa(self, name: str) -> list[str]: ...
    async def ns(self, name: str) -> list[str]: ...
    async def addresses(self, name: str) -> list[str]: ...
    async def axfr(self, nameserver_ip: str, zone: str) -> bool | None:
        """True = transfer succeeded, False = refused, None = could not test."""


class DnspythonBackend:
    """Real resolver. Every lookup returns [] on NXDOMAIN/NoAnswer/timeout."""

    def __init__(self, timeout: float = 5.0):
        import dns.asyncresolver

        self.r = dns.asyncresolver.Resolver()
        self.r.lifetime = timeout
        self.timeout = timeout

    async def _q(self, name: str, rtype: str):
        import dns.exception
        import dns.resolver

        try:
            return list(await self.r.resolve(name, rtype))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
                dns.exception.Timeout, dns.name.EmptyLabel, dns.name.LabelTooLong):
            return []

    async def txt(self, name):
        return [b"".join(r.strings).decode("utf-8", "replace") for r in await self._q(name, "TXT")]

    async def caa(self, name):
        return [r.to_text() for r in await self._q(name, "CAA")]

    async def ns(self, name):
        return [r.target.to_text().rstrip(".") for r in await self._q(name, "NS")]

    async def addresses(self, name):
        return [r.address for r in await self._q(name, "A")]

    async def axfr(self, nameserver_ip, zone):
        import dns.query
        import dns.xfr
        import dns.zone

        def attempt():
            try:
                z = dns.zone.from_xfr(dns.query.xfr(nameserver_ip, zone, timeout=self.timeout, lifetime=self.timeout * 2))
                return len(z.nodes) > 0
            except dns.xfr.TransferError:
                return False  # REFUSED / NOTAUTH
            except Exception as e:
                # EOF / connection reset after the query is how many servers refuse
                if isinstance(e, (EOFError, ConnectionResetError)):
                    return False
                return None

        return await asyncio.to_thread(attempt)


def mail_domain(ctx: ScanContext) -> str | None:
    if ctx.config.dns_domain:
        return ctx.config.dns_domain.lower().rstrip(".")
    t = ctx.target
    if t.is_ip or t.is_local:
        return None
    return t.host[4:] if t.host.startswith("www.") else t.host


def parse_tags(record: str) -> dict[str, str]:
    tags = {}
    for part in record.split(";"):
        k, _, v = part.strip().partition("=")
        if k:
            tags[k.strip().lower()] = v.strip()
    return tags


def analyze_spf(domain: str, txts: list[str]) -> list[Finding]:
    spf = [t for t in txts if t.lower().startswith("v=spf1")]
    base = dict(owasp="A05", cwe=290, cvss=CVSS_SPOOFING)
    if not spf:
        return [Finding(
            id="dns.spf.missing", title="No SPF record", severity=Severity.MEDIUM,
            evidence=f"no 'v=spf1' TXT record at {domain}",
            remediation=(
                "Publish an SPF record listing your legitimate senders, ending in `-all` "
                "(or `v=spf1 -all` if the domain sends no mail)."
            ), **base,
        )]
    if len(spf) > 1:
        return [Finding(
            id="dns.spf.multiple", title="Multiple SPF records (SPF permerror)", severity=Severity.MEDIUM,
            evidence=" | ".join(spf),
            remediation="Merge into a single v=spf1 record; multiple records make SPF evaluation fail.",
            **base,
        )]
    rec = spf[0]
    m = re.search(r"([+~?-]?)all\b", rec, re.I)
    if not m:
        return [Finding(
            id="dns.spf.no-all", title="SPF record has no 'all' mechanism", severity=Severity.LOW,
            evidence=rec, remediation="End the record with `-all` (or `~all` while rolling out).", **base,
        )]
    q = m.group(1) or "+"
    if q == "+":
        return [Finding(
            id="dns.spf.pass-all", title="SPF '+all' authorises every server on the internet",
            severity=Severity.HIGH, evidence=rec,
            remediation="Replace `+all` with `-all`. As written, SPF provides no protection at all.", **base,
        )]
    if q == "?":
        return [Finding(
            id="dns.spf.neutral-all", title="SPF ends in '?all' (neutral)", severity=Severity.MEDIUM,
            evidence=rec, remediation="Use `-all` (hard fail) or at least `~all`.", **base,
        )]
    return []


def analyze_dmarc(domain: str, txts: list[str]) -> list[Finding]:
    recs = [t for t in txts if t.lower().startswith("v=dmarc1")]
    base = dict(owasp="A05", cwe=290, cvss=CVSS_SPOOFING)
    if not recs:
        return [Finding(
            id="dns.dmarc.missing", title="No DMARC record", severity=Severity.MEDIUM,
            evidence=f"no v=DMARC1 TXT record at _dmarc.{domain}",
            remediation=(
                f"Publish `_dmarc.{domain} TXT \"v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}\"`, "
                "monitor reports, then move to p=reject."
            ), **base,
        )]
    tags = parse_tags(recs[0])
    p = tags.get("p", "").lower()
    out = []
    if p not in ("quarantine", "reject"):
        out.append(Finding(
            id="dns.dmarc.weak-policy", title=f"DMARC policy is p={p or '(missing)'} (monitor only)",
            severity=Severity.MEDIUM, evidence=recs[0],
            remediation="After reviewing aggregate reports, enforce with p=quarantine and then p=reject.",
            **base,
        ))
    else:
        try:
            pct = int(tags.get("pct", "100"))
        except ValueError:
            pct = 100
        if pct < 100:
            out.append(Finding(
                id="dns.dmarc.partial", title=f"DMARC enforcement applies to only {pct}% of mail",
                severity=Severity.LOW, evidence=recs[0],
                remediation="Raise pct to 100 once legitimate mail streams pass alignment.", **base,
            ))
        sp = tags.get("sp", p).lower()
        if sp == "none":
            out.append(Finding(
                id="dns.dmarc.weak-subdomain-policy", title="DMARC subdomain policy is sp=none",
                severity=Severity.LOW, evidence=recs[0],
                remediation="Set sp=quarantine or sp=reject so spoofed subdomains are also blocked.", **base,
            ))
    if "rua" not in tags:
        out.append(Finding(
            id="dns.dmarc.no-reporting", title="DMARC has no aggregate report address (rua)",
            severity=Severity.INFO, evidence=recs[0],
            remediation="Add rua=mailto:... to receive aggregate reports and spot spoofing.",
        ))
    return out


@register
class DnsEmailScanner(Scanner):
    name = "dns-email"
    description = "SPF, DKIM, DMARC, CAA and zone-transfer (AXFR) posture"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        domain = mail_domain(ctx)
        if domain is None:
            return [Finding(
                id="dns.skipped", title="DNS/email checks skipped (IP or local target)",
                severity=Severity.INFO, evidence=ctx.target.host,
                remediation="Pass --dns-domain <domain> to assess the domain's DNS records.",
            )]
        dns: DnsBackend = ctx.config.dns_backend or DnspythonBackend(ctx.config.timeout)

        async def q(fn, *args):
            await ctx.limiter.acquire()
            return await fn(*args)

        out: list[Finding] = []
        out += analyze_spf(domain, await q(dns.txt, domain))
        out += analyze_dmarc(domain, await q(dns.txt, f"_dmarc.{domain}"))

        # DKIM: selectors are arbitrary, so absence among common ones is only Low.
        found_sel = []
        for sel in DKIM_SELECTORS:
            recs = await q(dns.txt, f"{sel}._domainkey.{domain}")
            if any("p=" in r for r in recs):
                found_sel.append(sel)
        if found_sel:
            out.append(Finding(
                id="dns.dkim.found", title="DKIM selector(s) found", severity=Severity.INFO,
                evidence=", ".join(f"{s}._domainkey.{domain}" for s in found_sel),
                remediation="No action required.",
            ))
        else:
            out.append(Finding(
                id="dns.dkim.not-found", title="No DKIM key found at common selectors",
                severity=Severity.LOW,
                evidence=f"checked {len(DKIM_SELECTORS)} selectors: {', '.join(DKIM_SELECTORS[:6])}, ...",
                remediation=(
                    "Sign outbound mail with DKIM. (If you use a custom selector this may be a false "
                    "positive - verify against a message header.)"
                ),
                owasp="A05", cwe=290,
            ))

        # CAA: inherited from parent domains, so walk up to the registrable level.
        caa, caa_at = [], None
        labels = domain.split(".")
        for i in range(len(labels) - 1):
            name = ".".join(labels[i:])
            caa = await q(dns.caa, name)
            if caa:
                caa_at = name
                break
        if not caa:
            out.append(Finding(
                id="dns.caa.missing", title="No CAA record restricts certificate issuance",
                severity=Severity.LOW, evidence=f"no CAA at {domain} or its parents",
                remediation=f'Add e.g. `{domain}. CAA 0 issue "letsencrypt.org"` naming only the CAs you use.',
                owasp="A05", cwe=295,
            ))
        else:
            out.append(Finding(
                id="dns.caa.present", title="CAA records present", severity=Severity.INFO,
                evidence=f"{caa_at}: " + " | ".join(caa), remediation="No action required.",
            ))

        # AXFR: one attempt per authoritative nameserver address. Refused = pass.
        ns_names = await q(dns.ns, domain)
        open_ns, tested = [], 0
        for ns in ns_names:
            for ip in await q(dns.addresses, ns):
                res = await q(dns.axfr, ip, domain)
                if res is not None:
                    tested += 1
                if res:
                    open_ns.append(f"{ns} ({ip})")
        if open_ns:
            out.append(Finding(
                id="dns.axfr.open", title="DNS zone transfer (AXFR) allowed",
                severity=Severity.HIGH, evidence=f"AXFR of {domain} succeeded from: {', '.join(open_ns)}",
                remediation=(
                    "Restrict zone transfers to secondary nameservers only (BIND `allow-transfer { <ips>; };`, "
                    "or TSIG). An open AXFR hands out your entire host inventory."
                ),
                owasp="A05", cwe=200, cvss=CVSS_INFO_LEAK_LOW,
            ))
        elif ns_names and not tested:
            ctx.notes.append(f"[dns-email] AXFR could not be tested against {', '.join(ns_names)}")
        return out
