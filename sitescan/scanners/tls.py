"""TLS/SSL: protocol versions, weak cipher families, certificate & chain checks.

All probing is plain handshakes with Python's ``ssl`` module -- no payloads,
no renegotiation abuse. Each handshake goes through the shared rate limiter.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import ipaddress
import socket
import ssl
import warnings
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from ..core import Finding, ScanContext, Scanner, Severity, register
from ._common import CVSS_MITM_ACTIVE, CVSS_MITM_PASSIVE

PROTOCOLS = [
    ("TLSv1.0", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
]
# (label, OpenSSL cipher string, severity, why)
WEAK_CIPHERS = [
    ("NULL", "eNULL", Severity.HIGH, "no encryption at all"),
    ("anonymous", "aNULL:!eNULL", Severity.HIGH, "no server authentication (trivial MITM)"),
    ("EXPORT", "EXP", Severity.HIGH, "export-grade 40/56-bit keys"),
    ("RC4", "RC4", Severity.HIGH, "RC4 keystream biases (RFC 7465 prohibits it)"),
    ("DES/3DES", "DES:3DES", Severity.MEDIUM, "64-bit block cipher, SWEET32 (CVE-2016-2183)"),
    ("static-RSA", "kRSA", Severity.LOW, "no forward secrecy (RSA key exchange)"),
]
EXPIRY_WARN_DAYS = 30


@dataclass
class Probe:
    ok: bool
    cipher: tuple | None = None
    version: str | None = None
    cert_der: bytes | None = None
    error: str | None = None
    untestable: bool = False  # local OpenSSL can't even attempt it


def _client_ctx(min_v=None, max_v=None, ciphers="ALL:@SECLEVEL=0") -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        if min_v:
            ctx.minimum_version = min_v
        if max_v:
            ctx.maximum_version = max_v
    ctx.set_ciphers(ciphers)
    return ctx


def _handshake(host: str, port: int, ctx: ssl.SSLContext, timeout: float, sni: str | None) -> Probe:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as tls:
                return Probe(
                    ok=True,
                    cipher=tls.cipher(),
                    version=tls.version(),
                    cert_der=tls.getpeercert(binary_form=True),
                )
    except ssl.SSLCertVerificationError as e:
        return Probe(ok=False, error=e.verify_message or str(e))
    except (ssl.SSLError, ConnectionResetError, ConnectionAbortedError) as e:
        msg = str(e)
        untestable = "no protocols available" in msg or "NO_CIPHERS" in msg.upper()
        return Probe(ok=False, error=msg, untestable=untestable)
    except (OSError, socket.timeout) as e:
        return Probe(ok=False, error=f"{type(e).__name__}: {e}")


def host_matches(host: str, cert: x509.Certificate) -> bool:
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        dns_names = san.get_values_for_type(x509.DNSName)
        ips = [str(i) for i in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        # Legacy fallback to CN (browsers no longer do this, but report fairly)
        dns_names = [a.value for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
        ips = []
    try:
        return str(ipaddress.ip_address(host)) in ips
    except ValueError:
        pass
    host = host.lower()
    for name in dns_names:
        name = name.lower().rstrip(".")
        if name == host:
            return True
        if name.startswith("*.") and "." in host:
            if host.split(".", 1)[1] == name[2:]:
                return True
    return False


def _san_list(cert: x509.Certificate) -> list[str]:
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        return san.get_values_for_type(x509.DNSName) + [str(i) for i in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        return []


def is_self_signed(cert: x509.Certificate) -> bool:
    if cert.issuer != cert.subject:
        return False
    try:
        cert.verify_directly_issued_by(cert)
        return True
    except Exception:
        return False


def analyze_certificate(cert: x509.Certificate, host: str, now: dt.datetime | None = None) -> list[Finding]:
    now = now or dt.datetime.now(dt.timezone.utc)
    out: list[Finding] = []
    subject = cert.subject.rfc4514_string()
    not_after = cert.not_valid_after_utc
    not_before = cert.not_valid_before_utc
    days_left = (not_after - now).days

    if now > not_after:
        out.append(Finding(
            id="tls.cert.expired", title="TLS certificate has expired", severity=Severity.HIGH,
            evidence=f"notAfter={not_after.isoformat()} subject={subject}",
            remediation="Renew the certificate immediately and automate renewal (e.g. ACME/Let's Encrypt).",
            owasp="A02", cwe=298, cvss=CVSS_MITM_ACTIVE,
        ))
    elif now < not_before:
        out.append(Finding(
            id="tls.cert.not-yet-valid", title="TLS certificate is not yet valid", severity=Severity.HIGH,
            evidence=f"notBefore={not_before.isoformat()}",
            remediation="Check server clock and certificate issuance date.",
            owasp="A02", cwe=298,
        ))
    elif days_left <= EXPIRY_WARN_DAYS:
        out.append(Finding(
            id="tls.cert.expiring-soon", title=f"TLS certificate expires in {days_left} days",
            severity=Severity.MEDIUM,
            evidence=f"notAfter={not_after.isoformat()} ({days_left} days left)",
            remediation="Renew now and put certificate expiry under automated renewal + monitoring.",
            owasp="A02", cwe=298,
        ))

    if is_self_signed(cert):
        out.append(Finding(
            id="tls.cert.self-signed", title="TLS certificate is self-signed", severity=Severity.HIGH,
            evidence=f"issuer == subject == {subject}",
            remediation="Use a certificate issued by a publicly trusted CA so clients can authenticate the server.",
            owasp="A02", cwe=295, cvss=CVSS_MITM_ACTIVE,
        ))

    if not host_matches(host, cert):
        out.append(Finding(
            id="tls.cert.name-mismatch", title="Certificate does not cover the target hostname",
            severity=Severity.HIGH,
            evidence=f"host={host} SANs={_san_list(cert) or '(none)'} subject={subject}",
            remediation="Reissue the certificate with the hostname in the subjectAltName extension.",
            owasp="A02", cwe=297, cvss=CVSS_MITM_ACTIVE,
        ))

    key = cert.public_key()
    weak = None
    if isinstance(key, rsa.RSAPublicKey) and key.key_size < 2048:
        weak = f"RSA {key.key_size}-bit"
    elif isinstance(key, ec.EllipticCurvePublicKey) and key.curve.key_size < 256:
        weak = f"EC {key.curve.name} ({key.curve.key_size}-bit)"
    elif isinstance(key, dsa.DSAPublicKey):
        weak = f"DSA {key.key_size}-bit (DSA is deprecated for TLS)"
    if weak:
        out.append(Finding(
            id="tls.cert.weak-key", title="Certificate uses a weak public key", severity=Severity.HIGH,
            evidence=weak,
            remediation="Reissue with RSA >= 2048 bits (3072 recommended) or ECDSA P-256 or stronger.",
            owasp="A02", cwe=326, cvss=CVSS_MITM_ACTIVE,
        ))

    algo = cert.signature_hash_algorithm
    if algo is not None and algo.name.lower() in ("md5", "sha1"):
        out.append(Finding(
            id="tls.cert.weak-signature", title=f"Certificate signed with {algo.name.upper()}",
            severity=Severity.MEDIUM, evidence=f"signatureAlgorithm hash={algo.name}",
            remediation="Reissue the certificate with a SHA-256 (or stronger) signature.",
            owasp="A02", cwe=328,
        ))
    return out


@register
class TLSScanner(Scanner):
    name = "tls"
    description = "TLS protocol versions, cipher suites, certificate validity and chain"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        t = ctx.target
        if not t.is_https:
            return [Finding(
                id="tls.not-tested", title="TLS not assessed: target URL is plain HTTP",
                severity=Severity.INFO, evidence=t.url,
                remediation="Re-run against the https:// URL (see the transport findings for HTTPS availability).",
            )]
        host, port = t.host, t.port
        sni = None if t.is_ip else host
        timeout = ctx.config.timeout

        async def probe(c: ssl.SSLContext) -> Probe:
            await ctx.limiter.acquire()
            return await asyncio.to_thread(_handshake, host, port, c, timeout, sni)

        out: list[Finding] = []

        # 1. protocol versions ------------------------------------------------
        offered: dict[str, Probe] = {}
        untestable: list[str] = []
        for label, ver in PROTOCOLS:
            try:
                c = _client_ctx(ver, ver)
            except (ValueError, ssl.SSLError):
                untestable.append(label)
                continue
            p = await probe(c)
            if p.ok:
                offered[label] = p
            elif p.untestable:
                untestable.append(label)
            elif label == "TLSv1.3" and "Connection" in (p.error or "") and not offered:
                return [Finding(
                    id="tls.unreachable", title="Could not complete any TLS handshake",
                    severity=Severity.INFO, evidence=p.error or "",
                    remediation="Verify the HTTPS port is reachable from the scanning host.",
                )]

        if not offered:
            return [Finding(
                id="tls.unreachable", title="Could not complete any TLS handshake",
                severity=Severity.INFO, evidence=f"{host}:{port}",
                remediation="Verify the HTTPS port is reachable from the scanning host.",
            )]

        for label in ("TLSv1.0", "TLSv1.1"):
            if label in offered:
                out.append(Finding(
                    id=f"tls.protocol.{label.lower().replace('v', '').replace('.', '')}",
                    title=f"Deprecated protocol {label} is enabled", severity=Severity.MEDIUM,
                    evidence=f"handshake succeeded with {label}, cipher {offered[label].cipher[0]}",
                    remediation="Disable TLS 1.0 and 1.1 (deprecated by RFC 8996); support only TLS 1.2 and 1.3.",
                    owasp="A02", cwe=327, cvss=CVSS_MITM_PASSIVE,
                ))
        if "TLSv1.3" not in offered and "TLSv1.3" not in untestable:
            out.append(Finding(
                id="tls.protocol.no-tls13", title="TLS 1.3 is not supported", severity=Severity.LOW,
                evidence=f"offered: {', '.join(offered)}",
                remediation="Enable TLS 1.3 for faster handshakes and removal of legacy cipher constructions.",
                owasp="A02", cwe=327,
            ))
        if untestable:
            ctx.notes.append(f"[tls] local OpenSSL could not test: {', '.join(untestable)}")

        # 2. weak cipher families (on <= TLS 1.2, where suites are negotiable) --
        legacy = [v for lbl, v in PROTOCOLS if lbl in offered and lbl != "TLSv1.3"]
        if legacy:
            lo, hi = min(legacy), max(legacy)
            for label, spec, sev, why in WEAK_CIPHERS:
                try:
                    c = _client_ctx(lo, hi, f"{spec}:@SECLEVEL=0")
                except ssl.SSLError:
                    ctx.notes.append(f"[tls] local OpenSSL lacks {label} ciphers; not tested")
                    continue
                p = await probe(c)
                if p.ok:
                    out.append(Finding(
                        id=f"tls.cipher.{label.lower().replace('/', '-')}",
                        title=f"Server accepts {label} cipher suites", severity=sev,
                        evidence=f"negotiated {p.cipher[0]} over {p.version} ({why})",
                        remediation=(
                            "Restrict the cipher list to AEAD suites with ECDHE key exchange, e.g. Mozilla's "
                            "'intermediate' profile (ECDHE+AESGCM, ECDHE+CHACHA20)."
                        ),
                        owasp="A02", cwe=327,
                        cvss=CVSS_MITM_ACTIVE if sev is Severity.HIGH else CVSS_MITM_PASSIVE,
                    ))

        # 3. certificate --------------------------------------------------------
        best = offered.get("TLSv1.3") or offered.get("TLSv1.2") or next(iter(offered.values()))
        cert = None
        if best.cert_der:
            try:
                cert = x509.load_der_x509_certificate(best.cert_der)
            except ValueError as e:
                ctx.notes.append(f"[tls] could not parse certificate: {e}")
        if cert is not None:
            out += analyze_certificate(cert, host)

        # 4. chain validation against system trust (+ optional extra CA) ---------
        vctx = ssl.create_default_context(cafile=ctx.config.ca_bundle)
        vctx.check_hostname = False  # hostname checked separately above
        p = await probe(vctx)
        self_signed = any(f.id == "tls.cert.self-signed" for f in out)
        if not p.ok and not self_signed:
            out.append(Finding(
                id="tls.chain.invalid", title="Certificate chain does not validate",
                severity=Severity.HIGH, evidence=p.error or "verification failed",
                remediation=(
                    "Serve the full intermediate chain and use a certificate from a publicly trusted CA; "
                    "check `openssl s_client -showcerts` output."
                ),
                owasp="A02", cwe=295, cvss=CVSS_MITM_ACTIVE,
            ))

        if cert is not None:
            out.append(Finding(
                id="tls.summary", title="TLS configuration summary", severity=Severity.INFO,
                evidence=(
                    f"protocols={','.join(offered)}; preferred cipher={best.cipher[0]}; "
                    f"subject={cert.subject.rfc4514_string()}; issuer={cert.issuer.rfc4514_string()}; "
                    f"expires={cert.not_valid_after_utc.date()}"
                ),
                remediation="No action required; informational.",
            ))
        return out
