"""Exposed sensitive paths. HEAD requests ONLY - contents are never downloaded."""
from __future__ import annotations

from ..core import Finding, ScanContext, Scanner, Severity, register
from ._common import CVSS_INFO_LEAK_HIGH, CVSS_INFO_LEAK_LOW, CVSS_SECRETS_EXPOSED, random_path

C, H, M, L, I = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO

# path -> (severity if publicly readable, CWE, short description)
WORDLIST: dict[str, tuple[Severity, int, str]] = {
    "/.git/config": (H, 527, "Git repository metadata (full source code may be recoverable)"),
    "/.git/HEAD": (H, 527, "Git repository metadata"),
    "/.svn/entries": (H, 527, "Subversion metadata"),
    "/.hg/hgrc": (H, 527, "Mercurial metadata"),
    "/.env": (C, 538, "environment file (typically DB passwords, API keys)"),
    "/.env.local": (C, 538, "environment file"),
    "/.env.production": (C, 538, "environment file"),
    "/.aws/credentials": (C, 538, "AWS credential file"),
    "/.htpasswd": (H, 538, "Apache password hashes"),
    "/id_rsa": (C, 538, "SSH private key"),
    "/backup.sql": (C, 530, "database dump"),
    "/dump.sql": (C, 530, "database dump"),
    "/db.sql": (C, 530, "database dump"),
    "/database.sql": (C, 530, "database dump"),
    "/backup.zip": (H, 530, "backup archive"),
    "/backup.tar.gz": (H, 530, "backup archive"),
    "/site.tar.gz": (H, 530, "site archive"),
    "/wp-config.php.bak": (C, 530, "WordPress config backup"),
    "/config.php.bak": (H, 530, "config backup"),
    "/web.config": (M, 538, "IIS configuration"),
    "/phpinfo.php": (M, 200, "phpinfo() page (full environment disclosure)"),
    "/info.php": (M, 200, "possible phpinfo() page"),
    "/server-status": (M, 200, "Apache mod_status"),
    "/server-info": (M, 200, "Apache mod_info"),
    "/actuator/env": (H, 200, "Spring Boot actuator environment"),
    "/actuator/heapdump": (C, 200, "Spring Boot heap dump"),
    "/actuator": (L, 200, "Spring Boot actuator index"),
    "/.DS_Store": (L, 538, "macOS folder metadata (leaks file names)"),
    "/docker-compose.yml": (M, 538, "container orchestration config"),
    "/.npmrc": (H, 538, "npm config (may contain auth tokens)"),
    "/.vscode/sftp.json": (C, 538, "editor SFTP credentials"),
    "/admin": (L, 284, "admin interface"),
    "/administrator": (L, 284, "admin interface"),
    "/wp-admin/": (I, 284, "WordPress admin"),
    "/phpmyadmin/": (M, 284, "phpMyAdmin"),
}
ADMIN_LIKE = {"/admin", "/administrator", "/wp-admin/", "/phpmyadmin/"}


def slug(path: str) -> str:
    """'/.git/config' -> 'git.config' (stable finding-id fragment)."""
    return path.strip("/").replace("/", ".").lstrip(".")


@register
class SensitivePathsScanner(Scanner):
    name = "sensitive-paths"
    description = "HEAD-only probe of well-known sensitive paths (.git, .env, dumps, phpinfo...)"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        out: list[Finding] = []
        # Soft-404 baseline: what does a definitely-missing path return?
        baseline = await ctx.http.head(ctx.target.join(random_path()))
        if baseline is None:
            return [Finding(
                id="paths.unreachable", title="Path probe skipped: target did not respond",
                severity=Severity.INFO, evidence="; ".join(ctx.http.errors[-1:]) or "no response",
                remediation="Verify the target is reachable from the scanning host.",
            )]
        soft404 = baseline is not None and baseline.status == 200
        base_sig = (
            (baseline.headers.get("content-type"), baseline.headers.get("content-length"))
            if soft404 else None
        )
        if soft404:
            ctx.notes.append("[sensitive-paths] server answers 200 for unknown paths; matched baseline responses ignored")

        summary: list[str] = []
        for path, (sev, cwe, what) in WORDLIST.items():
            r = await ctx.http.head(ctx.target.join(path))
            if r is None:
                continue
            if r.status != 404:
                summary.append(f"{path}={r.status}")
            if r.status in (200, 206):
                if soft404 and (r.headers.get("content-type"), r.headers.get("content-length")) == base_sig:
                    continue
                ct = r.headers.get("content-type", "?")
                cl = r.headers.get("content-length", "?")
                if ct.startswith("text/html") and path not in ADMIN_LIKE and not path.endswith(".php"):
                    # A dotfile/dump served as HTML is almost always an app shell / custom 404.
                    sev_eff = Severity.INFO
                else:
                    sev_eff = sev
                cvss = (
                    CVSS_SECRETS_EXPOSED if sev_eff is C
                    else CVSS_INFO_LEAK_HIGH if sev_eff is H
                    else CVSS_INFO_LEAK_LOW if sev_eff in (M, L) else None
                )
                out.append(Finding(
                    id=f"paths.exposed.{slug(path)}",
                    title=f"Sensitive path publicly accessible: {path}",
                    severity=sev_eff,
                    evidence=f"HEAD {r.url} -> {r.status} (Content-Type: {ct}, Content-Length: {cl}); {what}. Content NOT downloaded.",
                    remediation=(
                        f"Remove {path} from the web root or deny access at the web server "
                        "(e.g. nginx `location ~ /\\. { deny all; }`). If it held secrets, assume they "
                        "are compromised and rotate them."
                        if path not in ADMIN_LIKE else
                        "Restrict administrative interfaces by network (VPN/IP allow-list) and require MFA."
                    ),
                    owasp="A01" if path in ADMIN_LIKE else "A05", cwe=cwe, cvss=cvss,
                ))
            elif r.status in (401, 403) and path in ADMIN_LIKE:
                out.append(Finding(
                    id=f"paths.protected.{slug(path)}",
                    title=f"Admin interface present (access-controlled): {path}",
                    severity=Severity.INFO,
                    evidence=f"HEAD {r.url} -> {r.status}"
                             + (f" WWW-Authenticate: {r.headers['www-authenticate']}" if "www-authenticate" in r.headers else ""),
                    remediation="Consider restricting admin interfaces to trusted networks in addition to authentication.",
                    owasp="A01", cwe=284,
                ))

        out.append(Finding(
            id="paths.summary",
            title=f"Probed {len(WORDLIST)} well-known paths with HEAD",
            severity=Severity.INFO,
            evidence="non-404 responses: " + (", ".join(summary) if summary else "none"),
            remediation="Informational: full status map of the path probe.",
        ))
        return out
