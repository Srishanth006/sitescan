from datetime import datetime, timezone

from sitescan.core import Severity
from sitescan.scanners.wellknown import analyze_security_txt
from tests.conftest import ids


def test_vulnerable_wellknown(scan, vuln_http):
    r = scan(vuln_http.url, "wellknown")
    found = ids(r)
    assert {"wellknown.robots.present", "wellknown.robots.sensitive-paths",
            "wellknown.sitemap.missing", "wellknown.security-txt.missing"} <= found
    juicy = next(f for f in r.findings if f.id == "wellknown.robots.sensitive-paths")
    assert "/admin/" in juicy.evidence and "/backup/" in juicy.evidence


def test_hardened_wellknown(scan, good_https):
    r = scan(good_https.url, "wellknown")
    assert ids(r) == {"wellknown.robots.present", "wellknown.sitemap.present", "wellknown.security-txt.ok"}
    assert all(f.severity is Severity.INFO for f in r.findings)


def test_security_txt_validation():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert {f.id for f in analyze_security_txt("Expires: 2025-01-01T00:00:00Z", "u", now)} == {
        "wellknown.security-txt.no-contact", "wellknown.security-txt.expired"}
    assert {f.id for f in analyze_security_txt("Contact: mailto:a@b\nExpires: nope", "u", now)} == {
        "wellknown.security-txt.bad-expires"}
