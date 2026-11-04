import httpx

from sitescan.core import Severity
from sitescan.core.cvss import base_score
from sitescan.scanners.dependencies import detect_in_text, detect_in_url
from tests.conftest import ids


def test_vulnerable_libraries_flagged(scan, vuln_https):
    r = scan(vuln_https.url, "dependencies")
    found = ids(r)
    assert {"deps.jquery.vulnerable", "deps.angular.vulnerable", "deps.bootstrap.vulnerable"} <= found
    jq = next(f for f in r.findings if f.id == "deps.jquery.vulnerable")
    assert "CVE-2020-11022" in jq.evidence and jq.severity is Severity.MEDIUM and jq.owasp == "A06"
    ng = next(f for f in r.findings if f.id == "deps.angular.vulnerable")
    assert ng.severity is Severity.HIGH and ng.cvss.startswith("CVSS:3.1/")


def test_current_library_clean(scan, good_https):
    r = scan(good_https.url, "dependencies")
    assert ids(r) == {"deps.jquery.detected"}
    assert "no known vulnerabilities" in r.findings[0].evidence


def test_osv_failure_is_graceful(scan, vuln_https):
    broken = httpx.MockTransport(lambda req: httpx.Response(503))
    r = scan(vuln_https.url, "dependencies", osv_transport=broken)
    assert r.runs[0].status == "ok"
    assert all(f.severity is Severity.INFO for f in r.findings)
    assert any("OSV query" in n for n in r.notes)


def test_no_osv_flag(scan, vuln_https):
    r = scan(vuln_https.url, "dependencies", osv_enabled=False)
    assert all(f.id.endswith(".detected") for f in r.findings) and r.findings


def test_detectors():
    assert [(l.npm, v) for l, v in detect_in_url("https://cdnjs.cloudflare.com/ajax/libs/jquery/3.4.1/jquery.min.js")] == [("jquery", "3.4.1")]
    assert [(l.npm, v) for l, v in detect_in_url("https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.min.js")] == [("bootstrap", "5.3.2")]
    assert [(l.npm, v) for l, v in detect_in_text("/*! jQuery v2.2.4 | (c) jQuery Foundation */")] == [("jquery", "2.2.4")]


def test_cvss_calculator_known_values():
    assert base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1
    assert base_score("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N") == 4.7
    assert base_score("garbage") is None
