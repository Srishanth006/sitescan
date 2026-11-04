from sitescan.scanners.headers import analyze_csp, parse_csp
from tests.conftest import ids


def test_vulnerable_headers_flagged(scan, vuln_https):
    r = scan(vuln_https.url, "headers")
    found = ids(r)
    assert {
        "headers.csp.unsafe-inline",
        "headers.csp.unsafe-eval",
        "headers.csp.wildcard-source",
        "headers.csp.base-uri",
        "headers.hsts.short-max-age",
        "headers.xfo.missing",
        "headers.xcto.missing",
        "headers.referrer-policy.unsafe",
        "headers.permissions-policy.missing",
    } <= found
    f = next(f for f in r.findings if f.id == "headers.csp.unsafe-inline")
    assert "unsafe-inline" in f.evidence and f.cwe == 79 and f.owasp == "A05"


def test_hardened_headers_clean(scan, good_https):
    r = scan(good_https.url, "headers")
    assert r.findings == [], [f.id for f in r.findings]


def test_hsts_not_required_over_plain_http(scan, vuln_http):
    found = ids(scan(vuln_http.url, "headers"))
    assert not any(i.startswith("headers.hsts") for i in found)
    assert "headers.xfo.missing" in found


def test_csp_parser_first_directive_wins():
    p = parse_csp("script-src 'self'; SCRIPT-SRC *; object-src 'none'")
    assert p["script-src"] == ["'self'"] and p["object-src"] == ["'none'"]


def test_nonce_neutralises_unsafe_inline():
    fs = analyze_csp("default-src 'self'; script-src 'unsafe-inline' 'nonce-abc'; base-uri 'none'")
    assert not any(f.id == "headers.csp.unsafe-inline" for f in fs)


def test_default_src_fallback_used():
    fs = {f.id for f in analyze_csp("default-src * 'unsafe-eval'")}
    assert {"headers.csp.unsafe-eval", "headers.csp.wildcard-source", "headers.csp.object-src"} <= fs
