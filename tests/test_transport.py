from sitescan.scanners.transport import find_mixed_content, preload_problems
from tests.conftest import ids


def test_plain_http_site_flagged(scan, vuln_http):
    found = ids(scan(vuln_http.url, "transport"))
    assert {"transport.no-https", "transport.no-https-redirect"} <= found


def test_https_site_with_mixed_content_and_no_redirect(scan, vuln_https, vuln_http):
    r = scan(vuln_https.url, "transport", http_url=vuln_http.url)
    found = ids(r)
    assert {"transport.mixed-content.active", "transport.mixed-content.passive",
            "transport.no-https-redirect", "transport.hsts.not-preload-eligible"} <= found
    active = next(f for f in r.findings if f.id == "transport.mixed-content.active")
    assert "analytics.js" in active.evidence and "<iframe>" in active.evidence and "<form>" in active.evidence


def test_hardened_transport_clean(scan, good_https, good_http):
    r = scan(good_https.url, "transport", http_url=good_http.url)
    assert ids(r) == {"transport.hsts.preload-eligible"}


def test_plain_anchor_links_are_not_mixed_content():
    assert find_mixed_content('<a href="http://x.test/">x</a><link rel="canonical" href="http://x.test/">') == []


def test_preload_problem_list():
    probs = preload_problems("max-age=300; preload", True)
    assert any("max-age" in p for p in probs) and any("includeSubDomains" in p for p in probs)
    assert preload_problems("max-age=31536000; includeSubDomains; preload", True) == []
