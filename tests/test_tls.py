from sitescan.core import Severity
from tests.conftest import ids


def test_bad_tls_flagged(scan, vuln_https):
    r = scan(vuln_https.url, "tls")
    found = ids(r)
    assert {
        "tls.cert.self-signed",
        "tls.cert.name-mismatch",
        "tls.cert.weak-key",
        "tls.cert.expiring-soon",
        "tls.protocol.no-tls13",
        "tls.cipher.static-rsa",
    } <= found, found
    weak = next(f for f in r.findings if f.id == "tls.cert.weak-key")
    assert "1024" in weak.evidence and weak.severity is Severity.HIGH
    # self-signed already explains the chain failure; don't double-report
    assert "tls.chain.invalid" not in found


def test_bad_tls_legacy_protocols(scan, vuln_https):
    """TLS 1.0/1.1 detection depends on the local OpenSSL still being able to
    speak them; when it can, the server (which enables them) must be flagged."""
    r = scan(vuln_https.url, "tls")
    if any("could not test" in n and "TLSv1.0" in n for n in r.notes):
        return
    assert {"tls.protocol.tls10", "tls.protocol.tls11"} <= ids(r)


def test_good_tls_clean(scan, good_https, certs):
    r = scan(good_https.url, "tls", ca_bundle=certs["good"]["ca"])
    non_info = [f.id for f in r.findings if f.severity is not Severity.INFO]
    assert non_info == []
    assert "tls.summary" in ids(r)


def test_untrusted_chain_reported(scan, good_https):
    # Same good server, but without trusting the local CA -> chain invalid.
    r = scan(good_https.url, "tls")
    assert "tls.chain.invalid" in ids(r)


def test_plain_http_target_skips(scan, vuln_http):
    assert ids(scan(vuln_http.url, "tls")) == {"tls.not-tested"}
