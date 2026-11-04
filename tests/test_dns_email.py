"""DNS tests run against the local target with an injected fake resolver:
the zone data lives here, so no query ever leaves the machine."""
from sitescan.core import Severity
from sitescan.scanners.dns_email import analyze_spf
from tests.conftest import ids


class FakeDNS:
    def __init__(self, txt=None, caa=None, ns=None, a=None, axfr_open=()):
        self._txt, self._caa = txt or {}, caa or {}
        self._ns, self._a = ns or {}, a or {}
        self._open = set(axfr_open)
        self.axfr_calls = []

    async def txt(self, name):
        return self._txt.get(name, [])

    async def caa(self, name):
        return self._caa.get(name, [])

    async def ns(self, name):
        return self._ns.get(name, [])

    async def addresses(self, name):
        return self._a.get(name, [])

    async def axfr(self, ip, zone):
        self.axfr_calls.append((ip, zone))
        return ip in self._open


WEAK = FakeDNS(
    txt={"weak.test": ["v=spf1 include:_spf.mail.test +all"], "_dmarc.weak.test": ["v=DMARC1; p=none"]},
    ns={"weak.test": ["ns1.weak.test"]},
    a={"ns1.weak.test": ["127.0.0.53"]},
    axfr_open={"127.0.0.53"},
)
STRONG = FakeDNS(
    txt={
        "strong.test": ["v=spf1 mx -all", "google-site-verification=abc"],
        "_dmarc.strong.test": ["v=DMARC1; p=reject; rua=mailto:d@strong.test"],
        "selector1._domainkey.strong.test": ["v=DKIM1; k=rsa; p=MIIBIjANBg"],
    },
    caa={"strong.test": ['0 issue "letsencrypt.org"']},
    ns={"strong.test": ["ns1.strong.test"]},
    a={"ns1.strong.test": ["127.0.0.54"]},
)


def test_weak_dns_flagged(scan, vuln_http):
    r = scan(vuln_http.url, "dns-email", dns_backend=WEAK, dns_domain="weak.test")
    found = ids(r)
    assert {"dns.spf.pass-all", "dns.dmarc.weak-policy", "dns.dkim.not-found",
            "dns.caa.missing", "dns.axfr.open"} <= found
    assert next(f for f in r.findings if f.id == "dns.axfr.open").severity is Severity.HIGH


def test_strong_dns_clean(scan, good_https):
    r = scan(good_https.url, "dns-email", dns_backend=STRONG, dns_domain="strong.test")
    assert ids(r) == {"dns.dkim.found", "dns.caa.present"}
    assert STRONG.axfr_calls == [("127.0.0.54", "strong.test")]


def test_ip_target_skipped_without_domain(scan, vuln_http):
    assert ids(scan(vuln_http.url, "dns-email", dns_backend=WEAK)) == {"dns.skipped"}


def test_spf_variants():
    assert {f.id for f in analyze_spf("d", [])} == {"dns.spf.missing"}
    assert {f.id for f in analyze_spf("d", ["v=spf1 -all", "v=spf1 mx -all"])} == {"dns.spf.multiple"}
    assert {f.id for f in analyze_spf("d", ["v=spf1 mx ?all"])} == {"dns.spf.neutral-all"}
    assert analyze_spf("d", ["v=spf1 mx ~all"]) == []
