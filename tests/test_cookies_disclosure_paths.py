from sitescan.core import Severity
from sitescan.scanners.cookies import analyze_cookie, parse_set_cookie
from tests.conftest import ids


# ---- cookies ---------------------------------------------------------------
def test_insecure_cookies_flagged(scan, vuln_https):
    r = scan(vuln_https.url, "cookies")
    found = ids(r)
    assert {"cookies.missing-secure", "cookies.missing-httponly",
            "cookies.missing-samesite", "cookies.samesite-none-insecure"} <= found
    sess = [f for f in r.findings if "PHPSESSID" in f.title and f.id == "cookies.missing-httponly"]
    assert sess and sess[0].severity is Severity.MEDIUM
    # values are never echoed
    assert all("8f3a1c9e" not in f.evidence for f in r.findings)


def test_secure_cookie_clean(scan, good_https):
    r = scan(good_https.url, "cookies")
    assert ids(r) == {"cookies.ok"}


def test_cookie_parser_case_insensitive_attrs():
    c = parse_set_cookie("id=1; SECURE; HttpOnly; samesite=Strict; Path=/")
    assert analyze_cookie(c, https=True) == []


# ---- disclosure ------------------------------------------------------------
def test_disclosure_flagged(scan, vuln_http):
    r = scan(vuln_http.url, "disclosure")
    found = ids(r)
    assert {"disclosure.banner.server", "disclosure.banner.x-powered-by",
            "disclosure.verbose-errors", "disclosure.directory-listing"} <= found
    ev = next(f for f in r.findings if f.id == "disclosure.verbose-errors").evidence
    assert "Python traceback" in ev


def test_disclosure_clean(scan, good_https):
    assert scan(good_https.url, "disclosure").findings == []


# ---- sensitive paths -------------------------------------------------------
def test_sensitive_paths_flagged(scan, vuln_http):
    r = scan(vuln_http.url, "sensitive-paths")
    found = ids(r)
    assert {"paths.exposed.git.config", "paths.exposed.env", "paths.exposed.backup.sql",
            "paths.exposed.phpinfo.php", "paths.exposed.DS_Store", "paths.protected.admin"} <= found
    env = next(f for f in r.findings if f.id == "paths.exposed.env")
    assert env.severity is Severity.CRITICAL and "NOT downloaded" in env.evidence


def test_sensitive_paths_clean(scan, good_https):
    r = scan(good_https.url, "sensitive-paths")
    assert ids(r) == {"paths.summary"}
    assert r.findings[0].evidence.endswith("none")


def test_sensitive_paths_use_head_only(vuln_http, scan, monkeypatch):
    from sitescan.core import http as http_mod

    methods = []
    orig = http_mod.HttpClient._send

    async def spy(self, method, url):
        methods.append(method)
        return await orig(self, method, url)

    monkeypatch.setattr(http_mod.HttpClient, "_send", spy)
    scan(vuln_http.url, "sensitive-paths")
    assert methods and set(methods) == {"HEAD"}
