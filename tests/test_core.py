import asyncio
import time

import pytest

from sitescan.core import Finding, ScanConfig, Scanner, Severity, Target, discover, register
from sitescan.core import scanner as scanner_mod
from sitescan.core.gate import AuthorizationError, check_authorization, denied_reason
from sitescan.core.orchestrator import run_scan
from sitescan.core.ratelimit import RateLimiter
from sitescan.core.scoring import grade, score

EXPECTED = {"headers", "tls", "cookies", "disclosure", "sensitive-paths",
            "transport", "dns-email", "dependencies", "wellknown"}


def F(sev: Severity) -> Finding:
    return Finding(id="x", title="x", severity=sev, evidence="e", remediation="r")


# ---- registry ---------------------------------------------------------------
def test_all_scanners_auto_discovered():
    assert EXPECTED <= set(discover())


def test_register_rejects_duplicates_and_non_scanners():
    with pytest.raises(TypeError):
        register(object)

    class Dup(Scanner):
        name = "headers"

        async def run(self, ctx):
            return []

    with pytest.raises(ValueError):
        register(Dup)


def test_new_scanner_needs_no_wiring(scan, vuln_http, monkeypatch):
    monkeypatch.setattr(scanner_mod, "_REGISTRY", dict(scanner_mod._REGISTRY))

    @register
    class Hello(Scanner):
        name = "hello-test"

        async def run(self, ctx):
            r = await ctx.root()
            return [Finding(id="hello", title="hi", severity=Severity.INFO,
                            evidence=str(r.status), remediation="-")]

    r = scan(vuln_http.url, "hello-test")
    assert [f.id for f in r.findings] == ["hello"] and r.findings[0].scanner == "hello-test"


# ---- failure containment ---------------------------------------------------
def test_crashing_scanner_does_not_break_run(scan, vuln_http, monkeypatch):
    monkeypatch.setattr(scanner_mod, "_REGISTRY", dict(scanner_mod._REGISTRY))

    @register
    class Boom(Scanner):
        name = "boom-test"

        async def run(self, ctx):
            raise RuntimeError("kaboom")

    r = scan(vuln_http.url, "boom-test", "cookies")
    runs = {x.name: x for x in r.runs}
    assert runs["boom-test"].status == "error" and "kaboom" in runs["boom-test"].error
    assert runs["cookies"].status == "ok" and r.findings


def test_slow_scanner_times_out(scan, vuln_http, monkeypatch):
    monkeypatch.setattr(scanner_mod, "_REGISTRY", dict(scanner_mod._REGISTRY))

    @register
    class Slow(Scanner):
        name = "slow-test"

        async def run(self, ctx):
            await asyncio.sleep(10)

    r = scan(vuln_http.url, "slow-test", scanner_timeout=0.2)
    assert r.runs[0].status == "timeout"


def test_unreachable_target_never_crashes(scan):
    # Port 9 (discard) on loopback: nothing listening -> connection refused everywhere.
    r = scan("https://127.0.0.1:9/", timeout=1)
    assert all(run.status == "ok" for run in r.runs), [(x.name, x.error) for x in r.runs]
    assert r.errors  # failures recorded, not raised


def test_redirect_loop_handled(scan):
    import threading

    from flask import Flask, redirect
    from werkzeug.serving import make_server

    app = Flask("loop")
    app.add_url_rule("/", "a", lambda: redirect("/b"))
    app.add_url_rule("/b", "b", lambda: redirect("/"))
    srv = make_server("127.0.0.1", 0, app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        r = scan(f"http://127.0.0.1:{srv.server_port}/", "headers", "cookies")
        assert all(x.status == "ok" for x in r.runs)
        assert any("too many redirects" in e for e in r.errors)
    finally:
        srv.shutdown()


# ---- rate limiting & user agent ----------------------------------------------
def test_rate_limiter_enforces_rate():
    async def go():
        rl = RateLimiter(20)
        t0 = time.monotonic()
        for _ in range(21):
            await rl.acquire()
        return time.monotonic() - t0

    assert go and asyncio.run(go()) >= 0.9  # 20 extra tokens at 20/s ~= 1s


def test_user_agent_sent(vuln_http, monkeypatch):
    seen = []
    from sitescan.core import http as http_mod

    orig = http_mod.HttpClient._send

    async def spy(self, method, url):
        seen.append(self._client.headers["user-agent"])
        return await orig(self, method, url)

    monkeypatch.setattr(http_mod.HttpClient, "_send", spy)
    asyncio.run(run_scan(Target.parse(vuln_http.url), ScanConfig(rate=500), only=["headers"]))
    assert seen and seen[0].startswith("sitescan/")


def test_only_safe_methods():
    from sitescan.core.http import HttpClient

    async def go():
        c = HttpClient(RateLimiter(100), "ua")
        try:
            await c.request("POST", "http://127.0.0.1/")
        finally:
            await c.aclose()

    with pytest.raises(ValueError):
        asyncio.run(go())


# ---- authorization gate ------------------------------------------------------
def test_denylist():
    assert denied_reason("www.google.com")
    assert denied_reason("api.github.com")
    assert denied_reason("agency.gov")
    assert denied_reason("notgoogle.com") is None
    assert denied_reason("127.0.0.1") is None


def test_gate_requires_flag_and_matching_confirmation():
    t = Target.parse("https://shop.example.org")
    with pytest.raises(AuthorizationError, match="i-am-authorized"):
        check_authorization(t, authorized_flag=False, confirm_host="shop.example.org")
    with pytest.raises(AuthorizationError, match="does not match"):
        check_authorization(t, authorized_flag=True, prompt=lambda _: "example.org")
    check_authorization(t, authorized_flag=True, prompt=lambda _: "SHOP.example.org ")
    with pytest.raises(AuthorizationError, match="TTY"):
        check_authorization(t, authorized_flag=True, interactive=False)


def test_gate_denylist_checked_before_prompt():
    asked = []
    with pytest.raises(AuthorizationError, match="denylisted"):
        check_authorization(Target.parse("https://facebook.com"), authorized_flag=True,
                            prompt=lambda m: asked.append(m) or "facebook.com")
    assert asked == []


# ---- scoring -----------------------------------------------------------------
def test_scoring():
    assert score([]) == 100 and grade([]) == "A"
    assert score([F(Severity.INFO)] * 50) == 100
    assert score([F(Severity.LOW)] * 50) == 88  # capped at 12
    assert grade([F(Severity.CRITICAL)]) == "D"  # 75 -> C, capped to D
    assert grade([F(Severity.HIGH)]) == "C"  # 88 -> B, capped to C
    assert score([F(s) for s in Severity for _ in range(20)]) == 0


def test_target_parse():
    t = Target.parse("Example.COM:8443/path?q=1")
    assert (t.scheme, t.host, t.port, t.url) == ("https", "example.com", 8443, "https://example.com:8443/")
    assert Target.parse("http://127.0.0.1").is_local
    with pytest.raises(ValueError):
        Target.parse("ftp://x")
