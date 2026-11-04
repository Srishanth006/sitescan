from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
import threading
import warnings

import httpx
import pytest
from werkzeug.serving import make_server

from sitescan.core.orchestrator import run_scan
from sitescan.core.scanner import ScanConfig
from sitescan.core.target import Target
from tests.target_app.app import TargetRequestHandler, create_app
from tests.target_app.certs import make_bad_cert, make_good_chain
from tests.target_app.osv_fixture import osv_handler

# --------------------------------------------------------------------------
# Guard: no test may reach the public internet.
# --------------------------------------------------------------------------
_real_connect = socket.socket.connect
_real_connect_ex = socket.socket.connect_ex
_real_sendto = socket.socket.sendto


def _check(address):
    host = address[0] if isinstance(address, tuple) else address
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        raise RuntimeError(f"test tried to resolve/connect to non-literal host {host!r}")
    if not ip.is_loopback:
        raise RuntimeError(f"test tried to reach non-loopback address {host!r}")


def _guarded_connect(self, address):
    if self.family in (socket.AF_INET, socket.AF_INET6):
        _check(address)
    return _real_connect(self, address)


def _guarded_connect_ex(self, address):
    if self.family in (socket.AF_INET, socket.AF_INET6):
        _check(address)
    return _real_connect_ex(self, address)


def _guarded_sendto(self, data, *args):
    _check(args[-1])
    return _real_sendto(self, data, *args)


@pytest.fixture(autouse=True, scope="session")
def no_internet():
    socket.socket.connect = _guarded_connect
    socket.socket.connect_ex = _guarded_connect_ex
    socket.socket.sendto = _guarded_sendto
    yield
    socket.socket.connect = _real_connect
    socket.socket.connect_ex = _real_connect_ex
    socket.socket.sendto = _real_sendto


# --------------------------------------------------------------------------
# Local servers
# --------------------------------------------------------------------------
class _Server:
    def __init__(self, app, ssl_context=None):
        self.srv = make_server(
            "127.0.0.1", 0, app, threaded=True, ssl_context=ssl_context,
            request_handler=TargetRequestHandler,
        )
        self.port = self.srv.server_port
        scheme = "https" if ssl_context else "http"
        self.url = f"{scheme}://127.0.0.1:{self.port}/"
        self.thread = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        self.srv.shutdown()


@pytest.fixture(scope="session")
def certs(tmp_path_factory):
    d = tmp_path_factory.mktemp("certs")
    return {"good": make_good_chain(d), "bad": make_bad_cert(d)}


def _good_tls(certs):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")
    ctx.load_cert_chain(certs["good"]["cert"], certs["good"]["key"])
    return ctx


def _bad_tls(certs):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("ALL:@SECLEVEL=0")
    ctx.load_cert_chain(certs["bad"]["cert"], certs["bad"]["key"])
    return ctx


@pytest.fixture(scope="session")
def vuln_http():
    s = _Server(create_app("vulnerable"))
    yield s
    s.stop()


@pytest.fixture(scope="session")
def vuln_https(certs):
    s = _Server(create_app("vulnerable"), _bad_tls(certs))
    yield s
    s.stop()


@pytest.fixture(scope="session")
def good_https(certs):
    s = _Server(create_app("hardened"), _good_tls(certs))
    yield s
    s.stop()


@pytest.fixture(scope="session")
def good_http(good_https):
    s = _Server(create_app("redirect", https_url=good_https.url))
    yield s
    s.stop()


# --------------------------------------------------------------------------
# OSV mock (the only "external" API, and it is fully mocked)
# --------------------------------------------------------------------------
@pytest.fixture
def osv_transport():
    return httpx.MockTransport(osv_handler)


# --------------------------------------------------------------------------
# Scan helper
# --------------------------------------------------------------------------
@pytest.fixture
def scan(osv_transport):
    def _scan(url: str, *only: str, **cfg):
        cfg.setdefault("rate", 500)
        cfg.setdefault("timeout", 5)
        cfg.setdefault("osv_transport", osv_transport)
        config = ScanConfig(**cfg)
        return asyncio.run(run_scan(Target.parse(url), config, only=list(only) or None))

    return _scan


def ids(result) -> set[str]:
    return {f.id for f in result.findings}
