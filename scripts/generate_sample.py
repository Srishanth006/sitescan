"""Generate the sample report in samples/ by scanning the local deliberately
misconfigured Flask target (tests/target_app). Fully offline: the target is on
127.0.0.1 and OSV responses come from the test fixture.

    python scripts/generate_sample.py
"""
from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import httpx  # noqa: E402

from sitescan import cli  # noqa: E402
from tests.conftest import _bad_tls, _Server  # noqa: E402
from tests.target_app.app import create_app  # noqa: E402
from tests.target_app.certs import make_bad_cert, make_good_chain  # noqa: E402
from tests.target_app.osv_fixture import osv_handler  # noqa: E402


def main() -> int:
    out = ROOT / "samples"
    out.mkdir(exist_ok=True)
    tmp = Path(tempfile.mkdtemp())
    certs = {"good": make_good_chain(tmp), "bad": make_bad_cert(tmp)}
    https = _Server(create_app("vulnerable"), _bad_tls(certs))
    http = _Server(create_app("vulnerable"))

    real = cli.ScanConfig
    cli.ScanConfig = lambda **kw: real(osv_transport=httpx.MockTransport(osv_handler), **kw)
    try:
        code = cli.main([
            https.url, "--i-am-authorized", "--confirm-host", "127.0.0.1",
            "--http-url", http.url, "--rate", "20",
            "--json", str(out / "sample-report.json"),
            "--html", str(out / "sample-report.html"),
            "--scans-dir", str(tmp / "scans"),
        ])
    finally:
        cli.ScanConfig = real
        https.stop()
        http.stop()
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"exit code {code} (1 = High/Critical findings present, as expected)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
