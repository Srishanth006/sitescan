import json

import pytest

from sitescan import cli


@pytest.fixture(autouse=True)
def mock_osv(monkeypatch, osv_transport):
    """CLI runs build their own ScanConfig; inject the OSV mock transport into it."""
    real = cli.ScanConfig

    def patched(**kw):
        kw.setdefault("osv_transport", osv_transport)
        return real(**kw)

    monkeypatch.setattr(cli, "ScanConfig", patched)


def run(argv, tmp_path):
    return cli.main([*argv, "--scans-dir", str(tmp_path / "scans"), "--rate", "50"])


def test_refuses_without_flag(tmp_path, capsys):
    assert run(["http://127.0.0.1/", "--confirm-host", "127.0.0.1"], tmp_path) == cli.EXIT_REFUSED
    assert not (tmp_path / "scans").exists()


def test_refuses_denylisted(tmp_path):
    assert run(["https://www.google.com", "--i-am-authorized", "--confirm-host", "www.google.com"],
               tmp_path) == cli.EXIT_REFUSED


def test_refuses_wrong_confirmation(tmp_path):
    assert run(["http://127.0.0.1/", "--i-am-authorized", "--confirm-host", "localhost"],
               tmp_path) == cli.EXIT_REFUSED


def test_full_scan_vulnerable_exit_1_and_outputs(vuln_https, vuln_http, tmp_path, capsys):
    j, h = tmp_path / "r.json", tmp_path / "r.html"
    code = run([vuln_https.url, "--i-am-authorized", "--confirm-host", "127.0.0.1",
                "--http-url", vuln_http.url, "--json", str(j), "--html", str(h)], tmp_path)
    assert code == cli.EXIT_FINDINGS
    data = json.loads(j.read_text(encoding="utf-8"))
    assert data["grade"] == "F" and data["severity_counts"]["Critical"] >= 1
    assert {"id", "title", "severity", "cvss", "evidence", "owasp", "cwe", "remediation"} <= data["findings"][0].keys()
    assert {s["name"] for s in data["scanners"]} >= {"headers", "tls", "dns-email"}
    html = h.read_text(encoding="utf-8")
    assert "Executive summary" in html and "Severity breakdown" in html and "paths.exposed.env" in html
    logs = list((tmp_path / "scans").glob("*-127.0.0.1.json"))
    assert len(logs) == 1 and json.loads(logs[0].read_text())["audit"]["authorized_flag"] is True
    assert "Severity" in capsys.readouterr().out


def test_hardened_scan_exit_0(good_https, good_http, certs, tmp_path):
    code = run([good_https.url, "--i-am-authorized", "--confirm-host", "127.0.0.1",
                "--http-url", good_http.url, "--ca-bundle", certs["good"]["ca"]], tmp_path)
    assert code == cli.EXIT_OK


def test_fail_on_threshold(good_https, good_http, certs, tmp_path):
    # Hardened site still has Low-severity items (e.g. missing DNS context is Info, but
    # nothing Medium+), so --fail-on Low only trips if Lows exist.
    code = run([good_https.url, "--i-am-authorized", "--confirm-host", "127.0.0.1",
                "--http-url", good_http.url, "--ca-bundle", certs["good"]["ca"], "--fail-on", "Medium"], tmp_path)
    assert code == cli.EXIT_OK


def test_json_stdout(vuln_http, tmp_path, capsys):
    run([vuln_http.url, "--i-am-authorized", "--confirm-host", "127.0.0.1", "--only", "cookies", "--json", "-"], tmp_path)
    data = json.loads(capsys.readouterr().out)
    assert data["target"] == vuln_http.url and data["findings"]


def test_html_escapes_evidence():
    from datetime import datetime, timezone

    from sitescan.core import Finding, Severity, Target
    from sitescan.core.orchestrator import ScanResult
    from sitescan.report import render_html

    now = datetime.now(timezone.utc)
    f = Finding(id="x", title="<script>alert(1)</script>", severity=Severity.HIGH,
                evidence="<img src=x onerror=alert(1)>", remediation="r")
    html = render_html(ScanResult(Target.parse("https://a.test"), now, now, [f], [], 0))
    assert "<img src=x" not in html and "&lt;img src=x" in html
    assert "<script>alert(1)" not in html


def test_list_scanners(capsys, tmp_path):
    assert cli.main(["--list-scanners"]) == 0
    assert "sensitive-paths" in capsys.readouterr().out
