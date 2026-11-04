"""Mocked OSV.dev responses shared by the test suite and the sample generator."""
import json

import httpx

OSV_DB = {
    ("jquery", "1.12.4"): [
        {
            "id": "GHSA-gxr4-xjj5-5px2",
            "aliases": ["CVE-2020-11022"],
            "summary": "Potential XSS vulnerability in jQuery",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N"}],
            "database_specific": {"severity": "MODERATE", "cwe_ids": ["CWE-79"]},
        },
        {
            "id": "GHSA-6c3j-c64m-qhgq",
            "aliases": ["CVE-2019-11358"],
            "summary": "XSS in jQuery as used in Drupal, Backdrop CMS, and other products",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}],
            "database_specific": {"severity": "MODERATE", "cwe_ids": ["CWE-79", "CWE-1321"]},
        },
    ],
    ("angular", "1.5.8"): [
        {
            "id": "GHSA-5cp4-xmrw-59wf",
            "aliases": ["CVE-2019-10768"],
            "summary": "XSS via JSONP / prototype pollution in AngularJS",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-1321"]},
        }
    ],
    ("bootstrap", "3.3.7"): [
        {
            "id": "GHSA-4p24-vmcr-4gqj",
            "aliases": ["CVE-2018-14042"],
            "summary": "XSS in data-container property of tooltip",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}],
            "database_specific": {"severity": "MODERATE"},
        }
    ],
}


def osv_handler(request: httpx.Request) -> httpx.Response:
    assert request.url.host == "api.osv.dev", request.url
    body = json.loads(request.content)
    key = (body["package"]["name"], body["version"])
    vulns = OSV_DB.get(key, [])
    return httpx.Response(200, json={"vulns": vulns} if vulns else {})
