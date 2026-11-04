# sitescan: How It Works and How to Run It

**Authors:** Harisudhan S (RA2411030020081), Tharun Suresh (RA2411030020084)
**Course:** 21CSE382T / Security Management

---

## 1. What sitescan is

sitescan is a command-line tool. You give it a website URL and it produces a
**security posture report** for that site. It is **passive**. It only sends
normal browser-like requests (GET/HEAD) and TLS/DNS lookups, then analyzes the
responses. It never sends exploit payloads, guesses passwords, fuzzes inputs or
floods the server.

A typical run takes 5–30 seconds and produces:

- a color-coded table in the terminal,
- an optional **JSON** file for automation,
- an optional **HTML** report with an executive summary, a severity chart and
  one card per finding,
- an audit log entry in `scans/`,
- an **exit code** that CI pipelines can use (1 if anything High or Critical was found).

---

## 2. How it works

### 2.1 End-to-end flow

```
 sitescan https://site --i-am-authorized
        │
        ▼
 ┌──────────────────────┐   refuses: no flag, wrong hostname,
 │ 1. Authorization gate │──► denylisted domain (google.com, *.gov ...)
 └──────────┬───────────┘
            ▼
 ┌──────────────────────┐   imports every module in sitescan/scanners/,
 │ 2. Scanner discovery  │   collecting classes marked with @register
 └──────────┬───────────┘
            ▼
 ┌──────────────────────┐   all 9 scanners run concurrently (asyncio),
 │ 3. Orchestrator       │   sharing ONE rate limiter (5 req/s) and ONE
 └──────────┬───────────┘   cached copy of the home page
            ▼
 ┌──────────────────────┐   each scanner returns Finding objects:
 │ 4. Findings           │   id, title, severity, CVSS, evidence,
 └──────────┬───────────┘   OWASP category, CWE, remediation
            ▼
 ┌──────────────────────┐
 │ 5. Scoring            │   0–100 score + letter grade A–F
 └──────────┬───────────┘
            ▼
 ┌──────────────────────┐
 │ 6. Reports + audit    │   terminal / JSON / HTML / scans/<time>-<host>.json
 └──────────────────────┘
```

### 2.2 Step 1: the authorization gate

Scanning a site you don't own can be illegal, so sitescan refuses to start unless:

1. the target is **not on the built-in denylist** (major platforms such as
   Google, Meta, Microsoft, AWS, GitHub, Cloudflare, payment providers, and the
   `.gov`/`.mil` domains), **and**
2. the `--i-am-authorized` flag is present, **and**
3. you **type the exact hostname** back when prompted. In CI, where nobody can
   type, use `--confirm-host <hostname>`.

The denylist is checked first, so you are never asked to confirm a refused target.

### 2.3 Step 2: the scanner registry

Each check lives in its own file in `sitescan/scanners/`. A check is a class
decorated with `@register`:

```python
@register
class HeadersScanner(Scanner):
    name = "headers"
    async def run(self, ctx): ...
```

At startup, `discover()` imports every file in that folder. Importing a file
runs its `@register` decorator, which adds the class to a dictionary. Adding a
new check therefore means **adding one file**. Nothing else in the code changes.
(Details in `ARCHITECTURE.md`.)

### 2.4 Step 3: the orchestrator and the safe HTTP layer

All scanners run at the same time, but they share:

- **One rate limiter** (a token bucket, 5 requests/second by default). Every
  HTTP request, redirect hop, TLS handshake and DNS query must take a token
  first, so the target never sees more than the configured rate.
- **One HTTP client** that:
  - only allows GET, HEAD and OPTIONS (anything else raises an error),
  - follows redirects one hop at a time (max 5) so each hop is rate-limited and recorded,
  - stops reading any response body after 2 MiB,
  - **never crashes** on timeouts or connection errors. It returns "no response" and logs the error,
  - fetches the home page **once** and shares it with every scanner.
- An identifying **User-Agent**: `sitescan/0.1.0 (+passive security posture scanner; authorized testing only)`.

If a scanner throws an exception or hangs, the orchestrator records it as
`error` or `timeout` and the other scanners carry on.

### 2.5 The nine checks

| # | Scanner | What it looks at | Example red flags |
|---|---|---|---|
| 1 | `headers` | Security response headers; parses the CSP | `unsafe-inline`, `unsafe-eval`, `*` in script-src, missing HSTS, no clickjacking protection |
| 2 | `tls` | TLS handshakes with each protocol version and weak cipher families; the certificate | TLS 1.0/1.1 enabled, anonymous or static-RSA ciphers, self-signed, expired or expiring, wrong hostname, RSA < 2048 bits, chain doesn't validate |
| 3 | `cookies` | Every `Set-Cookie` header (values are hidden in the report) | missing `Secure`, `HttpOnly`, `SameSite`; `SameSite=None` without `Secure` |
| 4 | `disclosure` | Version banners, a 404 page, common directories | `Server: Apache/2.4.29`, `X-Powered-By: PHP/7.2.3`, stack traces, "Index of /uploads" |
| 5 | `sensitive-paths` | **HEAD only** against ~35 well-known paths; contents are never downloaded | `/.env`, `/.git/config` or `/backup.sql` returning 200 |
| 6 | `transport` | HTTP→HTTPS redirect, `http://` resources on HTTPS pages, HSTS preload rules | no redirect, temporary (302) redirect, mixed scripts/iframes/forms |
| 7 | `dns-email` | SPF, DKIM, DMARC, CAA, zone transfer | `+all` SPF, `p=none` DMARC, no CAA, AXFR allowed |
| 8 | `dependencies` | JS/CSS library versions from URLs and banners → OSV.dev CVE lookup | jQuery 1.12.4 (CVE-2020-11022), AngularJS 1.5.8 |
| 9 | `wellknown` | robots.txt, sitemap.xml, security.txt (RFC 9116) | robots.txt listing `/admin/` and `/backup/`; missing or expired security.txt |

Two techniques reduce false positives:

- **Soft-404 detection:** before probing sensitive paths, sitescan requests a
  random path that can't exist. If the server answers 200 to everything,
  responses that look identical to that baseline are ignored.
- **"Not tested" is never treated as a pass.** If the local OpenSSL can't
  attempt an old cipher (e.g. RC4), the report says so in its notes instead of
  claiming the server is safe.

### 2.6 Step 4: what a finding contains

```json
{
  "id": "paths.exposed.env",
  "title": "Sensitive path publicly accessible: /.env",
  "severity": "Critical",
  "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
  "evidence": "HEAD https://site/.env -> 200 (Content-Type: application/octet-stream ...). Content NOT downloaded.",
  "owasp": "A05:2021-Security Misconfiguration",
  "cwe": "CWE-538",
  "remediation": "Remove /.env from the web root or deny access ...",
  "scanner": "sensitive-paths"
}
```

The `id` stays the same between runs, so CI can track or allow-list specific findings.

### 2.7 Step 5: scoring

Each severity costs points per finding, up to a cap, so many small issues
can't outweigh one serious one:

| Severity | Points per finding | Max deduction |
|---|---|---|
| Critical | 25 | 60 |
| High | 12 | 45 |
| Medium | 6 | 30 |
| Low | 2 | 12 |
| Info | 0 | 0 |

`score = 100 − total deduction` (minimum 0). Grade: **A** ≥ 90, **B** ≥ 80,
**C** ≥ 70, **D** ≥ 60, otherwise **F**. Any Critical caps the grade at **D**,
and any High caps it at **C**.

### 2.8 Step 6: reports and audit log

- **Terminal:** a summary panel (score, grade, counts) plus a table colored by severity.
- **JSON** (`--json file.json` or `--json -` for stdout): the full result for scripts and CI.
- **HTML** (`--html report.html`): one self-contained file with no internet
  needed to view it. It has the score and grade, a severity bar chart, an
  executive summary with top priorities, findings grouped by OWASP category,
  filter buttons and one card per finding. All evidence is HTML-escaped, so a
  malicious site can't inject script into your report.
- **Audit log:** every scan writes `scans/<timestamp>-<host>.json` with the
  result, the exact command line and the operator's username.

---

## 3. How to run it

### 3.1 Requirements

- Python **3.11 or newer**
- Windows, macOS or Linux
- Internet access to the target (and to `api.osv.dev` for CVE lookups, unless you pass `--no-osv`)

### 3.2 Install (one time)

**Windows (PowerShell)**

```powershell
cd sitescan
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

**macOS / Linux**

```bash
cd sitescan
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

`pip install -e .` adds the `sitescan` command. Without it, use `python -m sitescan`.

### 3.3 Your first scan

```bash
sitescan https://your-site.example --i-am-authorized
```

sitescan asks:

```
Type the target hostname (your-site.example) to confirm you are authorized:
```

Type `your-site.example` and press Enter. The table prints when the scan finishes.

### 3.4 Saving reports

```bash
sitescan https://your-site.example --i-am-authorized --html report.html --json report.json
```

Open `report.html` in any browser.

### 3.5 Common options

| Goal | Command |
|---|---|
| List the checks | `sitescan --list-scanners` |
| Run only some checks | `--only headers,tls,cookies` |
| Skip a check | `--skip dns-email` |
| Go slower / faster | `--rate 2` (max 50) |
| Longer timeout | `--timeout 20` |
| Offline (no CVE lookup) | `--no-osv` |
| Internal company CA | `--ca-bundle company-ca.pem` |
| Check email DNS of the parent domain | `--dns-domain example.com` |
| Hide informational rows | `--no-info` |
| Fail CI on Medium and above | `--fail-on Medium` |

### 3.6 Running in CI (e.g. GitHub Actions)

```yaml
- run: pip install -r requirements.txt && pip install -e .
- run: >
    sitescan https://staging.example.com
    --i-am-authorized --confirm-host staging.example.com
    --json sitescan.json --html sitescan.html
```

The step fails (exit code 1) if any High or Critical finding is present.

| Exit code | Meaning |
|---|---|
| 0 | No findings at or above the threshold |
| 1 | High/Critical (or `--fail-on`) findings found |
| 2 | Wrong command-line usage |
| 3 | Refused by the authorization gate / denylist |
| 4 | Unexpected fatal error |

### 3.7 Trying it safely without a real website

The repository includes a deliberately misconfigured practice site:

```bash
python scripts/generate_sample.py
```

This starts the practice site on your own machine (127.0.0.1), scans it and
writes `samples/sample-report.html` and `samples/sample-report.json`. It works
offline.

To scan the practice site yourself:

```bash
python -m tests.target_app.app --profile vulnerable --port 8080
# in a second terminal:
sitescan http://127.0.0.1:8080 --i-am-authorized --confirm-host 127.0.0.1
```

### 3.8 Running the tests

```bash
pip install -r requirements.txt
pytest
```

The suite has 61 tests and takes about 15 seconds. It runs entirely on your
machine: a guard makes any test fail if it tries to contact the internet.

---

## 4. Responsible use

- Only scan systems you own or have **written permission** to test.
- Results are **indicators for human review**. Confirm each finding before acting on it.
- A clean report does not prove a site is secure. sitescan doesn't test
  application logic, authentication flows or injection flaws, because doing so
  would require active attacks.
