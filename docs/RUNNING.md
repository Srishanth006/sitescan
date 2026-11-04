# Running sitescan Manually

Copy-paste commands for installing, running, and testing sitescan by hand.
Commands are given for **Windows (PowerShell)** and **macOS / Linux (bash)**.

> Only scan websites you own or have **written permission** to test.
> Steps 4–5 use a practice site that runs on your own machine, so they are always safe.

---

## 1. Prerequisites

| Tool | Check | Needed version |
|---|---|---|
| Python | `python --version` (Windows) / `python3 --version` | 3.11 or newer |
| Git | `git --version` | any recent |

---

## 2. Get the code

```bash
git clone https://github.com/Srishanth006/sitescan.git
cd sitescan
```

---

## 3. Install (one time)

**Windows (PowerShell)**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -e .
```

**macOS / Linux**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

Check that it installed:

```bash
sitescan --version
sitescan --list-scanners
```

Expected output: `sitescan 0.1.0`, then the 9 scanners (`cookies`, `dependencies`, `disclosure`,
`dns-email`, `headers`, `sensitive-paths`, `tls`, `transport`, `wellknown`).

> Each time you open a new terminal, activate the environment again
> (`.venv\Scripts\Activate.ps1` or `source .venv/bin/activate`) before running `sitescan`.

---

## 4. Start the practice site (Terminal 1)

The repo includes a deliberately misconfigured website for safe practice.
Run this from the `sitescan` folder and **leave it running**:

```bash
python -m tests.target_app.app --profile vulnerable --port 8080
```

You should see `Running on http://127.0.0.1:8080`. To check it, open http://127.0.0.1:8080 in a browser.

To compare, there is also a well-configured version:

```bash
python -m tests.target_app.app --profile hardened --port 8081
```

---

## 5. Scan the practice site (Terminal 2)

Open a **second** terminal, `cd` into the `sitescan` folder, activate the venv, then run:

```bash
sitescan http://127.0.0.1:8080 --i-am-authorized
```

sitescan asks you to confirm the host:

```
Type the target hostname (127.0.0.1) to confirm you are authorized:
```

Type `127.0.0.1` and press **Enter**. The scan takes about 10–15 seconds and ends with a
colour-coded table (on this site: score **0/100, grade F**).

### Save HTML and JSON reports

```bash
sitescan http://127.0.0.1:8080 --i-am-authorized --html report.html --json report.json
```

Open the HTML report:

| OS | Command |
|---|---|
| Windows | `start report.html` |
| macOS | `open report.html` |
| Linux | `xdg-open report.html` |

### Skip the confirmation prompt (scripts / CI)

```bash
sitescan http://127.0.0.1:8080 --i-am-authorized --confirm-host 127.0.0.1
```

### Check the exit code

**Windows (PowerShell)**

```powershell
sitescan http://127.0.0.1:8080 --i-am-authorized --confirm-host 127.0.0.1 --no-info
echo "exit code: $LASTEXITCODE"
```

**macOS / Linux**

```bash
sitescan http://127.0.0.1:8080 --i-am-authorized --confirm-host 127.0.0.1 --no-info
echo "exit code: $?"
```

| Code | Meaning |
|---|---|
| `0` | Nothing at or above the `--fail-on` level (default High) |
| `1` | High or Critical findings found (the practice site always returns this) |
| `2` | Mistake in the command (wrong option, missing URL) |
| `3` | Refused: no `--i-am-authorized`, wrong hostname, or denylisted site |
| `4` | Unexpected error |

Press **Ctrl + C** in Terminal 1 to stop the practice site when you are done.

---

## 6. Useful options

| What you want | Command |
|---|---|
| Run only some checks | `sitescan http://127.0.0.1:8080 --i-am-authorized --only headers,cookies,disclosure` |
| Skip a check | `... --skip dns-email` |
| Hide Info rows | `... --no-info` |
| Slower / gentler scanning | `... --rate 2` (requests per second, max 50) |
| Longer timeout for slow sites | `... --timeout 20` |
| Work fully offline (no CVE lookup) | `... --no-osv` |
| JSON printed to the screen | `... --confirm-host 127.0.0.1 --json -` |
| Fail on Medium and above (CI) | `... --fail-on Medium` |
| Trust an internal company CA | `... --ca-bundle path\to\company-ca.pem` |
| Check email DNS of the main domain | `... --dns-domain example.com` |
| Store audit logs elsewhere | `... --scans-dir my-scan-logs` |
| Show all options | `sitescan --help` |

Every scan also writes an audit log to `scans/<timestamp>-<host>.json`.

If `sitescan` is not found, use `python -m sitescan` instead (same options).

---

## 7. Scan a real website you are authorised to test

```bash
sitescan https://your-site.example --i-am-authorized --html report.html --json report.json
```

Type the hostname (`your-site.example`) when asked.

sitescan refuses major third-party sites (Google, GitHub, Microsoft, AWS, etc.) and `.gov`/`.mil`
domains. It also refuses to start without `--i-am-authorized`. Both refusals use exit code `3`:

```bash
sitescan https://www.google.com --i-am-authorized
# refusing to scan: www.google.com matches denylisted third-party domain 'google.com'
```

---

## 8. Generate the bundled sample report

```bash
python scripts/generate_sample.py
```

This starts the practice site over HTTP and HTTPS by itself, scans it, and writes
`samples/sample-report.html` and `samples/sample-report.json`. It runs fully offline.

---

## 9. Run the test suite

```bash
pytest
```

Expected: `61 passed` in about 15 seconds. The tests never contact the internet.

Run one area only:

```bash
pytest tests/test_tls.py
pytest tests/test_headers.py -v
```

---

## 10. Troubleshooting

| Problem | Fix |
|---|---|
| PowerShell: *"running scripts is disabled on this system"* when activating | Run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, answer `Y`, then activate again |
| `sitescan: command not found` / not recognized | Activate the venv, or run `pip install -e .`, or use `python -m sitescan` |
| `No module named tests.target_app` | Run the command from inside the `sitescan` folder |
| Port 8080 already in use | Use another port, e.g. `--port 9090`, and scan `http://127.0.0.1:9090` |
| `confirmation ... does not match target host` | Type exactly the host shown in the prompt (no `http://`, no port) |
| `no TTY for confirmation` | Add `--confirm-host <hostname>` |
| Odd `�` characters in long table cells on old Windows consoles | Cosmetic only; use Windows Terminal, or read the `--html` / `--json` report |
| Scan of a real site is slow | Normal at 5 req/s; raise `--rate` only if the owner allows it |
