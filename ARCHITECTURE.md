# Architecture

```
sitescan/
├── cli.py                 argparse entrypoint: gate → run → render → audit log → exit code
├── core/
│   ├── severity.py        Severity enum (rank, score weight, terminal color)
│   ├── finding.py         Finding dataclass + OWASP Top 10 2021 table
│   ├── target.py          URL normalisation (scheme/host/port, is_ip, is_local)
│   ├── gate.py            --i-am-authorized + hostname confirmation + denylist
│   ├── ratelimit.py       async token bucket shared by every scanner
│   ├── http.py            rate-limited, manual-redirect, never-raising HTTP client
│   ├── scanner.py         Scanner ABC, ScanContext, ScanConfig, @register, discover()
│   ├── orchestrator.py    runs scanners concurrently, contains failures, ScanResult
│   ├── scoring.py         0-100 score + letter grade
│   └── cvss.py            CVSS 3.1 base-score calculator
├── scanners/              one module per check, auto-discovered
│   └── _common.py         shared helpers (underscore = not a scanner module)
└── report/                terminal (rich), JSON, HTML (jinja2, self-contained)
```

## The scanner registry pattern

A scanner is a class with a `name` and an async `run(ctx)` that returns a list
of `Finding`s. To get it into every scan you decorate it. Nothing else needs to
change:

```python
# sitescan/scanners/server_timing.py
from ..core import Finding, ScanContext, Scanner, Severity, register

@register
class ServerTimingScanner(Scanner):
    name = "server-timing"
    description = "Flags verbose Server-Timing headers"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        resp = await ctx.root()
        if resp is None or "server-timing" not in resp.headers:
            return []
        return [Finding(
            id="server-timing.exposed",
            title="Server-Timing header exposes backend metrics",
            severity=Severity.LOW,
            evidence=resp.headers["server-timing"],
            remediation="Strip Server-Timing in production or limit it to internal clients.",
            owasp="A05", cwe=200,
        )]
```

That file is the entire change. There is no list to edit, no import to add to
`__init__.py`, and no CLI change: `--only server-timing` and `--list-scanners`
pick it up automatically.

### How it works

1. **`@register`** (`core/scanner.py`) is a class decorator. It checks that the
   class is a `Scanner` subclass with a non-empty `name` that no other scanner
   already uses, records it in the module-level `_REGISTRY` dict, and returns
   the class unchanged. Registration is a side effect of **importing** the
   module.

2. **`discover()`** walks `sitescan.scanners` with `pkgutil.iter_modules` and
   imports every module whose name doesn't start with `_`. Importing triggers
   each module's `@register` calls. It then returns a copy of the registry.
   Underscore modules (`_common.py`) are a place for shared helpers that aren't
   scanners.

3. **The orchestrator** (`core/orchestrator.py`) calls `discover()`, applies
   `--only`/`--skip`, creates one instance per scanner, and runs them all with
   `asyncio.gather`. Each one is wrapped in `_run_one`, which:
   - applies a per-scanner timeout (`ScanConfig.scanner_timeout`),
   - turns any exception into a `ScannerRun(status="error")` record (plus a
     short traceback in the notes) so one buggy scanner can't break the run,
   - stamps `finding.scanner = scanner.name` on every finding.

   It then de-duplicates findings on `(id, evidence)`, sorts them by severity
   and builds a `ScanResult`.

Why a decorator plus import-time discovery rather than entry points or an
explicit list? It keeps "add a check" to a single file, which was the design
goal. The duplicate-name check catches copy-paste mistakes at import time. And
because the registry is a plain dict, tests can monkeypatch it to register
throwaway scanners (see `tests/test_core.py::test_new_scanner_needs_no_wiring`).
Moving to `importlib.metadata` entry points later would be a small change to
`discover()` if third-party plugins are ever needed.

## ScanContext: what a scanner gets

| Attribute | Purpose |
|---|---|
| `ctx.target` | Normalised `Target` (url, scheme, host, port, `is_ip`, `is_local`, `join(path)`) |
| `ctx.http` | Shared `HttpClient` with `get()`, `head()` and `request()` |
| `await ctx.root()` | The cached GET of the target URL (one fetch shared by every scanner) |
| `ctx.limiter` | The shared `RateLimiter`. Call `await ctx.limiter.acquire()` before any non-HTTP traffic (TLS handshakes, DNS) |
| `ctx.config` | `ScanConfig` (rate, timeout, CA bundle, DNS backend, OSV transport, ...) |
| `ctx.notes` | Free-text diagnostics that appear in the JSON/log (e.g. "local OpenSSL lacks RC4") |

### HTTP layer guarantees (`core/http.py`)

- **Rate-limited per hop.** Redirects are followed manually, so each hop
  acquires a token and shows up in `Response.history`.
- **Never raises on network failure.** Timeouts, refused connections, TLS
  errors and redirect loops return `None` and are appended to
  `ctx.http.errors`. Scanners only need to handle `None`.
- **Safe methods only.** `request()` raises `ValueError` for anything other
  than GET/HEAD/OPTIONS. This is a hard guarantee, not a convention.
- **Bounded bodies.** Bodies are streamed and cut off at 2 MiB, and HEAD bodies
  are never read.
- **Memoised GETs.** With `cache=True` (the default for `get`), concurrent
  scanners that ask for the same URL share one request. A per-key lock stops
  two scanners from both fetching it.

## Failure model

| Failure | Where it's contained | What the user sees |
|---|---|---|
| Timeout / connection error | `HttpClient._do` | `None` response, an entry in `errors`, scanner degrades gracefully |
| Redirect loop | `HttpClient._do` (max 5 hops) | "too many redirects" in `errors` |
| Scanner bug (exception) | `orchestrator._run_one` | `ScannerRun.status = "error"` in the report diagnostics, other scanners unaffected |
| Scanner hangs | `asyncio.wait_for` | `status = "timeout"` |
| OSV unreachable | `dependencies.query_osv` | Library reported as Info with "vulnerability status unknown" |
| Local OpenSSL can't test a protocol/cipher | `tls._client_ctx` / `Probe.untestable` | Note "not tested". This is never reported as a pass. |

## Testability seams

Every external dependency can be swapped through `ScanConfig`, so the suite
never touches the internet:

- `transport` on `run_scan()` takes an httpx transport for the target client.
- `ScanConfig.osv_transport` takes `httpx.MockTransport` for OSV.
- `ScanConfig.dns_backend` takes any object that implements the `DnsBackend`
  protocol (`txt`, `caa`, `ns`, `addresses`, `axfr`).
- `ScanConfig.ca_bundle` lets tests validate a chain issued by a throwaway CA.
- `ScanConfig.http_url` points the redirect check at a local HTTP port.
