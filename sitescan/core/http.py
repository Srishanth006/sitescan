"""Rate-limited, redirect-aware, crash-proof HTTP layer used by all scanners."""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from urllib.parse import urljoin

import httpx

from .ratelimit import RateLimiter

log = logging.getLogger("sitescan.http")

MAX_BODY_BYTES = 2 * 1024 * 1024  # never pull more than 2 MiB of any body


@dataclass
class Hop:
    status: int
    url: str
    location: str | None


@dataclass
class Response:
    """A trimmed, immutable view of an HTTP response.

    ``history`` lists every redirect hop *before* the final response.
    ``text`` is empty for HEAD requests and truncated at MAX_BODY_BYTES.
    """

    url: str
    status: int
    headers: httpx.Headers
    text: str = ""
    history: list[Hop] = field(default_factory=list)
    truncated: bool = False

    def header_list(self, name: str) -> list[str]:
        return self.headers.get_list(name)


class HttpClient:
    """Thin wrapper over ``httpx.AsyncClient``.

    * Every hop (including each redirect) goes through the shared RateLimiter.
    * Redirects are followed manually so each hop is observable and limited.
    * Network errors / timeouts never raise: the call returns ``None`` and the
      error is recorded in ``self.errors`` for the report.
    * GET responses can be memoised so several scanners share one fetch.
    """

    def __init__(
        self,
        limiter: RateLimiter,
        user_agent: str,
        timeout: float = 10.0,
        verify: bool | str = False,
        max_redirects: int = 5,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        # verify=False by default: we are *assessing* TLS, not relying on it.
        # The TLS scanner validates the chain explicitly and reports on it.
        self.limiter = limiter
        self.max_redirects = max_redirects
        self.errors: list[str] = []
        self._cache: dict[tuple[str, str], Response | None] = {}
        self._locks: dict[tuple[str, str], asyncio.Lock] = {}
        self._client = httpx.AsyncClient(
            headers={"User-Agent": user_agent, "Accept": "*/*"},
            timeout=httpx.Timeout(timeout),
            verify=verify,
            follow_redirects=False,
            transport=transport,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def get(self, url: str, *, follow: bool = True, cache: bool = True) -> Response | None:
        return await self.request("GET", url, follow=follow, cache=cache)

    async def head(self, url: str, *, follow: bool = False) -> Response | None:
        return await self.request("HEAD", url, follow=follow, cache=False)

    async def request(
        self, method: str, url: str, *, follow: bool = True, cache: bool = False
    ) -> Response | None:
        method = method.upper()
        if method not in ("GET", "HEAD", "OPTIONS"):
            # Hard guarantee: sitescan never sends state-changing requests.
            raise ValueError(f"sitescan only issues safe methods, not {method}")
        key = (method, url if follow else url + "#nofollow")
        if not cache:
            return await self._do(method, url, follow)
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            if key not in self._cache:
                self._cache[key] = await self._do(method, url, follow)
            return self._cache[key]

    async def _do(self, method: str, url: str, follow: bool) -> Response | None:
        history: list[Hop] = []
        current = url
        try:
            for _ in range(self.max_redirects + 1):
                await self.limiter.acquire()
                resp = await self._send(method, current)
                location = resp.headers.get("location")
                if follow and resp.status in (301, 302, 303, 307, 308) and location:
                    history.append(Hop(resp.status, current, location))
                    current = urljoin(current, location)
                    continue
                resp.history = history
                return resp
            self.errors.append(f"{method} {url}: too many redirects")
            return None
        except httpx.TimeoutException:
            self.errors.append(f"{method} {current}: timeout")
        except httpx.HTTPError as e:
            self.errors.append(f"{method} {current}: {type(e).__name__}: {e}")
        except Exception as e:  # pragma: no cover - defensive
            self.errors.append(f"{method} {current}: unexpected {type(e).__name__}: {e}")
        log.debug("request failed: %s", self.errors[-1])
        return None

    async def _send(self, method: str, url: str) -> Response:
        async with self._client.stream(method, url) as r:
            body = bytearray()
            truncated = False
            if method != "HEAD":
                async for chunk in r.aiter_bytes():
                    body.extend(chunk)
                    if len(body) >= MAX_BODY_BYTES:
                        truncated = True
                        del body[MAX_BODY_BYTES:]
                        break
            encoding = r.encoding or "utf-8"
            try:
                text = bytes(body).decode(encoding, errors="replace")
            except LookupError:
                text = bytes(body).decode("utf-8", errors="replace")
            return Response(
                url=str(r.url),
                status=r.status_code,
                headers=r.headers,
                text=text,
                truncated=truncated,
            )
