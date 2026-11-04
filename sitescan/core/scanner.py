"""Scanner base class, scan context and the auto-discovery registry.

Adding a check = drop a module in ``sitescan/scanners/`` containing::

    @register
    class MyScanner(Scanner):
        name = "my-check"
        description = "What it looks at"

        async def run(self, ctx: ScanContext) -> list[Finding]:
            ...

Nothing else needs wiring: ``discover()`` imports every module in the
package, and ``@register`` records the class as a side effect of import.
"""
from __future__ import annotations

import importlib
import pkgutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar

from .finding import Finding
from .http import HttpClient, Response
from .ratelimit import RateLimiter
from .target import Target

if TYPE_CHECKING:  # pragma: no cover
    import httpx

_REGISTRY: dict[str, type["Scanner"]] = {}


def register(cls: type["Scanner"]) -> type["Scanner"]:
    """Class decorator: make a Scanner subclass discoverable by name."""
    if not (isinstance(cls, type) and issubclass(cls, Scanner)):
        raise TypeError("@register can only decorate Scanner subclasses")
    if not cls.name:
        raise ValueError(f"{cls.__name__} must define a non-empty `name`")
    existing = _REGISTRY.get(cls.name)
    if existing is not None and existing is not cls:
        raise ValueError(f"duplicate scanner name {cls.name!r}: {existing} vs {cls}")
    _REGISTRY[cls.name] = cls
    return cls


def registry() -> dict[str, type["Scanner"]]:
    return dict(_REGISTRY)


def discover(package: str = "sitescan.scanners") -> dict[str, type["Scanner"]]:
    """Import every module in ``package`` so their @register calls fire."""
    pkg = importlib.import_module(package)
    for mod in pkgutil.iter_modules(pkg.__path__, pkg.__name__ + "."):
        if not mod.name.rsplit(".", 1)[-1].startswith("_"):
            importlib.import_module(mod.name)
    return registry()


@dataclass
class ScanConfig:
    rate: float = 5.0
    timeout: float = 10.0
    user_agent: str = ""
    # TLS: extra CA bundle to trust when validating the chain (e.g. internal CA)
    ca_bundle: str | None = None
    # Transport: override the plain-HTTP URL used for the HTTP->HTTPS check
    http_url: str | None = None
    # Dependency scanner
    osv_enabled: bool = True
    osv_url: str = "https://api.osv.dev/v1/query"
    osv_transport: "httpx.AsyncBaseTransport | None" = None
    # DNS: injectable backend (see scanners/dns_email.py); None = real resolver
    dns_backend: Any = None
    # DNS: domain to assess for email/CAA records (default: target host minus "www.")
    dns_domain: str | None = None
    # Hard ceiling for any one scanner's runtime (seconds)
    scanner_timeout: float = 180.0
    extra: dict[str, Any] = field(default_factory=dict)


class ScanContext:
    """Everything a scanner needs; shared across all scanners in a run."""

    def __init__(
        self,
        target: Target,
        config: ScanConfig,
        limiter: RateLimiter,
        http: HttpClient,
    ):
        self.target = target
        self.config = config
        self.limiter = limiter
        self.http = http
        self.notes: list[str] = []

    async def root(self) -> Response | None:
        """The (cached) GET of the target URL, following redirects."""
        return await self.http.get(self.target.url)


class Scanner(ABC):
    name: ClassVar[str] = ""
    description: ClassVar[str] = ""

    @abstractmethod
    async def run(self, ctx: ScanContext) -> list[Finding]:
        """Return findings. May raise: the orchestrator contains failures."""
