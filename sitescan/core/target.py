from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Target:
    url: str  # normalised, e.g. https://example.com:8443/
    scheme: str
    host: str
    port: int

    @classmethod
    def parse(cls, raw: str) -> "Target":
        raw = raw.strip()
        if "://" not in raw:
            raw = "https://" + raw
        parts = urlsplit(raw)
        if parts.scheme not in ("http", "https"):
            raise ValueError(f"unsupported scheme: {parts.scheme!r}")
        if not parts.hostname:
            raise ValueError(f"no hostname in {raw!r}")
        host = parts.hostname.lower().rstrip(".")
        port = parts.port or (443 if parts.scheme == "https" else 80)
        default = (parts.scheme == "https" and port == 443) or (
            parts.scheme == "http" and port == 80
        )
        netloc = _fmt_host(host) + ("" if default else f":{port}")
        return cls(url=f"{parts.scheme}://{netloc}/", scheme=parts.scheme, host=host, port=port)

    @property
    def is_https(self) -> bool:
        return self.scheme == "https"

    @property
    def is_ip(self) -> bool:
        try:
            ipaddress.ip_address(self.host)
            return True
        except ValueError:
            return False

    @property
    def is_local(self) -> bool:
        if self.host == "localhost" or self.host.endswith(".localhost"):
            return True
        try:
            ip = ipaddress.ip_address(self.host)
            return ip.is_loopback or ip.is_private or ip.is_link_local
        except ValueError:
            return False

    def join(self, path: str) -> str:
        return self.url.rstrip("/") + "/" + path.lstrip("/")


def _fmt_host(host: str) -> str:
    return f"[{host}]" if ":" in host else host
