"""Helpers shared by scanner modules. Underscore-prefixed so discover() skips it."""
from __future__ import annotations

import secrets

# Reusable CVSS 3.1 vectors for configuration-class findings. These describe
# the *exposure* the misconfiguration creates, not a specific exploit.
CVSS_MITM_PASSIVE = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N"  # 4.2
CVSS_MITM_ACTIVE = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"  # 7.4
CVSS_XSS_MITIGATION = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N"  # 4.7
CVSS_CLICKJACK = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"  # 4.3
CVSS_INFO_LEAK_LOW = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"  # 5.3
CVSS_INFO_LEAK_HIGH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"  # 7.5
CVSS_SECRETS_EXPOSED = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"  # 9.1
CVSS_COOKIE_THEFT = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N"  # 5.3
CVSS_SPOOFING = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"  # 4.3


def random_path(prefix: str = "sitescan-probe") -> str:
    """A path that should not exist; used for soft-404 / error-page baselines."""
    return f"/{prefix}-{secrets.token_hex(6)}"


def clip(s: str, n: int = 300) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[: n - 1] + "…"
