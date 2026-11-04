"""Authorization gate: explicit flag + typed hostname confirmation + denylist."""
from __future__ import annotations

from collections.abc import Callable

from .target import Target

# Major third-party platforms. Scanning these is almost never authorised for
# the person running this tool, and they have their own bug bounty scopes /
# rules of engagement. Matching is exact-or-subdomain.
DENYLIST: frozenset[str] = frozenset(
    {
        # search / social / big tech
        "google.com", "googleapis.com", "gstatic.com", "youtube.com", "gmail.com",
        "facebook.com", "fb.com", "instagram.com", "whatsapp.com", "meta.com",
        "twitter.com", "x.com", "linkedin.com", "tiktok.com", "reddit.com",
        "pinterest.com", "snapchat.com", "discord.com", "telegram.org",
        "microsoft.com", "live.com", "outlook.com", "office.com", "bing.com",
        "azure.com", "windows.net", "apple.com", "icloud.com",
        "amazon.com", "aws.amazon.com", "amazonaws.com", "netflix.com",
        "yahoo.com", "baidu.com", "yandex.ru", "wikipedia.org",
        # infra / dev platforms
        "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org",
        "cloudflare.com", "akamai.com", "fastly.com", "cloudfront.net",
        "stackoverflow.com", "npmjs.com", "pypi.org",
        # payments / finance
        "paypal.com", "stripe.com", "visa.com", "mastercard.com",
        # AI providers
        "openai.com", "anthropic.com", "claude.ai",
    }
)
# Whole TLDs we refuse to touch.
DENY_SUFFIXES: tuple[str, ...] = (".gov", ".mil")


class AuthorizationError(Exception):
    pass


def denied_reason(host: str) -> str | None:
    host = host.lower().rstrip(".")
    for d in DENYLIST:
        if host == d or host.endswith("." + d):
            return f"{host} matches denylisted third-party domain {d!r}"
    for suf in DENY_SUFFIXES:
        if host.endswith(suf):
            return f"{host} is under the denylisted {suf} TLD"
    return None


def check_authorization(
    target: Target,
    *,
    authorized_flag: bool,
    confirm_host: str | None = None,
    prompt: Callable[[str], str] = input,
    interactive: bool = True,
) -> None:
    """Raise AuthorizationError unless every gate passes.

    Order matters: the denylist is checked first so no confirmation prompt is
    ever shown for a refused target.
    """
    reason = denied_reason(target.host)
    if reason:
        raise AuthorizationError(f"refusing to scan: {reason}")
    if not authorized_flag:
        raise AuthorizationError(
            "refusing to scan without --i-am-authorized. Only scan systems you "
            "own or have written permission to test."
        )
    if confirm_host is None:
        if not interactive:
            raise AuthorizationError(
                "no TTY for confirmation; pass --confirm-host <hostname> explicitly"
            )
        confirm_host = prompt(
            f"Type the target hostname ({target.host}) to confirm you are authorized: "
        )
    if confirm_host.strip().lower().rstrip(".") != target.host:
        raise AuthorizationError(
            f"confirmation {confirm_host.strip()!r} does not match target host {target.host!r}"
        )
