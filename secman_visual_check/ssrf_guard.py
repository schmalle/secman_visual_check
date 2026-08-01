"""Guard against SSRF via a server-controlled redirect.

Both ``status.py`` (manual redirect walk) and ``capture.py`` (Chromium
navigation) follow HTTP redirects wherever a target sends them, with no
restriction on the destination host. The *initial* target of a scan is an
operator's deliberate choice — including a legitimate internal/on-prem site
— and is never blocked here.

What this blocks by default is a *redirect* that lands on a private,
loopback, link-local, or otherwise reserved address on a **different host**
than the one the operator asked for. That is exactly the shape of an SSRF
attack on this tool: one of the (deliberately arbitrary, often external)
monitored targets is compromised or abused to send a 3xx at
``169.254.169.254`` (cloud instance metadata), ``127.0.0.1``, or an internal
admin panel. Without this guard, the scanner would follow it, attach
whatever Basic-Auth/headers were configured for the *original* host,
screenshot the response, feed its text into a third-party LLM call, and
write it into reports/emails — turning the scanning host's own network
reachability into an attacker-controlled exfiltration channel.

Same-host redirects are always allowed regardless of address, since they
carry no privilege the operator didn't already grant by choosing that target.
"""

from __future__ import annotations

import asyncio
import ipaddress
from urllib.parse import urlsplit


def _is_blocked_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


async def _resolves_to_blocked_ip(host: str) -> bool:
    """Best-effort DNS check. A lookup failure is not a block — an
    unreachable host is reported as such by the caller's own request."""
    try:
        infos = await asyncio.get_event_loop().getaddrinfo(host, None)
    except (OSError, asyncio.TimeoutError):
        return False
    return any(_is_blocked_ip(info[4][0]) for info in infos)


def same_host(url_a: str, url_b: str) -> bool:
    """Hostname-only comparison (scheme/port ignored) — a redirect from http
    to https on the same host, or vice versa, still counts as "the target
    the operator asked for" for credential-scoping purposes."""
    return (urlsplit(url_a).hostname or "").lower() == (urlsplit(url_b).hostname or "").lower()


async def is_unsafe_redirect(original_url: str, redirect_url: str) -> bool:
    """True if ``redirect_url`` should be blocked as a likely SSRF hop.

    Only cross-host redirects onto a private/loopback/link-local/reserved
    address are blocked; a redirect that stays on the same host the operator
    targeted is never blocked, no matter what address it resolves to.
    """
    if same_host(original_url, redirect_url):
        return False
    redirect_host = (urlsplit(redirect_url).hostname or "").lower()
    if not redirect_host:
        return False
    if _is_blocked_ip(redirect_host):
        return True
    return await _resolves_to_blocked_ip(redirect_host)
