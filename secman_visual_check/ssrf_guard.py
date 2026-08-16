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
from dataclasses import dataclass
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


def is_blocked_address(value: str) -> bool:
    """Public wrapper around :func:`_is_blocked_ip`, for callers that already
    have a concrete address in hand — e.g. ``capture.py``'s post-connect
    check, which reads the address Chromium actually connected to via
    Playwright's ``response.server_addr()`` rather than doing a lookup of
    its own."""
    return _is_blocked_ip(value)


async def _resolves_to_blocked_ip(host: str) -> bool:
    """Best-effort DNS check. A lookup failure is not a block — an
    unreachable host is reported as such by the caller's own request."""
    try:
        infos = await asyncio.get_event_loop().getaddrinfo(host, None)
    except (OSError, asyncio.TimeoutError):
        return False
    return any(_is_blocked_ip(info[4][0]) for info in infos)


async def _resolve_pinned(host: str) -> tuple[bool, str | None]:
    """One lookup, both jobs: is ``host`` safe, and — if so — which literal
    IP address must the *connection* use.

    Doing the safety check and returning the address it was decided against
    are the same operation on purpose: a caller that re-resolves ``host`` for
    the actual connection reopens a DNS-rebinding gap — an attacker-run
    nameserver can answer this lookup with a public IP and the very next one
    (issued moments later, at connect time) with ``127.0.0.1`` or
    ``169.254.169.254``. Returning the resolved address lets the caller pin
    the connection to it and skip the second lookup entirely.

    Returns ``(blocked, pinned_ip)``. ``pinned_ip`` is ``None`` when the
    lookup itself failed (the caller falls back to normal resolution, and an
    unreachable host is reported as such by the request that follows) or
    when it returned no usable address.
    """
    try:
        infos = await asyncio.get_event_loop().getaddrinfo(host, None)
    except (OSError, asyncio.TimeoutError):
        return False, None
    addresses = [info[4][0] for info in infos]
    if any(_is_blocked_ip(addr) for addr in addresses):
        return True, None
    return False, (addresses[0] if addresses else None)


@dataclass(frozen=True)
class RedirectCheck:
    """Outcome of validating a redirect hop before connecting to it.

    ``pinned_ip`` is set exactly when a DNS lookup decided the outcome — see
    :func:`_resolve_pinned` for why the caller must connect to that literal
    address rather than letting the transport re-resolve the hostname.
    """

    unsafe: bool
    pinned_ip: str | None = None


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

    A thin, DNS-rebinding-vulnerable convenience wrapper around
    :func:`check_redirect` for callers that cannot pin the address a lookup
    was validated against to their own connection (``capture.py``'s
    Chromium navigation, which has no such hook — see its own post-connect
    check). Any caller that *can* connect over an address it controls
    (``status.py``'s httpx client) must use :func:`check_redirect` and pin
    the connection to ``pinned_ip`` instead of calling this.
    """
    return (await check_redirect(original_url, redirect_url)).unsafe


async def check_redirect(original_url: str, redirect_url: str) -> RedirectCheck:
    """Safety check for a redirect hop, returning the address the caller
    must pin its connection to (see :func:`_resolve_pinned`).

    Only cross-host redirects onto a private/loopback/link-local/reserved
    address are blocked; a redirect that stays on the same host the operator
    targeted is never blocked, no matter what address it resolves to — and
    is never pinned, since no lookup was performed to decide that.
    """
    if same_host(original_url, redirect_url):
        return RedirectCheck(unsafe=False)
    redirect_host = (urlsplit(redirect_url).hostname or "").lower()
    if not redirect_host:
        return RedirectCheck(unsafe=False)
    if _is_blocked_ip(redirect_host):
        return RedirectCheck(unsafe=True)
    blocked, pinned_ip = await _resolve_pinned(redirect_host)
    return RedirectCheck(unsafe=blocked, pinned_ip=pinned_ip)


async def is_unsafe_destination(url: str) -> bool:
    """True if ``url``'s host is a private/loopback/link-local/reserved address.

    Unlike :func:`is_unsafe_redirect`, there is no same-host exemption here —
    that exemption exists because the *original* target is the operator's
    deliberate choice. This function is for requests where no such original
    target exists: a page a scanned target's own JavaScript opened itself
    (``window.open()``, ``target="_blank"``, a form that opens a tab), which
    Playwright creates as a brand-new page in the shared browser context and
    does **not** route through the per-target guard installed on the page the
    operator actually navigated to. The operator never asked to visit that
    URL at all, so any private destination is blocked outright, regardless of
    host.
    """
    host = (urlsplit(url).hostname or "").lower()
    if not host:
        return False
    if _is_blocked_ip(host):
        return True
    return await _resolves_to_blocked_ip(host)
