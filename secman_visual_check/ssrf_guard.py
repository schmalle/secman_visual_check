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


def is_unsafe_connected_addr(original_url: str, response_url: str, remote_ip: str | None) -> bool:
    """True if a request's *actual* connected address should be blocked as an
    SSRF hop, after the fact.

    ``is_unsafe_redirect``/``is_unsafe_destination`` decide *before* the
    request is sent, from this module's own DNS lookup. That lookup can race
    the browser's (or HTTP client's) independent resolution of the same
    hostname moments later — a classic DNS-rebinding TOCTOU: a malicious
    target's nameserver answers the guard's lookup with a public IP and the
    real connection's lookup with ``169.254.169.254``/``127.0.0.1``/an
    RFC-1918 address, defeating the pre-connect guard entirely for the exact
    attacker already in scope (one who controls the target's DNS).

    This closes that gap for callers that can report the address a
    connection *actually* used (a browser response's ``server_addr()``, an
    HTTP client's transport/connection info) — no further DNS lookup is
    performed, so there is nothing left to race. Same same-host exemption as
    ``is_unsafe_redirect``: the operator's own original target is never
    blocked, whatever it resolves to.
    """
    if remote_ip is None:
        return False
    if same_host(original_url, response_url):
        return False
    return _is_blocked_ip(remote_ip)


def connected_ip(response: object) -> str | None:
    """The IP address a completed httpx response's connection actually used.

    Read from the transport's own network stream (``response.extensions
    ["network_stream"].get_extra_info("server_addr")``), never from a fresh
    DNS lookup — a fresh lookup is exactly what a DNS-rebinding target could
    answer differently from the connection that was really made, which is
    the whole TOCTOU :func:`is_unsafe_connected_addr` exists to close.
    Returns ``None`` whenever that information is not available (a mock
    transport in tests, a proxy, a pooled connection whose socket has since
    closed, or any other backend that does not expose it) — a caller passing
    ``None`` through to :func:`is_unsafe_connected_addr` fails open, the same
    way ``capture.py``'s own ``_safe(response.server_addr)`` does: this is a
    defense-in-depth closer for a real client, not something correctness
    depends on.
    """
    stream = (getattr(response, "extensions", None) or {}).get("network_stream")
    get_extra_info = getattr(stream, "get_extra_info", None)
    if get_extra_info is None:
        return None
    try:
        addr = get_extra_info("server_addr")
    except Exception:
        return None
    if not addr:
        return None
    try:
        return str(addr[0])
    except (TypeError, IndexError):
        return None


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
