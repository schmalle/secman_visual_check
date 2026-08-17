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

``is_unsafe_redirect``/``is_unsafe_destination`` below are advisory: they
resolve a hostname purely to answer allow/block, and say nothing about what
a *later*, independent resolution by the real transport will return. A
target with a short/zero-TTL DNS record can answer this module's lookup
with a public IP and the transport's own subsequent lookup with
``169.254.169.254`` — a classic DNS-rebinding TOCTOU. ``resolve_pinned_address``
closes that gap for callers that can act on it: it resolves once, validates
that result, and returns the exact address to connect to, so there is no
second lookup for a rebinding record to answer differently. ``status.py``
uses it to pin every hop's httpx connection. ``capture.py`` cannot — Playwright
gives no hook to pin the IP Chromium itself connects to — so the browser
capture path keeps only the advisory check above, re-run immediately before
each request is allowed through (shrinking, not closing, the race window).
See the DNS-rebinding note in ``capture.py`` and ``docs/STATUS_CHECK.md``.
"""

from __future__ import annotations

import asyncio
import ipaddress
from urllib.parse import urlsplit


def is_blocked_ip(value: str) -> bool:
    """True if ``value`` parses as an IP literal on the blocklist (private,
    loopback, link-local, reserved, multicast or unspecified). Not an IP at
    all (a hostname) is not blocked here — that is a DNS question, not an
    address question."""
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


# Back-compat alias: kept private-looking since it started that way, but it is
# now the same function other modules import — see is_blocked_ip above.
_is_blocked_ip = is_blocked_ip


async def resolve_addresses(host: str) -> list[str]:
    """Resolve ``host`` to its distinct numeric addresses via one DNS lookup.

    Raises ``OSError``/``asyncio.TimeoutError`` on a lookup failure, exactly
    like the underlying resolver would — this is the shared resolution step
    both ``_resolves_to_blocked_ip`` (best-effort, pre-connect advisory
    check) and ``resolve_pinned_address`` (real IP pinning, see below) build
    on, so there is exactly one place that talks to DNS.
    """
    infos = await asyncio.get_event_loop().getaddrinfo(host, None)
    seen: list[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in seen:
            seen.append(ip)
    return seen


class UnsafeAddressError(Exception):
    """Every address ``host`` resolved to is on the SSRF blocklist."""

    def __init__(self, host: str, addresses: list[str]):
        self.host = host
        self.addresses = addresses
        super().__init__(
            f"{host} resolves only to blocked address(es): {', '.join(addresses)}"
        )


async def resolve_pinned_address(host: str, *, validate: bool = True) -> str:
    """Resolve ``host`` once and return a single address to connect to
    directly — the fix for the DNS-rebinding TOCTOU this module was
    previously exposed to.

    The bug: a guard resolves a hostname purely to decide allow/block, then
    hands the *hostname* back to the real transport, which independently
    re-resolves at actual connect time. An attacker controlling a short/zero
    TTL record can answer the guard's lookup with a public IP and the
    transport's later, separate lookup with ``169.254.169.254`` or
    ``127.0.0.1`` — the decision and the connection never see the same
    address.

    The fix: resolve exactly once and hand *that resolved address itself* to
    the transport as the connection target (with the original hostname
    preserved for the ``Host`` header and TLS SNI/certificate validation —
    see ``status.py``'s pinning helpers). There is no second, independent
    resolution for a rebinding record to answer differently.

    ``validate=True`` (the default) additionally requires the returned
    address to be off the SSRF blocklist, raising :class:`UnsafeAddressError`
    if every resolved address is blocked. Pass ``validate=False`` for a host
    a caller has already decided is exempt from that check (e.g. the
    operator's own chosen target, or a same-host hop — see
    ``is_unsafe_redirect``'s same-host exemption) — pinning still applies,
    only the block decision is skipped.

    Lets ``OSError``/``asyncio.TimeoutError`` propagate on a lookup failure —
    an unreachable host is a different, non-blocked outcome the caller
    reports as such, same as everywhere else in this module.
    """
    addresses = await resolve_addresses(host)
    if not addresses:
        raise OSError(f"no addresses returned for {host}")
    if not validate:
        return addresses[0]
    safe = [ip for ip in addresses if not is_blocked_ip(ip)]
    if not safe:
        raise UnsafeAddressError(host, addresses)
    return safe[0]


async def _resolves_to_blocked_ip(host: str) -> bool:
    """Best-effort DNS check. A lookup failure is not a block — an
    unreachable host is reported as such by the caller's own request.

    This is the advisory, pre-connect check used by ``is_unsafe_redirect``/
    ``is_unsafe_destination`` below. It is inherently TOCTOU-prone on its
    own (see ``resolve_pinned_address``'s docstring) — callers that go on to
    make a real network connection based on its answer (``status.py``) pin
    that connection to a freshly, independently validated address rather
    than trusting this check alone. ``capture.py`` cannot do that (Chromium
    gives no hook to pin a connection's IP), so for the browser-driven
    capture path this remains a best-effort mitigation, not a full fix —
    see the DNS-rebinding note in ``capture.py`` and ``docs/STATUS_CHECK.md``.
    """
    try:
        addresses = await resolve_addresses(host)
    except (OSError, asyncio.TimeoutError):
        return False
    return any(is_blocked_ip(ip) for ip in addresses)


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
