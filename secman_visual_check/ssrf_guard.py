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


@dataclass
class HostCheck:
    """The result of validating one hop's destination host.

    ``pinned_ip`` is the literal address the validation lookup resolved to,
    captured at the moment of that lookup. A caller that goes on to make the
    actual request should connect to this exact address instead of letting
    its own HTTP client (or Chromium) resolve the hostname a second time —
    otherwise an attacker controlling DNS for the redirect/popup target with
    a zero-TTL record can answer with a public address for this check and a
    private one moments later for the real connection (DNS rebinding),
    defeating the check entirely. ``None`` when no address was captured:
    either no resolution was needed (see ``check_redirect``'s same-host
    exemption) or the lookup failed, in which case the caller falls back to
    its normal hostname-based connection — an unreachable host is reported
    as such by that request itself.
    """

    blocked: bool
    pinned_ip: str | None = None


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


async def _resolve(host: str) -> HostCheck:
    """Best-effort single DNS lookup, both to decide whether ``host`` is
    blocked and to capture the address it resolved to for pinning. A lookup
    failure is not a block — an unreachable host is reported as such by the
    caller's own request — and yields no pin either."""
    try:
        infos = await asyncio.get_event_loop().getaddrinfo(host, None)
    except (OSError, asyncio.TimeoutError):
        return HostCheck(blocked=False)
    ips = [info[4][0] for info in infos]
    if any(_is_blocked_ip(ip) for ip in ips):
        return HostCheck(blocked=True)
    return HostCheck(blocked=False, pinned_ip=ips[0] if ips else None)


def same_host(url_a: str, url_b: str) -> bool:
    """Hostname-only comparison (scheme/port ignored) — a redirect from http
    to https on the same host, or vice versa, still counts as "the target
    the operator asked for" for credential-scoping purposes."""
    return (urlsplit(url_a).hostname or "").lower() == (urlsplit(url_b).hostname or "").lower()


async def check_redirect(original_url: str, redirect_url: str) -> HostCheck:
    """Validate ``redirect_url`` as a likely SSRF hop, in one DNS lookup.

    Only cross-host redirects onto a private/loopback/link-local/reserved
    address are blocked; a redirect that stays on the same host the operator
    targeted is never blocked, no matter what address it resolves to (and no
    lookup is performed for it — there is no pin to capture either).
    """
    if same_host(original_url, redirect_url):
        return HostCheck(blocked=False)
    redirect_host = (urlsplit(redirect_url).hostname or "").lower()
    if not redirect_host:
        return HostCheck(blocked=False)
    if _is_blocked_ip(redirect_host):
        return HostCheck(blocked=True)
    return await _resolve(redirect_host)


async def check_destination(url: str) -> HostCheck:
    """Validate ``url`` as a destination, in one DNS lookup.

    Unlike :func:`check_redirect`, there is no same-host exemption here —
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
        return HostCheck(blocked=False)
    if _is_blocked_ip(host):
        return HostCheck(blocked=True)
    return await _resolve(host)


async def is_unsafe_redirect(original_url: str, redirect_url: str) -> bool:
    """True if ``redirect_url`` should be blocked as a likely SSRF hop.

    Thin boolean wrapper around :func:`check_redirect` for callers (and
    tests) that only need the verdict, not the pinned address.
    """
    return (await check_redirect(original_url, redirect_url)).blocked


async def is_unsafe_destination(url: str) -> bool:
    """True if ``url``'s host is a private/loopback/link-local/reserved address.

    Thin boolean wrapper around :func:`check_destination`; see there for why
    there is no same-host exemption here.
    """
    return (await check_destination(url)).blocked
