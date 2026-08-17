import asyncio

import pytest

from secman_visual_check import ssrf_guard
from secman_visual_check.ssrf_guard import (
    UnsafeAddressError,
    is_unsafe_destination,
    is_unsafe_redirect,
    resolve_pinned_address,
    same_host,
)


def run(coro):
    return asyncio.run(coro)


def test_same_host_ignores_scheme_and_path():
    assert same_host("http://example.com/a", "https://example.com/b")


def test_same_host_differs_on_hostname():
    assert not same_host("https://example.com/", "https://evil.example/")


def test_redirect_to_metadata_ip_is_unsafe():
    assert run(is_unsafe_redirect("https://monitored.example/", "http://169.254.169.254/latest/meta-data/"))


def test_redirect_to_loopback_is_unsafe():
    assert run(is_unsafe_redirect("https://monitored.example/", "http://127.0.0.1:8080/admin"))


def test_redirect_to_private_range_is_unsafe():
    assert run(is_unsafe_redirect("https://monitored.example/", "http://10.0.0.5/"))


def test_redirect_to_public_host_is_safe():
    assert not run(is_unsafe_redirect("https://monitored.example/", "https://other-public-site.example/"))


def test_redirect_within_same_host_is_always_safe():
    # Even if the same host somehow resolved to a private address, staying on
    # the operator's own target carries no extra privilege.
    assert not run(is_unsafe_redirect("https://monitored.example/a", "https://monitored.example/b"))


def test_unresolvable_host_is_not_treated_as_unsafe():
    # A DNS failure is the request's own problem to report as "unreachable";
    # this guard must not turn it into a false "blocked" verdict.
    assert not run(
        is_unsafe_redirect(
            "https://monitored.example/", "https://this-host-should-not-resolve.invalid/"
        )
    )


# --------------------------------------------------------------------------- #
# is_unsafe_destination — no "operator's target" to exempt, unlike
# is_unsafe_redirect. Used for pages the scanner never asked to visit at all
# (a popup a scanned target's own JS opened via window.open()).
# --------------------------------------------------------------------------- #


def test_destination_metadata_ip_is_unsafe():
    assert run(is_unsafe_destination("http://169.254.169.254/latest/meta-data/"))


def test_destination_loopback_is_unsafe():
    assert run(is_unsafe_destination("http://127.0.0.1:8080/admin"))


def test_destination_private_range_is_unsafe():
    assert run(is_unsafe_destination("http://10.0.0.5/"))


def test_destination_public_host_is_safe():
    assert not run(is_unsafe_destination("https://other-public-site.example/"))


def test_destination_unresolvable_host_is_not_treated_as_unsafe():
    assert not run(is_unsafe_destination("https://this-host-should-not-resolve.invalid/"))


def test_destination_has_no_same_host_exemption():
    # A private IP is unsafe regardless of what "host" it might otherwise be
    # compared against — there is no operator-chosen original URL here.
    assert run(is_unsafe_destination("http://169.254.169.254/"))


# --------------------------------------------------------------------------- #
# resolve_pinned_address — the DNS-rebinding fix. Unlike `is_unsafe_redirect`
# above (which only ever answers allow/block, then hands the *hostname* back
# for someone else to connect to — the TOCTOU bug), this resolves once and
# returns the exact address a caller should connect to, so the decision and
# the connection are guaranteed to agree.
# --------------------------------------------------------------------------- #


def test_resolve_pinned_address_returns_a_safe_resolved_address():
    async def resolver(host):
        return ["93.184.216.34"]

    original = ssrf_guard.resolve_addresses
    ssrf_guard.resolve_addresses = resolver
    try:
        assert run(resolve_pinned_address("example.com")) == "93.184.216.34"
    finally:
        ssrf_guard.resolve_addresses = original


def test_resolve_pinned_address_rejects_a_host_that_resolves_only_to_blocked_addresses():
    async def resolver(host):
        return ["169.254.169.254"]

    original = ssrf_guard.resolve_addresses
    ssrf_guard.resolve_addresses = resolver
    try:
        with pytest.raises(UnsafeAddressError):
            run(resolve_pinned_address("attacker.example"))
    finally:
        ssrf_guard.resolve_addresses = original


def test_resolve_pinned_address_resolves_exactly_once_and_never_re_resolves():
    """The literal proof that the fix closes the DNS-rebinding race: a
    resolver that would answer a public IP on a first call and cloud
    metadata on a hypothetical second call must only ever be called once —
    and the address returned (and thus the one a caller connects to) is the
    first, safe answer, never the second, unsafe one it never asks for."""
    calls: list[str] = []

    async def rebinding_resolver(host):
        calls.append(host)
        if len(calls) == 1:
            return ["8.8.8.8"]  # the "guard" lookup: public, safe
        return ["169.254.169.254"]  # a later lookup would be cloud metadata

    original = ssrf_guard.resolve_addresses
    ssrf_guard.resolve_addresses = rebinding_resolver
    try:
        pinned = run(resolve_pinned_address("rebinding.example"))
    finally:
        ssrf_guard.resolve_addresses = original

    assert pinned == "8.8.8.8"
    assert calls == ["rebinding.example"]  # exactly one lookup


def test_resolve_pinned_address_with_validate_false_skips_the_blocklist():
    """The exemption `status.py` uses for the operator's own target and for
    same-host hops: still resolves and pins, just never blocks."""

    async def resolver(host):
        return ["169.254.169.254"]

    original = ssrf_guard.resolve_addresses
    ssrf_guard.resolve_addresses = resolver
    try:
        assert run(resolve_pinned_address("internal.example", validate=False)) == "169.254.169.254"
    finally:
        ssrf_guard.resolve_addresses = original


def test_resolve_pinned_address_propagates_a_lookup_failure():
    # A DNS failure is the caller's problem to report as unreachable, not a
    # block — consistent with `is_unsafe_redirect`'s own fail-open lookup.
    async def resolver(host):
        raise OSError("Name or service not known")

    original = ssrf_guard.resolve_addresses
    ssrf_guard.resolve_addresses = resolver
    try:
        with pytest.raises(OSError):
            run(resolve_pinned_address("this-host-should-not-resolve.invalid"))
    finally:
        ssrf_guard.resolve_addresses = original
