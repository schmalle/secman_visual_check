import asyncio
from unittest.mock import AsyncMock, patch

from secman_visual_check.ssrf_guard import (
    check_destination,
    check_redirect,
    is_unsafe_destination,
    is_unsafe_redirect,
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
# check_redirect / check_destination — the DNS-pinning API. is_unsafe_redirect
# and is_unsafe_destination are thin boolean wrappers around these; the tests
# above exercise them adequately. What needs its own coverage is the address
# these two capture, since a caller (status.py) connects to exactly that
# address rather than re-resolving the hostname a second time.
# --------------------------------------------------------------------------- #


def _mock_resolution(*ips):
    """Patch asyncio's resolver to answer with the given IPs, as getaddrinfo would."""
    infos = [(2, 1, 6, "", (ip, 0)) for ip in ips]
    loop = AsyncMock()
    loop.getaddrinfo = AsyncMock(return_value=infos)
    return patch("asyncio.get_event_loop", return_value=loop)


def test_check_redirect_pins_the_resolved_address_for_a_cross_host_hop():
    with _mock_resolution("93.184.216.34"):
        result = run(check_redirect("https://monitored.example/", "https://other-public-site.example/"))

    assert result.blocked is False
    assert result.pinned_ip == "93.184.216.34"


def test_check_redirect_same_host_never_resolves_or_pins():
    loop = AsyncMock()
    loop.getaddrinfo = AsyncMock(side_effect=AssertionError("must not resolve a same-host redirect"))
    with patch("asyncio.get_event_loop", return_value=loop):
        result = run(check_redirect("https://monitored.example/a", "https://monitored.example/b"))

    assert result.blocked is False
    assert result.pinned_ip is None


def test_check_redirect_blocked_address_carries_no_pin():
    with _mock_resolution("169.254.169.254"):
        result = run(check_redirect("https://monitored.example/", "https://attacker-controlled.example/"))

    assert result.blocked is True
    assert result.pinned_ip is None


def test_check_redirect_unresolvable_host_carries_no_pin():
    result = run(
        check_redirect("https://monitored.example/", "https://this-host-should-not-resolve.invalid/")
    )
    assert result.blocked is False
    assert result.pinned_ip is None


def test_check_destination_pins_the_resolved_address():
    with _mock_resolution("93.184.216.34"):
        result = run(check_destination("https://other-public-site.example/"))

    assert result.blocked is False
    assert result.pinned_ip == "93.184.216.34"


def test_check_destination_blocked_address_carries_no_pin():
    with _mock_resolution("127.0.0.1"):
        result = run(check_destination("https://attacker-controlled.example/"))

    assert result.blocked is True
    assert result.pinned_ip is None
