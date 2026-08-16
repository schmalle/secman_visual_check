import asyncio

import secman_visual_check.ssrf_guard as ssrf_guard
from secman_visual_check.ssrf_guard import (
    check_redirect,
    is_unsafe_destination,
    is_unsafe_redirect,
    same_host,
)


def run(coro):
    return asyncio.run(coro)


def _mock_getaddrinfo(monkeypatch, addresses):
    """Deterministic stand-in for the real resolver, in the exact shape
    check_redirect/_resolve_pinned reads (``info[4][0]`` per entry)."""

    class FakeLoop:
        async def getaddrinfo(self, host, port):
            return [(None, None, None, "", (addr, 0)) for addr in addresses]

    monkeypatch.setattr(ssrf_guard.asyncio, "get_event_loop", lambda: FakeLoop())


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
# check_redirect — the DNS-rebinding-safe entry point. A caller (status.py)
# that can pin its own connection to a specific address must use this, not
# is_unsafe_redirect, or the safety check and the actual connection can see
# two different DNS answers for the same hostname.
# --------------------------------------------------------------------------- #


def test_check_redirect_pins_the_resolved_address_of_a_safe_target(monkeypatch):
    _mock_getaddrinfo(monkeypatch, ["93.184.216.34"])

    result = run(check_redirect("https://monitored.example/", "https://other-public-site.example/"))

    assert result.unsafe is False
    assert result.pinned_ip == "93.184.216.34"


def test_check_redirect_picks_the_first_resolved_address(monkeypatch):
    _mock_getaddrinfo(monkeypatch, ["93.184.216.34", "93.184.216.35"])

    result = run(check_redirect("https://monitored.example/", "https://other-public-site.example/"))

    assert result.pinned_ip == "93.184.216.34"


def test_check_redirect_blocks_and_never_pins_when_any_answer_is_private(monkeypatch):
    # A rebinding nameserver could answer with a mix; if any candidate is
    # private the whole lookup is untrustworthy, matching is_unsafe_redirect's
    # existing "any" semantics.
    _mock_getaddrinfo(monkeypatch, ["93.184.216.34", "127.0.0.1"])

    result = run(check_redirect("https://monitored.example/", "https://other-public-site.example/"))

    assert result.unsafe is True
    assert result.pinned_ip is None


def test_check_redirect_does_not_pin_a_literal_blocked_ip():
    # No DNS lookup happens here at all — the host is already an IP literal —
    # so there is nothing to pin (and nothing to rebind).
    result = run(check_redirect("https://monitored.example/", "http://127.0.0.1:8080/admin"))

    assert result.unsafe is True
    assert result.pinned_ip is None


def test_check_redirect_does_not_pin_a_same_host_target():
    # No lookup is performed for a same-host hop (it is never blocked), so
    # there is nothing to pin either.
    result = run(check_redirect("https://monitored.example/a", "https://monitored.example/b"))

    assert result.unsafe is False
    assert result.pinned_ip is None


def test_check_redirect_unresolvable_host_has_no_pin(monkeypatch):
    class FailingLoop:
        async def getaddrinfo(self, host, port):
            raise OSError("mock DNS failure")

    monkeypatch.setattr(ssrf_guard.asyncio, "get_event_loop", lambda: FailingLoop())

    result = run(check_redirect("https://monitored.example/", "https://this-host-should-not-resolve.invalid/"))

    assert result.unsafe is False
    assert result.pinned_ip is None
