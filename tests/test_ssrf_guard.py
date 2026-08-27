import asyncio

from secman_visual_check.ssrf_guard import (
    is_unsafe_connected_addr,
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
# is_unsafe_connected_addr — the DNS-rebinding closer. Unlike the two guards
# above, this never performs its own DNS lookup: it re-checks the address a
# connection *actually* used, which the pre-connect guards' own lookup can
# race against a hostile target's nameserver (TTL-0 rebinding: public IP to
# the guard's lookup, private IP to the real connection's lookup moments
# later).
# --------------------------------------------------------------------------- #


def test_connected_addr_rebind_to_metadata_ip_is_unsafe():
    # The guard's pre-connect DNS check saw a public IP and allowed the
    # redirect; the browser's own, later lookup landed on the metadata
    # address instead. This is exactly the race this function closes.
    assert is_unsafe_connected_addr(
        "https://monitored.example/", "https://evil.example/", "169.254.169.254"
    )


def test_connected_addr_rebind_to_loopback_is_unsafe():
    assert is_unsafe_connected_addr(
        "https://monitored.example/", "https://evil.example/", "127.0.0.1"
    )


def test_connected_addr_public_ip_is_safe():
    assert not is_unsafe_connected_addr(
        "https://monitored.example/", "https://other-public-site.example/", "93.184.216.34"
    )


def test_connected_addr_same_host_is_always_safe():
    # Same same-host exemption as is_unsafe_redirect: the operator's own
    # target is never blocked, whatever address it actually connects to.
    assert not is_unsafe_connected_addr(
        "https://monitored.example/a", "https://monitored.example/b", "127.0.0.1"
    )


def test_connected_addr_missing_is_not_treated_as_unsafe():
    # server_addr() can return None (e.g. a cached/service-worker response);
    # that is not itself evidence of anything and must not false-positive.
    assert not is_unsafe_connected_addr(
        "https://monitored.example/", "https://evil.example/", None
    )
