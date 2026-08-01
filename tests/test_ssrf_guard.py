import asyncio

from secman_visual_check.ssrf_guard import is_unsafe_redirect, same_host


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
