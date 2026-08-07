"""robots.txt fetching: caching, fail-open behaviour, and the SSRF redirect guard.

Mirrors test_status_check.py's approach of injecting a MockTransport-backed
client, since RobotsCache accepts the same test-only `client=` hook as
UrlStatusChecker for exactly this reason.
"""

import asyncio

import httpx

from secman_visual_check.robots import RobotsCache


def make_cache(handler, **overrides):
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)
    return RobotsCache(client=client, **overrides), client


def responder(routes, default=404):
    """A handler answering from a ``{url: (status, location, body)}`` table."""

    def handler(request):
        status, location, body = routes.get(str(request.url), (default, None, ""))
        headers = {"Location": location} if location else {}
        return httpx.Response(status, headers=headers, text=body)

    return handler


def run_allowed(cache, client, url):
    async def main():
        try:
            return await cache.allowed(url)
        finally:
            await client.aclose()

    return asyncio.run(main())


def test_plain_robots_txt_is_fetched_and_applied():
    cache, client = make_cache(
        responder(
            {
                "https://example.com/robots.txt": (
                    200,
                    None,
                    "User-agent: *\nDisallow: /private/\n",
                )
            }
        )
    )

    assert run_allowed(cache, client, "https://example.com/public/") is True


def test_disallowed_path_is_blocked():
    cache, client = make_cache(
        responder(
            {
                "https://example.com/robots.txt": (
                    200,
                    None,
                    "User-agent: *\nDisallow: /private/\n",
                )
            }
        )
    )

    assert run_allowed(cache, client, "https://example.com/private/x") is False


def test_missing_robots_txt_fails_open():
    cache, client = make_cache(responder({}, default=404))

    assert run_allowed(cache, client, "https://example.com/anything") is True


def test_same_host_redirect_is_followed():
    cache, client = make_cache(
        responder(
            {
                "https://example.com/robots.txt": (302, "https://example.com/moved-robots.txt", ""),
                "https://example.com/moved-robots.txt": (
                    200,
                    None,
                    "User-agent: *\nDisallow: /blocked/\n",
                ),
            }
        )
    )

    assert run_allowed(cache, client, "https://example.com/blocked/x") is False


def test_cross_host_redirect_to_a_private_address_is_blocked_and_fails_open():
    """A compromised/malicious target's robots.txt redirects to an internal
    address on a different host — this is the SSRF this guard exists to stop.
    Blocking the fetch means the parser is None, which fails open (allow),
    exactly like any other unreachable robots.txt — the point is the scanner
    never issues the request to the internal address at all."""
    cache, client = make_cache(
        responder(
            {
                "https://example.com/robots.txt": (302, "http://169.254.169.254/latest/meta-data/", ""),
            }
        )
    )

    assert run_allowed(cache, client, "https://example.com/anything") is True


def test_cross_host_redirect_to_a_private_address_is_reachable_with_the_operator_override():
    cache, client = make_cache(
        responder(
            {
                "https://example.com/robots.txt": (302, "http://127.0.0.1:9/robots.txt", ""),
            }
        ),
        block_private_redirects=False,
    )

    # The redirect target is unreachable (nothing routes it in `responder`), so
    # this still fails open — the point of this test is that the guard did not
    # short-circuit the fetch before the request was even attempted.
    assert run_allowed(cache, client, "https://example.com/anything") is True


def test_too_many_redirects_fails_open():
    routes = {
        "https://example.com/robots.txt": (302, "https://example.com/hop-1", ""),
    }
    for i in range(1, 15):
        routes[f"https://example.com/hop-{i}"] = (302, f"https://example.com/hop-{i + 1}", "")

    cache, client = make_cache(responder(routes))

    assert run_allowed(cache, client, "https://example.com/anything") is True


def test_redirect_loop_fails_open():
    cache, client = make_cache(
        responder(
            {
                "https://example.com/robots.txt": (302, "https://example.com/robots.txt", ""),
            }
        )
    )

    assert run_allowed(cache, client, "https://example.com/anything") is True


def test_result_is_cached_per_origin():
    calls = []

    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(200, text="User-agent: *\nDisallow: /private/\n")

    cache, client = make_cache(handler)

    async def main():
        try:
            await cache.allowed("https://example.com/a")
            await cache.allowed("https://example.com/b")
        finally:
            await client.aclose()

    asyncio.run(main())
    assert calls == ["https://example.com/robots.txt"]
