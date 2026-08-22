"""robots.txt fetching: cache-per-origin, fail-open, and the SSRF guard on redirects."""

import asyncio

import httpx

from secman_visual_check.robots import RobotsCache


def make_cache(handler, **kwargs) -> RobotsCache:
    return RobotsCache(transport=httpx.MockTransport(handler), **kwargs)


def responder(routes, default=404):
    """A handler answering from a ``{url: (status, location, body)}`` table."""

    def handler(request):
        status, location, body = routes.get(str(request.url), (default, None, ""))
        headers = {"Location": location} if location else {}
        return httpx.Response(status, headers=headers, text=body)

    return handler


def test_plain_robots_txt_is_parsed_and_enforced():
    cache = make_cache(
        responder(
            {
                "https://example.com/robots.txt": (
                    200,
                    None,
                    "User-agent: *\nDisallow: /admin\n",
                )
            }
        )
    )
    assert asyncio.run(cache.allowed("https://example.com/public")) is True
    assert asyncio.run(cache.allowed("https://example.com/admin")) is False


def test_unreachable_robots_txt_fails_open():
    cache = make_cache(lambda request: (_ for _ in ()).throw(httpx.ConnectError("down")))
    assert asyncio.run(cache.allowed("https://example.com/anything")) is True


def test_404_robots_txt_fails_open():
    cache = make_cache(responder({}, default=404))
    assert asyncio.run(cache.allowed("https://example.com/anything")) is True


def test_same_host_redirect_is_followed():
    cache = make_cache(
        responder(
            {
                "https://example.com/robots.txt": (
                    302,
                    "https://example.com/robots-real.txt",
                    "",
                ),
                "https://example.com/robots-real.txt": (
                    200,
                    None,
                    "User-agent: *\nDisallow: /secret\n",
                ),
            }
        )
    )
    assert asyncio.run(cache.allowed("https://example.com/secret")) is False


def test_redirect_to_private_address_is_blocked_not_followed():
    """A compromised/malicious target's robots.txt must not be able to make the
    scanner issue a request to an internal address — the same SSRF class
    ssrf_guard closes for status.py and capture.py. Regression test for a gap
    where RobotsCache used ``follow_redirects=True`` with no such check."""
    seen: list[str] = []

    def handler(request):
        seen.append(str(request.url))
        if str(request.url) == "https://example.com/robots.txt":
            return httpx.Response(302, headers={"Location": "http://169.254.169.254/robots.txt"})
        # Should never be reached: the redirect above must be blocked first.
        return httpx.Response(200, text="User-agent: *\nDisallow: /\n")

    cache = make_cache(handler)
    # Fails open (no parser), so nothing is disallowed — but the point is the
    # internal host must never have been requested.
    assert asyncio.run(cache.allowed("https://example.com/anything")) is True
    assert seen == ["https://example.com/robots.txt"]


def test_redirect_to_loopback_is_blocked():
    seen: list[str] = []

    def handler(request):
        seen.append(str(request.url))
        if str(request.url) == "https://example.com/robots.txt":
            return httpx.Response(301, headers={"Location": "http://127.0.0.1:8080/admin"})
        return httpx.Response(200, text="User-agent: *\nDisallow: /\n")

    cache = make_cache(handler)
    assert asyncio.run(cache.allowed("https://example.com/anything")) is True
    assert seen == ["https://example.com/robots.txt"]


def test_redirect_loop_is_bounded_not_infinite():
    def handler(request):
        return httpx.Response(302, headers={"Location": str(request.url)})

    cache = make_cache(handler)
    assert asyncio.run(cache.allowed("https://example.com/anything")) is True


def test_cache_is_per_origin_and_only_fetched_once():
    calls: list[str] = []

    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(200, text="User-agent: *\nDisallow: /blocked\n")

    cache = make_cache(handler)
    asyncio.run(cache.allowed("https://example.com/a"))
    asyncio.run(cache.allowed("https://example.com/b"))
    assert calls == ["https://example.com/robots.txt"]
