"""robots.txt fetch: caching, fail-open behaviour, and the redirect SSRF guard."""

import asyncio

import httpx

from secman_visual_check.robots import RobotsCache


def make_cache(handler, **overrides) -> RobotsCache:
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), follow_redirects=False
    )
    return RobotsCache(client=client, **overrides)


def responder(routes, default=(404, None, "")):
    """A handler answering from a ``{url: (status, location, body)}`` table."""

    def handler(request):
        status, location, body = routes.get(str(request.url), default)
        headers = {"Location": location} if location else {}
        return httpx.Response(status, headers=headers, text=body)

    return handler


def run(coro):
    return asyncio.run(coro)


def test_allows_everything_when_no_robots_txt_present():
    cache = make_cache(responder({}))
    assert run(cache.allowed("https://example.com/anything"))


def test_disallow_rule_is_honoured():
    routes = {
        "https://example.com/robots.txt": (
            200,
            None,
            "User-agent: *\nDisallow: /private\n",
        ),
    }
    cache = make_cache(responder(routes))
    assert not run(cache.allowed("https://example.com/private/page"))
    assert run(cache.allowed("https://example.com/public/page"))


def test_result_is_cached_per_origin():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return httpx.Response(200, text="User-agent: *\nDisallow: /x\n")

    cache = make_cache(handler)
    assert not run(cache.allowed("https://example.com/x"))
    assert not run(cache.allowed("https://example.com/x/y"))
    assert calls["n"] == 1


def test_same_host_redirect_is_followed():
    routes = {
        "https://example.com/robots.txt": (301, "https://example.com/real-robots.txt", ""),
        "https://example.com/real-robots.txt": (
            200,
            None,
            "User-agent: *\nDisallow: /blocked\n",
        ),
    }
    cache = make_cache(responder(routes))
    assert not run(cache.allowed("https://example.com/blocked"))


def test_redirect_to_private_address_is_blocked_not_followed():
    """A compromised/malicious target's robots.txt redirects to cloud metadata.

    Without the guard the client would fetch 169.254.169.254; here the
    redirect must simply not be taken, and the origin fails open (treated as
    allowing everything) exactly like an unreachable robots.txt would.
    """
    seen = []

    def handler(request):
        seen.append(str(request.url))
        if str(request.url) == "https://example.com/robots.txt":
            return httpx.Response(
                302, headers={"Location": "http://169.254.169.254/latest/meta-data/"}
            )
        # Should never be reached.
        return httpx.Response(200, text="User-agent: *\nDisallow: /\n")

    cache = make_cache(handler)
    assert run(cache.allowed("https://example.com/anything"))
    assert seen == ["https://example.com/robots.txt"]


def test_redirect_to_loopback_is_blocked():
    def handler(request):
        if str(request.url) == "https://example.com/robots.txt":
            return httpx.Response(302, headers={"Location": "http://127.0.0.1:8080/admin"})
        return httpx.Response(200, text="User-agent: *\nDisallow: /\n")

    cache = make_cache(handler)
    assert run(cache.allowed("https://example.com/anything"))


def test_redirect_guard_can_be_disabled():
    """--allow-private-redirects threads through to the robots.txt fetch too."""
    routes = {
        "https://example.com/robots.txt": (
            302,
            "http://169.254.169.254/robots.txt",
            "",
        ),
        "http://169.254.169.254/robots.txt": (
            200,
            None,
            "User-agent: *\nDisallow: /\n",
        ),
    }
    cache = make_cache(responder(routes), block_private_redirects=False)
    assert not run(cache.allowed("https://example.com/anything"))


class _FakeNetworkStream:
    """Stands in for httpx's ``network_stream`` extension: the real transport
    exposes the actual connected peer address through ``get_extra_info``."""

    def __init__(self, remote_ip: str) -> None:
        self._remote_ip = remote_ip

    def get_extra_info(self, info: str):
        if info == "server_addr":
            return (self._remote_ip, 443)
        return None


def test_a_dns_rebound_redirect_target_is_blocked_after_connecting(monkeypatch):
    # The pre-connect guard's own DNS lookup for attacker.example saw a
    # public address and let this redirect through; the real connection
    # (mocked here via the network_stream extension) landed on cloud
    # metadata instead — the DNS-rebinding TOCTOU the pre-connect check
    # alone cannot close (the same gap status.py and capture.py already
    # close for their own fetches).
    async def _resolves_to_blocked_ip(host):
        return False

    monkeypatch.setattr(
        "secman_visual_check.ssrf_guard._resolves_to_blocked_ip", _resolves_to_blocked_ip
    )

    def handler(request):
        if str(request.url) == "https://example.com/robots.txt":
            return httpx.Response(302, headers={"Location": "https://attacker.example/robots.txt"})
        return httpx.Response(
            200,
            text="User-agent: *\nDisallow: /\n",
            extensions={"network_stream": _FakeNetworkStream("169.254.169.254")},
        )

    cache = make_cache(handler)
    assert run(cache.allowed("https://example.com/anything"))


def test_a_response_from_its_own_public_address_is_not_blocked():
    def handler(request):
        return httpx.Response(
            200,
            text="User-agent: *\nDisallow: /blocked\n",
            extensions={"network_stream": _FakeNetworkStream("93.184.216.34")},
        )

    cache = make_cache(handler)
    assert not run(cache.allowed("https://example.com/blocked"))


def test_the_operators_own_target_is_never_blocked_by_the_post_connect_check():
    # Same-host exemption: the operator's own target host is never blocked
    # by this check, whatever address it actually resolves to.
    def handler(request):
        return httpx.Response(
            200,
            text="User-agent: *\nDisallow: /blocked\n",
            extensions={"network_stream": _FakeNetworkStream("127.0.0.1")},
        )

    cache = make_cache(handler)
    assert not run(cache.allowed("https://example.com/blocked"))


def test_redirect_loop_stops_and_fails_open():
    routes = {
        "https://example.com/robots.txt": (302, "https://example.com/a", ""),
        "https://example.com/a": (302, "https://example.com/robots.txt", ""),
    }
    cache = make_cache(responder(routes))
    assert run(cache.allowed("https://example.com/anything"))


def test_too_many_redirects_fails_open():
    def handler(request):
        url = str(request.url)
        if url.endswith("/robots.txt"):
            return httpx.Response(302, headers={"Location": "https://example.com/r/0"})
        n = int(url.rsplit("/", 1)[-1])
        return httpx.Response(302, headers={"Location": f"https://example.com/r/{n + 1}"})

    cache = make_cache(handler)
    assert run(cache.allowed("https://example.com/anything"))
