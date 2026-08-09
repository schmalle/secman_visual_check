"""robots.txt fetching must go through the same SSRF guard as every other
outbound fetch in this tool (status.py, capture.py) - a target's robots.txt
response is just as attacker-controlled as its page content."""

import asyncio

import httpx

from secman_visual_check.robots import RobotsCache


def run(coro):
    return asyncio.run(coro)


def _patch_async_client(monkeypatch, handler):
    """Make robots.py's internal `httpx.AsyncClient(...)` route through a
    MockTransport, mirroring the injection style status.py's own tests use."""

    class _MockedClient(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _MockedClient)


def responder(routes, default=404):
    """A handler answering from a ``{url: (status, location, body)}`` table."""

    def handler(request):
        status, location, body = routes.get(str(request.url), (default, None, ""))
        headers = {"Location": location} if location else {}
        return httpx.Response(status, headers=headers, text=body)

    return handler


def test_fetches_and_parses_robots_txt_directly(monkeypatch):
    _patch_async_client(
        monkeypatch,
        responder({"https://example.com/robots.txt": (200, None, "User-agent: *\nDisallow: /admin\n")}),
    )
    cache = RobotsCache()
    assert run(cache.allowed("https://example.com/")) is True
    assert run(cache.allowed("https://example.com/admin")) is False


def test_follows_a_same_host_redirect(monkeypatch):
    _patch_async_client(
        monkeypatch,
        responder(
            {
                "https://example.com/robots.txt": (301, "https://example.com/robots-real.txt", ""),
                "https://example.com/robots-real.txt": (200, None, "User-agent: *\nDisallow: /secret\n"),
            }
        ),
    )
    cache = RobotsCache()
    assert run(cache.allowed("https://example.com/secret")) is False
    assert run(cache.allowed("https://example.com/public")) is True


def test_blocks_a_cross_host_redirect_to_a_private_address(monkeypatch):
    """Regression test: previously follow_redirects=True with no SSRF check
    meant a compromised target could 3xx robots.txt straight at
    169.254.169.254 (or any internal host) and this client would follow it."""
    _patch_async_client(
        monkeypatch,
        responder(
            {
                "https://example.com/robots.txt": (302, "http://169.254.169.254/latest/meta-data/", ""),
            }
        ),
    )
    cache = RobotsCache()
    # Fail-open on a blocked/unfetchable robots.txt: treated as allow-all,
    # same contract as a network error or a 4xx/5xx.
    assert run(cache.allowed("https://example.com/anything")) is True


def test_blocks_a_redirect_loop(monkeypatch):
    _patch_async_client(
        monkeypatch,
        responder(
            {
                "https://example.com/robots.txt": (302, "https://example.com/robots.txt", ""),
            }
        ),
    )
    cache = RobotsCache()
    assert run(cache.allowed("https://example.com/anything")) is True


def test_blocks_a_non_http_redirect_scheme(monkeypatch):
    _patch_async_client(
        monkeypatch,
        responder(
            {
                "https://example.com/robots.txt": (302, "file:///etc/passwd", ""),
            }
        ),
    )
    cache = RobotsCache()
    assert run(cache.allowed("https://example.com/anything")) is True


def test_too_many_redirects_fails_open(monkeypatch):
    routes = {
        f"https://example.com/hop{i}": (302, f"https://example.com/hop{i + 1}", "")
        for i in range(10)
    }
    routes["https://example.com/robots.txt"] = (302, "https://example.com/hop0", "")
    _patch_async_client(monkeypatch, responder(routes))
    cache = RobotsCache()
    assert run(cache.allowed("https://example.com/anything")) is True
