"""robots.txt fetching: fail-open behaviour and the SSRF guard on its redirects."""

import asyncio

import httpx

from secman_visual_check.robots import RobotsCache


def _patched_client(monkeypatch, handler):
    """Route every httpx.AsyncClient built inside robots.py through a mock transport."""
    orig_init = httpx.AsyncClient.__init__

    def patched_init(self, *args, **kwargs):
        kwargs.pop("timeout", None)
        kwargs["transport"] = httpx.MockTransport(handler)
        orig_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)


def test_plain_robots_txt_is_parsed(monkeypatch):
    def handler(request):
        assert str(request.url) == "https://monitored.example/robots.txt"
        return httpx.Response(200, text="User-agent: *\nDisallow: /secret\n")

    _patched_client(monkeypatch, handler)
    cache = RobotsCache()
    parser = asyncio.run(cache._fetch("https://monitored.example/robots.txt"))

    assert parser is not None
    assert parser.can_fetch("*", "https://monitored.example/public")
    assert not parser.can_fetch("*", "https://monitored.example/secret")


def test_cross_host_redirect_to_private_ip_is_blocked(monkeypatch):
    def handler(request):
        if str(request.url) == "https://monitored.example/robots.txt":
            return httpx.Response(
                302, headers={"Location": "http://169.254.169.254/latest/meta-data/"}
            )
        return httpx.Response(200, text="User-agent: *\nDisallow: /\n")

    _patched_client(monkeypatch, handler)
    cache = RobotsCache()
    parser = asyncio.run(cache._fetch("https://monitored.example/robots.txt"))

    # Blocked: fail-open means "treat as allowing everything", not "raise".
    assert parser is None


def test_cross_host_redirect_to_loopback_is_blocked(monkeypatch):
    def handler(request):
        if str(request.url) == "https://monitored.example/robots.txt":
            return httpx.Response(302, headers={"Location": "http://127.0.0.1:8080/admin"})
        return httpx.Response(200, text="User-agent: *\nDisallow: /\n")

    _patched_client(monkeypatch, handler)
    cache = RobotsCache()
    parser = asyncio.run(cache._fetch("https://monitored.example/robots.txt"))

    assert parser is None


def test_same_host_redirect_to_new_path_is_followed(monkeypatch):
    def handler(request):
        if str(request.url) == "https://monitored.example/robots.txt":
            return httpx.Response(
                301, headers={"Location": "https://monitored.example/canonical-robots.txt"}
            )
        return httpx.Response(200, text="User-agent: *\nDisallow: /admin\n")

    _patched_client(monkeypatch, handler)
    cache = RobotsCache()
    parser = asyncio.run(cache._fetch("https://monitored.example/robots.txt"))

    assert parser is not None
    assert not parser.can_fetch("*", "https://monitored.example/admin")


def test_redirect_loop_fails_open(monkeypatch):
    def handler(request):
        url = str(request.url)
        other = (
            "https://monitored.example/b"
            if url == "https://monitored.example/robots.txt"
            else "https://monitored.example/robots.txt"
        )
        return httpx.Response(301, headers={"Location": other})

    _patched_client(monkeypatch, handler)
    cache = RobotsCache()
    parser = asyncio.run(cache._fetch("https://monitored.example/robots.txt"))

    assert parser is None


def test_server_error_fails_open(monkeypatch):
    def handler(request):
        return httpx.Response(500)

    _patched_client(monkeypatch, handler)
    cache = RobotsCache()
    parser = asyncio.run(cache._fetch("https://monitored.example/robots.txt"))

    assert parser is None
