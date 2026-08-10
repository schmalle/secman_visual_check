"""robots.txt fetch: redirect handling must go through the SSRF guard, just
like status.py's manual walk and capture.py's route handlers — a robots.txt
host is exactly as capable of redirecting the scanner at an internal address
as any other target.
"""

from __future__ import annotations

import asyncio

import httpx

from secman_visual_check.robots import RobotsCache


class _FakeResponse:
    def __init__(self, status_code: int, *, location: str | None = None, text: str = ""):
        self.status_code = status_code
        self.headers = {"location": location} if location else {}
        self.text = text


class _FakeAsyncClient:
    """Records every GET and answers from a canned URL -> response map."""

    def __init__(self, handler, **kwargs):
        assert kwargs.get("follow_redirects") is False, (
            "robots.py must disable httpx's automatic redirect following so "
            "every hop can be checked against the SSRF guard"
        )
        self._handler = handler
        self.requested: list[str] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        return False

    async def get(self, url, **kwargs):
        self.requested.append(url)
        return self._handler(url)


def _install_fake_client(monkeypatch, handler):
    def factory(**kwargs):
        return _FakeAsyncClient(handler, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)


def test_plain_robots_txt_is_fetched(monkeypatch):
    def handler(url):
        assert url == "https://example.com/robots.txt"
        return _FakeResponse(200, text="User-agent: *\nDisallow: /admin")

    _install_fake_client(monkeypatch, handler)
    cache = RobotsCache()

    async def go():
        return await cache.allowed("https://example.com/admin/secret")

    assert asyncio.run(go()) is False


def test_redirect_to_public_host_is_followed(monkeypatch):
    calls = {"n": 0}

    def handler(url):
        calls["n"] += 1
        if url == "https://example.com/robots.txt":
            return _FakeResponse(301, location="https://other-public.example/robots.txt")
        assert url == "https://other-public.example/robots.txt"
        return _FakeResponse(200, text="User-agent: *\nDisallow: /blocked")

    _install_fake_client(monkeypatch, handler)
    cache = RobotsCache()

    async def go():
        return await cache.allowed("https://example.com/blocked")

    assert asyncio.run(go()) is False
    assert calls["n"] == 2


def test_redirect_to_metadata_ip_is_blocked_fail_open(monkeypatch):
    """A robots.txt on a compromised target redirecting at cloud metadata (or
    any other private/loopback/link-local address) must not be followed —
    the fetch fails open (treated as unreachable -> allow everything) rather
    than the scanner issuing a request to an internal address."""

    def handler(url):
        if url == "https://example.com/robots.txt":
            return _FakeResponse(
                302, location="http://169.254.169.254/latest/meta-data/"
            )
        raise AssertionError(f"must never request {url}")

    _install_fake_client(monkeypatch, handler)
    cache = RobotsCache()

    async def go():
        return await cache.allowed("https://example.com/anything")

    assert asyncio.run(go()) is True


def test_redirect_to_loopback_is_blocked(monkeypatch):
    def handler(url):
        if url == "https://example.com/robots.txt":
            return _FakeResponse(302, location="http://127.0.0.1:8080/admin")
        raise AssertionError(f"must never request {url}")

    _install_fake_client(monkeypatch, handler)
    cache = RobotsCache()

    async def go():
        return await cache.allowed("https://example.com/anything")

    assert asyncio.run(go()) is True


def test_same_host_redirect_to_private_address_is_allowed(monkeypatch):
    """Mirrors ssrf_guard's same-host exemption: staying on the operator's own
    target carries no extra privilege even if it resolves to a private IP."""

    def handler(url):
        if url == "https://example.com/robots.txt":
            return _FakeResponse(302, location="https://example.com/robots-real.txt")
        return _FakeResponse(200, text="User-agent: *\nDisallow: /x")

    _install_fake_client(monkeypatch, handler)
    cache = RobotsCache()

    async def go():
        return await cache.allowed("https://example.com/x")

    assert asyncio.run(go()) is False


def test_redirect_loop_gives_up_and_fails_open(monkeypatch):
    def handler(url):
        return _FakeResponse(302, location="https://example.com/robots.txt")

    _install_fake_client(monkeypatch, handler)
    cache = RobotsCache()

    async def go():
        return await cache.allowed("https://example.com/anything")

    assert asyncio.run(go()) is True
