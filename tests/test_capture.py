"""Capture-layer tests that do not need a real browser."""

import asyncio

import pytest

from secman_visual_check.capture import (
    BrowserCapturer,
    CaptureOptions,
    _make_secure_route_handler,
    screenshot_filename,
)


class FakePage:
    """Records screenshot calls and how many ran at the same time."""

    def __init__(self, tracker):
        self.tracker = tracker

    async def screenshot(self, **kwargs):
        self.tracker["active"] += 1
        self.tracker["peak"] = max(self.tracker["peak"], self.tracker["active"])
        self.tracker["calls"].append(kwargs)
        await asyncio.sleep(0.01)
        self.tracker["active"] -= 1


def make_capturer(tmp_path, **option_overrides) -> BrowserCapturer:
    return BrowserCapturer(CaptureOptions(**option_overrides), tmp_path)


def test_filenames_are_stable_and_filesystem_safe():
    name = screenshot_filename("https://example.com/a/b?q=1", 7)
    assert name == screenshot_filename("https://example.com/a/b?q=1", 7)
    assert name.startswith("0007-example.com")
    assert name.endswith(".png")
    assert "/" not in name and "?" not in name


def test_different_urls_get_different_filenames():
    a = screenshot_filename("https://example.com/one", 1)
    b = screenshot_filename("https://example.com/two", 1)
    assert a != b


def test_screenshots_are_serialised(tmp_path):
    """Concurrent full-page captures in one browser corrupt each other."""
    tracker = {"active": 0, "peak": 0, "calls": []}
    capturer = make_capturer(tmp_path)

    async def go():
        capturer._screenshot_lock = asyncio.Lock()
        pages = [FakePage(tracker) for _ in range(5)]
        await asyncio.gather(
            *(capturer._screenshot(p, tmp_path / f"{i}.png", 500) for i, p in enumerate(pages))
        )

    asyncio.run(go())
    assert tracker["peak"] == 1
    assert len(tracker["calls"]) == 5


def test_full_page_screenshot_by_default(tmp_path):
    tracker = {"active": 0, "peak": 0, "calls": []}
    capturer = make_capturer(tmp_path)

    async def go():
        capturer._screenshot_lock = asyncio.Lock()
        await capturer._screenshot(FakePage(tracker), tmp_path / "s.png", page_height=800)

    asyncio.run(go())
    assert tracker["calls"][0]["full_page"] is True
    assert "clip" not in tracker["calls"][0]


def test_tall_pages_are_clamped_with_a_clip(tmp_path):
    tracker = {"active": 0, "peak": 0, "calls": []}
    capturer = make_capturer(tmp_path, max_capture_height=1000, viewport_width=1200)

    async def go():
        capturer._screenshot_lock = asyncio.Lock()
        await capturer._screenshot(FakePage(tracker), tmp_path / "s.png", page_height=50_000)

    asyncio.run(go())
    call = tracker["calls"][0]
    assert call["clip"] == {"x": 0, "y": 0, "width": 1200, "height": 1000}
    assert "full_page" not in call


def test_clamp_can_be_disabled(tmp_path):
    tracker = {"active": 0, "peak": 0, "calls": []}
    capturer = make_capturer(tmp_path, max_capture_height=0)

    async def go():
        capturer._screenshot_lock = asyncio.Lock()
        await capturer._screenshot(FakePage(tracker), tmp_path / "s.png", page_height=50_000)

    asyncio.run(go())
    assert tracker["calls"][0]["full_page"] is True


def test_viewport_only_mode(tmp_path):
    tracker = {"active": 0, "peak": 0, "calls": []}
    capturer = make_capturer(tmp_path, full_page=False)

    async def go():
        capturer._screenshot_lock = asyncio.Lock()
        await capturer._screenshot(FakePage(tracker), tmp_path / "s.png", page_height=50_000)

    asyncio.run(go())
    call = tracker["calls"][0]
    assert "full_page" not in call and "clip" not in call


def test_capture_requires_the_context_manager(tmp_path):
    with pytest.raises(RuntimeError):
        asyncio.run(make_capturer(tmp_path).capture("https://example.com/"))


class FakeRequest:
    def __init__(self, url, resource_type="document", headers=None):
        self.url = url
        self.resource_type = resource_type
        self._headers = headers or {}

    async def all_headers(self):
        return dict(self._headers)


class FakeRoute:
    def __init__(self, request):
        self.request = request
        self.aborted = False
        self.continued_with = None

    async def abort(self):
        self.aborted = True

    async def continue_(self, **kwargs):
        self.continued_with = kwargs


def run(coro):
    return asyncio.run(coro)


def test_route_handler_aborts_cross_host_redirect_to_a_private_address():
    handler = _make_secure_route_handler(
        "https://example.com/", None, None, block_private_redirects=True
    )
    route = FakeRoute(FakeRequest("http://169.254.169.254/latest/meta-data/"))

    run(handler(route))

    assert route.aborted is True
    assert route.continued_with is None


def test_route_handler_allows_private_redirect_when_disabled():
    handler = _make_secure_route_handler(
        "https://example.com/", None, None, block_private_redirects=False
    )
    route = FakeRoute(FakeRequest("http://169.254.169.254/latest/meta-data/"))

    run(handler(route))

    assert route.aborted is False


def test_route_handler_injects_credentials_only_for_same_host_requests():
    handler = _make_secure_route_handler(
        "https://example.com/",
        {"X-Scan": "yes"},
        ("alice", "hunter2"),
        block_private_redirects=True,
    )
    route = FakeRoute(FakeRequest("https://example.com/next", headers={"accept": "*/*"}))

    run(handler(route))

    assert route.aborted is False
    assert route.continued_with is not None
    headers = route.continued_with["headers"]
    assert headers["X-Scan"] == "yes"
    assert headers["authorization"].startswith("Basic ")
    assert headers["accept"] == "*/*"  # existing headers preserved


def test_route_handler_never_sends_credentials_cross_host():
    handler = _make_secure_route_handler(
        "https://example.com/",
        {"X-Scan": "yes"},
        ("alice", "hunter2"),
        block_private_redirects=True,
    )
    # A public, non-private cross-host target (e.g. a third-party subresource
    # or a redirect target) — not blocked, but must never see credentials
    # meant for example.com.
    route = FakeRoute(FakeRequest("https://cdn.other-example.com/lib.js", resource_type="script"))

    run(handler(route))

    assert route.aborted is False
    assert route.continued_with == {}  # continue_() called with no header override
