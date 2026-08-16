"""Capture-layer tests that do not need a real browser."""

import asyncio

import pytest

from secman_visual_check.capture import (
    BrowserCapturer,
    CaptureOptions,
    _check_response_address,
    _make_context_guard_handler,
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


# --------------------------------------------------------------------------- #
# Finding 2 — the guard must not be limited to document/navigation requests.
# A page's own JS can blind-SSRF an internal host via fetch()/XHR/etc, and if
# the response is reflected into the DOM it flows into text_excerpt, the
# screenshot and the AI analysis — an exfiltration path, not just an
# availability one.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("resource_type", ["fetch", "xhr", "script", "image", "beacon"])
def test_route_handler_aborts_non_document_requests_to_a_private_address(resource_type):
    handler = _make_secure_route_handler(
        "https://example.com/", None, None, block_private_redirects=True
    )
    route = FakeRoute(
        FakeRequest("http://169.254.169.254/latest/meta-data/", resource_type=resource_type)
    )

    run(handler(route))

    assert route.aborted is True
    assert route.continued_with is None


def test_route_handler_allows_non_document_requests_when_disabled():
    handler = _make_secure_route_handler(
        "https://example.com/", None, None, block_private_redirects=False
    )
    route = FakeRoute(
        FakeRequest("http://169.254.169.254/latest/meta-data/", resource_type="fetch")
    )

    run(handler(route))

    assert route.aborted is False


# --------------------------------------------------------------------------- #
# Finding 1 — a popup/new-tab page (window.open(), target="_blank") is a new
# Page in the same shared BrowserContext, and Playwright does not apply a
# page-level route registered on a *different* page to it. The context-level
# guard installed once in __aenter__ is what covers it.
# --------------------------------------------------------------------------- #


def test_context_guard_aborts_a_document_request_to_a_private_address():
    handler = _make_context_guard_handler(block_private_redirects=True)
    route = FakeRoute(FakeRequest("http://169.254.169.254/latest/meta-data/"))

    run(handler(route))

    assert route.aborted is True
    assert route.continued_with is None


@pytest.mark.parametrize("resource_type", ["document", "fetch", "xhr", "script"])
def test_context_guard_aborts_every_resource_type_to_a_private_address(resource_type):
    """A popup can navigate itself (document) or issue subresources — both
    must be blocked, exactly like the per-page guard."""
    handler = _make_context_guard_handler(block_private_redirects=True)
    route = FakeRoute(FakeRequest("http://127.0.0.1:8080/admin", resource_type=resource_type))

    run(handler(route))

    assert route.aborted is True


def test_context_guard_allows_a_public_destination():
    handler = _make_context_guard_handler(block_private_redirects=True)
    route = FakeRoute(FakeRequest("https://other-public-site.example/"))

    run(handler(route))

    assert route.aborted is False
    assert route.continued_with == {}


def test_context_guard_never_attaches_credentials():
    """Unlike the per-page handler, the context guard has no 'operator's
    target' to scope same-host credentials to, so it must never attach any —
    a popup was not a URL the operator ever typed."""
    handler = _make_context_guard_handler(block_private_redirects=True)
    route = FakeRoute(FakeRequest("https://example.com/", headers={"accept": "*/*"}))

    run(handler(route))

    assert route.continued_with == {}
    assert "authorization" not in (route.continued_with or {})


def test_context_guard_respects_the_disable_flag():
    handler = _make_context_guard_handler(block_private_redirects=False)
    route = FakeRoute(FakeRequest("http://169.254.169.254/latest/meta-data/"))

    run(handler(route))

    assert route.aborted is False


# --------------------------------------------------------------------------- #
# Wiring: BrowserCapturer.__aenter__ must install the context-level guard —
# this is what actually covers a popup Chromium creates outside of any single
# capture() call. Faked in the same spirit as FakePage/FakeRoute above: no
# real browser, just enough of the Playwright surface to prove the guard is
# registered and that it does what the unit tests above expect.
# --------------------------------------------------------------------------- #


class FakePWContext:
    def __init__(self):
        self.routes: list[tuple[str, object]] = []

    def set_default_timeout(self, _timeout):
        pass

    async def route(self, pattern, handler):
        self.routes.append((pattern, handler))

    async def new_page(self):
        return FakePage({"active": 0, "peak": 0, "calls": []})

    async def close(self):
        pass


class FakePWBrowser:
    def __init__(self, context):
        self._context = context

    async def new_context(self, **kwargs):
        return self._context

    async def close(self):
        pass


class FakePWChromium:
    def __init__(self, browser):
        self._browser = browser

    async def launch(self, **kwargs):
        return self._browser


class FakePlaywright:
    def __init__(self, browser):
        self.chromium = FakePWChromium(browser)

    async def stop(self):
        pass


class FakePlaywrightContextManager:
    def __init__(self, playwright):
        self._playwright = playwright

    async def start(self):
        return self._playwright


def test_aenter_registers_the_context_level_guard(tmp_path, monkeypatch):
    fake_context = FakePWContext()
    fake_playwright = FakePlaywright(FakePWBrowser(fake_context))

    import secman_visual_check.capture as capture_module
    import playwright.async_api as playwright_async_api

    monkeypatch.setattr(
        playwright_async_api,
        "async_playwright",
        lambda: FakePlaywrightContextManager(fake_playwright),
    )

    capturer = capture_module.BrowserCapturer(CaptureOptions(), tmp_path)

    async def go():
        async with capturer:
            pass

    run(go())

    assert len(fake_context.routes) == 1
    pattern, handler = fake_context.routes[0]
    assert pattern == "**/*"

    # And the registered handler is the real guard, not a stub: it still
    # blocks a private destination.
    route = FakeRoute(FakeRequest("http://169.254.169.254/latest/meta-data/"))
    run(handler(route))
    assert route.aborted is True


def test_aenter_skips_the_context_guard_when_disabled(tmp_path, monkeypatch):
    fake_context = FakePWContext()
    fake_playwright = FakePlaywright(FakePWBrowser(fake_context))

    import secman_visual_check.capture as capture_module
    import playwright.async_api as playwright_async_api

    monkeypatch.setattr(
        playwright_async_api,
        "async_playwright",
        lambda: FakePlaywrightContextManager(fake_playwright),
    )

    capturer = capture_module.BrowserCapturer(
        CaptureOptions(block_private_redirects=False), tmp_path
    )

    async def go():
        async with capturer:
            pass

    run(go())

    assert fake_context.routes == []


# --------------------------------------------------------------------------- #
# _check_response_address — the post-connect DNS-rebinding check. Chromium
# resolves and connects on its own once route.continue_() lets a request
# through, so a rebinding nameserver can still answer differently than it
# answered the pre-connect guards above; this is what catches that after the
# fact (see PageCapture.blocked_ssrf / worth_analyzing).
# --------------------------------------------------------------------------- #


class FakeResponse:
    def __init__(self, url, status=200, server_addr=None, raise_on_server_addr=False):
        self.url = url
        self.status = status
        self._server_addr = server_addr
        self._raise = raise_on_server_addr

    async def server_addr(self):
        if self._raise:
            raise RuntimeError("connection already closed")
        return self._server_addr


def test_response_address_check_flags_a_cross_host_private_connection():
    response = FakeResponse(
        "https://third-party.example/beacon", server_addr={"ipAddress": "127.0.0.1", "port": 80}
    )

    blocked_host = run(_check_response_address(response, "https://example.com/"))

    assert blocked_host == "third-party.example"


def test_response_address_check_allows_a_cross_host_public_connection():
    response = FakeResponse(
        "https://third-party.example/beacon", server_addr={"ipAddress": "93.184.216.34", "port": 443}
    )

    assert run(_check_response_address(response, "https://example.com/")) is None


def test_response_address_check_has_no_same_host_exemption_bypass_but_skips_same_host():
    # Same host as the operator's own target is never flagged, no matter what
    # address it connected to — matches every other guard's same-host rule.
    response = FakeResponse("https://example.com/", server_addr={"ipAddress": "127.0.0.1", "port": 443})

    assert run(_check_response_address(response, "https://example.com/")) is None


def test_response_address_check_tolerates_a_missing_server_addr():
    # E.g. a response served from cache — Playwright returns None.
    response = FakeResponse("https://third-party.example/beacon", server_addr=None)

    assert run(_check_response_address(response, "https://example.com/")) is None


def test_response_address_check_fails_open_on_a_lookup_error():
    response = FakeResponse("https://third-party.example/beacon", raise_on_server_addr=True)

    assert run(_check_response_address(response, "https://example.com/")) is None


# --------------------------------------------------------------------------- #
# Wiring: BrowserCapturer.capture() must collect the post-connect checks and
# flag the capture, excluding it from AI analysis, without a real browser.
# --------------------------------------------------------------------------- #


class FakeCapturePage:
    """Just enough of Playwright's Page for BrowserCapturer.capture()."""

    def __init__(self, goto_response, other_responses=()):
        self._handlers: dict[str, list] = {}
        self._goto_response = goto_response
        self._other_responses = other_responses
        self.url = goto_response.url

    def on(self, event, handler):
        self._handlers.setdefault(event, []).append(handler)

    async def route(self, pattern, handler):
        pass

    async def goto(self, url, wait_until=None, timeout=None):
        for handler in self._handlers.get("response", []):
            handler(self._goto_response)
        for response in self._other_responses:
            for handler in self._handlers.get("response", []):
                handler(response)
        return self._goto_response

    async def wait_for_timeout(self, ms):
        return None

    async def title(self):
        return "A title"

    async def inner_text(self, selector):
        return "body text"

    async def evaluate(self, script):
        return 100

    async def screenshot(self, **kwargs):
        return None

    async def close(self):
        return None


class FakeCaptureContext:
    def __init__(self, page):
        self._page = page

    async def new_page(self):
        return self._page


def _make_capturer_with_page(tmp_path, page, **option_overrides) -> BrowserCapturer:
    capturer = BrowserCapturer(CaptureOptions(**option_overrides), tmp_path)
    capturer._context = FakeCaptureContext(page)
    capturer._screenshot_lock = asyncio.Lock()
    return capturer


def test_capture_flags_blocked_ssrf_from_a_subresource_and_excludes_it_from_analysis(tmp_path):
    main = FakeResponse("https://example.com/", server_addr={"ipAddress": "93.184.216.34", "port": 443})
    beacon = FakeResponse(
        "https://third-party.example/beacon", server_addr={"ipAddress": "169.254.169.254", "port": 80}
    )
    page = FakeCapturePage(goto_response=main, other_responses=[beacon])
    capturer = _make_capturer_with_page(tmp_path, page)

    capture = run(capturer.capture("https://example.com/"))

    assert capture.blocked_ssrf is True
    assert capture.worth_analyzing is False
    assert "third-party.example" in (capture.load_error or "")


def test_capture_leaves_blocked_ssrf_false_when_every_response_is_safe(tmp_path):
    main = FakeResponse("https://example.com/", server_addr={"ipAddress": "93.184.216.34", "port": 443})
    page = FakeCapturePage(goto_response=main)
    capturer = _make_capturer_with_page(tmp_path, page)

    capture = run(capturer.capture("https://example.com/"))

    assert capture.blocked_ssrf is False
    assert capture.worth_analyzing is True
    assert capture.load_error is None


def test_capture_does_not_check_response_addresses_when_disabled(tmp_path):
    main = FakeResponse("https://example.com/", server_addr={"ipAddress": "93.184.216.34", "port": 443})
    beacon = FakeResponse(
        "https://third-party.example/beacon", server_addr={"ipAddress": "127.0.0.1", "port": 80}
    )
    page = FakeCapturePage(goto_response=main, other_responses=[beacon])
    capturer = _make_capturer_with_page(tmp_path, page, block_private_redirects=False)

    capture = run(capturer.capture("https://example.com/"))

    assert capture.blocked_ssrf is False
