"""Headless-browser capture: navigate to a URL and take a screenshot."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from .models import PageCapture
from .ssrf_guard import is_unsafe_redirect, same_host

_SLUG_RE = re.compile(r"[^a-zA-Z0-9._-]+")


def _make_secure_route_handler(
    original_url: str,
    extra_headers: dict[str, str] | None,
    basic_auth: tuple[str, str] | None,
    block_private_redirects: bool,
):
    """Build a Playwright route handler that:

    1. Aborts document navigations (main frame or iframe — a redirect or an
       embedded frame) that land on a private/internal address on a
       different host than ``original_url`` (SSRF guard, see ssrf_guard.py).
    2. Attaches ``extra_headers``/``basic_auth`` only to requests that stay
       on ``original_url``'s host — never to a redirect target, an embedded
       cross-origin iframe, or a third-party subresource (ads, trackers,
       CDNs), which would otherwise silently receive credentials meant for
       one origin.
    """

    async def handler(route):
        request = route.request
        if (
            block_private_redirects
            and request.resource_type == "document"
            and await is_unsafe_redirect(original_url, request.url)
        ):
            await route.abort()
            return

        if (extra_headers or basic_auth) and same_host(original_url, request.url):
            headers = dict(await request.all_headers())
            if extra_headers:
                headers.update(extra_headers)
            if basic_auth:
                username, password = basic_auth
                token = base64.b64encode(f"{username}:{password}".encode()).decode()
                headers["authorization"] = f"Basic {token}"
            await route.continue_(headers=headers)
            return

        await route.continue_()

    return handler


@dataclass
class CaptureOptions:
    viewport_width: int = 1440
    viewport_height: int = 900
    full_page: bool = True
    max_capture_height: int = 4000
    timeout_ms: int = 30_000
    wait_until: str = "load"
    settle_ms: int = 1500
    user_agent: str | None = None
    ignore_https_errors: bool = False
    extra_headers: dict[str, str] = field(default_factory=dict)
    basic_auth: tuple[str, str] | None = None
    storage_state: str | None = None
    text_excerpt_chars: int = 4000
    device_scale_factor: float = 1.0
    browser_channel: str | None = None
    executable_path: str | None = None
    #: A compromised or malicious target can redirect (or embed an iframe
    #: pointing) at 169.254.169.254, 127.0.0.1, or other internal addresses;
    #: on by default, blocks navigation to such a host unless it matches the
    #: host originally requested. See ssrf_guard.py.
    block_private_redirects: bool = True


def screenshot_filename(url: str, index: int) -> str:
    """A stable, filesystem-safe name that still hints at the origin URL."""
    parsed = urlparse(url)
    host = _SLUG_RE.sub("-", parsed.hostname or "unknown").strip("-") or "unknown"
    path = _SLUG_RE.sub("-", parsed.path or "").strip("-")
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:10]
    stem = f"{index:04d}-{host}"
    if path:
        stem = f"{stem}-{path[:40]}"
    return f"{stem}-{digest}.png"


class BrowserCapturer:
    """Async context manager wrapping a single Chromium instance.

    All pages share one browser context, so cookies and storage state set via
    ``--storage-state`` apply to every target.
    """

    def __init__(self, options: CaptureOptions, output_dir: Path) -> None:
        self.options = options
        self.output_dir = Path(output_dir)
        self._playwright = None
        self._browser = None
        self._context = None
        self._counter = 0
        # Chromium corrupts full-page screenshots when several pages in the same
        # browser capture at once (content from one tab bleeds into another's
        # image), so the screenshot step is serialised even though navigation
        # stays parallel.
        self._screenshot_lock: asyncio.Lock | None = None

    async def __aenter__(self) -> "BrowserCapturer":
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:  # pragma: no cover - dependency guard
            raise RuntimeError(
                "playwright is not installed. Run: pip install -r requirements.txt "
                "&& playwright install chromium"
            ) from exc

        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._playwright = await async_playwright().start()

        launch_kwargs: dict[str, object] = {
            "headless": True,
            "args": ["--no-sandbox", "--disable-dev-shm-usage"],
        }
        if self.options.browser_channel:
            launch_kwargs["channel"] = self.options.browser_channel
        executable = self.options.executable_path or os.environ.get(
            "SECMAN_BROWSER_EXECUTABLE"
        )
        if executable:
            launch_kwargs["executable_path"] = executable

        try:
            self._browser = await self._playwright.chromium.launch(**launch_kwargs)
        except Exception as exc:
            await self._playwright.stop()
            self._playwright = None
            if "Executable doesn't exist" in str(exc):
                raise RuntimeError(
                    "Chromium is not installed for this Playwright version. Run "
                    "`playwright install chromium`, or point at an existing binary "
                    "with --browser-executable / $SECMAN_BROWSER_EXECUTABLE."
                ) from exc
            raise RuntimeError(f"could not launch Chromium: {_short_error(exc)}") from exc

        context_kwargs: dict[str, object] = {
            "viewport": {
                "width": self.options.viewport_width,
                "height": self.options.viewport_height,
            },
            "ignore_https_errors": self.options.ignore_https_errors,
            "device_scale_factor": self.options.device_scale_factor,
        }
        if self.options.user_agent:
            context_kwargs["user_agent"] = self.options.user_agent
        # extra_headers/basic_auth are deliberately NOT set here: a
        # context-level default (extra_http_headers / http_credentials) is
        # attached to every request the shared browser context makes,
        # including cross-origin redirects, embedded iframes, and
        # third-party subresources (ads, trackers, CDNs) — not just the
        # target page. They are instead injected per-request by the route
        # handler installed in `capture()`, only for requests that stay on
        # the host the operator targeted for that specific capture.
        if self.options.storage_state:
            context_kwargs["storage_state"] = self.options.storage_state

        self._context = await self._browser.new_context(**context_kwargs)
        self._context.set_default_timeout(self.options.timeout_ms)
        self._screenshot_lock = asyncio.Lock()
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        for closer in (self._context, self._browser):
            if closer is not None:
                try:
                    await closer.close()
                except Exception:  # pragma: no cover - teardown best effort
                    pass
        if self._playwright is not None:
            try:
                await self._playwright.stop()
            except Exception:  # pragma: no cover - teardown best effort
                pass

    def _next_index(self) -> int:
        self._counter += 1
        return self._counter

    async def capture(self, url: str) -> PageCapture:
        """Navigate to ``url`` and screenshot it, degrading gracefully on errors."""
        if self._context is None:
            raise RuntimeError("BrowserCapturer must be used as an async context manager")

        from playwright.async_api import Error as PlaywrightError

        options = self.options
        started = time.monotonic()
        capture = PageCapture(
            url=url, viewport=(options.viewport_width, options.viewport_height)
        )
        index = self._next_index()
        page = await self._context.new_page()
        console_errors: list[str] = []
        page.on(
            "console",
            lambda msg: console_errors.append(f"{msg.type}: {msg.text}"[:300])
            if msg.type == "error"
            else None,
        )
        page.on("pageerror", lambda err: console_errors.append(f"pageerror: {err}"[:300]))

        if self.options.block_private_redirects or self.options.extra_headers or self.options.basic_auth:
            await page.route(
                "**/*",
                _make_secure_route_handler(
                    url,
                    self.options.extra_headers if self.options.extra_headers else None,
                    self.options.basic_auth,
                    self.options.block_private_redirects,
                ),
            )

        try:
            try:
                response = await page.goto(
                    url,
                    wait_until=options.wait_until,
                    timeout=options.timeout_ms,
                )
                if response is not None:
                    capture.status = response.status
            except PlaywrightError as exc:
                # Keep going: a timed-out page often still has renderable content.
                capture.load_error = _short_error(exc)

            if options.settle_ms > 0:
                await page.wait_for_timeout(options.settle_ms)

            capture.final_url = page.url
            capture.title = await _safe(page.title)
            capture.text_excerpt = _truncate(
                await _safe(lambda: page.inner_text("body")) or "",
                options.text_excerpt_chars,
            )
            capture.page_height = await _safe(
                lambda: page.evaluate(
                    "() => Math.max(document.documentElement.scrollHeight,"
                    " document.body ? document.body.scrollHeight : 0)"
                )
            )

            path = self.output_dir / screenshot_filename(url, index)
            await self._screenshot(page, path, capture.page_height)
            capture.screenshot_path = str(path)
        except PlaywrightError as exc:
            if capture.load_error is None:
                capture.load_error = _short_error(exc)
        except Exception as exc:  # pragma: no cover - unexpected driver failure
            if capture.load_error is None:
                capture.load_error = f"{type(exc).__name__}: {exc}"
        finally:
            capture.console_errors = console_errors[:10]
            capture.duration_s = time.monotonic() - started
            try:
                await page.close()
            except Exception:  # pragma: no cover - teardown best effort
                pass

        return capture

    async def _screenshot(self, page, path: Path, page_height: int | None) -> None:
        """Screenshot the page, clamping very tall pages to a sane height.

        Full-page screenshots of infinite-scroll pages can be tens of thousands of
        pixels tall, which wastes vision tokens and often gets rejected by the API.

        Held under a lock: concurrent captures in one browser produce images with
        content from the wrong tab spliced in.
        """
        options = self.options
        limit = options.max_capture_height
        lock = self._screenshot_lock or asyncio.Lock()
        async with lock:
            if not options.full_page:
                await page.screenshot(path=str(path))
                return
            if limit > 0 and page_height and page_height > limit:
                await page.screenshot(
                    path=str(path),
                    clip={
                        "x": 0,
                        "y": 0,
                        "width": options.viewport_width,
                        "height": limit,
                    },
                )
                return
            await page.screenshot(path=str(path), full_page=True)


async def _safe(fn):
    """Run a page accessor, returning None instead of raising."""
    try:
        return await fn()
    except Exception:
        return None


def _truncate(text: str, limit: int) -> str:
    collapsed = re.sub(r"\n{3,}", "\n\n", text).strip()
    return collapsed[:limit]


def _short_error(exc: BaseException) -> str:
    message = str(exc).strip().splitlines()
    first = message[0] if message else exc.__class__.__name__
    return first[:300]
