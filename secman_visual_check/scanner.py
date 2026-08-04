"""Orchestration: capture every target, then analyse each capture."""

from __future__ import annotations

import asyncio
import contextlib
from typing import Callable, Sequence

from .analyzer import VisionAnalyzer
from .capture import BrowserCapturer
from .config import ScanConfig
from .models import ScanReport, ScanResult, utcnow
from .robots import RobotsCache
from .status import UrlStatusChecker

ProgressHook = Callable[[ScanResult, int, int], None]


async def run_scan(
    targets: Sequence[str],
    config: ScanConfig,
    progress: ProgressHook | None = None,
    tool_version: str = "",
    secrets: Sequence[str] = (),
) -> ScanReport:
    """Capture and analyse every target, with independent concurrency limits.

    Capture and analysis are pipelined per target: one page can be analysed while
    another is still loading, so the AI round-trip does not stall the browser.

    ``secrets`` (``resolver.values``) is forwarded to the analyzer so a resolved
    credential a target reflects back is scrubbed out of the prompt before it
    ever reaches the third-party AI provider — see
    :meth:`~secman_visual_check.analyzer.VisionAnalyzer.analyze`.
    """
    report = ScanReport(
        started_at=utcnow(),
        model=config.analyzer.model if config.analyzer else "",
        tool_version=tool_version,
    )
    if not targets:
        report.finished_at = utcnow()
        return report

    capture_sem = asyncio.Semaphore(max(1, config.concurrency))
    analysis_sem = asyncio.Semaphore(max(1, config.ai_concurrency))
    robots = RobotsCache() if config.respect_robots else None

    results: list[ScanResult | None] = [None] * len(targets)
    completed = 0
    completed_lock = asyncio.Lock()

    async with contextlib.AsyncExitStack() as stack:
        # Skipping the visual check must skip the *launch*, not just the
        # screenshot: starting Chromium is the expensive part, and a status-only
        # run should work on a host that has no browser installed at all.
        capturer: BrowserCapturer | None = None
        if config.visual_check:
            capturer = await stack.enter_async_context(
                BrowserCapturer(config.capture, config.screenshot_dir)
            )
        checker: UrlStatusChecker | None = None
        if config.status_check.enabled:
            checker = await stack.enter_async_context(UrlStatusChecker(config.status_check))
        analyzer: VisionAnalyzer | None = None
        if config.analyzer is not None:
            analyzer = await stack.enter_async_context(
                VisionAnalyzer(config.analyzer, config.categories)
            )

        async def process(index: int, url: str) -> None:
            nonlocal completed
            result = ScanResult(url=url)
            try:
                if robots is not None and not await robots.allowed(url):
                    result.skipped_reason = "disallowed by robots.txt"
                else:
                    # Ahead of the capture and outside capture_sem: it is one cheap
                    # request that should not hold a browser slot, and running it
                    # first means the status is known even if Chromium then dies on
                    # the page. The checker bounds its own fan-out.
                    if checker is not None:
                        result.status_check = await checker.check(url)
                    if capturer is not None:
                        async with capture_sem:
                            result.capture = await capturer.capture(url)
                        if analyzer is not None and result.capture.worth_analyzing:
                            async with analysis_sem:
                                result.analysis = await analyzer.analyze(result.capture, secrets)
            except Exception as exc:
                result.error = f"{type(exc).__name__}: {exc}"[:400]

            results[index] = result
            async with completed_lock:
                completed += 1
                position = completed
            if progress is not None:
                progress(result, position, len(targets))

        await asyncio.gather(
            *(process(i, url) for i, url in enumerate(targets)),
            return_exceptions=False,
        )

    report.results = [r for r in results if r is not None]
    report.finished_at = utcnow()
    return report
