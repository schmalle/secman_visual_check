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

ProgressHook = Callable[[ScanResult, int, int], None]


async def run_scan(
    targets: Sequence[str],
    config: ScanConfig,
    progress: ProgressHook | None = None,
    tool_version: str = "",
) -> ScanReport:
    """Capture and analyse every target, with independent concurrency limits.

    Capture and analysis are pipelined per target: one page can be analysed while
    another is still loading, so the AI round-trip does not stall the browser.
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
        capturer = await stack.enter_async_context(
            BrowserCapturer(config.capture, config.screenshot_dir)
        )
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
                    async with capture_sem:
                        result.capture = await capturer.capture(url)
                    if analyzer is not None and result.capture.worth_analyzing:
                        async with analysis_sem:
                            result.analysis = await analyzer.analyze(result.capture)
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
