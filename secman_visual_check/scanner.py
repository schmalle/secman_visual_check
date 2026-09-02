"""Orchestration: capture every target, then analyse each capture."""

from __future__ import annotations

import asyncio
import contextlib
from typing import Callable, Sequence

from .analyzer import VisionAnalyzer
from .capture import BrowserCapturer
from .config import ScanConfig
from .content import check_content, text_from_html
from .models import (
    Analysis,
    ContentCheck,
    ScanReport,
    ScanResult,
    Severity,
    utcnow,
)
from .robots import RobotsCache
from .status import UrlStatusChecker

ProgressHook = Callable[[ScanResult, int, int], None]


def classify_evaluation(result: ScanResult, config: ScanConfig, model_ok: bool | None) -> str:
    """Which :data:`~.models.EVALUATION_STATES` member describes ``result``.

    ``model_ok`` is what the scanner itself observed: ``True`` when the model
    returned a usable verdict, ``False`` when it was asked and failed, ``None``
    when it was never asked. It is passed in rather than read back off
    ``result.analysis`` because the content check may have attached findings
    of its own to a page the model never judged — that page is still
    ``analysis_failed`` or ``captured``, not ``analysed``.
    """
    if result.skipped_reason:
        return "skipped"
    if result.error:
        return "error"
    if not config.visual_check:
        return "status_only"
    capture = result.capture
    if capture is None or not capture.worth_analyzing:
        return "capture_failed"
    if config.analyzer is None:
        return "captured"
    if model_ok:
        return "analysed"
    return "analysis_failed"


def run_content_check(result: ScanResult, config: ScanConfig) -> None:
    """Pattern-check whatever content the earlier stages left on ``result``.

    Findings are merged into ``result.analysis`` so every consumer — the
    reports, ``--fail-on``, the SecMan upload — sees them exactly like the
    model's. When there is no model verdict to merge into, a bare one is
    created around them: a page that contains a private key has a finding
    whether or not anything looked at its screenshot.
    """
    sources: dict[str, str] = {}
    if result.capture is not None:
        if result.capture.page_text:
            sources["text"] = result.capture.page_text
        if result.capture.page_html:
            sources["html"] = result.capture.page_html
    if result.status_check is not None and result.status_check.body_sample:
        sources["body"] = result.status_check.body_sample
        if "text" not in sources:
            # No browser rendered this page, so give the visible-text patterns
            # a rough rendering of the body; the raw body is still searched
            # on its own for everything that may see it.
            derived = text_from_html(sources["body"])
            if derived:
                sources["text"] = derived
    if not sources:
        return

    findings, matches = check_content(sources, config.content_patterns)
    result.content_check = ContentCheck(
        sources=[name for name in ("text", "html", "body") if name in sources],
        chars_scanned=sum(len(text) for text in sources.values()),
        matches=matches,
        findings=len(findings),
    )
    if not findings:
        return

    worst = max((f.severity for f in findings), key=lambda s: s.rank)
    analysis = result.analysis
    if analysis is None:
        result.analysis = Analysis(
            risk_level=worst,
            summary=(
                f"No model verdict; the content check matched {len(findings)} "
                f"pattern(s) in the page content."
            ),
            findings=findings,
            requires_review=True,
            model="content-check",
        )
        return
    analysis.findings.extend(findings)
    analysis.requires_review = True
    # The same floor parse_analysis applies to the model's own findings: a page
    # is never reported below the severity of its worst finding.
    if worst.rank > analysis.risk_level.rank:
        analysis.risk_level = worst


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
    robots = (
        RobotsCache(block_private_redirects=config.capture.block_private_redirects)
        if config.respect_robots
        else None
    )

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
            model_ok: bool | None = None
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
                                result.analysis = await analyzer.analyze(result.capture)
                            model_ok = result.analysis.error is None
            except Exception as exc:
                result.error = f"{type(exc).__name__}: {exc}"[:400]

            if config.content_check and not result.error:
                # After the model, never instead of it, and outside both
                # semaphores: it is pure CPU over text already in memory.
                try:
                    run_content_check(result, config)
                except Exception as exc:  # pragma: no cover - a regex cannot fail, but never lose a target
                    result.error = f"content check: {type(exc).__name__}: {exc}"[:400]

            result.evaluation = classify_evaluation(result, config, model_ok)

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
