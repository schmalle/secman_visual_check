"""Runtime configuration assembled by the CLI and consumed by the scanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .analyzer import AnalyzerOptions
from .capture import CaptureOptions
from .categories import Category
from .content import DEFAULT_PATTERNS, ContentPattern
from .models import Severity
from .status import StatusCheckOptions


@dataclass
class ScanConfig:
    output_dir: Path
    #: When False the browser is never launched: no screenshots, no analysis.
    #: The scan degrades to a pure status/checksum check.
    visual_check: bool = True
    capture: CaptureOptions = field(default_factory=CaptureOptions)
    status_check: StatusCheckOptions = field(default_factory=StatusCheckOptions)
    analyzer: AnalyzerOptions | None = None
    categories: list[Category] = field(default_factory=list)
    #: The deterministic pattern check over page text, DOM and raw body. On by
    #: default and independent of the model: it is what still finds a private
    #: key when the model is off, failed, or could not see below the clamp.
    content_check: bool = True
    content_patterns: list[ContentPattern] = field(default_factory=lambda: list(DEFAULT_PATTERNS))
    concurrency: int = 4
    ai_concurrency: int = 3
    respect_robots: bool = False
    fail_on: Severity | None = Severity.HIGH

    @property
    def screenshot_dir(self) -> Path:
        return self.output_dir / "screenshots"
