"""Runtime configuration assembled by the CLI and consumed by the scanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .analyzer import AnalyzerOptions
from .capture import CaptureOptions
from .categories import Category
from .models import Severity


@dataclass
class ScanConfig:
    output_dir: Path
    capture: CaptureOptions = field(default_factory=CaptureOptions)
    analyzer: AnalyzerOptions | None = None
    categories: list[Category] = field(default_factory=list)
    concurrency: int = 4
    ai_concurrency: int = 3
    respect_robots: bool = False
    fail_on: Severity | None = Severity.HIGH

    @property
    def screenshot_dir(self) -> Path:
        return self.output_dir / "screenshots"
