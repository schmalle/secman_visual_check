"""Core data structures shared by the capture, analysis and reporting stages."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Severity(str, enum.Enum):
    """Ordered severity scale used for findings and for the ``--fail-on`` gate."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER.index(self)

    def __lt__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    @classmethod
    def parse(cls, value: Any, default: "Severity | None" = None) -> "Severity":
        """Best-effort parse of a model-supplied severity string."""
        if isinstance(value, Severity):
            return value
        if isinstance(value, str):
            candidate = value.strip().lower()
            for member in cls:
                if member.value == candidate:
                    return member
            # Tolerate a few synonyms the model may produce.
            alias = {
                "informational": cls.INFO,
                "none": cls.INFO,
                "moderate": cls.MEDIUM,
                "severe": cls.HIGH,
                "urgent": cls.CRITICAL,
            }.get(candidate)
            if alias is not None:
                return alias
        if default is not None:
            return default
        return cls.INFO


_SEVERITY_ORDER = [
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]


@dataclass
class Finding:
    """A single piece of sensitive or otherwise notable content on a page."""

    category: str
    severity: Severity
    title: str
    evidence: str = ""
    recommendation: str = ""
    confidence: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "severity": self.severity.value,
            "title": self.title,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "confidence": round(self.confidence, 3),
        }


@dataclass
class PageCapture:
    """Everything the browser learned about a URL."""

    url: str
    final_url: str | None = None
    status: int | None = None
    title: str | None = None
    screenshot_path: str | None = None
    text_excerpt: str = ""
    console_errors: list[str] = field(default_factory=list)
    load_error: str | None = None
    duration_s: float = 0.0
    viewport: tuple[int, int] = (0, 0)
    page_height: int | None = None

    @property
    def ok(self) -> bool:
        return self.screenshot_path is not None

    @property
    def is_browser_error_page(self) -> bool:
        """True when the browser rendered its own error page rather than the site."""
        return bool(self.final_url and self.final_url.startswith("chrome-error://"))

    @property
    def worth_analyzing(self) -> bool:
        """Only spend model tokens on screenshots that show real page content."""
        return self.ok and not self.is_browser_error_page

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "final_url": self.final_url,
            "status": self.status,
            "title": self.title,
            "screenshot_path": self.screenshot_path,
            "text_excerpt": self.text_excerpt,
            "console_errors": self.console_errors,
            "load_error": self.load_error,
            "duration_s": round(self.duration_s, 3),
            "viewport": list(self.viewport),
            "page_height": self.page_height,
        }


#: Outcomes of the HTTP status pre-check, worst-to-best ordering is not implied.
STATUS_STATES = (
    "ok",
    "redirect",
    "redirect_broken",
    "unexpected_status",
    "client_error",
    "server_error",
    "unreachable",
    "unknown",
)


@dataclass
class RedirectHop:
    """One response in a redirect chain."""

    url: str
    status: int | None = None
    #: The raw ``Location`` header, exactly as sent — may be relative.
    location: str | None = None
    elapsed_s: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "status": self.status,
            "location": self.location,
            "elapsed_s": round(self.elapsed_s, 3),
        }


@dataclass
class UrlStatus:
    """What a plain HTTP client sees at a target URL.

    Deliberately separate from :class:`PageCapture`: the browser follows redirects
    internally, uses its cache and runs service workers, so ``PageCapture.status``
    only ever shows the end of the story. This records the first response verbatim
    and every hop after it.
    """

    url: str
    state: str = "unknown"
    #: The method that produced ``first_status`` — ``HEAD`` or ``GET``.
    method: str = ""
    first_status: int | None = None
    final_status: int | None = None
    final_url: str | None = None
    chain: list[RedirectHop] = field(default_factory=list)
    expected_statuses: tuple[int, ...] = (200,)
    #: sha256 of the response body, set only when the target answered an
    #: expected status *and* actually returned content. ``None`` means "not
    #: computed" — an empty body is recorded as a checksum of zero bytes, which
    #: is a different fact from having no checksum at all.
    content_checksum: str | None = None
    content_length: int | None = None
    content_type: str | None = None
    content_truncated: bool = False
    error: str | None = None
    elapsed_s: float = 0.0
    checked_at: datetime = field(default_factory=utcnow)

    @property
    def ok(self) -> bool:
        return self.final_status is not None and self.final_status in self.expected_statuses

    @property
    def redirect_count(self) -> int:
        return max(0, len(self.chain) - 1)

    @property
    def label(self) -> str:
        """A short human-readable verdict, shared by every renderer."""
        if self.first_status is None:
            return self.state
        if self.redirect_count and self.final_status is not None:
            return f"{self.first_status}->{self.final_status} {self.state}"
        return f"{self.first_status} {self.state}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "state": self.state,
            "ok": self.ok,
            "method": self.method,
            "first_status": self.first_status,
            "final_status": self.final_status,
            "final_url": self.final_url,
            "redirect_count": self.redirect_count,
            "expected_statuses": list(self.expected_statuses),
            "chain": [hop.to_dict() for hop in self.chain],
            "content_checksum": self.content_checksum,
            "content_length": self.content_length,
            "content_type": self.content_type,
            "content_truncated": self.content_truncated,
            "error": self.error,
            "elapsed_s": round(self.elapsed_s, 3),
            "checked_at": self.checked_at.isoformat(),
        }


@dataclass
class Analysis:
    """The verdict returned by the vision model for one screenshot."""

    risk_level: Severity
    summary: str
    findings: list[Finding] = field(default_factory=list)
    page_type: str = ""
    requires_review: bool = False
    model: str = ""
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    duration_s: float = 0.0
    error: str | None = None
    raw_response: str | None = None

    def to_dict(self, include_raw: bool = False) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "risk_level": self.risk_level.value,
            "summary": self.summary,
            "page_type": self.page_type,
            "requires_review": self.requires_review,
            "findings": [f.to_dict() for f in self.findings],
            "model": self.model,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "duration_s": round(self.duration_s, 3),
            "error": self.error,
        }
        if include_raw:
            payload["raw_response"] = self.raw_response
        return payload


@dataclass
class ScanResult:
    """Capture + analysis for a single target."""

    url: str
    capture: PageCapture | None = None
    status_check: UrlStatus | None = None
    analysis: Analysis | None = None
    error: str | None = None
    skipped_reason: str | None = None

    @property
    def max_severity(self) -> Severity:
        if self.analysis is None:
            return Severity.INFO
        severities = [f.severity for f in self.analysis.findings]
        severities.append(self.analysis.risk_level)
        return max(severities, key=lambda s: s.rank)

    @property
    def findings(self) -> list[Finding]:
        return list(self.analysis.findings) if self.analysis else []

    def to_dict(self, include_raw: bool = False) -> dict[str, Any]:
        return {
            "url": self.url,
            "error": self.error,
            "skipped_reason": self.skipped_reason,
            "max_severity": self.max_severity.value,
            "status_check": self.status_check.to_dict() if self.status_check else None,
            "capture": self.capture.to_dict() if self.capture else None,
            "analysis": self.analysis.to_dict(include_raw) if self.analysis else None,
        }


@dataclass
class ScanReport:
    """The full result set for one scanner invocation."""

    results: list[ScanResult] = field(default_factory=list)
    started_at: datetime = field(default_factory=utcnow)
    finished_at: datetime | None = None
    model: str = ""
    tool_version: str = ""

    @property
    def duration_s(self) -> float:
        end = self.finished_at or utcnow()
        return (end - self.started_at).total_seconds()

    def severity_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for result in self.results:
            for finding in result.findings:
                counts[finding.severity.value] += 1
        return counts

    @property
    def max_severity(self) -> Severity:
        if not self.results:
            return Severity.INFO
        return max((r.max_severity for r in self.results), key=lambda s: s.rank)

    @property
    def failed(self) -> list[ScanResult]:
        return [r for r in self.results if r.error or (r.capture and r.capture.load_error)]

    def status_counts(self) -> dict[str, int]:
        counts = {state: 0 for state in STATUS_STATES}
        for result in self.results:
            if result.status_check is not None:
                counts[result.status_check.state] = counts.get(result.status_check.state, 0) + 1
        return counts

    def status_code_counts(self) -> dict[str, int]:
        """How many targets ended on each HTTP status code.

        Keyed by the code as a string so the mapping survives JSON; targets that
        never produced a response are counted under ``"none"``. This is the
        answer to "how many 200s and how many of something else", which the
        state buckets only approximate — ``client_error`` covers 401 and 404
        alike, and ``ok`` follows ``--status-expect`` rather than meaning 200.
        """
        counts: dict[str, int] = {}
        for result in self.results:
            status = result.status_check
            if status is None:
                continue
            key = str(status.final_status) if status.final_status is not None else "none"
            counts[key] = counts.get(key, 0) + 1
        return counts

    @property
    def status_checked(self) -> bool:
        return any(r.status_check is not None for r in self.results)

    @property
    def status_failures(self) -> list[ScanResult]:
        return [r for r in self.results if r.status_check is not None and not r.status_check.ok]

    def to_dict(self, include_raw: bool = False) -> dict[str, Any]:
        return {
            "tool": "secman_visual_check",
            "tool_version": self.tool_version,
            "model": self.model,
            "started_at": self.started_at.isoformat(),
            "finished_at": (self.finished_at or utcnow()).isoformat(),
            "duration_s": round(self.duration_s, 3),
            "target_count": len(self.results),
            "severity_counts": self.severity_counts(),
            "status_counts": self.status_counts(),
            "status_code_counts": self.status_code_counts(),
            "max_severity": self.max_severity.value,
            "results": [r.to_dict(include_raw) for r in self.results],
        }
