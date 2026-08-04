"""Orchestration tests with the browser and model layers stubbed out."""

import asyncio
from pathlib import Path

import pytest

from secman_visual_check import scanner
from secman_visual_check.analyzer import AnalyzerOptions
from secman_visual_check.config import ScanConfig
from secman_visual_check.models import Analysis, PageCapture, Severity, UrlStatus
from secman_visual_check.status import StatusCheckOptions


class FakeCapturer:
    instances: list["FakeCapturer"] = []

    def __init__(self, options, output_dir):
        self.options = options
        self.output_dir = Path(output_dir)
        self.seen: list[str] = []
        FakeCapturer.instances.append(self)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None

    async def capture(self, url):
        self.seen.append(url)
        await asyncio.sleep(0)
        if "broken" in url:
            return PageCapture(url=url, load_error="net::ERR_FAILED")
        if "dead" in url:
            return PageCapture(
                url=url,
                final_url="chrome-error://chromewebdata/",
                screenshot_path="/tmp/err.png",
                load_error="net::ERR_CONNECTION_REFUSED",
            )
        return PageCapture(url=url, status=200, screenshot_path=f"/tmp/{len(self.seen)}.png")


class FakeChecker:
    instances: list["FakeChecker"] = []

    def __init__(self, options, client=None):
        self.options = options
        self.checked: list[str] = []
        FakeChecker.instances.append(self)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None

    async def check(self, url):
        self.checked.append(url)
        await asyncio.sleep(0)
        return UrlStatus(url=url, state="ok", first_status=200, final_status=200)


class FakeAnalyzer:
    def __init__(self, options, categories):
        self.options = options
        self.analyzed: list[str] = []
        self.secrets_seen: list[tuple] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None

    async def analyze(self, capture, secrets=()):
        self.analyzed.append(capture.url)
        self.secrets_seen.append(tuple(secrets))
        return Analysis(
            risk_level=Severity.HIGH,
            summary="stub",
            model="stub/model",
        )


@pytest.fixture
def patched(monkeypatch):
    FakeCapturer.instances.clear()
    FakeChecker.instances.clear()
    created: dict[str, FakeAnalyzer] = {}

    def make_analyzer(options, categories):
        analyzer = FakeAnalyzer(options, categories)
        created["analyzer"] = analyzer
        return analyzer

    monkeypatch.setattr(scanner, "BrowserCapturer", FakeCapturer)
    monkeypatch.setattr(scanner, "VisionAnalyzer", make_analyzer)
    monkeypatch.setattr(scanner, "UrlStatusChecker", FakeChecker)
    return created


def make_config(tmp_path, with_ai=True, **kwargs) -> ScanConfig:
    return ScanConfig(
        output_dir=tmp_path,
        analyzer=AnalyzerOptions(api_key="k", model="stub/model") if with_ai else None,
        **kwargs,
    )


def test_scan_captures_and_analyses_every_target(patched, tmp_path):
    targets = ["https://a.example/", "https://b.example/"]
    report = asyncio.run(scanner.run_scan(targets, make_config(tmp_path), tool_version="9.9"))

    assert [r.url for r in report.results] == targets  # order preserved
    assert sorted(patched["analyzer"].analyzed) == targets
    assert report.model == "stub/model"
    assert report.tool_version == "9.9"
    assert report.finished_at is not None
    assert report.max_severity is Severity.HIGH


def test_secrets_are_forwarded_to_the_analyzer(patched, tmp_path):
    """run_scan's secrets parameter must reach VisionAnalyzer.analyze so a
    resolved credential a target reflects back gets scrubbed before the
    prompt is built — see analyzer._redact_capture_for_prompt."""
    targets = ["https://a.example/", "https://b.example/"]
    asyncio.run(
        scanner.run_scan(targets, make_config(tmp_path), secrets=["s3cret-value"])
    )
    assert patched["analyzer"].secrets_seen == [("s3cret-value",), ("s3cret-value",)]


def test_no_secrets_defaults_to_an_empty_sequence(patched, tmp_path):
    asyncio.run(scanner.run_scan(["https://a.example/"], make_config(tmp_path)))
    assert patched["analyzer"].secrets_seen == [()]


def test_browser_error_pages_are_not_sent_to_the_model(patched, tmp_path):
    targets = ["https://ok.example/", "https://dead.example/", "https://broken.example/"]
    report = asyncio.run(scanner.run_scan(targets, make_config(tmp_path)))

    assert patched["analyzer"].analyzed == ["https://ok.example/"]
    assert len(report.failed) == 2
    assert report.results[1].analysis is None


def test_no_analyzer_means_capture_only(patched, tmp_path):
    report = asyncio.run(
        scanner.run_scan(["https://a.example/"], make_config(tmp_path, with_ai=False))
    )
    assert "analyzer" not in patched
    assert report.results[0].analysis is None
    assert report.results[0].capture.ok


def test_robots_disallow_skips_the_target(patched, tmp_path, monkeypatch):
    class DenyAll:
        async def allowed(self, url):
            return "allowed" in url

    monkeypatch.setattr(scanner, "RobotsCache", lambda: DenyAll())
    targets = ["https://allowed.example/", "https://denied.example/"]
    report = asyncio.run(
        scanner.run_scan(targets, make_config(tmp_path, respect_robots=True))
    )

    assert FakeCapturer.instances[0].seen == ["https://allowed.example/"]
    assert report.results[1].skipped_reason == "disallowed by robots.txt"


def test_progress_hook_reports_every_target(patched, tmp_path):
    seen = []
    asyncio.run(
        scanner.run_scan(
            ["https://a.example/", "https://b.example/"],
            make_config(tmp_path),
            progress=lambda result, done, total: seen.append((result.url, done, total)),
        )
    )
    assert sorted(done for _, done, _ in seen) == [1, 2]
    assert {total for _, _, total in seen} == {2}


def test_empty_target_list_returns_an_empty_report(tmp_path):
    report = asyncio.run(scanner.run_scan([], make_config(tmp_path, with_ai=False)))
    assert report.results == []
    assert report.max_severity is Severity.INFO


def test_screenshots_go_into_a_subdirectory(patched, tmp_path):
    asyncio.run(scanner.run_scan(["https://a.example/"], make_config(tmp_path)))
    assert FakeCapturer.instances[0].output_dir == tmp_path / "screenshots"


def test_every_target_gets_a_status_check(patched, tmp_path):
    targets = ["https://a.example/", "https://b.example/"]
    report = asyncio.run(scanner.run_scan(targets, make_config(tmp_path)))

    assert sorted(FakeChecker.instances[0].checked) == targets
    assert [r.status_check.state for r in report.results] == ["ok", "ok"]
    assert report.status_counts()["ok"] == 2
    assert report.status_checked is True
    assert report.status_failures == []


def test_disabling_the_status_check_never_constructs_a_checker(patched, tmp_path):
    config = make_config(tmp_path, status_check=StatusCheckOptions(enabled=False))
    report = asyncio.run(scanner.run_scan(["https://a.example/"], config))

    assert FakeChecker.instances == []
    assert report.results[0].status_check is None
    assert report.status_checked is False


def test_a_robots_skipped_target_is_never_touched_by_the_status_check(
    patched, tmp_path, monkeypatch
):
    class DenyAll:
        async def allowed(self, url):
            return "allowed" in url

    monkeypatch.setattr(scanner, "RobotsCache", lambda: DenyAll())
    targets = ["https://allowed.example/", "https://denied.example/"]
    report = asyncio.run(
        scanner.run_scan(targets, make_config(tmp_path, respect_robots=True))
    )

    assert FakeChecker.instances[0].checked == ["https://allowed.example/"]
    assert report.results[1].status_check is None


def test_the_status_check_still_records_a_target_the_browser_could_not_load(
    patched, tmp_path
):
    report = asyncio.run(scanner.run_scan(["https://broken.example/"], make_config(tmp_path)))

    assert report.results[0].capture.load_error
    assert report.results[0].status_check.state == "ok"


def test_no_visual_check_never_launches_the_browser(patched, tmp_path):
    config = make_config(tmp_path, with_ai=True, visual_check=False)
    report = asyncio.run(scanner.run_scan(["https://a.example/"], config))

    assert FakeCapturer.instances == []
    assert "analyzer" in patched  # the analyzer was built...
    assert patched["analyzer"].analyzed == []  # ...but had nothing to look at
    assert report.results[0].capture is None
    assert report.results[0].status_check.state == "ok"


def test_a_browserless_run_still_produces_a_report(patched, tmp_path):
    config = make_config(tmp_path, with_ai=False, visual_check=False)
    report = asyncio.run(scanner.run_scan(["https://a.example/", "https://b.example/"], config))

    assert len(report.results) == 2
    assert report.status_counts()["ok"] == 2
    assert report.failed == []
