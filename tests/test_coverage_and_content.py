"""Coverage accounting (was every target evaluated?) and the content check."""

import asyncio
import csv
import io
import json
from pathlib import Path

import pytest

from secman_visual_check import scanner
from secman_visual_check.analyzer import AnalyzerOptions
from secman_visual_check.cli import build_config, build_parser, main
from secman_visual_check.config import ScanConfig
from secman_visual_check.content import (
    DEFAULT_PATTERNS,
    ContentPatternError,
    check_content,
    load_patterns,
    redact_secret,
)
from secman_visual_check.mailer import build_subject, render_text_email
from secman_visual_check.models import (
    EVALUATION_STATES,
    Analysis,
    ContentCheck,
    Finding,
    PageCapture,
    ScanReport,
    ScanResult,
    Severity,
    UrlStatus,
)
from secman_visual_check.plan import ScanPlan, write_plan
from secman_visual_check.reporting import (
    render_html,
    render_stats,
    report_statistics,
    write_console_report,
    write_csv_report,
    write_json_report,
)
from secman_visual_check.status import StatusCheckOptions

# --------------------------------------------------------------------------- #
# content.py
# --------------------------------------------------------------------------- #


def findings_for(text: str, **sources):
    findings, _ = check_content({"text": text, **sources})
    return {f.title: f for f in findings}


def test_every_built_in_pattern_has_a_distinct_id_and_a_known_source():
    ids = [p.id for p in DEFAULT_PATTERNS]
    assert len(ids) == len(set(ids))
    for pattern in DEFAULT_PATTERNS:
        assert pattern.sources <= {"text", "html", "body"}
        assert 0.0 < pattern.confidence <= 1.0


@pytest.mark.parametrize(
    "text, title",
    [
        ("key AKIAIOSFODNN7EXAMPLE here", "AWS access key ID in page content"),
        ("-----BEGIN RSA PRIVATE KEY-----\nMIIE", "Private key material in page content"),
        ("ghp_" + "a" * 36, "GitHub token in page content"),
        ("mysql://root:s3cret@db.internal:3306/app", "Connection string with embedded password"),
        ("DB_PASSWORD=hunter2\n", "Environment file secret rendered in page"),
        ("Traceback (most recent call last):\n  File", "Stack trace or framework error in page text"),
        ("Index of /backup\nParent Directory", "Auto-generated directory index"),
        ("box at 192.168.1.20", "Private network address in page text"),
        ("IBAN DE89 3704 0044 0532 0130 00", "Bank account number (IBAN) in page text"),
        ("card 4111 1111 1111 1111", "Payment card number in page text"),
    ],
)
def test_built_in_patterns_match_their_canonical_examples(text, title):
    assert title in findings_for(text)


def test_secret_evidence_is_redacted_to_four_characters():
    found = findings_for("AWS key AKIAIOSFODNN7EXAMPLE")
    evidence = found["AWS access key ID in page content"].evidence
    assert evidence.startswith("AKIA…")
    assert "IOSFODNN" not in evidence


def test_captured_value_is_redacted_but_its_label_survives():
    found = findings_for("DB_PASSWORD=hunter2\n")
    evidence = found["Environment file secret rendered in page"].evidence
    assert evidence.startswith("DB_PASSWORD=hunt…")
    assert "hunter2" not in evidence


def test_redact_secret_never_reveals_short_values():
    assert redact_secret("abc") == "…"
    assert redact_secret("abcdefgh") == "abcd…"


def test_login_form_labels_are_not_credentials():
    """``Password:`` followed by a field or a link is the most common text on the web."""
    text = "Username:\nPassword:\nForgot password? Login\npassword: required"
    assert "Credential assignment visible in page text" not in findings_for(text)


def test_placeholder_and_code_values_are_not_credentials():
    for value in ("********", "${DB_PASSWORD}", "<redacted>", "changeme", "e.target.value"):
        assert "Credential assignment visible in page text" not in findings_for(
            f"password = {value}"
        ), value


def test_a_real_looking_credential_assignment_is_reported():
    found = findings_for("admin password = Tr0ub4dor&3")
    finding = found["Credential assignment visible in page text"]
    assert finding.source == "content"
    assert "Tr0ub4dor" not in finding.evidence


def test_loose_patterns_stay_off_the_html_and_raw_body():
    """Minified scripts are full of ``password:`` — only visible text is judged."""
    findings, _ = check_content({"html": "var cfg={password:'Tr0ub4dor&3'}"})
    assert findings == []
    findings, _ = check_content({"text": "password: Tr0ub4dor&3"})
    assert len(findings) == 1


def test_format_patterns_are_found_in_html_comments_and_raw_bodies():
    findings, _ = check_content({"html": "<!-- AKIAIOSFODNN7EXAMPLE -->"})
    assert [f.title for f in findings] == ["AWS access key ID in page content"]
    assert "page HTML" in findings[0].evidence
    findings, _ = check_content({"body": "[core]\n\trepositoryformatversion = 0\n"})
    assert [f.category for f in findings] == ["backup_or_source_disclosure"]
    assert "response body" in findings[0].evidence


def test_matches_collapse_to_one_finding_per_pattern_with_a_count():
    text = "\n".join(f"host{i} 10.0.0.{i}" for i in range(40))
    findings, matches = check_content({"text": text})
    assert len(findings) == 1
    assert matches == 40
    assert "(+39 more)" in findings[0].evidence


def test_the_same_match_in_two_sources_counts_once():
    findings, matches = check_content(
        {"text": "AKIAIOSFODNN7EXAMPLE", "html": "<p>AKIAIOSFODNN7EXAMPLE</p>"}
    )
    assert matches == 1
    assert "more" not in findings[0].evidence


def test_a_single_email_address_is_not_a_customer_list():
    assert "Bulk list of email addresses in page text" not in findings_for("mail me: a@b.example")
    listing = "\n".join(f"user{i}@corp.example" for i in range(12))
    assert "Bulk list of email addresses in page text" in findings_for(listing)


def test_luhn_and_iban_validators_reject_random_digits():
    assert "Payment card number in page text" not in findings_for("ref 4111 1111 1111 1112")
    assert "Bank account number (IBAN) in page text" not in findings_for("DE00 0000 0000 0000 0000 01")


def test_max_chars_bounds_what_is_read():
    text = "x" * 100 + " AKIAIOSFODNN7EXAMPLE"
    findings, _ = check_content({"text": text}, max_chars=50)
    assert findings == []


def test_pattern_file_extends_the_built_ins(tmp_path):
    path = tmp_path / "patterns.json"
    path.write_text(
        json.dumps(
            [
                {
                    "id": "internal_marker",
                    "category": "internal_documents",
                    "severity": "high",
                    "title": "Internal-only banner",
                    "regex": "INTERNAL USE ONLY",
                    "sources": ["text"],
                }
            ]
        )
    )
    patterns = load_patterns(path)
    assert len(patterns) == len(DEFAULT_PATTERNS) + 1
    findings, _ = check_content({"text": "INTERNAL USE ONLY"}, patterns)
    assert findings[0].category == "internal_documents"
    assert findings[0].severity is Severity.HIGH


def test_pattern_file_can_override_one_built_in_and_replace_the_set(tmp_path):
    path = tmp_path / "patterns.json"
    path.write_text(
        json.dumps(
            {
                "replace": True,
                "patterns": [
                    {
                        "id": "private_ip",
                        "category": "infrastructure_disclosure",
                        "severity": "critical",
                        "title": "Private address",
                        "regex": r"10\.\d+\.\d+\.\d+",
                    }
                ],
            }
        )
    )
    patterns = load_patterns(path)
    assert [p.id for p in patterns] == ["private_ip"]
    assert patterns[0].severity is Severity.CRITICAL


@pytest.mark.parametrize(
    "content",
    [
        "not json",
        "[]",
        '[{"id": "x"}]',
        '[{"id": "x", "category": "c", "title": "t", "regex": "("}]',
        '[{"id": "x", "category": "c", "title": "t", "regex": "a", "sources": ["screenshot"]}]',
        '{"replace": true, "patterns": []}',
    ],
)
def test_pattern_file_validation(tmp_path, content):
    path = tmp_path / "patterns.json"
    path.write_text(content)
    with pytest.raises(ContentPatternError):
        load_patterns(path)


# --------------------------------------------------------------------------- #
# Scanner: evaluation states and the content check in the pipeline
# --------------------------------------------------------------------------- #


class FakeCapturer:
    instances: list = []

    def __init__(self, options, output_dir):
        self.options = options
        self.output_dir = Path(output_dir)
        FakeCapturer.instances.append(self)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None

    async def capture(self, url):
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
        capture = PageCapture(url=url, status=200, screenshot_path="/tmp/shot.png")
        if "leaky" in url:
            capture.page_text = "config\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
            capture.page_html = "<!-- -----BEGIN RSA PRIVATE KEY----- -->"
        else:
            capture.page_text = "Welcome to our site"
            capture.page_html = "<html><body>Welcome to our site</body></html>"
        return capture


class FakeChecker:
    def __init__(self, options, client=None):
        self.options = options

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None

    async def check(self, url):
        await asyncio.sleep(0)
        status = UrlStatus(url=url, state="ok", first_status=200, final_status=200)
        if "env" in url:
            status.body_sample = "APP_ENV=prod\nDB_PASSWORD=hunter2\n"
        return status


class FakeAnalyzer:
    def __init__(self, options, categories):
        self.options = options

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None

    async def analyze(self, capture):
        await asyncio.sleep(0)
        if "garbled" in capture.url:
            return Analysis(
                risk_level=Severity.INFO,
                summary="",
                model="stub/model",
                error="could not parse JSON from model response",
            )
        return Analysis(
            risk_level=Severity.LOW,
            summary="Looks fine.",
            model="stub/model",
            findings=[
                Finding("infrastructure_disclosure", Severity.LOW, "Version footer", confidence=0.5)
            ],
        )


@pytest.fixture
def patched(monkeypatch):
    FakeCapturer.instances.clear()
    monkeypatch.setattr(scanner, "BrowserCapturer", FakeCapturer)
    monkeypatch.setattr(scanner, "VisionAnalyzer", FakeAnalyzer)
    monkeypatch.setattr(scanner, "UrlStatusChecker", FakeChecker)


def make_config(tmp_path, with_ai=True, **kwargs) -> ScanConfig:
    return ScanConfig(
        output_dir=tmp_path,
        analyzer=AnalyzerOptions(api_key="k", model="stub/model") if with_ai else None,
        **kwargs,
    )


def scan(targets, config):
    return asyncio.run(scanner.run_scan(targets, config))


def test_every_result_gets_an_evaluation_state(patched, tmp_path):
    targets = [
        "https://ok.example/",
        "https://broken.example/",
        "https://dead.example/",
        "https://garbled.example/",
    ]
    report = scan(targets, make_config(tmp_path))
    states = {r.url: r.evaluation for r in report.results}
    assert states == {
        "https://ok.example/": "analysed",
        "https://broken.example/": "capture_failed",
        "https://dead.example/": "capture_failed",
        "https://garbled.example/": "analysis_failed",
    }
    assert all(state in EVALUATION_STATES for state in states.values())
    assert [r.url for r in report.unevaluated] == targets[1:]
    assert report.evaluation_counts()["analysed"] == 1
    assert report.evaluation_known


def test_no_ai_counts_a_screenshot_as_evaluated(patched, tmp_path):
    report = scan(["https://ok.example/"], make_config(tmp_path, with_ai=False))
    assert report.results[0].evaluation == "captured"
    assert report.results[0].evaluated
    assert report.unevaluated == []


def test_a_browserless_run_counts_the_status_check_as_evaluated(patched, tmp_path):
    report = scan(["https://ok.example/"], make_config(tmp_path, with_ai=False, visual_check=False))
    assert report.results[0].evaluation == "status_only"
    assert report.results[0].evaluated


def test_a_robots_skip_is_not_evaluated(patched, tmp_path, monkeypatch):
    class DenyAll:
        async def allowed(self, url):
            return False

    monkeypatch.setattr(scanner, "RobotsCache", lambda **kwargs: DenyAll())
    report = scan(["https://denied.example/"], make_config(tmp_path, respect_robots=True))
    assert report.results[0].evaluation == "skipped"
    assert report.results[0].evaluation_detail == "disallowed by robots.txt"
    assert report.unevaluated == report.results


def test_an_unexpected_exception_is_an_error_state(patched, tmp_path, monkeypatch):
    async def boom(self, url):
        raise RuntimeError("browser crashed")

    monkeypatch.setattr(FakeCapturer, "capture", boom)
    report = scan(["https://ok.example/"], make_config(tmp_path))
    assert report.results[0].evaluation == "error"
    assert "browser crashed" in report.results[0].evaluation_detail


def test_content_findings_are_merged_into_the_model_verdict(patched, tmp_path):
    report = scan(["https://leaky.example/"], make_config(tmp_path))
    result = report.results[0]
    assert result.evaluation == "analysed"
    sources = {f.source for f in result.analysis.findings}
    assert sources == {"model", "content"}
    titles = {f.title for f in result.analysis.findings}
    assert "AWS access key ID in page content" in titles
    assert "Private key material in page content" in titles
    # The page is never reported below its worst finding, whoever found it.
    assert result.analysis.risk_level is Severity.CRITICAL
    assert result.analysis.requires_review
    assert result.content_check.sources == ["text", "html"]
    assert result.content_check.findings == 2
    assert report.severity_counts()["critical"] == 2


def test_content_findings_stand_alone_when_no_model_ran(patched, tmp_path):
    report = scan(["https://leaky.example/"], make_config(tmp_path, with_ai=False))
    result = report.results[0]
    assert result.evaluation == "captured"
    assert result.analysis is not None
    assert result.analysis.model == "content-check"
    assert all(f.source == "content" for f in result.analysis.findings)
    assert result.max_severity is Severity.CRITICAL


def test_content_findings_survive_a_failed_model_call(patched, tmp_path, monkeypatch):
    async def fail(self, capture):
        return Analysis(risk_level=Severity.INFO, summary="", model="m", error="HTTP 502")

    monkeypatch.setattr(FakeAnalyzer, "analyze", fail)
    report = scan(["https://leaky.example/"], make_config(tmp_path))
    result = report.results[0]
    assert result.evaluation == "analysis_failed"
    assert not result.evaluated
    assert result.analysis.error == "HTTP 502"
    assert [f.source for f in result.analysis.findings] == ["content", "content"]


def test_the_raw_body_is_checked_without_a_browser(patched, tmp_path):
    report = scan(["https://env.example/.env"], make_config(tmp_path, with_ai=False, visual_check=False))
    result = report.results[0]
    # The raw body plus a rough text rendering of it, since no browser ran.
    assert result.content_check.sources == ["text", "body"]
    assert [f.category for f in result.analysis.findings] == ["backup_or_source_disclosure"]
    assert "hunter2" not in result.analysis.findings[0].evidence


def test_a_clean_page_records_the_check_without_findings(patched, tmp_path):
    report = scan(["https://ok.example/"], make_config(tmp_path, with_ai=False))
    result = report.results[0]
    assert result.content_check is not None
    assert result.content_check.findings == 0
    assert result.analysis is None


def test_the_content_check_can_be_turned_off(patched, tmp_path):
    report = scan(["https://leaky.example/"], make_config(tmp_path, content_check=False))
    result = report.results[0]
    assert result.content_check is None
    assert all(f.source == "model" for f in result.analysis.findings)


def test_a_capture_without_content_leaves_no_check(patched, tmp_path):
    report = scan(["https://broken.example/"], make_config(tmp_path))
    assert report.results[0].content_check is None


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #


def coverage_report() -> ScanReport:
    good = ScanResult(
        url="https://good.example/",
        capture=PageCapture(url="https://good.example/", status=200, screenshot_path="/x.png"),
        analysis=Analysis(
            risk_level=Severity.CRITICAL,
            summary="Leak.",
            findings=[
                Finding("exposed_credentials", Severity.CRITICAL, "Key in page", source="content"),
                Finding("infrastructure_disclosure", Severity.LOW, "Banner"),
            ],
        ),
        content_check=ContentCheck(sources=["text", "html"], chars_scanned=120, matches=1, findings=1),
        evaluation="analysed",
    )
    failed = ScanResult(
        url="https://failed.example/",
        capture=PageCapture(url="https://failed.example/", status=200, screenshot_path="/y.png"),
        analysis=Analysis(risk_level=Severity.INFO, summary="", error="HTTP 502: upstream"),
        evaluation="analysis_failed",
    )
    skipped = ScanResult(
        url="https://skipped.example/", skipped_reason="disallowed by robots.txt", evaluation="skipped"
    )
    return ScanReport(results=[good, failed, skipped], model="m", tool_version="t")


def test_json_report_carries_coverage_and_finding_sources(tmp_path):
    data = json.loads(write_json_report(coverage_report(), tmp_path / "r.json").read_text())
    assert data["evaluation_counts"]["analysed"] == 1
    assert data["evaluation_counts"]["analysis_failed"] == 1
    assert data["unevaluated_count"] == 2
    good = data["results"][0]
    assert good["evaluation"] == "analysed"
    assert good["evaluated"] is True
    assert good["content_check"] == {
        "sources": ["text", "html"],
        "chars_scanned": 120,
        "matches": 1,
        "findings": 1,
    }
    assert [f["source"] for f in good["analysis"]["findings"]] == ["content", "model"]
    assert data["results"][1]["evaluated"] is False
    assert data["results"][2]["content_check"] is None


def test_hand_built_results_have_no_coverage_verdict():
    result = ScanResult(url="https://x.example/")
    assert result.evaluation == ""
    assert result.evaluated is False
    report = ScanReport(results=[result])
    assert report.evaluation_known is False
    assert report.unevaluated == []
    assert report.to_dict()["unevaluated_count"] == 0


def test_console_report_names_unevaluated_targets_and_content_findings():
    stream = io.StringIO()
    write_console_report(coverage_report(), stream=stream, color=False)
    out = stream.getvalue()
    assert "2 target(s) were not evaluated:" in out
    assert "https://failed.example/ — analysis failed (analysis error: HTTP 502: upstream)" in out
    assert "https://skipped.example/ — skipped (disallowed by robots.txt)" in out
    assert "not evaluated: analysis failed" in out
    assert "Key in page  (exposed_credentials, conf 0.00, content check)" in out
    assert "evaluated" in out and "not evaluated" in out


def test_statistics_count_coverage_and_content_findings():
    stats = report_statistics(coverage_report())
    assert stats["evaluated"] == 1
    assert stats["unevaluated"] == 2
    assert stats["evaluation_counts"]["skipped"] == 1
    assert stats["content_checked"] == 1
    assert stats["content_findings"] == 1
    text = render_stats(coverage_report())
    assert "Coverage" in text
    assert "not evaluated" in text
    assert "Content check" in text


def test_statistics_omit_coverage_when_nothing_recorded():
    report = ScanReport(results=[ScanResult(url="https://x.example/")])
    assert "Coverage" not in render_stats(report)
    stream = io.StringIO()
    write_console_report(report, stream=stream, color=False)
    assert "not evaluated" not in stream.getvalue()


def test_csv_report_carries_the_coverage_columns(tmp_path):
    path = write_csv_report(coverage_report(), tmp_path / "r.csv")
    rows = list(csv.DictReader(path.open(encoding="utf-8")))
    assert rows[0]["evaluation"] == "analysed"
    assert rows[0]["evaluated"] == "true"
    assert rows[0]["content_findings"] == "1"
    assert rows[1]["evaluated"] == "false"


def test_html_report_shows_the_coverage_cards_and_pill(tmp_path):
    page = render_html(coverage_report(), tmp_path)
    assert "not evaluated" in page
    assert "content check" in page
    assert "analysis failed" in page


def test_mail_subject_and_body_mention_unevaluated_targets():
    report = coverage_report()
    assert "2 not evaluated" in build_subject(report)
    body = render_text_email(report)
    assert "2 target(s) were not evaluated:" in body
    assert "[analysis_failed] https://failed.example/" in body


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def parse(*argv):
    return build_parser().parse_args([*argv, "https://example.com"])


def test_content_check_is_on_by_default_and_wired_through(tmp_path):
    config = build_config(parse("-o", str(tmp_path)))
    assert config.content_check is True
    assert len(config.content_patterns) == len(DEFAULT_PATTERNS)
    assert config.capture.content_max_chars == 500_000
    assert config.status_check.keep_body_chars == 500_000


def test_no_content_check_keeps_no_content_anywhere(tmp_path):
    config = build_config(parse("-o", str(tmp_path), "--no-content-check"))
    assert config.content_check is False
    assert config.capture.content_max_chars == 0
    assert config.status_check.keep_body_chars == 0


def test_content_max_chars_is_wired_through(tmp_path):
    config = build_config(parse("-o", str(tmp_path), "--content-max-chars", "1000"))
    assert config.capture.content_max_chars == 1000
    assert config.status_check.keep_body_chars == 1000


def test_a_bad_pattern_file_is_a_configuration_error(tmp_path, capsys):
    path = tmp_path / "p.json"
    path.write_text("nope")
    code = main(["--content-patterns-file", str(path), "-o", str(tmp_path), "https://example.com"])
    assert code == 2
    assert "not valid JSON" in capsys.readouterr().err


def test_fail_on_unevaluated_gates_the_exit_code(tmp_path, monkeypatch, capsys):
    async def fake_scan(targets, config, progress=None, tool_version=""):
        result = ScanResult(url=targets[0], error="browser died", evaluation="error")
        if progress:
            progress(result, 1, 1)
        return ScanReport(results=[result])

    monkeypatch.setattr("secman_visual_check.cli.run_scan", fake_scan)
    base = ["-o", str(tmp_path), "--no-ai", "-q", "https://example.com"]
    assert main(base) == 0
    assert main(["--fail-on-unevaluated", *base]) == 1
    assert "1 target(s) were not evaluated" in capsys.readouterr().out


def test_the_plan_describes_the_content_check(tmp_path, capsys):
    config = build_config(parse("-o", str(tmp_path)))
    write_plan(ScanPlan(targets=["https://example.com/"], config=config))
    out = capsys.readouterr().out
    assert f"content check  {len(DEFAULT_PATTERNS)} pattern(s) over page text and DOM, raw response body" in out

    config = build_config(parse("-o", str(tmp_path), "--no-content-check"))
    write_plan(ScanPlan(targets=["https://example.com/"], config=config))
    assert "content check  disabled (--no-content-check)" in capsys.readouterr().out

    config = build_config(parse("-o", str(tmp_path), "--no-visual-check", "--no-status-checksum"))
    write_plan(ScanPlan(targets=["https://example.com/"], config=config))
    assert "nothing — no input stage keeps content" in capsys.readouterr().out


def test_status_options_keep_body_chars_default_is_off():
    assert StatusCheckOptions().keep_body_chars == 0


# --------------------------------------------------------------------------- #
# Browserless runs: a rough text rendering of the raw body
# --------------------------------------------------------------------------- #


def test_text_from_html_strips_tags_scripts_and_comments():
    from secman_visual_check.content import text_from_html

    raw = (
        "<html><head><title>T</title><style>p{}</style></head><body>"
        "<!-- AKIAIOSFODNN7EXAMPLE --><h1>Index of /backup</h1>"
        "<a href='../'>Parent Directory</a> db.sql<script>var x = 1;</script>"
        "<p>caf&eacute; &amp; bar</p></body></html>"
    )
    text = text_from_html(raw)
    assert "Index of /backup" in text.splitlines()
    assert "AKIA" not in text  # comments are dropped; the raw body still sees them
    assert "var x" not in text
    assert "café & bar" in text


def test_text_from_html_returns_plain_bodies_unchanged():
    from secman_visual_check.content import text_from_html

    assert text_from_html("DB_PASSWORD=hunter2\n") == "DB_PASSWORD=hunter2\n"


def test_a_browserless_run_derives_visible_text_from_the_body(patched, tmp_path, monkeypatch):
    async def listing(self, url):
        status = UrlStatus(url=url, state="ok", first_status=200, final_status=200)
        status.body_sample = "<html><body><h1>Index of /backup</h1><a href='../'>Parent Directory</a></body></html>"
        return status

    monkeypatch.setattr(FakeChecker, "check", listing)
    report = scan(["https://x.example/backup/"], make_config(tmp_path, with_ai=False, visual_check=False))
    result = report.results[0]
    assert result.content_check.sources == ["text", "body"]
    assert [f.category for f in result.analysis.findings] == ["directory_listing"]


def test_a_content_only_verdict_does_not_count_as_analysed():
    result = ScanResult(
        url="https://x.example/",
        analysis=Analysis(risk_level=Severity.HIGH, summary="", model="content-check"),
    )
    assert report_statistics(ScanReport(results=[result]))["analysed"] == 0
