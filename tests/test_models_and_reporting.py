import io
import json

from secman_visual_check.models import (
    Analysis,
    Finding,
    PageCapture,
    RedirectHop,
    ScanReport,
    ScanResult,
    Severity,
    UrlStatus,
)
from secman_visual_check.reporting import (
    render_html,
    write_console_report,
    write_json_report,
)


def make_report() -> ScanReport:
    capture = PageCapture(
        url="https://example.com/admin",
        final_url="https://example.com/admin",
        status=200,
        title="Admin <console>",
        screenshot_path="/nonexistent/shot.png",
        text_excerpt="Index of /backup",
    )
    analysis = Analysis(
        risk_level=Severity.CRITICAL,
        summary="Admin console reachable without login.",
        page_type="admin panel",
        requires_review=True,
        model="test/model",
        findings=[
            Finding(
                category="unauthenticated_admin",
                severity=Severity.CRITICAL,
                title='Admin panel open <script>alert("x")</script>',
                evidence="User management table visible",
                recommendation="Require authentication.",
                confidence=0.95,
            ),
            Finding(
                category="infrastructure_disclosure",
                severity=Severity.MEDIUM,
                title="Server version shown",
                confidence=0.6,
            ),
        ],
    )
    redirect = UrlStatus(
        url="https://example.com/admin",
        state="redirect",
        method="HEAD",
        first_status=301,
        final_status=200,
        final_url="https://example.com/admin/",
        elapsed_s=0.34,
        chain=[
            RedirectHop(
                url="https://example.com/admin",
                status=301,
                # A Location is attacker-controlled, so it must be escaped.
                location='/admin/"><script>alert("x")</script>',
            ),
            RedirectHop(url="https://example.com/admin/", status=200),
        ],
    )
    unreachable = UrlStatus(
        url="https://broken.example/",
        state="unreachable",
        error="ConnectError: Name or service not known",
    )
    report = ScanReport(model="test/model", tool_version="0.2.0")
    report.results = [
        ScanResult(
            url="https://example.com/admin",
            capture=capture,
            status_check=redirect,
            analysis=analysis,
        ),
        ScanResult(
            url="https://broken.example/",
            status_check=unreachable,
            error="net::ERR_NAME_NOT_RESOLVED",
        ),
    ]
    return report


def test_severity_ordering():
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.MEDIUM.rank
    assert Severity.LOW.rank > Severity.INFO.rank
    assert max([Severity.LOW, Severity.CRITICAL, Severity.INFO], key=lambda s: s.rank) is Severity.CRITICAL


def test_severity_parse_handles_aliases_and_junk():
    assert Severity.parse("HIGH") is Severity.HIGH
    assert Severity.parse("informational") is Severity.INFO
    assert Severity.parse(None, Severity.MEDIUM) is Severity.MEDIUM
    assert Severity.parse("nonsense") is Severity.INFO


def test_report_aggregates_severity():
    report = make_report()
    assert report.max_severity is Severity.CRITICAL
    counts = report.severity_counts()
    assert counts["critical"] == 1
    assert counts["medium"] == 1
    assert counts["low"] == 0
    assert len(report.failed) == 1


def test_json_report_roundtrips(tmp_path):
    path = write_json_report(make_report(), tmp_path / "report.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["target_count"] == 2
    assert data["max_severity"] == "critical"
    assert data["results"][0]["analysis"]["findings"][0]["severity"] == "critical"
    assert "raw_response" not in data["results"][0]["analysis"]


def test_json_report_can_include_raw(tmp_path):
    report = make_report()
    report.results[0].analysis.raw_response = "{}"
    path = write_json_report(report, tmp_path / "raw.json", include_raw=True)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["results"][0]["analysis"]["raw_response"] == "{}"


def test_html_report_escapes_model_supplied_text(tmp_path):
    html_out = render_html(make_report(), tmp_path, embed_images=True)
    assert "<script>alert" not in html_out
    assert "&lt;script&gt;alert" in html_out
    assert "Admin &lt;console&gt;" in html_out
    # A missing screenshot must not break rendering.
    assert "<figure>" not in html_out
    assert "net::ERR_NAME_NOT_RESOLVED" in html_out


def test_html_embeds_screenshot_when_present(tmp_path):
    png = tmp_path / "shot.png"
    png.write_bytes(b"\x89PNG\r\n\x1a\n")
    report = make_report()
    report.results[0].capture.screenshot_path = str(png)
    html_out = render_html(report, tmp_path, embed_images=True)
    assert "data:image/png;base64," in html_out

    linked = render_html(report, tmp_path, embed_images=False)
    assert 'src="shot.png"' in linked


def test_report_aggregates_status_checks():
    report = make_report()

    counts = report.status_counts()
    assert counts["redirect"] == 1
    assert counts["unreachable"] == 1
    assert counts["ok"] == 0
    assert report.status_checked is True
    # The redirect landed on 200, so only the unreachable target is a failure.
    assert [r.url for r in report.status_failures] == ["https://broken.example/"]


def test_json_report_carries_the_status_check(tmp_path):
    path = write_json_report(make_report(), tmp_path / "report.json")
    data = json.loads(path.read_text(encoding="utf-8"))

    status = data["results"][0]["status_check"]
    assert status["state"] == "redirect"
    assert status["ok"] is True
    assert status["first_status"] == 301
    assert status["final_status"] == 200
    assert status["redirect_count"] == 1
    assert [hop["status"] for hop in status["chain"]] == [301, 200]
    assert data["status_counts"]["redirect"] == 1
    assert data["results"][1]["status_check"]["state"] == "unreachable"


def test_json_report_omits_the_status_check_when_it_did_not_run(tmp_path):
    report = make_report()
    for result in report.results:
        result.status_check = None

    data = json.loads(
        write_json_report(report, tmp_path / "report.json").read_text(encoding="utf-8")
    )

    assert data["results"][0]["status_check"] is None
    assert data["status_counts"]["ok"] == 0


def test_html_shows_the_status_pill_and_the_redirect_chain(tmp_path):
    html_out = render_html(make_report(), tmp_path, embed_images=True)

    assert "301-&gt;200 redirect" in html_out
    assert '<ol class="chain">' in html_out
    assert "unreachable" in html_out


def test_html_escapes_the_location_header(tmp_path):
    html_out = render_html(make_report(), tmp_path, embed_images=True)

    assert '"><script>alert' not in html_out
    assert "&lt;script&gt;alert" in html_out


def test_html_omits_the_status_block_when_no_check_ran(tmp_path):
    report = make_report()
    for result in report.results:
        result.status_check = None

    html_out = render_html(report, tmp_path, embed_images=True)

    assert '<span class="status"' not in html_out
    assert '<ol class="chain">' not in html_out


def test_console_report_prints_the_status_line_and_summary():
    stream = io.StringIO()
    write_console_report(make_report(), stream=stream, color=False)
    out = stream.getvalue()

    assert "status: 301->200 redirect" in out
    assert "1 hop" in out
    assert "status: unreachable" in out
    assert "Status checks:" in out
    assert "1 target(s) did not return an expected status:" in out
    assert "ConnectError: Name or service not known" in out


def test_console_report_omits_the_status_block_when_no_check_ran():
    report = make_report()
    for result in report.results:
        result.status_check = None
    stream = io.StringIO()

    write_console_report(report, stream=stream, color=False)

    assert "Status checks:" not in stream.getvalue()
