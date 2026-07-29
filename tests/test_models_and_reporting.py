import csv
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
    report_statistics,
    write_console_report,
    write_csv_report,
    write_json_report,
    write_stats_report,
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


def test_console_report_prints_statistics():
    stream = io.StringIO()
    write_console_report(make_report(), stream=stream, color=False)
    out = stream.getvalue()

    assert "Statistics:" in out
    assert "targets" in out
    assert "findings" in out
    assert "answered HTTP 200" in out
    assert "answered another code" in out


def test_console_statistics_hide_the_expected_row_when_it_equals_the_200_count():
    """--status-expect defaults to 200, so the two rows would say the same thing."""
    stream = io.StringIO()
    write_console_report(make_report(), stream=stream, color=False)

    assert "answering as expected" not in statistics_block(stream.getvalue())


def test_console_statistics_show_the_expected_row_when_it_diverges():
    report = make_report()
    # A tolerated 403 is "expected" but is not a 200 — now the rows differ.
    report.results[1].status_check.final_status = 403
    report.results[1].status_check.expected_statuses = (200, 403)

    stream = io.StringIO()
    write_console_report(report, stream=stream, color=False)

    assert "answering as expected" in statistics_block(stream.getvalue())


def test_console_statistics_can_be_suppressed():
    stream = io.StringIO()
    write_console_report(make_report(), stream=stream, color=False, statistics=False)

    assert "Statistics:" not in stream.getvalue()


def statistics_block(text: str) -> str:
    """Just the Statistics section — 'captured' also occurs in failure lines."""
    _, _, tail = text.partition("Statistics:")
    return tail.split("\n\n")[0]


def test_console_statistics_omit_capture_rows_for_a_status_only_run():
    report = make_report()
    for result in report.results:
        result.capture = None
    stream = io.StringIO()

    write_console_report(report, stream=stream, color=False)
    block = statistics_block(stream.getvalue())

    assert "targets" in block
    assert "captured" not in block
    assert "answered HTTP 200" in block


def test_console_report_omits_the_status_block_when_no_check_ran():
    report = make_report()
    for result in report.results:
        result.status_check = None
    stream = io.StringIO()

    write_console_report(report, stream=stream, color=False)

    assert "Status checks:" not in stream.getvalue()


# --------------------------------------------------------------------------- #
# CSV report
# --------------------------------------------------------------------------- #


def read_csv(path):
    with open(path, newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def test_csv_report_has_one_row_per_target(tmp_path):
    rows = read_csv(write_csv_report(make_report(), tmp_path / "report.csv"))

    assert [row["url"] for row in rows] == [
        "https://example.com/admin",
        "https://broken.example/",
    ]


def test_csv_report_carries_status_capture_and_findings(tmp_path):
    rows = read_csv(write_csv_report(make_report(), tmp_path / "report.csv"))
    first, second = rows

    assert first["status_state"] == "redirect"
    assert first["status_ok"] == "true"
    assert first["first_status"] == "301"
    assert first["final_status"] == "200"
    assert first["redirect_count"] == "1"
    assert first["http_status"] == "200"
    assert first["max_severity"] == "critical"
    assert first["findings"] == "2"
    # Categories are what a triage spreadsheet actually filters on.
    assert first["categories"] == "infrastructure_disclosure;unauthenticated_admin"
    assert first["page_type"] == "admin panel"

    assert second["status_state"] == "unreachable"
    assert second["status_ok"] == "false"
    assert second["error"] == "net::ERR_NAME_NOT_RESOLVED"
    assert second["findings"] == "0"


def test_csv_report_survives_a_status_only_run(tmp_path):
    """--no-visual-check leaves no capture and no analysis; the CSV still writes."""
    report = make_report()
    for result in report.results:
        result.capture = None
        result.analysis = None

    rows = read_csv(write_csv_report(report, tmp_path / "report.csv"))

    assert len(rows) == 2
    assert rows[0]["status_state"] == "redirect"
    assert rows[0]["http_status"] == ""
    assert rows[0]["title"] == ""
    assert rows[0]["findings"] == "0"
    assert rows[0]["max_severity"] == "info"


def test_csv_report_neutralises_spreadsheet_formulas(tmp_path):
    """Page and model text lands in a spreadsheet; it must not become a formula."""
    report = make_report()
    report.results[0].capture.title = '=HYPERLINK("http://evil.test","click")'
    report.results[0].analysis.summary = "+1+1"
    report.results[0].analysis.page_type = "-nope"

    rows = read_csv(write_csv_report(report, tmp_path / "report.csv"))

    assert rows[0]["title"].startswith("'=")
    assert rows[0]["summary"].startswith("'+")
    assert rows[0]["page_type"].startswith("'-")


# --------------------------------------------------------------------------- #
# Statistics report
# --------------------------------------------------------------------------- #


def test_statistics_aggregate_the_run():
    stats = report_statistics(make_report())

    assert stats["targets"] == 2
    assert stats["captured"] == 1
    assert stats["capture_failed"] == 1
    assert stats["analysed"] == 1
    assert stats["targets_with_findings"] == 1
    assert stats["findings_total"] == 2
    assert stats["severity_counts"]["critical"] == 1
    assert stats["status_checked"] == 2
    assert stats["status_ok"] == 1
    assert stats["status_failed"] == 1
    assert stats["status_counts"]["unreachable"] == 1


def make_mixed_status_report() -> ScanReport:
    """A fleet answering a spread of codes, plus one host that never answered."""
    codes = [200, 200, 200, 403, 404, 404, 500, None]
    report = ScanReport(model="test/model")
    report.results = [
        ScanResult(
            url=f"https://host{i}.example/",
            status_check=UrlStatus(
                url=f"https://host{i}.example/",
                state="ok" if code == 200 else ("unreachable" if code is None else "client_error"),
                first_status=code,
                final_status=code,
            ),
        )
        for i, code in enumerate(codes)
    ]
    return report


def test_status_code_counts_split_200_from_everything_else():
    counts = make_mixed_status_report().status_code_counts()

    assert counts["200"] == 3
    assert counts["404"] == 2
    assert counts["403"] == 1
    assert counts["500"] == 1
    assert counts["none"] == 1


def test_statistics_headline_the_200_versus_other_split():
    stats = report_statistics(make_mixed_status_report())

    assert stats["answered_200"] == 3
    assert stats["answered_other"] == 4
    assert stats["no_response"] == 1
    # Every checked target lands in exactly one of the three.
    assert stats["answered_200"] + stats["answered_other"] + stats["no_response"] == 8


def test_200_split_ignores_status_expect():
    """--status-expect 200,401 makes a 401 'expected'; it is still not a 200."""
    report = make_mixed_status_report()
    for result in report.results:
        if result.status_check.final_status == 403:
            result.status_check.expected_statuses = (200, 403)

    stats = report_statistics(report)

    assert stats["status_ok"] == 4  # three 200s plus the tolerated 403
    assert stats["answered_200"] == 3
    assert stats["answered_other"] == 4


def test_console_lists_each_status_code():
    stream = io.StringIO()
    write_console_report(make_mixed_status_report(), stream=stream, color=False)
    out = stream.getvalue()

    assert "HTTP status codes:" in out
    assert "HTTP 200" in out
    assert "HTTP 404" in out
    assert "no response" in out
    assert "answered another code" in out


def test_json_report_carries_the_status_code_counts(tmp_path):
    data = json.loads(
        write_json_report(
            make_mixed_status_report(), tmp_path / "report.json"
        ).read_text(encoding="utf-8")
    )

    assert data["status_code_counts"]["200"] == 3
    assert data["status_code_counts"]["none"] == 1


def test_stats_file_breaks_down_the_status_codes(tmp_path):
    text = write_stats_report(
        make_mixed_status_report(), tmp_path / "statistics.txt"
    ).read_text(encoding="utf-8")

    assert "HTTP status codes" in text
    assert "answered HTTP 200" in text
    assert "answered another code" in text


def test_statistics_count_checksummed_bodies():
    report = make_report()
    report.results[0].status_check.content_checksum = "a" * 64
    report.results[0].status_check.content_length = 2048

    stats = report_statistics(report)

    assert stats["checksummed"] == 1
    assert stats["bytes_hashed"] == 2048


def test_stats_report_is_readable_text(tmp_path):
    path = write_stats_report(make_report(), tmp_path / "statistics.txt")
    text = path.read_text(encoding="utf-8")

    assert "Targets" in text
    assert "Findings by severity" in text
    assert "Status checks" in text
    assert "critical" in text
    assert "test/model" in text
    # Percentages make the counts comparable between runs of different sizes.
    assert "%" in text


def test_stats_report_omits_the_capture_block_for_a_status_only_run(tmp_path):
    report = make_report()
    for result in report.results:
        result.capture = None

    text = write_stats_report(report, tmp_path / "statistics.txt").read_text(encoding="utf-8")

    assert "Capture\n" not in text
    assert "Status checks" in text


def test_stats_report_handles_an_empty_run(tmp_path):
    """No targets means no divisions — the percentage maths must not blow up."""
    path = write_stats_report(ScanReport(model="test/model"), tmp_path / "statistics.txt")

    assert "Targets" in path.read_text(encoding="utf-8")
