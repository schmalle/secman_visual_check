"""Tests for the SecMan upload path: mapping, de-duplication, both transports."""

import json

import httpx
import pytest

from secman_visual_check.cli import build_parser, build_secman_options
from secman_visual_check.models import (
    Analysis,
    Finding,
    PageCapture,
    ScanReport,
    ScanResult,
    Severity,
)
from secman_visual_check.secman import (
    DEFAULT_ID_PREFIX,
    HttpUploader,
    McpUploader,
    SecmanError,
    SecmanOptions,
    UploadItem,
    asset_name,
    build_items,
    load_report_json,
    merge_duplicates,
    upload_findings,
    vulnerability_id,
    write_upload_report,
)


def make_report(*results: ScanResult) -> ScanReport:
    return ScanReport(results=list(results), model="test-model", tool_version="0.0.0")


def make_result(url: str, *findings: Finding, risk: Severity = Severity.HIGH) -> ScanResult:
    return ScanResult(
        url=url,
        capture=PageCapture(url=url, status=200, screenshot_path="shot.png"),
        analysis=Analysis(risk_level=risk, summary="s", findings=list(findings)),
    )


def finding(category: str, severity: Severity, title: str = "t") -> Finding:
    return Finding(category=category, severity=severity, title=title, confidence=0.9)


# --------------------------------------------------------------------------- #
# Mapping
# --------------------------------------------------------------------------- #


def test_asset_name_is_the_host_without_port():
    assert asset_name("https://Web-01.example.com:8443/admin") == "web-01.example.com"


def test_asset_name_override_wins():
    assert asset_name("https://a.example.com/", "inventory-name") == "inventory-name"


def test_asset_name_rejects_hostless_url():
    with pytest.raises(SecmanError):
        asset_name("not a url")


def test_vulnerability_id_is_stable_and_readable():
    first = vulnerability_id("https://example.com/admin", "unauthenticated_admin")
    second = vulnerability_id("https://example.com/admin", "unauthenticated_admin")
    assert first == second
    assert first.startswith(f"{DEFAULT_ID_PREFIX}-UNAUTHENTICATED-ADMIN-")


def test_vulnerability_id_varies_with_page_port_query_and_category():
    base = vulnerability_id("https://example.com/admin", "unauthenticated_admin")
    assert base != vulnerability_id("https://example.com/other", "unauthenticated_admin")
    assert base != vulnerability_id("https://example.com:8443/admin", "unauthenticated_admin")
    assert base != vulnerability_id("https://example.com/admin?x=1", "unauthenticated_admin")
    assert base != vulnerability_id("https://example.com/admin", "directory_listing")


def test_vulnerability_id_ignores_model_wording():
    """The model rephrases findings every run; the id must not move with it."""
    report_a = make_report(make_result("https://example.com/a", finding("debug_output", Severity.HIGH, "Stack trace")))
    report_b = make_report(make_result("https://example.com/a", finding("debug_output", Severity.HIGH, "Traceback shown")))
    (a,), _ = build_items(report_a)
    (b,), _ = build_items(report_b)
    assert a.vulnerability_id == b.vulnerability_id


def test_build_items_maps_severity_to_criticality_and_applies_threshold():
    report = make_report(
        make_result(
            "https://example.com/x",
            finding("exposed_credentials", Severity.CRITICAL),
            finding("open_api_surface", Severity.MEDIUM),
            finding("error_page", Severity.INFO),
        )
    )
    items, dropped = build_items(report, min_severity=Severity.MEDIUM)
    assert dropped == 1
    assert {i.criticality for i in items} == {"CRITICAL", "MEDIUM"}


def test_build_items_maps_info_and_low_onto_low():
    report = make_report(
        make_result("https://example.com/x", finding("error_page", Severity.INFO))
    )
    items, _ = build_items(report, min_severity=Severity.INFO)
    assert items[0].criticality == "LOW"


def test_build_items_accepts_a_parsed_json_report():
    report = make_report(
        make_result("https://example.com/x", finding("directory_listing", Severity.HIGH))
    )
    from_object, _ = build_items(report)
    from_json, _ = build_items(json.loads(json.dumps(report.to_dict())))
    assert [i.key for i in from_object] == [i.key for i in from_json]


def test_build_items_skips_results_without_analysis_or_title():
    report = make_report(
        ScanResult(url="https://example.com/dead", error="boom"),
        make_result("https://example.com/x", Finding(category="c", severity=Severity.HIGH, title="")),
    )
    items, _ = build_items(report)
    assert items == []


def test_build_items_rejects_a_non_report():
    with pytest.raises(SecmanError):
        build_items({"nope": True})


# --------------------------------------------------------------------------- #
# De-duplication
# --------------------------------------------------------------------------- #


def test_merge_duplicates_keeps_the_worst_severity():
    report = make_report(
        make_result(
            "https://example.com/admin",
            finding("exposed_credentials", Severity.MEDIUM, "first"),
            finding("exposed_credentials", Severity.CRITICAL, "second"),
        )
    )
    items, _ = build_items(report)
    merged, count = merge_duplicates(items)
    assert count == 1
    assert len(merged) == 1
    assert merged[0].criticality == "CRITICAL"


def test_distinct_pages_on_one_host_are_not_merged():
    report = make_report(
        make_result("https://example.com/a", finding("debug_output", Severity.HIGH)),
        make_result("https://example.com/b", finding("debug_output", Severity.HIGH)),
    )
    merged, count = merge_duplicates(build_items(report)[0])
    assert count == 0
    assert len(merged) == 2


def test_asset_override_merges_findings_across_hosts():
    """Filing everything under one asset makes same-category findings collide."""
    report = make_report(
        make_result("https://a.example.com/admin", finding("unauthenticated_admin", Severity.HIGH)),
        make_result("https://b.example.com/admin", finding("unauthenticated_admin", Severity.HIGH)),
    )
    items, _ = build_items(report, asset_override="shared-asset")
    assert len({i.hostname for i in items}) == 1
    # Different hosts still hash to different ids, so both rows survive.
    assert len(merge_duplicates(items)[0]) == 2


# --------------------------------------------------------------------------- #
# Fake uploader — orchestration behaviour
# --------------------------------------------------------------------------- #


class FakeUploader:
    transport = "fake"
    endpoint = "fake://secman"

    def __init__(self, existing=(), fail_on=(), lookup_error=None):
        self.existing = set(existing)
        self.fail_on = set(fail_on)
        self.lookup_error = lookup_error
        self.uploaded: list[UploadItem] = []
        self.connected = False
        self.closed = False

    def connect(self):
        self.connected = True

    def existing_vulnerability_ids(self, hostnames, id_prefix):
        if self.lookup_error:
            raise SecmanError(self.lookup_error)
        return {k for k in self.existing if k[0] in {h.lower() for h in hostnames}}

    def upload(self, item, owner):
        if item.vulnerability_id in self.fail_on:
            raise SecmanError("rejected")
        self.uploaded.append(item)
        return "created", "ok"

    def close(self):
        self.closed = True


def two_finding_report() -> ScanReport:
    return make_report(
        make_result("https://example.com/admin", finding("unauthenticated_admin", Severity.CRITICAL)),
        make_result("https://example.com/backup/", finding("directory_listing", Severity.HIGH)),
    )


def test_upload_writes_each_unique_finding_once():
    fake = FakeUploader()
    summary = upload_findings(two_finding_report(), SecmanOptions(), fake)
    assert fake.connected
    assert summary.count("created") == 2
    assert len(fake.uploaded) == 2


def test_upload_skips_findings_secman_already_holds():
    report = two_finding_report()
    items, _ = build_items(report)
    fake = FakeUploader(existing={items[0].key})
    summary = upload_findings(report, SecmanOptions(), fake)
    assert summary.count("skipped") == 1
    assert summary.count("created") == 1
    assert items[0].vulnerability_id not in {i.vulnerability_id for i in fake.uploaded}


def test_allow_existing_re_sends_everything():
    report = two_finding_report()
    items, _ = build_items(report)
    fake = FakeUploader(existing={i.key for i in items})
    summary = upload_findings(report, SecmanOptions(allow_existing=True), fake)
    assert summary.count("created") == 2


def test_a_failed_lookup_degrades_to_the_backend_upsert():
    fake = FakeUploader(lookup_error="listing blew up")
    summary = upload_findings(two_finding_report(), SecmanOptions(), fake)
    assert "listing blew up" in (summary.existing_lookup_error or "")
    assert summary.count("created") == 2


def test_dry_run_writes_nothing_but_still_reports_the_payloads():
    fake = FakeUploader()
    summary = upload_findings(two_finding_report(), SecmanOptions(dry_run=True), fake)
    assert fake.uploaded == []
    assert summary.dry_run
    assert summary.count("planned") == 2
    assert summary.count("created") == 0
    assert {o.detail for o in summary.outcomes} == {"would be uploaded"}


def test_dry_run_still_flags_findings_that_already_exist():
    report = two_finding_report()
    items, _ = build_items(report)
    fake = FakeUploader(existing={items[0].key})
    summary = upload_findings(report, SecmanOptions(dry_run=True), fake)
    details = {o.item.vulnerability_id: o.detail for o in summary.outcomes}
    assert details[items[0].vulnerability_id] == "already present in SecMan"
    assert fake.uploaded == []


def test_dry_run_without_credentials_never_builds_a_client():
    """The offline mode: no network at all, yet the payloads still print."""
    summary = upload_findings(two_finding_report(), SecmanOptions(dry_run=True))
    assert summary.count("planned") == 2
    assert "not contacted" in summary.endpoint


def test_per_item_failures_do_not_stop_the_rest():
    report = two_finding_report()
    items, _ = build_items(report)
    fake = FakeUploader(fail_on={items[0].vulnerability_id})
    summary = upload_findings(report, SecmanOptions(), fake)
    assert summary.count("failed") == 1
    assert summary.count("created") == 1
    assert summary.failures[0].detail == "rejected"


def test_summary_counts_merged_and_filtered_findings():
    report = make_report(
        make_result(
            "https://example.com/a",
            finding("debug_output", Severity.HIGH, "one"),
            finding("debug_output", Severity.CRITICAL, "two"),
            finding("error_page", Severity.INFO, "three"),
        )
    )
    summary = upload_findings(report, SecmanOptions(), FakeUploader())
    assert summary.merged == 1
    assert summary.below_threshold == 1
    assert summary.count("created") == 1
    assert summary.to_dict()["counts"]["created"] == 1


def test_write_upload_report_renders(capsys):
    summary = upload_findings(two_finding_report(), SecmanOptions(), FakeUploader())
    write_upload_report(summary)
    out = capsys.readouterr().out
    assert "SecMan upload — http — fake://secman" in out
    assert "2 created" in out


# --------------------------------------------------------------------------- #
# HTTP transport
# --------------------------------------------------------------------------- #


def http_uploader(handler, **kwargs) -> HttpUploader:
    client = httpx.Client(
        base_url="https://secman.test",
        transport=httpx.MockTransport(handler),
        headers={"Accept": "application/json"},
    )
    return HttpUploader("https://secman.test", client=client, max_retries=0, **kwargs)


def test_http_login_then_upload():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        if request.url.path == "/api/auth/login":
            return httpx.Response(200, json={"id": 1, "username": "bot", "roles": ["VULN"]})
        assert request.url.path == "/api/vulnerabilities/cli-add"
        body = json.loads(request.content)
        assert body == {
            "hostname": "example.com",
            "cve": "X-1",
            "criticality": "HIGH",
            "daysOpen": 0,
            "owner": "me",
        }
        return httpx.Response(200, json={"operation": "CREATED", "message": "added"})

    uploader = http_uploader(handler, username="bot", password="pw")
    uploader.connect()
    item = UploadItem("example.com", "X-1", "HIGH", Severity.HIGH, "https://example.com/", "c", "t")
    assert uploader.upload(item, "me") == ("created", "added")
    assert seen == ["/api/auth/login", "/api/vulnerabilities/cli-add"]


def test_http_token_auth_skips_login():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path != "/api/auth/login"
        assert request.headers["Authorization"] == "Bearer jwt-123"
        return httpx.Response(200, json={"operation": "UPDATED", "message": "refreshed"})

    uploader = HttpUploader("https://secman.test", token="jwt-123", max_retries=0)
    uploader._client = httpx.Client(
        base_url="https://secman.test",
        transport=httpx.MockTransport(handler),
        headers={"Authorization": "Bearer jwt-123"},
    )
    uploader.connect()
    item = UploadItem("h", "X-1", "LOW", Severity.LOW, "https://h/", "c", "t")
    assert uploader.upload(item, "me") == ("updated", "refreshed")


def test_http_login_reports_mfa_clearly():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"mfaRequired": True, "username": "bot"})

    uploader = http_uploader(handler, username="bot", password="pw")
    with pytest.raises(SecmanError, match="MFA"):
        uploader.connect()


def test_http_login_failure_surfaces_the_server_message():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "Invalid credentials"})

    uploader = http_uploader(handler, username="bot", password="bad")
    with pytest.raises(SecmanError, match="Invalid credentials"):
        uploader.connect()


def test_http_existing_ids_paginate_and_ignore_other_hosts():
    """`system` is a substring filter, so sibling hostnames come back too."""
    pages = {
        0: {
            "content": [
                {"assetName": "example.com", "vulnerabilityId": "X-1"},
                {"assetName": "other.example.com", "vulnerabilityId": "X-9"},
            ],
            "hasNext": True,
        },
        1: {
            "content": [{"assetName": "Example.com", "vulnerabilityId": "X-2"}],
            "hasNext": False,
        },
    }
    asked = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/vulnerabilities/current"
        params = dict(request.url.params)
        asked.append(params)
        return httpx.Response(200, json=pages[int(params["page"])])

    uploader = http_uploader(handler)
    found = uploader.existing_vulnerability_ids(["example.com"], DEFAULT_ID_PREFIX)
    assert found == {("example.com", "X-1"), ("example.com", "X-2")}
    # Excepted findings must be visible, or they get re-uploaded every run.
    assert asked[0]["exceptionStatus"] == "all"


def test_http_upload_error_is_reported_not_raised_through():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": "Criticality must be CRITICAL, HIGH, MEDIUM, or LOW"})

    uploader = http_uploader(handler)
    item = UploadItem("h", "X-1", "BOGUS", Severity.HIGH, "https://h/", "c", "t")
    with pytest.raises(SecmanError, match="Criticality must be"):
        uploader.upload(item, "me")


def test_http_endpoint_is_the_cli_add_path():
    assert HttpUploader("https://secman.test/", token="t").endpoint == (
        "https://secman.test/api/vulnerabilities/cli-add"
    )


# --------------------------------------------------------------------------- #
# MCP transport
# --------------------------------------------------------------------------- #


def mcp_uploader(handler) -> McpUploader:
    uploader = McpUploader(
        "https://secman.test", api_key="sk-test", user_email="bot@example.com", max_retries=0
    )
    uploader._client = httpx.Client(
        base_url="https://secman.test",
        transport=httpx.MockTransport(handler),
        headers={
            "X-MCP-API-Key": "sk-test",
            "X-MCP-User-Email": "bot@example.com",
        },
    )
    return uploader


def tool_result(payload) -> dict:
    """Mirror how SecMan wraps a tool result: JSON inside a single text block."""
    return {"content": [{"type": "text", "text": json.dumps(payload)}], "isError": False}


def test_mcp_handshake_then_tool_call():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/mcp"
        assert request.headers["X-MCP-API-Key"] == "sk-test"
        assert request.headers["X-MCP-User-Email"] == "bot@example.com"
        body = json.loads(request.content)
        calls.append(body["method"])
        assert body["jsonrpc"] == "2.0"
        if body["method"] == "initialize":
            assert body["params"]["protocolVersion"] == "2024-11-05"
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": {}})
        if body["method"] == "notifications/initialized":
            assert "id" not in body
            return httpx.Response(204)
        assert body["method"] == "tools/call"
        assert body["params"]["name"] == "add_vulnerability"
        assert body["params"]["arguments"] == {
            "hostname": "example.com",
            "cve": "X-1",
            "criticality": "HIGH",
            "daysOpen": 0,
            "owner": "me",
        }
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": body["id"],
                "result": tool_result({"vulnerabilityCreated": True, "message": "added"}),
            },
        )

    uploader = mcp_uploader(handler)
    uploader.connect()
    item = UploadItem("example.com", "X-1", "HIGH", Severity.HIGH, "https://example.com/", "c", "t")
    assert uploader.upload(item, "me") == ("created", "added")
    assert calls == ["initialize", "notifications/initialized", "tools/call"]


def test_mcp_reports_an_updated_row_as_updated():
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": body["id"],
                "result": tool_result({"vulnerabilityCreated": False, "message": "updated"}),
            },
        )

    item = UploadItem("h", "X-1", "LOW", Severity.LOW, "https://h/", "c", "t")
    assert mcp_uploader(handler).upload(item, "me") == ("updated", "updated")


def test_mcp_existing_ids_filter_by_prefix_and_host():
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        args = body["params"]["arguments"]
        assert args["cveId"] == DEFAULT_ID_PREFIX
        # Excepted rows still occupy the (asset, cve) slot.
        assert args["includeExcepted"] is True
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": body["id"],
                "result": tool_result(
                    {
                        "vulnerabilities": [
                            {"assetName": "example.com", "vulnerabilityId": "X-1"},
                            {"assetName": "elsewhere.test", "vulnerabilityId": "X-2"},
                        ],
                        "totalPages": 1,
                    }
                ),
            },
        )

    found = mcp_uploader(handler).existing_vulnerability_ids(["example.com"], DEFAULT_ID_PREFIX)
    assert found == {("example.com", "X-1")}


def test_mcp_jsonrpc_error_becomes_a_secman_error():
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": body["id"],
                "error": {"code": -32000, "message": "DELEGATION_HEADER_REQUIRED"},
            },
        )

    item = UploadItem("h", "X-1", "LOW", Severity.LOW, "https://h/", "c", "t")
    with pytest.raises(SecmanError, match="DELEGATION_HEADER_REQUIRED"):
        mcp_uploader(handler).upload(item, "me")


def test_mcp_tool_error_flag_is_honoured():
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": body["id"],
                "result": {"content": [{"type": "text", "text": "{}"}], "isError": True},
            },
        )

    item = UploadItem("h", "X-1", "LOW", Severity.LOW, "https://h/", "c", "t")
    with pytest.raises(SecmanError, match="reported an error"):
        mcp_uploader(handler).upload(item, "me")


def test_mcp_endpoint_is_not_doubled_when_url_already_ends_in_mcp():
    assert McpUploader("https://secman.test/mcp", api_key="k", user_email="e").endpoint == (
        "https://secman.test/mcp"
    )


# --------------------------------------------------------------------------- #
# CLI wiring
# --------------------------------------------------------------------------- #


def parse(argv):
    return build_parser().parse_args(argv)


def test_cli_defaults_and_env_resolution(monkeypatch):
    monkeypatch.setenv("SECMAN_URL", "https://secman.internal")
    monkeypatch.setenv("SECMAN_TOKEN", "jwt-env")
    options = build_secman_options(parse(["--secman-upload", "https://example.com"]))
    assert options.transport == "http"
    assert options.base_url == "https://secman.internal"
    assert options.token == "jwt-env"
    assert options.min_severity is Severity.MEDIUM


def test_cli_flags_beat_the_environment(monkeypatch):
    monkeypatch.setenv("SECMAN_TOKEN", "jwt-env")
    options = build_secman_options(
        parse(["--secman-upload", "--secman-token", "jwt-flag", "https://example.com"])
    )
    assert options.token == "jwt-flag"


def test_mcp_key_does_not_come_from_the_model_api_key_variable(monkeypatch):
    """SECMAN_API_KEY is the vision model's key — it must not leak into MCP auth."""
    monkeypatch.setenv("SECMAN_API_KEY", "model-key")
    monkeypatch.setenv("SECMAN_MCP_API_KEY", "sk-mcp")
    monkeypatch.setenv("SECMAN_MCP_USER_EMAIL", "bot@example.com")
    options = build_secman_options(
        parse(["--secman-upload", "--secman-transport", "mcp", "https://example.com"])
    )
    assert options.api_key == "sk-mcp"


@pytest.mark.parametrize(
    "argv, message",
    [
        (["--secman-upload", "https://example.com"], "--secman-token"),
        (
            ["--secman-upload", "--secman-transport", "mcp", "https://example.com"],
            "--secman-api-key",
        ),
    ],
)
def test_missing_credentials_are_rejected_up_front(monkeypatch, argv, message):
    for var in (
        "SECMAN_TOKEN",
        "SECMAN_USERNAME",
        "SECMAN_PASSWORD",
        "SECMAN_MCP_API_KEY",
        "SECMAN_MCP_USER_EMAIL",
    ):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(ValueError, match=message):
        build_secman_options(parse(argv))


def test_dry_run_does_not_require_credentials(monkeypatch):
    for var in ("SECMAN_TOKEN", "SECMAN_USERNAME", "SECMAN_MCP_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    options = build_secman_options(
        parse(["--secman-upload", "--secman-dry-run", "https://example.com"])
    )
    assert options.dry_run and not options.has_credentials


def test_main_uploads_a_stored_report(tmp_path, monkeypatch, capsys):
    from secman_visual_check import cli

    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(two_finding_report().to_dict()), encoding="utf-8")

    fake = FakeUploader()
    monkeypatch.setattr(SecmanOptions, "build_uploader", lambda self: fake)

    code = cli.main(
        [
            "--secman-upload-report",
            str(report_path),
            "--secman-token",
            "jwt",
        ]
    )
    assert code == 0
    assert len(fake.uploaded) == 2
    assert "2 created" in capsys.readouterr().out


def test_main_upload_report_needs_no_targets(tmp_path, monkeypatch):
    from secman_visual_check import cli

    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(make_report().to_dict()), encoding="utf-8")
    monkeypatch.setattr(SecmanOptions, "build_uploader", lambda self: FakeUploader())
    assert cli.main(["--secman-upload-report", str(report_path), "--secman-token", "j"]) == 0


def test_main_reports_a_missing_report_file(tmp_path, capsys):
    from secman_visual_check import cli

    code = cli.main(
        ["--secman-upload-report", str(tmp_path / "nope.json"), "--secman-token", "j"]
    )
    assert code == 2
    assert "cannot read" in capsys.readouterr().err


def test_fail_on_error_changes_the_exit_code(tmp_path, monkeypatch):
    from secman_visual_check import cli

    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(two_finding_report().to_dict()), encoding="utf-8")
    items, _ = build_items(two_finding_report())
    fake = FakeUploader(fail_on={i.vulnerability_id for i in items})
    monkeypatch.setattr(SecmanOptions, "build_uploader", lambda self: fake)

    argv = ["--secman-upload-report", str(report_path), "--secman-token", "j"]
    assert cli.main(argv) == 0
    assert cli.main(argv + ["--secman-fail-on-error"]) == 2


def test_load_report_json_rejects_a_non_object(tmp_path):
    path = tmp_path / "r.json"
    path.write_text("[1, 2]", encoding="utf-8")
    with pytest.raises(SecmanError, match="scan report object"):
        load_report_json(path)
