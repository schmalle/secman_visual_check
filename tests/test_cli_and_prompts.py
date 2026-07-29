import json

import pytest

from secman_visual_check.categories import DEFAULT_CATEGORIES, load_categories
from secman_visual_check.cli import (
    _progress_hook,
    build_config,
    build_db_options,
    build_parser,
    build_secman_options,
    main,
    parse_headers,
    parse_status_list,
    parse_viewport,
)
from secman_visual_check.models import PageCapture, ScanResult, Severity, UrlStatus
from secman_visual_check.prompts import build_user_prompt


def parse(argv):
    return build_parser().parse_args(argv)


def test_parse_viewport_variants():
    assert parse_viewport("1280x720") == (1280, 720)
    assert parse_viewport("800,600") == (800, 600)
    with pytest.raises(Exception):
        parse_viewport("wide")


def test_parse_headers():
    assert parse_headers(["X-Token: abc", "Accept:text/html"]) == {
        "X-Token": "abc",
        "Accept": "text/html",
    }
    with pytest.raises(Exception):
        parse_headers(["nope"])


def test_build_config_reads_api_key_from_env(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test")
    monkeypatch.delenv("SECMAN_MODEL", raising=False)
    config = build_config(parse(["https://example.com", "-o", str(tmp_path)]))
    assert config.analyzer is not None
    assert config.analyzer.api_key == "sk-test"
    assert config.fail_on is Severity.HIGH
    assert config.screenshot_dir == tmp_path / "screenshots"


def test_no_ai_disables_the_analyzer(tmp_path):
    config = build_config(parse(["https://example.com", "--no-ai", "-o", str(tmp_path)]))
    assert config.analyzer is None


def test_fail_on_none_disables_the_gate(tmp_path):
    config = build_config(parse(["https://example.com", "--fail-on", "none", "-o", str(tmp_path)]))
    assert config.fail_on is None


def test_browser_options_are_wired_through(tmp_path):
    config = build_config(
        parse(
            [
                "https://example.com",
                "-o",
                str(tmp_path),
                "--viewport",
                "800x600",
                "--viewport-only",
                "--timeout",
                "5",
                "--settle",
                "0.5",
                "--insecure",
                "--basic-auth",
                "user:pw",
                "-H",
                "X-Env: staging",
            ]
        )
    )
    assert config.capture.viewport_width == 800
    assert config.capture.full_page is False
    assert config.capture.timeout_ms == 5000
    assert config.capture.settle_ms == 500
    assert config.capture.ignore_https_errors is True
    assert config.capture.basic_auth == ("user", "pw")
    assert config.capture.extra_headers == {"X-Env": "staging"}


def test_parse_status_list_accepts_codes_and_wildcards():
    assert parse_status_list("200") == (200,)
    assert parse_status_list("200, 401") == (200, 401)
    assert parse_status_list("2xx") == tuple(range(200, 300))
    assert parse_status_list("200,200") == (200,)


def test_parse_status_list_rejects_junk():
    for value in ("nope", "", "99", "600", "9xx"):
        with pytest.raises(Exception):
            parse_status_list(value)


def test_status_check_is_on_by_default(tmp_path):
    config = build_config(parse(["https://example.com", "-o", str(tmp_path)]))

    assert config.status_check.enabled is True
    assert config.status_check.method == "auto"
    assert config.status_check.expect_statuses == (200,)


def test_no_status_check_disables_it(tmp_path):
    config = build_config(
        parse(["https://example.com", "--no-status-check", "-o", str(tmp_path)])
    )
    assert config.status_check.enabled is False


def test_status_options_are_wired_through(tmp_path):
    config = build_config(
        parse(
            [
                "https://example.com",
                "-o",
                str(tmp_path),
                "--status-method",
                "get",
                "--status-timeout",
                "3.5",
                "--status-max-redirects",
                "2",
                "--status-expect",
                "200,401",
                "--status-concurrency",
                "16",
            ]
        )
    )

    assert config.status_check.method == "get"
    assert config.status_check.timeout_s == 3.5
    assert config.status_check.max_redirects == 2
    assert config.status_check.expect_statuses == (200, 401)
    assert config.status_check.max_concurrency == 16


def test_the_status_check_inherits_the_browser_identity(tmp_path):
    config = build_config(
        parse(
            [
                "https://example.com",
                "-o",
                str(tmp_path),
                "--insecure",
                "--user-agent",
                "scanner/1.0",
                "-H",
                "X-Env: staging",
                "--basic-auth",
                "user:pw",
            ]
        )
    )

    assert config.status_check.verify_tls is False
    assert config.status_check.user_agent == "scanner/1.0"
    assert config.status_check.extra_headers == {"X-Env": "staging"}
    assert config.status_check.basic_auth == ("user", "pw")


def test_progress_hook_prefixes_the_status(capsys):
    hook = _progress_hook(quiet=False)
    ok = ScanResult(
        url="https://example.com/",
        status_check=UrlStatus(url="https://example.com/", state="ok", first_status=200),
    )
    dead = ScanResult(
        url="https://dead.example/",
        status_check=UrlStatus(url="https://dead.example/", state="unreachable"),
        error="TimeoutError",
    )

    hook(ok, 1, 2)
    hook(dead, 2, 2)
    err = capsys.readouterr().err

    assert "[1/2] https://example.com/ -> 200 ok | info" in err
    assert "[2/2] https://dead.example/ -> unreachable | error: TimeoutError" in err


def test_progress_hook_without_a_status_check_is_unchanged(capsys):
    _progress_hook(quiet=False)(ScanResult(url="https://example.com/"), 1, 1)

    assert capsys.readouterr().err.strip() == "[1/1] https://example.com/ -> info"


def test_secman_status_flags_reach_the_options():
    options = build_secman_options(
        parse(
            [
                "https://example.com",
                "--secman-upload",
                "--secman-dry-run",
                "--secman-status-findings",
                "--secman-status-severity",
                "critical",
                "--secman-register-assets",
                "--secman-asset-type",
                "Network Host",
            ]
        )
    )

    assert options.status_findings is True
    assert options.status_severity is Severity.CRITICAL
    assert options.register_assets is True
    assert options.asset_type == "Network Host"


def test_secman_status_severity_auto_means_the_built_in_mapping():
    options = build_secman_options(
        parse(["https://example.com", "--secman-upload", "--secman-dry-run"])
    )
    assert options.status_severity is None


def test_db_options_default_to_disabled():
    options = build_db_options(parse(["https://example.com"]))

    assert options.enabled is False
    assert options.table_prefix == "svc_"


def test_db_url_is_parsed_and_flags_override_it():
    options = build_db_options(
        parse(
            [
                "https://example.com",
                "--db-store",
                "--db-url",
                "mysql://scanner:pw@db.internal:3307/results",
                "--db-table-prefix",
                "scan_",
                "--db-fail-on-error",
            ]
        )
    )

    assert options.enabled is True
    assert (options.host, options.port) == ("db.internal", 3307)
    assert options.database == "results"
    assert options.table_prefix == "scan_"
    assert options.fail_on_error is True


def test_db_options_come_from_the_environment(monkeypatch):
    monkeypatch.setenv("SECMAN_DB_STORE", "1")
    monkeypatch.setenv("SECMAN_DB_HOST", "db.example")
    monkeypatch.setenv("SECMAN_DB_USER", "scanner")
    monkeypatch.setenv("SECMAN_DB_NAME", "results")

    options = build_db_options(parse(["https://example.com"]))

    assert options.enabled is True
    assert options.host == "db.example"
    assert options.database == "results"


def test_db_credentials_are_validated_before_the_scan(capsys):
    # --db-store without a user is unusable; main must refuse before scanning.
    assert main(["https://example.com", "--db-store", "--no-ai"]) == 2
    assert "--db-user" in capsys.readouterr().err


def test_dry_run_prints_targets_and_exits_ok(capsys):
    code = main(["example.com", "https://example.org/x", "--dry-run"])
    assert code == 0
    out = capsys.readouterr().out.split()
    assert out == ["https://example.com/", "https://example.org/x"]


def test_missing_targets_is_a_usage_error():
    with pytest.raises(SystemExit):
        main([])


def test_invalid_target_exits_with_error_code(capsys):
    assert main(["ftp://example.com", "--dry-run"]) == 2
    assert "error:" in capsys.readouterr().err


def test_custom_categories_file(tmp_path):
    path = tmp_path / "cats.json"
    path.write_text(
        json.dumps(
            [
                {
                    "id": "pricing_leak",
                    "title": "Unreleased pricing",
                    "description": "Prices not yet public.",
                    "default_severity": "high",
                }
            ]
        ),
        encoding="utf-8",
    )
    categories = load_categories(path)
    assert len(categories) == 1
    assert categories[0].id == "pricing_leak"
    assert categories[0].default_severity is Severity.HIGH


def test_custom_categories_file_validates(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps([{"id": "x"}]), encoding="utf-8")
    with pytest.raises(ValueError):
        load_categories(path)


def test_prompt_includes_metadata_and_categories():
    capture = PageCapture(
        url="https://example.com/a",
        final_url="https://example.com/b",
        status=200,
        title="Index of /backup",
        text_excerpt="db_dump.sql  2.4M",
    )
    prompt = build_user_prompt(capture, DEFAULT_CATEGORIES, extra_instructions="Ignore the cookie banner.")
    assert "https://example.com/a" in prompt
    assert "Final URL after redirects: https://example.com/b" in prompt
    assert "HTTP status: 200" in prompt
    assert "db_dump.sql" in prompt
    assert "directory_listing" in prompt
    assert "Ignore the cookie banner." in prompt


def test_prompt_truncates_long_page_text():
    capture = PageCapture(url="https://example.com/", text_excerpt="x" * 5000)
    prompt = build_user_prompt(capture, DEFAULT_CATEGORIES, text_excerpt_chars=100)
    assert "x" * 100 in prompt
    assert "x" * 200 not in prompt
