import json

import pytest

from secman_visual_check.categories import DEFAULT_CATEGORIES, load_categories
from secman_visual_check.cli import build_config, build_parser, main, parse_headers, parse_viewport
from secman_visual_check.models import PageCapture, Severity
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
