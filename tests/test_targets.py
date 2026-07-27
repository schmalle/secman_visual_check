import pytest

from secman_visual_check.targets import (
    TargetError,
    load_targets,
    normalize_url,
    parse_target_lines,
)


def test_adds_https_scheme_and_root_path():
    assert normalize_url("example.com") == "https://example.com/"


def test_preserves_path_query_and_port():
    url = "http://example.com:8080/admin?debug=1"
    assert normalize_url(url) == url


def test_strips_fragment():
    assert normalize_url("https://example.com/a#section") == "https://example.com/a"


def test_lowercases_scheme():
    assert normalize_url("HTTPS://example.com/x") == "https://example.com/x"


@pytest.mark.parametrize(
    "bad",
    ["", "   ", "ftp://example.com", "javascript:alert(1)", "file:///etc/passwd", "https://"],
)
def test_rejects_non_web_targets(bad):
    with pytest.raises(TargetError):
        normalize_url(bad)


def test_parse_lines_skips_comments_and_blanks():
    urls, errors = parse_target_lines(
        [
            "# a comment",
            "",
            "example.com  # inline comment",
            "   ",
            "https://example.org/admin",
        ]
    )
    assert urls == ["https://example.com/", "https://example.org/admin"]
    assert errors == []


def test_parse_lines_reports_bad_line_numbers():
    _, errors = parse_target_lines(["good.com", "ftp://nope"])
    assert len(errors) == 1
    assert errors[0].startswith("line 2:")


def test_load_targets_dedupes_preserving_order(tmp_path):
    listing = tmp_path / "urls.txt"
    listing.write_text("b.example\na.example\n", encoding="utf-8")
    result = load_targets(["a.example"], [listing])
    assert result == ["https://a.example/", "https://b.example/"]


def test_load_targets_raises_on_missing_file(tmp_path):
    with pytest.raises(TargetError):
        load_targets(files=[tmp_path / "missing.txt"])
