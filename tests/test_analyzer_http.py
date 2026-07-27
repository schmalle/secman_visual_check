"""Transport-level tests for the analyzer: retries, schema downgrade, parsing."""

import asyncio
import json

import httpx
import pytest

from secman_visual_check.analyzer import (
    AnalyzerError,
    AnalyzerOptions,
    VisionAnalyzer,
    _downgrade,
    _is_response_format_error,
    _lower_mode,
)
from secman_visual_check.categories import DEFAULT_CATEGORIES
from secman_visual_check.models import PageCapture, Severity

VERDICT = {
    "page_type": "directory listing",
    "summary": "Backup directory is browsable.",
    "risk_level": "high",
    "requires_review": True,
    "findings": [
        {
            "category": "directory_listing",
            "severity": "high",
            "title": "Directory index exposed",
            "evidence": "Index of /backup",
            "recommendation": "Disable autoindex.",
            "confidence": 0.9,
        }
    ],
}


def completion(content: str) -> dict:
    return {
        "choices": [{"message": {"content": content}}],
        "usage": {"prompt_tokens": 1200, "completion_tokens": 90},
    }


@pytest.fixture
def screenshot(tmp_path):
    path = tmp_path / "shot.png"
    path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 64)
    return path


def run_analysis(handler, screenshot, **option_overrides):
    """Drive VisionAnalyzer.analyze against a mocked transport."""
    options = AnalyzerOptions(api_key="sk-test", model="mock/vision", **option_overrides)
    capture = PageCapture(
        url="https://example.com/backup/",
        status=200,
        title="Index of /backup",
        screenshot_path=str(screenshot),
    )

    async def go():
        analyzer = VisionAnalyzer(options, DEFAULT_CATEGORIES)
        async with analyzer:
            await analyzer._client.aclose()
            analyzer._client = httpx.AsyncClient(
                base_url="https://api.test/v1", transport=httpx.MockTransport(handler)
            )
            return await analyzer.analyze(capture), analyzer

    return asyncio.run(go())


def test_missing_api_key_is_a_hard_error():
    with pytest.raises(AnalyzerError):
        VisionAnalyzer(AnalyzerOptions(api_key=""), DEFAULT_CATEGORIES)


def test_successful_analysis_sends_a_multimodal_request(screenshot):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content)
        seen["path"] = request.url.path
        return httpx.Response(200, json=completion(json.dumps(VERDICT)))

    analysis, _ = run_analysis(handler, screenshot)

    assert seen["path"].endswith("/chat/completions")
    content = seen["body"]["messages"][1]["content"]
    assert content[0]["type"] == "text"
    assert content[1]["image_url"]["url"].startswith("data:image/png;base64,")
    assert seen["body"]["response_format"]["type"] == "json_schema"
    assert analysis.risk_level is Severity.HIGH
    assert analysis.prompt_tokens == 1200
    assert analysis.error is None


def test_retries_then_succeeds(screenshot):
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] < 3:
            return httpx.Response(429, headers={"retry-after": "0"}, json={"error": "slow down"})
        return httpx.Response(200, json=completion(json.dumps(VERDICT)))

    analysis, _ = run_analysis(handler, screenshot, max_retries=3)
    assert calls["n"] == 3
    assert analysis.error is None


def test_gives_up_after_max_retries_without_raising(screenshot):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, headers={"retry-after": "0"}, json={"error": "down"})

    analysis, _ = run_analysis(handler, screenshot, max_retries=1)
    assert analysis.error is not None
    assert "503" in analysis.error
    assert analysis.risk_level is Severity.INFO


def test_downgrades_structured_output_when_rejected(screenshot):
    modes = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        modes.append((body.get("response_format") or {}).get("type"))
        if body.get("response_format", {}).get("type") == "json_schema":
            return httpx.Response(
                400, json={"error": {"message": "response_format json_schema unsupported"}}
            )
        return httpx.Response(200, json=completion(json.dumps(VERDICT)))

    analysis, analyzer = run_analysis(handler, screenshot)
    assert modes == ["json_schema", "json_object"]
    # The downgrade sticks so later pages do not repeat the failed round trip.
    assert analyzer._structured_mode == "json_object"
    assert analysis.error is None


def test_unrelated_400_is_not_treated_as_a_schema_problem(screenshot):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": {"message": "image too large"}})

    analysis, _ = run_analysis(handler, screenshot)
    assert analysis.error is not None
    assert "image too large" in analysis.error


def test_bad_api_key_aborts_the_run(screenshot):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": {"message": "invalid key"}})

    with pytest.raises(AnalyzerError):
        run_analysis(handler, screenshot)


def test_missing_screenshot_short_circuits():
    options = AnalyzerOptions(api_key="sk-test")

    async def go():
        async with VisionAnalyzer(options, DEFAULT_CATEGORIES) as analyzer:
            return await analyzer.analyze(PageCapture(url="https://example.com/"))

    analysis = asyncio.run(go())
    assert analysis.error == "missing screenshot"


def test_mode_downgrade_helpers():
    assert _downgrade("json_schema") == "json_object"
    assert _downgrade("json_object") == "none"
    assert _downgrade("none") == "none"
    # Concurrent downgrades must not cascade past one step.
    assert _lower_mode("json_object", "json_object") == "json_object"
    assert _lower_mode("json_object", "none") == "none"
    assert _lower_mode("none", "json_object") == "none"
    assert _is_response_format_error("Unsupported response_format")
    assert not _is_response_format_error("context length exceeded")
