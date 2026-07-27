import json

from secman_visual_check.analyzer import extract_json, parse_analysis
from secman_visual_check.models import Severity

SAMPLE = {
    "page_type": "directory listing",
    "summary": "Apache directory index exposing backup archives.",
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


def test_extract_json_from_plain_text():
    assert extract_json(json.dumps(SAMPLE))["page_type"] == "directory listing"


def test_extract_json_from_markdown_fence():
    text = "Here you go:\n```json\n" + json.dumps(SAMPLE) + "\n```\nDone."
    assert extract_json(text)["risk_level"] == "high"


def test_extract_json_ignores_braces_inside_strings():
    text = 'prelude {"summary": "contains } brace", "findings": []} trailer'
    parsed = extract_json(text)
    assert parsed == {"summary": "contains } brace", "findings": []}


def test_extract_json_returns_none_for_garbage():
    assert extract_json("no json here at all") is None
    assert extract_json("") is None


def test_parse_analysis_maps_findings():
    analysis = parse_analysis(json.dumps(SAMPLE), "test/model")
    assert analysis.risk_level is Severity.HIGH
    assert analysis.model == "test/model"
    assert len(analysis.findings) == 1
    finding = analysis.findings[0]
    assert finding.category == "directory_listing"
    assert finding.severity is Severity.HIGH
    assert finding.confidence == 0.9


def test_page_risk_is_raised_to_worst_finding():
    payload = dict(SAMPLE, risk_level="low")
    payload["findings"] = [dict(SAMPLE["findings"][0], severity="critical")]
    analysis = parse_analysis(json.dumps(payload), "m")
    assert analysis.risk_level is Severity.CRITICAL


def test_findings_without_a_title_are_dropped():
    payload = dict(SAMPLE, findings=[{"severity": "high", "title": "  "}])
    assert parse_analysis(json.dumps(payload), "m").findings == []


def test_confidence_on_a_0_to_100_scale_is_normalised():
    payload = dict(SAMPLE)
    payload["findings"] = [dict(SAMPLE["findings"][0], confidence=85)]
    assert parse_analysis(json.dumps(payload), "m").findings[0].confidence == 0.85


def test_unparseable_response_becomes_an_error_analysis():
    analysis = parse_analysis("I refuse to answer.", "m")
    assert analysis.error is not None
    assert analysis.risk_level is Severity.INFO
    assert "refuse" in analysis.summary


def test_unknown_severity_falls_back_to_medium_for_findings():
    payload = dict(SAMPLE)
    payload["findings"] = [dict(SAMPLE["findings"][0], severity="spicy")]
    assert parse_analysis(json.dumps(payload), "m").findings[0].severity is Severity.MEDIUM
