"""Prompt construction and the JSON schema the model must answer with."""

from __future__ import annotations

from typing import Any, Sequence

from .categories import Category
from .models import PageCapture, Severity

SYSTEM_PROMPT = """\
You are a web exposure analyst supporting an authorised security assessment. You \
are shown a screenshot of a page from a system the operator owns or is permitted \
to test, together with metadata captured by the browser.

Your job is to decide whether the page exposes content that should not be \
reachable by whoever can open this URL, and to report it factually.

Rules:
- Judge only what is actually visible in the screenshot and the supplied metadata. \
Never speculate about code, endpoints or data you cannot see.
- Quote short, literal evidence from the page. Redact secret values: keep at most \
the first four characters and replace the rest with '...'.
- A normal marketing page, a login form that is actually gating content, or a plain \
error page is NOT a finding. Do not inflate risk to seem useful.
- If the page failed to load, or the screenshot is blank, say so and report no \
findings.
- Report each distinct issue once. Set confidence to how certain you are that the \
issue is real, from 0.0 to 1.0.
- Answer with JSON only, matching the requested schema exactly."""


RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "page_type": {
            "type": "string",
            "description": "Short label for what this page is, e.g. 'login form', "
            "'directory listing', 'marketing homepage'.",
        },
        "summary": {
            "type": "string",
            "description": "One or two sentences describing what is on the page and "
            "whether anything sensitive is exposed.",
        },
        "risk_level": {
            "type": "string",
            "enum": [s.value for s in Severity],
            "description": "Overall risk for this page.",
        },
        "requires_review": {
            "type": "boolean",
            "description": "True if a human should look at this page.",
        },
        "findings": {
            "type": "array",
            "description": "One entry per distinct exposure. Empty when nothing is "
            "exposed.",
            "items": {
                "type": "object",
                "properties": {
                    "category": {
                        "type": "string",
                        "description": "The id of the matching category, or 'other'.",
                    },
                    "severity": {
                        "type": "string",
                        "enum": [s.value for s in Severity],
                    },
                    "title": {
                        "type": "string",
                        "description": "Short headline for the exposure.",
                    },
                    "evidence": {
                        "type": "string",
                        "description": "Literal text or visual detail from the page "
                        "that supports the finding, with secrets redacted.",
                    },
                    "recommendation": {
                        "type": "string",
                        "description": "Concrete remediation step.",
                    },
                    "confidence": {
                        "type": "number",
                        "minimum": 0,
                        "maximum": 1,
                    },
                },
                "required": [
                    "category",
                    "severity",
                    "title",
                    "evidence",
                    "recommendation",
                    "confidence",
                ],
                "additionalProperties": False,
            },
        },
    },
    "required": ["page_type", "summary", "risk_level", "requires_review", "findings"],
    "additionalProperties": False,
}


def render_categories(categories: Sequence[Category]) -> str:
    lines = []
    for category in categories:
        lines.append(
            f"- {category.id} ({category.default_severity.value}): "
            f"{category.title} — {category.description}"
        )
    return "\n".join(lines)


def build_user_prompt(
    capture: PageCapture,
    categories: Sequence[Category],
    extra_instructions: str = "",
    text_excerpt_chars: int = 2000,
) -> str:
    """Assemble the text half of the multimodal user message."""
    parts = [
        "Assess the attached screenshot for exposed critical content.",
        "",
        "## Page metadata",
        f"- Requested URL: {capture.url}",
    ]
    if capture.final_url and capture.final_url != capture.url:
        parts.append(f"- Final URL after redirects: {capture.final_url}")
    if capture.status is not None:
        parts.append(f"- HTTP status: {capture.status}")
    if capture.title:
        parts.append(f"- Document title: {capture.title}")
    if capture.load_error:
        parts.append(f"- Load error: {capture.load_error}")

    excerpt = (capture.text_excerpt or "").strip()
    if excerpt:
        truncated = excerpt[:text_excerpt_chars]
        suffix = "…" if len(excerpt) > text_excerpt_chars else ""
        parts += [
            "",
            "## Extracted page text (may be truncated; the screenshot is authoritative)",
            "```",
            truncated + suffix,
            "```",
        ]

    parts += [
        "",
        "## Categories of critical content",
        render_categories(categories),
        "",
        "Use the category id that fits best. If something is clearly sensitive but "
        "matches no category, use 'other'.",
    ]

    if extra_instructions.strip():
        parts += ["", "## Additional operator instructions", extra_instructions.strip()]

    return "\n".join(parts)
