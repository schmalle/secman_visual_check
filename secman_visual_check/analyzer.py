"""Vision analysis of a screenshot via OpenRouter (or any OpenAI-compatible API)."""

from __future__ import annotations

import asyncio
import base64
import json
import re
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Sequence

from .categories import Category
from .models import Analysis, Finding, PageCapture, Severity
from .prompts import RESPONSE_SCHEMA, SYSTEM_PROMPT, build_user_prompt
from .secrets import redact

DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"

# Any vision-capable OpenRouter slug works; override with --model / SECMAN_MODEL.
# Check https://openrouter.ai/models?modality=text%2Bimage-%3Etext for current ids.
DEFAULT_MODEL = "anthropic/claude-sonnet-4.5"

_RETRY_STATUSES = frozenset({408, 409, 425, 429, 500, 502, 503, 504, 529})


class AnalyzerError(RuntimeError):
    """Raised for configuration problems that should abort the whole run."""


@dataclass
class AnalyzerOptions:
    api_key: str
    model: str = DEFAULT_MODEL
    base_url: str = DEFAULT_BASE_URL
    max_tokens: int = 2000
    temperature: float = 0.0
    timeout_s: float = 120.0
    max_retries: int = 3
    structured_output: str = "json_schema"  # json_schema | json_object | none
    extra_instructions: str = ""
    prompt_text_chars: int = 2000
    referer: str = "https://github.com/schmalle/secman_visual_check"
    app_title: str = "secman_visual_check"
    extra_body: dict[str, Any] = field(default_factory=dict)


class VisionAnalyzer:
    """Sends screenshots to a vision model and parses the structured verdict."""

    def __init__(
        self, options: AnalyzerOptions, categories: Sequence[Category]
    ) -> None:
        if not options.api_key:
            raise AnalyzerError(
                "No API key. Set OPENROUTER_API_KEY (or pass --api-key), or run with "
                "--no-ai to capture screenshots only."
            )
        self.options = options
        self.categories = list(categories)
        self._client = None
        self._structured_mode = options.structured_output

    async def __aenter__(self) -> "VisionAnalyzer":
        import httpx

        headers = {
            "Authorization": f"Bearer {self.options.api_key}",
            "Content-Type": "application/json",
            # OpenRouter attribution headers; harmless on other providers.
            "HTTP-Referer": self.options.referer,
            "X-Title": self.options.app_title,
        }
        self._client = httpx.AsyncClient(
            base_url=self.options.base_url.rstrip("/"),
            headers=headers,
            timeout=httpx.Timeout(self.options.timeout_s),
        )
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        if self._client is not None:
            await self._client.aclose()

    async def analyze(self, capture: PageCapture, secrets: Sequence[str] = ()) -> Analysis:
        """Analyse one capture. Transport failures become Analysis.error, not raises.

        ``secrets`` (typically ``resolver.values`` from the CLI's
        :class:`~secman_visual_check.secrets.SecretResolver`) is scrubbed out of
        the capture *before* it is turned into a prompt: a target that reflects a
        resolved credential back — a Basic-Auth password rejected onto an error
        page, a custom header echoed in a debug response — lands in
        ``capture.text_excerpt``/``title``/``load_error`` and, unless stopped here,
        would be sent verbatim to a third-party AI provider. ``reporting.
        redact_report`` scrubs the same fields for on-disk reports and email, but
        that happens *after* this request has already gone out, so it cannot
        protect the outbound prompt on its own.
        """
        started = time.monotonic()
        if not capture.screenshot_path:
            return Analysis(
                risk_level=Severity.INFO,
                summary="No screenshot was captured, so no visual analysis was run.",
                model=self.options.model,
                error="missing screenshot",
            )

        safe_capture = _redact_capture_for_prompt(capture, secrets)
        prompt = build_user_prompt(
            safe_capture,
            self.categories,
            extra_instructions=self.options.extra_instructions,
            text_excerpt_chars=self.options.prompt_text_chars,
        )
        image_url = _data_url(Path(capture.screenshot_path))

        try:
            payload, raw_text = await self._request(prompt, image_url)
        except AnalyzerError:
            raise
        except Exception as exc:
            return Analysis(
                risk_level=Severity.INFO,
                summary="Analysis failed.",
                model=self.options.model,
                error=f"{type(exc).__name__}: {exc}"[:400],
                duration_s=time.monotonic() - started,
            )

        analysis = parse_analysis(raw_text, self.options.model)
        analysis.duration_s = time.monotonic() - started
        usage = (payload or {}).get("usage") or {}
        analysis.prompt_tokens = usage.get("prompt_tokens")
        analysis.completion_tokens = usage.get("completion_tokens")
        return analysis

    async def _request(self, prompt: str, image_url: str) -> tuple[dict, str]:
        """POST /chat/completions with retries; returns (payload, message text)."""
        import httpx

        assert self._client is not None
        mode = self._structured_mode
        body = self._build_body(prompt, image_url, mode)
        delay = 1.0
        attempt = 0
        last_error: Exception | None = None

        while True:
            try:
                response = await self._client.post("/chat/completions", json=body)
            except httpx.HTTPError as exc:
                last_error = exc
                if attempt >= self.options.max_retries:
                    raise
                attempt += 1
                await asyncio.sleep(delay)
                delay = min(delay * 2, 30.0)
                continue

            if response.status_code in (401, 403):
                raise AnalyzerError(
                    f"Provider rejected the API key ({response.status_code}): "
                    f"{_error_text(response)}"
                )

            if (
                response.status_code in (400, 404, 422)
                and mode != "none"
                and _is_response_format_error(_error_text(response))
            ):
                # Not every model accepts response_format. Step down one level and
                # remember it for later calls so we only pay this cost once.
                mode = _downgrade(mode)
                self._structured_mode = _lower_mode(self._structured_mode, mode)
                body = self._build_body(prompt, image_url, mode)
                continue  # a downgrade is not a failed attempt

            if response.status_code in _RETRY_STATUSES:
                last_error = RuntimeError(
                    f"HTTP {response.status_code}: {_error_text(response)}"
                )
                if attempt >= self.options.max_retries:
                    raise last_error
                attempt += 1
                await asyncio.sleep(_retry_after(response, delay))
                delay = min(delay * 2, 30.0)
                continue

            if response.status_code >= 400:
                raise RuntimeError(f"HTTP {response.status_code}: {_error_text(response)}")

            payload = response.json()
            error = payload.get("error")
            if error:
                raise RuntimeError(f"Provider error: {json.dumps(error)[:300]}")
            return payload, _message_text(payload)

    def _build_body(self, prompt: str, image_url: str, mode: str) -> dict[str, Any]:
        body: dict[str, Any] = {
            "model": self.options.model,
            "max_tokens": self.options.max_tokens,
            "temperature": self.options.temperature,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": prompt},
                        {"type": "image_url", "image_url": {"url": image_url}},
                    ],
                },
            ],
        }
        if mode == "json_schema":
            body["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": "page_exposure_assessment",
                    "strict": True,
                    "schema": RESPONSE_SCHEMA,
                },
            }
        elif mode == "json_object":
            body["response_format"] = {"type": "json_object"}
        body.update(self.options.extra_body)
        return body


def _redact_capture_for_prompt(capture: PageCapture, secrets: Sequence[str]) -> PageCapture:
    """Scrub resolved secrets out of the target-influenced fields before they
    ever reach ``build_user_prompt`` — see :meth:`VisionAnalyzer.analyze`."""
    if not secrets:
        return capture
    return replace(
        capture,
        title=redact(capture.title, secrets) if capture.title else capture.title,
        text_excerpt=redact(capture.text_excerpt, secrets),
        load_error=redact(capture.load_error, secrets) if capture.load_error else capture.load_error,
    )


def parse_analysis(raw_text: str, model: str) -> Analysis:
    """Turn the model's reply into an Analysis, tolerating prose around the JSON."""
    data = extract_json(raw_text)
    if data is None:
        return Analysis(
            risk_level=Severity.INFO,
            summary=(raw_text or "").strip()[:500] or "Model returned no content.",
            model=model,
            error="could not parse JSON from model response",
            raw_response=raw_text,
        )

    findings: list[Finding] = []
    for entry in data.get("findings") or []:
        if not isinstance(entry, dict):
            continue
        title = str(entry.get("title") or "").strip()
        if not title:
            continue
        findings.append(
            Finding(
                category=str(entry.get("category") or "other").strip() or "other",
                severity=Severity.parse(entry.get("severity"), Severity.MEDIUM),
                title=title,
                evidence=str(entry.get("evidence") or "").strip(),
                recommendation=str(entry.get("recommendation") or "").strip(),
                confidence=_as_confidence(entry.get("confidence")),
            )
        )

    risk_level = Severity.parse(data.get("risk_level"), Severity.INFO)
    if findings:
        # Never report a page as lower risk than its own worst finding.
        worst = max((f.severity for f in findings), key=lambda s: s.rank)
        if worst.rank > risk_level.rank:
            risk_level = worst

    return Analysis(
        risk_level=risk_level,
        summary=str(data.get("summary") or "").strip(),
        findings=findings,
        page_type=str(data.get("page_type") or "").strip(),
        requires_review=bool(data.get("requires_review", bool(findings))),
        model=model,
        raw_response=raw_text,
    )


def extract_json(text: str | None) -> dict[str, Any] | None:
    """Pull the first JSON object out of a model reply, ignoring markdown fences."""
    if not text:
        return None
    candidate = text.strip()

    fence = re.search(r"```(?:json)?\s*(.+?)```", candidate, re.DOTALL)
    if fence:
        candidate = fence.group(1).strip()

    try:
        parsed = json.loads(candidate)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        pass

    # Fall back to scanning for a balanced object, respecting strings and escapes.
    start = candidate.find("{")
    while start != -1:
        depth = 0
        in_string = False
        escaped = False
        for pos in range(start, len(candidate)):
            char = candidate[pos]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
                continue
            if char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    try:
                        parsed = json.loads(candidate[start : pos + 1])
                    except json.JSONDecodeError:
                        break
                    return parsed if isinstance(parsed, dict) else None
        start = candidate.find("{", start + 1)
    return None


_MODE_RANK = {"json_schema": 2, "json_object": 1, "none": 0}


def _downgrade(mode: str) -> str:
    return {"json_schema": "json_object", "json_object": "none"}.get(mode, "none")


def _lower_mode(current: str, candidate: str) -> str:
    """Keep the least demanding of two structured-output modes.

    Concurrent requests can each discover the same rejection; without this a
    single 400 could cascade json_schema -> json_object -> none.
    """
    return current if _MODE_RANK.get(current, 0) <= _MODE_RANK.get(candidate, 0) else candidate


def _is_response_format_error(detail: str) -> bool:
    lowered = detail.lower()
    return any(
        token in lowered
        for token in ("response_format", "response format", "json_schema", "json schema")
    )


def _as_confidence(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    if number > 1.0:  # tolerate 0-100 scales
        number = number / 100.0
    return max(0.0, min(1.0, number))


def _data_url(path: Path) -> str:
    encoded = base64.b64encode(path.read_bytes()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def _message_text(payload: dict[str, Any]) -> str:
    choices = payload.get("choices") or []
    if not choices:
        return ""
    message = choices[0].get("message") or {}
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        # Some providers return content parts rather than a plain string.
        return "".join(
            part.get("text", "") for part in content if isinstance(part, dict)
        )
    return ""


def _error_text(response) -> str:
    try:
        payload = response.json()
    except Exception:
        return response.text[:300]
    error = payload.get("error", payload)
    if isinstance(error, dict):
        return str(error.get("message") or json.dumps(error))[:300]
    return str(error)[:300]


def _retry_after(response, fallback: float) -> float:
    header = response.headers.get("retry-after")
    if header:
        try:
            return min(float(header), 60.0)
        except ValueError:
            pass
    return fallback
