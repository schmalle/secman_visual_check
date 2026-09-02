"""Deterministic check of page *content* for confidential data.

The vision model judges what a page shows; this module checks what it
contains. It runs a fixed set of regular expressions over three inputs when
they are available — the rendered page text, the DOM serialisation, and the
raw response body the status check already downloaded for its checksum — and
turns matches into ordinary :class:`~.models.Finding` objects tagged
``source="content"``.

It exists for the cases a screenshot cannot cover:

- text the browser never paints — HTML comments, inline scripts, data
  attributes — where a leaked key or an internal hostname hides in plain sight;
- pages taller than the ``--max-height`` clamp, whose lower half is never seen;
- runs without a model (``--no-ai``), or with a model that failed, which
  would otherwise produce no finding at all for a page that literally contains
  ``AWS_SECRET_ACCESS_KEY=``;
- runs without a browser (``--no-visual-check``), which can still catch a
  private key or a database URL in the raw body.

Everything here is a heuristic. Each pattern carries the confidence it
deserves, secrets are redacted in the evidence the same way the model is asked
to redact them (first four characters, then ``…``), and loose patterns are
restricted to visible text so minified JavaScript does not spray false
positives. The set is data: replace or extend it with ``--content-patterns-file``.
"""

from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

from .models import Finding, Severity

#: Inputs a pattern may be applied to. ``text`` is what a visitor can read,
#: ``html`` is the DOM after scripts ran, ``body`` is the raw response.
SOURCES = ("text", "html", "body")
ALL_SOURCES = frozenset(SOURCES)
TEXT_ONLY = frozenset({"text"})

#: Findings per pattern per page are collapsed to one, so a page listing 400
#: private addresses yields one "private addresses" finding, not 400 rows.
MAX_EVIDENCE_CHARS = 160
#: How many characters of a secret survive into the evidence string.
SECRET_KEEP = 4

_PLACEHOLDER_VALUES = frozenset(
    {
        "required", "optional", "null", "none", "true", "false", "undefined",
        "password", "secret", "changeme", "example", "redacted", "hidden",
        "string", "text", "value", "xxx", "xxxx", "xxxxx", "yes", "no",
    }
)


def _looks_like_placeholder(value: str) -> bool:
    lowered = value.strip("'\"`").lower()
    if lowered in _PLACEHOLDER_VALUES:
        return True
    if set(lowered) <= set("*x•·-_."):
        return True
    if lowered.startswith(("${", "{{", "<", "%(", "$(")):
        return True
    return False


def _looks_like_code(value: str) -> bool:
    """Reject ``password: e.target.value`` and friends from minified scripts."""
    return any(token in value for token in ("(", ")", "{", "}", "=>", "this.", ".value", "[", "]"))


def _plausible_secret_value(match: re.Match) -> bool:
    value = match.group(match.lastindex or 0)
    if _looks_like_placeholder(value) or _looks_like_code(value):
        return False
    # A password that is one dictionary word is a heuristic too far; require
    # a digit or a symbol, which real credentials almost always carry.
    return any(not ch.isalpha() for ch in value)


def _luhn_ok(match: re.Match) -> bool:
    digits = [int(ch) for ch in match.group(0) if ch.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _iban_ok(match: re.Match) -> bool:
    raw = match.group(0).replace(" ", "")
    if not 15 <= len(raw) <= 34:
        return False
    rearranged = raw[4:] + raw[:4]
    numeric = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(numeric) % 97 == 1


@dataclass(frozen=True)
class ContentPattern:
    """One thing to look for, and how to report it when found."""

    id: str
    category: str
    severity: Severity
    title: str
    regex: re.Pattern
    recommendation: str = ""
    confidence: float = 0.7
    #: Redact the match in the evidence (credentials) or quote it (a banner).
    secret: bool = False
    #: Which inputs this pattern is allowed to see; loose patterns stay on
    #: visible text.
    sources: frozenset = field(default=ALL_SOURCES)
    #: Extra check on a match, for formats a regex cannot verify (Luhn, IBAN).
    validator: Callable[[re.Match], bool] | None = None
    #: Only report when at least this many distinct matches were found — for
    #: patterns whose single occurrence is normal (one email address is a
    #: contact line; forty are a customer list).
    min_matches: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "severity": self.severity.value,
            "title": self.title,
            "regex": self.regex.pattern,
            "recommendation": self.recommendation,
            "confidence": self.confidence,
            "secret": self.secret,
            "sources": sorted(self.sources),
            "min_matches": self.min_matches,
        }


def _p(
    id: str,
    category: str,
    severity: Severity,
    title: str,
    pattern: str,
    *,
    recommendation: str = "",
    confidence: float = 0.7,
    secret: bool = False,
    sources: Iterable[str] = SOURCES,
    validator: Callable[[re.Match], bool] | None = None,
    min_matches: int = 1,
    flags: int = 0,
) -> ContentPattern:
    return ContentPattern(
        id=id,
        category=category,
        severity=severity,
        title=title,
        regex=re.compile(pattern, flags),
        recommendation=recommendation,
        confidence=confidence,
        secret=secret,
        sources=frozenset(sources),
        validator=validator,
        min_matches=min_matches,
    )


_ROTATE = "Rotate the credential and remove it from the page."

DEFAULT_PATTERNS: tuple[ContentPattern, ...] = (
    # --- credentials with a recognisable format: safe on every source ------
    _p(
        "private_key_block", "exposed_credentials", Severity.CRITICAL,
        "Private key material in page content",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----",
        recommendation="Revoke the key, generate a new one and remove the file from the web root.",
        # The match is the armour header, not the key itself, so it can be quoted.
        confidence=0.95,
    ),
    _p(
        "aws_access_key_id", "exposed_credentials", Severity.CRITICAL,
        "AWS access key ID in page content",
        r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        recommendation=_ROTATE, confidence=0.9, secret=True,
    ),
    _p(
        "aws_secret_access_key", "exposed_credentials", Severity.CRITICAL,
        "AWS secret access key assigned in page content",
        r"(?i)aws[_\-]?secret(?:[_\-]?access)?[_\-]?key\b[ \t]*[:=][ \t]*['\"]?([A-Za-z0-9/+=]{40})\b",
        recommendation=_ROTATE, confidence=0.9, secret=True,
    ),
    _p(
        "github_token", "exposed_credentials", Severity.CRITICAL,
        "GitHub token in page content",
        r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b",
        recommendation=_ROTATE, confidence=0.9, secret=True,
    ),
    _p(
        "slack_token", "exposed_credentials", Severity.CRITICAL,
        "Slack token in page content",
        r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b",
        recommendation=_ROTATE, confidence=0.85, secret=True,
    ),
    _p(
        "google_api_key", "exposed_credentials", Severity.HIGH,
        "Google API key in page content",
        r"\bAIza[0-9A-Za-z_\-]{35}\b",
        recommendation="Restrict the key to the intended referrers and APIs, or rotate it.",
        confidence=0.75, secret=True,
    ),
    _p(
        "stripe_secret_key", "exposed_credentials", Severity.CRITICAL,
        "Stripe secret key in page content",
        r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b",
        recommendation=_ROTATE, confidence=0.9, secret=True,
    ),
    _p(
        "openai_style_key", "exposed_credentials", Severity.HIGH,
        "API key in page content (sk- prefix)",
        r"\bsk-(?:proj-|ant-|or-v1-)?[A-Za-z0-9_\-]{24,}\b",
        recommendation=_ROTATE, confidence=0.7, secret=True,
    ),
    _p(
        "jwt", "exposed_credentials", Severity.HIGH,
        "JSON Web Token in page content",
        r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b",
        recommendation="Never render tokens into page content; invalidate this one.",
        confidence=0.7, secret=True,
    ),
    _p(
        "connection_string_with_password", "exposed_credentials", Severity.CRITICAL,
        "Connection string with embedded password",
        r"\b(?:mysql|mariadb|postgres(?:ql)?|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|jdbc:[a-z]+)://[^\s/:@'\"<>]+:[^\s@'\"<>]+@[^\s'\"<>]+",
        recommendation=_ROTATE, confidence=0.9, secret=True,
    ),
    _p(
        "url_with_credentials", "exposed_credentials", Severity.HIGH,
        "URL with embedded username and password",
        r"\bhttps?://[^\s/:@'\"<>]+:[^\s@/'\"<>]+@[^\s'\"<>]+",
        recommendation=_ROTATE, confidence=0.7, secret=True,
    ),
    _p(
        "dotenv_secret", "backup_or_source_disclosure", Severity.CRITICAL,
        "Environment file secret rendered in page",
        r"(?m)^[ \t]*(?:DB_PASSWORD|DATABASE_URL|APP_KEY|APP_SECRET|SECRET_KEY|SECRET_KEY_BASE|DJANGO_SECRET_KEY|JWT_SECRET|AWS_SECRET_ACCESS_KEY|MAIL_PASSWORD|REDIS_PASSWORD|SMTP_PASSWORD)[ \t]*=[ \t]*(\S{4,})",
        recommendation="Block access to .env and similar files at the web server, then rotate every value in it.",
        confidence=0.9, secret=True,
    ),
    _p(
        "git_config", "backup_or_source_disclosure", Severity.HIGH,
        "Git repository metadata served",
        r"\[core\]\s*\n\s*repositoryformatversion\s*=",
        recommendation="Deny access to .git/ at the web server and remove the directory from the web root.",
        confidence=0.9,
    ),
    # --- heuristics: visible text only ----------------------------------
    _p(
        "password_assignment", "exposed_credentials", Severity.HIGH,
        "Credential assignment visible in page text",
        r"(?i)\b(?:password|passwd|pwd|passphrase|secret|api[_\- ]?key|access[_\- ]?token|auth[_\- ]?token|client[_\- ]?secret|private[_\- ]?key)\b[ \t]*[:=][ \t]*['\"]?([^\s'\"<>,;]{8,})",
        recommendation=_ROTATE, confidence=0.55, secret=True,
        sources=TEXT_ONLY, validator=_plausible_secret_value,
    ),
    _p(
        "bearer_token", "exposed_credentials", Severity.HIGH,
        "Bearer token visible in page text",
        r"(?i)\bbearer[ \t]+([A-Za-z0-9._~+/\-]{24,}=*)",
        recommendation="Invalidate the token; never render authorisation headers into pages.",
        confidence=0.6, secret=True, sources=TEXT_ONLY,
    ),
    _p(
        "iban", "personal_data", Severity.HIGH,
        "Bank account number (IBAN) in page text",
        r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b",
        recommendation="Remove financial identifiers from unauthenticated pages.",
        confidence=0.8, secret=True, sources=TEXT_ONLY, validator=_iban_ok,
    ),
    _p(
        "payment_card", "personal_data", Severity.HIGH,
        "Payment card number in page text",
        r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011|65\d{2})(?:[ \-]?\d{4}){2,3}(?:[ \-]?\d{1,4})?\b",
        recommendation="Remove card numbers from page content; store only tokens or the last four digits.",
        confidence=0.6, secret=True, sources=TEXT_ONLY, validator=_luhn_ok,
    ),
    _p(
        "email_list", "personal_data", Severity.MEDIUM,
        "Bulk list of email addresses in page text",
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
        recommendation="Confirm the page is meant to publish these contacts; otherwise gate or remove it.",
        confidence=0.5, sources=TEXT_ONLY, min_matches=10,
    ),
    _p(
        "private_ip", "infrastructure_disclosure", Severity.MEDIUM,
        "Private network address in page text",
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b",
        recommendation="Remove internal addressing from public pages.",
        confidence=0.6, sources=TEXT_ONLY,
    ),
    _p(
        "server_banner", "infrastructure_disclosure", Severity.LOW,
        "Server software version in page text",
        r"\b(?:Apache|nginx|Microsoft-IIS|LiteSpeed|OpenSSL|PHP|Tomcat|Jetty)/\d+\.\d+(?:\.\d+)?\b",
        recommendation="Disable server signatures (ServerTokens Prod, server_tokens off).",
        confidence=0.6, sources=TEXT_ONLY,
    ),
    _p(
        "stack_trace", "debug_output", Severity.HIGH,
        "Stack trace or framework error in page text",
        r"(?m)^[ \t]*(?:Traceback \(most recent call last\)|at [\w$.<>]+\([\w$]+\.(?:java|kt|scala):\d+\)|Caused by: [\w.]+(?:Exception|Error)\b|Fatal error: Uncaught|Warning: \w+\(\).* on line \d+|System\.\w+Exception:|\w+Error: .+\n[ \t]+at .+\(.+:\d+:\d+\))",
        recommendation="Disable debug output in production and log errors server-side instead.",
        confidence=0.85, sources=TEXT_ONLY,
    ),
    _p(
        "django_debug_page", "debug_output", Severity.HIGH,
        "Django debug page",
        r"You're seeing this error because you have DEBUG = True",
        recommendation="Set DEBUG = False in production.",
        confidence=0.95, sources=TEXT_ONLY,
    ),
    _p(
        "phpinfo", "debug_output", Severity.HIGH,
        "phpinfo() output",
        r"\bLoaded Configuration File\b|\bphpinfo\(\)",
        recommendation="Remove the phpinfo page.",
        confidence=0.85, sources=TEXT_ONLY,
    ),
    _p(
        "spring_actuator_env", "debug_output", Severity.HIGH,
        "Spring Boot actuator environment dump",
        r"\"propertySources\"\s*:\s*\[|\"activeProfiles\"\s*:",
        recommendation="Restrict actuator endpoints to an internal management port and require authentication.",
        confidence=0.8, sources=("text", "body"),
    ),
    _p(
        "directory_index", "directory_listing", Severity.HIGH,
        "Auto-generated directory index",
        r"(?m)^[ \t]*Index of /|\bParent Directory\b",
        recommendation="Disable directory listing (Options -Indexes / autoindex off).",
        confidence=0.85, sources=TEXT_ONLY,
    ),
)


class ContentPatternError(ValueError):
    """A ``--content-patterns-file`` that cannot be used."""


def load_patterns(path: str | Path | None = None) -> list[ContentPattern]:
    """The built-in patterns, or the set defined in a JSON file.

    The file is either a list of pattern objects — appended to the built-ins —
    or ``{"replace": true, "patterns": [...]}`` to start from nothing. Each
    object needs ``id``, ``category``, ``title`` and ``regex``; ``severity``
    (default ``medium``), ``recommendation``, ``confidence``, ``secret``,
    ``sources`` and ``min_matches`` are optional.
    """
    if path is None:
        return list(DEFAULT_PATTERNS)
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise ContentPatternError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ContentPatternError(f"{path} is not valid JSON: {exc}") from exc

    replace = False
    if isinstance(data, dict):
        replace = bool(data.get("replace"))
        data = data.get("patterns")
    if not isinstance(data, list) or not data:
        raise ContentPatternError(f"{path}: expected a non-empty list of pattern objects")

    patterns = [] if replace else list(DEFAULT_PATTERNS)
    known = {p.id for p in patterns}
    for index, entry in enumerate(data):
        if not isinstance(entry, dict):
            raise ContentPatternError(f"{path}: entry {index} is not an object")
        missing = [k for k in ("id", "category", "title", "regex") if not entry.get(k)]
        if missing:
            raise ContentPatternError(f"{path}: entry {index} is missing {', '.join(missing)}")
        try:
            regex = re.compile(str(entry["regex"]))
        except re.error as exc:
            raise ContentPatternError(f"{path}: entry {index} has an invalid regex: {exc}") from exc
        sources = entry.get("sources") or list(SOURCES)
        if not isinstance(sources, list) or not sources or not set(sources) <= ALL_SOURCES:
            raise ContentPatternError(
                f"{path}: entry {index} sources must be a list drawn from {', '.join(SOURCES)}"
            )
        pattern = ContentPattern(
            id=str(entry["id"]),
            category=str(entry["category"]),
            severity=Severity.parse(entry.get("severity"), Severity.MEDIUM),
            title=str(entry["title"]),
            regex=regex,
            recommendation=str(entry.get("recommendation") or ""),
            confidence=_clamp(entry.get("confidence", 0.7)),
            secret=bool(entry.get("secret", False)),
            sources=frozenset(sources),
            min_matches=max(1, int(entry.get("min_matches") or 1)),
        )
        # A file entry with a built-in id overrides the built-in, so one
        # pattern's severity or regex can be tuned without replacing the set.
        if pattern.id in known:
            patterns = [pattern if p.id == pattern.id else p for p in patterns]
        else:
            patterns.append(pattern)
            known.add(pattern.id)
    if not patterns:
        raise ContentPatternError(f"{path}: the pattern set is empty")
    return patterns


def _clamp(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.7
    return max(0.0, min(1.0, number))


_HTML_DROP_RE = re.compile(
    r"<!--.*?-->|<script\b[^>]*>.*?</script>|<style\b[^>]*>.*?</style>",
    re.IGNORECASE | re.DOTALL,
)
_HTML_BLOCK_RE = re.compile(
    r"</?(?:p|div|br|li|ul|ol|tr|td|th|h[1-6]|pre|section|article|header|footer|"
    r"table|blockquote|form|hr|title|dt|dd)\b[^>]*>",
    re.IGNORECASE,
)
_HTML_TAG_RE = re.compile(r"<[^>]+>")


def text_from_html(raw: str) -> str:
    """A rough ``innerText`` for a body no browser rendered.

    Used only on ``--no-visual-check`` runs, so the visible-text patterns get
    something to read. Comments, scripts and styles are dropped (the raw body
    is still searched separately, so nothing in them is lost to the
    format-based patterns), block-level tags become line breaks, the rest are
    stripped, entities are unescaped. A body without a single tag is returned
    as is — a ``.env`` is its own text.
    """
    if "<" not in raw or ">" not in raw:
        return raw
    text = _HTML_DROP_RE.sub(" ", raw)
    text = _HTML_BLOCK_RE.sub("\n", text)
    text = _HTML_TAG_RE.sub(" ", text)
    text = html.unescape(text)
    lines = [" ".join(line.split()) for line in text.splitlines()]
    return "\n".join(line for line in lines if line)


def redact_secret(value: str, keep: int = SECRET_KEEP) -> str:
    """``AKIAIOSFODNN7EXAMPLE`` → ``AKIA…`` — the same rule the model follows."""
    value = value.strip()
    if len(value) <= keep:
        return "…"
    return value[:keep] + "…"


def _evidence(pattern: ContentPattern, match: re.Match, source: str, count: int) -> str:
    if pattern.secret:
        # Prefer the captured value when the regex isolates one (the part
        # after ``password=``), so the label survives and the secret does not.
        if match.lastindex:
            prefix = match.group(0)[: match.start(match.lastindex) - match.start(0)]
            prefix = " ".join(prefix.split())[:60]
            glue = "" if prefix.endswith(("=", ":", "'", '"')) else " "
            shown = prefix + glue + redact_secret(match.group(match.lastindex))
        else:
            shown = redact_secret(match.group(0))
    else:
        shown = " ".join(match.group(0).split())[:MAX_EVIDENCE_CHARS]
    where = {"text": "page text", "html": "page HTML", "body": "response body"}[source]
    suffix = f" (+{count - 1} more)" if count > 1 else ""
    return f"{shown} — in {where}{suffix}"[: MAX_EVIDENCE_CHARS + 40]


def check_content(
    sources: dict[str, str],
    patterns: Sequence[ContentPattern] = DEFAULT_PATTERNS,
    max_chars: int = 0,
) -> tuple[list[Finding], int]:
    """Run every pattern over every source it is allowed to see.

    ``sources`` maps a name from :data:`SOURCES` to its text; empty entries
    are ignored. Returns ``(findings, total_matches)``: one finding per
    pattern that matched, carrying the first (redacted) hit and a count, so a
    page cannot flood the report or SecMan with hundreds of rows for one
    root cause.
    """
    findings: list[Finding] = []
    total = 0
    for pattern in patterns:
        seen: set[str] = set()
        first: tuple[str, re.Match] | None = None
        for name in SOURCES:
            if name not in pattern.sources:
                continue
            text = sources.get(name) or ""
            if not text:
                continue
            if max_chars and len(text) > max_chars:
                text = text[:max_chars]
            for match in pattern.regex.finditer(text):
                if pattern.validator is not None and not pattern.validator(match):
                    continue
                key = match.group(0)
                if key in seen:
                    continue
                seen.add(key)
                if first is None:
                    first = (name, match)
        if first is None or len(seen) < pattern.min_matches:
            continue
        total += len(seen)
        source_name, match = first
        findings.append(
            Finding(
                category=pattern.category,
                severity=pattern.severity,
                title=pattern.title,
                evidence=_evidence(pattern, match, source_name, len(seen)),
                recommendation=pattern.recommendation,
                confidence=pattern.confidence,
                source="content",
            )
        )
    return findings, total
