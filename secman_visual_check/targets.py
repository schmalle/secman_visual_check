"""Loading and normalising the list of URLs to scan."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse, urlunparse

ALLOWED_SCHEMES = ("http", "https")


class TargetError(ValueError):
    """Raised when a target cannot be turned into a scannable http(s) URL."""


def normalize_url(raw: str) -> str:
    """Normalise a single URL, defaulting to https:// when no scheme is given.

    Raises TargetError for anything that is not an http(s) URL with a host.
    """
    candidate = raw.strip()
    if not candidate:
        raise TargetError("empty URL")

    # Reject obvious non-web schemes before we assume https://.
    if "://" in candidate:
        scheme = candidate.split("://", 1)[0].lower()
        if scheme not in ALLOWED_SCHEMES:
            raise TargetError(f"unsupported scheme {scheme!r} in {raw!r}")
    elif candidate.split(":", 1)[0].lower() in ("javascript", "data", "file", "mailto"):
        raise TargetError(f"unsupported scheme in {raw!r}")
    else:
        candidate = f"https://{candidate}"

    parsed = urlparse(candidate)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise TargetError(f"unsupported scheme {parsed.scheme!r} in {raw!r}")
    if not parsed.hostname:
        raise TargetError(f"missing host in {raw!r}")

    path = parsed.path or "/"
    # Drop any embedded userinfo (``user:pass@host``). This tool never reads
    # credentials out of the URL for authentication — the only supported
    # mechanism is ``--basic-auth`` (see capture.py/status.py), which is
    # resolved through secrets.py and redacted like any other credential — so
    # a `user:pass@` prefix typed into a target URL is pure liability: it
    # would ride untouched as the *structural* `url` field into every report,
    # the mailer, and (via `--secman-register-assets`) into SecMan's own
    # asset inventory as the `uri` field, none of which redact URLs (redact()
    # only scrubs *resolved* secrets it was told about, and structural fields
    # are deliberately left alone otherwise — see reporting.py). Stripping it
    # here, once, at the single choke point every target passes through,
    # closes that leak without changing any documented behaviour.
    netloc = parsed.netloc.rsplit("@", 1)[-1]
    return urlunparse((parsed.scheme.lower(), netloc, path, parsed.params, parsed.query, ""))


def parse_target_lines(lines: Iterable[str]) -> tuple[list[str], list[str]]:
    """Parse URL-list lines. Returns (urls, errors).

    Blank lines and lines starting with ``#`` are ignored. Trailing ``  # comment``
    is stripped so annotated target files stay readable.
    """
    urls: list[str] = []
    errors: list[str] = []
    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # Strip trailing comments (require whitespace before # so fragments survive).
        for sep in (" #", "\t#"):
            if sep in stripped:
                stripped = stripped.split(sep, 1)[0].strip()
        if not stripped:
            continue
        try:
            urls.append(normalize_url(stripped))
        except TargetError as exc:
            errors.append(f"line {lineno}: {exc}")
    return urls, errors


def load_targets(
    urls: Iterable[str] = (),
    files: Iterable[str | Path] = (),
    read_stdin: bool = False,
) -> list[str]:
    """Collect targets from CLI args, files and optionally stdin.

    The result is de-duplicated while preserving first-seen order.
    """
    collected: list[str] = []
    errors: list[str] = []

    for raw in urls:
        try:
            collected.append(normalize_url(raw))
        except TargetError as exc:
            errors.append(str(exc))

    for path in files:
        p = Path(path)
        try:
            content = p.read_text(encoding="utf-8")
        except OSError as exc:
            errors.append(f"cannot read {p}: {exc}")
            continue
        parsed, file_errors = parse_target_lines(content.splitlines())
        collected.extend(parsed)
        errors.extend(f"{p}: {e}" for e in file_errors)

    if read_stdin:
        parsed, stdin_errors = parse_target_lines(sys.stdin.read().splitlines())
        collected.extend(parsed)
        errors.extend(f"<stdin>: {e}" for e in stdin_errors)

    if errors:
        raise TargetError("; ".join(errors))

    seen: set[str] = set()
    unique: list[str] = []
    for url in collected:
        if url not in seen:
            seen.add(url)
            unique.append(url)
    return unique
