"""Command line interface for the visual exposure scanner."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

from . import __version__
from .analyzer import DEFAULT_BASE_URL, DEFAULT_MODEL, AnalyzerError, AnalyzerOptions
from .capture import CaptureOptions
from .categories import load_categories
from .config import ScanConfig
from .models import ScanResult, Severity
from .reporting import (
    should_colorize,
    write_console_report,
    write_html_report,
    write_json_report,
)
from .scanner import run_scan
from .targets import TargetError, load_targets

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

DESCRIPTION = """\
Screenshot one or more URLs with a headless browser and ask a vision model
whether the page exposes critical content.

Only scan systems you own or are explicitly authorised to test."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secman-visual-check",
        description=DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("urls", nargs="*", help="URLs to scan")
    parser.add_argument(
        "-f",
        "--file",
        action="append",
        default=[],
        metavar="PATH",
        help="file with one URL per line (# starts a comment); repeatable",
    )
    parser.add_argument(
        "--stdin", action="store_true", help="also read URLs from standard input"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    out = parser.add_argument_group("output")
    out.add_argument(
        "-o",
        "--output-dir",
        default="scan-output",
        metavar="DIR",
        help="directory for screenshots and reports (default: %(default)s)",
    )
    out.add_argument("--json", metavar="PATH", help="JSON report path (default: DIR/report.json)")
    out.add_argument("--html", metavar="PATH", help="HTML report path (default: DIR/report.html)")
    out.add_argument("--no-json", action="store_true", help="skip the JSON report")
    out.add_argument("--no-html", action="store_true", help="skip the HTML report")
    out.add_argument(
        "--link-images",
        action="store_true",
        help="link screenshots from the HTML report instead of embedding them",
    )
    out.add_argument(
        "--include-raw",
        action="store_true",
        help="include raw model responses in the JSON report",
    )
    out.add_argument("-v", "--verbose", action="store_true", help="show evidence and fixes")
    out.add_argument("-q", "--quiet", action="store_true", help="suppress progress output")
    color = out.add_mutually_exclusive_group()
    color.add_argument("--color", dest="color", action="store_true", default=None)
    color.add_argument("--no-color", dest="color", action="store_false")

    ai = parser.add_argument_group("analysis")
    ai.add_argument("--no-ai", action="store_true", help="capture screenshots only")
    ai.add_argument(
        "--api-key",
        default=None,
        help="API key (default: $OPENROUTER_API_KEY, then $SECMAN_API_KEY)",
    )
    ai.add_argument(
        "--model",
        default=None,
        metavar="SLUG",
        help=f"vision model slug (default: $SECMAN_MODEL or {DEFAULT_MODEL})",
    )
    ai.add_argument(
        "--base-url",
        default=None,
        help=f"OpenAI-compatible API base URL (default: $SECMAN_BASE_URL or {DEFAULT_BASE_URL})",
    )
    ai.add_argument("--max-tokens", type=int, default=2000, help="model output cap (default: %(default)s)")
    ai.add_argument("--temperature", type=float, default=0.0, help="sampling temperature (default: %(default)s)")
    ai.add_argument("--ai-timeout", type=float, default=120.0, metavar="SECONDS")
    ai.add_argument("--ai-retries", type=int, default=3, metavar="N")
    ai.add_argument(
        "--structured-output",
        choices=("json_schema", "json_object", "none"),
        default="json_schema",
        help="how to constrain the model's JSON output (default: %(default)s)",
    )
    ai.add_argument(
        "--categories-file",
        metavar="PATH",
        help="JSON file overriding the built-in categories of critical content",
    )
    ai.add_argument(
        "--instructions",
        default="",
        help="extra site-specific guidance appended to the analysis prompt",
    )
    ai.add_argument(
        "--instructions-file",
        metavar="PATH",
        help="read extra guidance from a file (appended after --instructions)",
    )
    ai.add_argument(
        "--prompt-text-chars",
        type=int,
        default=2000,
        help="how much extracted page text to send with the screenshot (default: %(default)s)",
    )

    browser = parser.add_argument_group("browser")
    browser.add_argument(
        "--viewport", default="1440x900", metavar="WxH", help="viewport size (default: %(default)s)"
    )
    fullpage = browser.add_mutually_exclusive_group()
    fullpage.add_argument("--full-page", dest="full_page", action="store_true", default=True)
    fullpage.add_argument(
        "--viewport-only",
        dest="full_page",
        action="store_false",
        help="capture only the visible viewport instead of the whole page",
    )
    browser.add_argument(
        "--max-height",
        type=int,
        default=4000,
        metavar="PX",
        help="clamp full-page screenshots to this height, 0 to disable (default: %(default)s)",
    )
    browser.add_argument(
        "--timeout", type=float, default=30.0, metavar="SECONDS", help="navigation timeout (default: %(default)s)"
    )
    browser.add_argument(
        "--wait-until",
        choices=("load", "domcontentloaded", "networkidle", "commit"),
        default="load",
        help="navigation completion signal (default: %(default)s)",
    )
    browser.add_argument(
        "--settle",
        type=float,
        default=1.5,
        metavar="SECONDS",
        help="extra wait after navigation before screenshotting (default: %(default)s)",
    )
    browser.add_argument("--user-agent", default=None)
    browser.add_argument(
        "--insecure", action="store_true", help="ignore TLS certificate errors"
    )
    browser.add_argument(
        "-H",
        "--header",
        action="append",
        default=[],
        metavar="'K: V'",
        help="extra HTTP request header; repeatable",
    )
    browser.add_argument("--basic-auth", metavar="USER:PASS", help="HTTP basic auth credentials")
    browser.add_argument(
        "--storage-state",
        metavar="PATH",
        help="Playwright storage state JSON (cookies/localStorage) for authenticated scans",
    )
    browser.add_argument(
        "--browser-channel", metavar="NAME", help="Chromium channel, e.g. chrome or msedge"
    )
    browser.add_argument(
        "--browser-executable", metavar="PATH", help="path to a Chromium binary"
    )

    run = parser.add_argument_group("run control")
    run.add_argument("-c", "--concurrency", type=int, default=4, help="parallel page loads (default: %(default)s)")
    run.add_argument(
        "--ai-concurrency", type=int, default=3, help="parallel model requests (default: %(default)s)"
    )
    run.add_argument(
        "--respect-robots",
        action="store_true",
        help="skip URLs disallowed by the origin's robots.txt",
    )
    run.add_argument(
        "--fail-on",
        choices=("critical", "high", "medium", "low", "info", "none"),
        default="high",
        help="exit 1 when a finding at this severity or above exists (default: %(default)s)",
    )
    run.add_argument("--dry-run", action="store_true", help="print the resolved targets and exit")
    return parser


def parse_viewport(value: str) -> tuple[int, int]:
    for sep in ("x", "X", ","):
        if sep in value:
            left, _, right = value.partition(sep)
            try:
                width, height = int(left), int(right)
            except ValueError:
                break
            if width > 0 and height > 0:
                return width, height
            break
    raise argparse.ArgumentTypeError(f"invalid viewport {value!r}; expected e.g. 1440x900")


def parse_headers(raw: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for item in raw:
        if ":" not in item:
            raise argparse.ArgumentTypeError(f"invalid header {item!r}; expected 'Name: value'")
        name, _, value = item.partition(":")
        name = name.strip()
        if not name:
            raise argparse.ArgumentTypeError(f"invalid header {item!r}; empty name")
        headers[name] = value.strip()
    return headers


def parse_basic_auth(value: str | None) -> tuple[str, str] | None:
    if not value:
        return None
    if ":" not in value:
        raise argparse.ArgumentTypeError("--basic-auth expects USER:PASS")
    user, _, password = value.partition(":")
    return user, password


def build_config(args: argparse.Namespace) -> ScanConfig:
    """Turn parsed arguments into a ScanConfig, raising ValueError on bad input."""
    width, height = parse_viewport(args.viewport)
    output_dir = Path(args.output_dir)

    capture = CaptureOptions(
        viewport_width=width,
        viewport_height=height,
        full_page=args.full_page,
        max_capture_height=max(0, args.max_height),
        timeout_ms=int(args.timeout * 1000),
        wait_until=args.wait_until,
        settle_ms=int(args.settle * 1000),
        user_agent=args.user_agent,
        ignore_https_errors=args.insecure,
        extra_headers=parse_headers(args.header),
        basic_auth=parse_basic_auth(args.basic_auth),
        storage_state=args.storage_state,
        browser_channel=args.browser_channel,
        executable_path=args.browser_executable,
    )

    categories = load_categories(args.categories_file)

    analyzer: AnalyzerOptions | None = None
    if not args.no_ai:
        instructions = args.instructions or ""
        if args.instructions_file:
            extra = Path(args.instructions_file).read_text(encoding="utf-8")
            instructions = f"{instructions}\n{extra}".strip()
        api_key = (
            args.api_key
            or os.environ.get("OPENROUTER_API_KEY")
            or os.environ.get("SECMAN_API_KEY")
            or ""
        )
        analyzer = AnalyzerOptions(
            api_key=api_key,
            model=args.model or os.environ.get("SECMAN_MODEL") or DEFAULT_MODEL,
            base_url=args.base_url or os.environ.get("SECMAN_BASE_URL") or DEFAULT_BASE_URL,
            max_tokens=args.max_tokens,
            temperature=args.temperature,
            timeout_s=args.ai_timeout,
            max_retries=max(0, args.ai_retries),
            structured_output=args.structured_output,
            extra_instructions=instructions,
            prompt_text_chars=max(0, args.prompt_text_chars),
        )

    return ScanConfig(
        output_dir=output_dir,
        capture=capture,
        analyzer=analyzer,
        categories=categories,
        concurrency=max(1, args.concurrency),
        ai_concurrency=max(1, args.ai_concurrency),
        respect_robots=args.respect_robots,
        fail_on=None if args.fail_on == "none" else Severity(args.fail_on),
    )


def _progress_hook(quiet: bool):
    def hook(result: ScanResult, done: int, total: int) -> None:
        if quiet:
            return
        if result.skipped_reason:
            state = f"skipped ({result.skipped_reason})"
        elif result.error:
            state = f"error: {result.error}"
        elif result.capture and result.capture.load_error:
            state = f"load failed: {result.capture.load_error}"
        else:
            state = result.max_severity.value
        print(f"[{done}/{total}] {result.url} -> {state}", file=sys.stderr, flush=True)

    return hook


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.urls and not args.file and not args.stdin:
        parser.error("no targets given; pass URLs, --file PATH or --stdin")

    try:
        targets = load_targets(args.urls, args.file, args.stdin)
    except TargetError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if not targets:
        print("error: no valid targets after parsing input", file=sys.stderr)
        return EXIT_ERROR

    if args.dry_run:
        for url in targets:
            print(url)
        return EXIT_OK

    try:
        config = build_config(args)
    except (argparse.ArgumentTypeError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if not args.quiet:
        mode = "capture only" if config.analyzer is None else config.analyzer.model
        print(
            f"Scanning {len(targets)} target(s) with {config.concurrency} browser worker(s); "
            f"analysis: {mode}",
            file=sys.stderr,
        )

    try:
        report = asyncio.run(
            run_scan(
                targets,
                config,
                progress=_progress_hook(args.quiet),
                tool_version=__version__,
            )
        )
    except AnalyzerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return EXIT_ERROR

    write_console_report(
        report,
        color=should_colorize(sys.stdout, args.color),
        verbose=args.verbose,
    )

    if not args.no_json:
        path = Path(args.json) if args.json else config.output_dir / "report.json"
        write_json_report(report, path, include_raw=args.include_raw)
        print(f"\nJSON report: {path}")
    if not args.no_html:
        path = Path(args.html) if args.html else config.output_dir / "report.html"
        write_html_report(report, path, embed_images=not args.link_images)
        print(f"HTML report: {path}")

    if config.fail_on is not None and report.max_severity.rank >= config.fail_on.rank:
        if any(f.severity.rank >= config.fail_on.rank for r in report.results for f in r.findings):
            return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
