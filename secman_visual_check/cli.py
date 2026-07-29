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
from .db import (
    DEFAULT_DB_NAME,
    DEFAULT_TABLE_PREFIX,
    DbOptions,
    store_report,
    write_db_report,
)
from .scanner import run_scan
from .secman import (
    DEFAULT_ASSET_TYPE,
    DEFAULT_BACKEND_URL,
    DEFAULT_ID_PREFIX,
    DEFAULT_OWNER,
    DEFAULT_TIMEOUT_S,
    SecmanError,
    SecmanOptions,
    load_report_json,
    upload_findings,
    write_upload_report,
)
from .status import DEFAULT_CONCURRENCY as DEFAULT_STATUS_CONCURRENCY
from .status import DEFAULT_MAX_REDIRECTS
from .status import DEFAULT_TIMEOUT_S as DEFAULT_STATUS_TIMEOUT_S
from .status import StatusCheckOptions
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

    status = parser.add_argument_group(
        "status check",
        "Before the browser opens a target, ask a plain HTTP client what it "
        "answers: 200, a redirect (and where to), an error, or nothing at all. "
        "Redirects are walked by hand, so the first response is recorded verbatim "
        "instead of being swallowed by the browser.",
    )
    status.add_argument(
        "--no-status-check",
        dest="status_check",
        action="store_false",
        default=True,
        help="skip the HTTP status/redirect pre-check",
    )
    status.add_argument(
        "--status-method",
        choices=("auto", "head", "get"),
        default="auto",
        help="auto tries HEAD and falls back to GET where HEAD is refused (default: %(default)s)",
    )
    status.add_argument(
        "--status-timeout",
        type=float,
        default=DEFAULT_STATUS_TIMEOUT_S,
        metavar="SECONDS",
        help="status-check request timeout (default: %(default)s)",
    )
    status.add_argument(
        "--status-max-redirects",
        type=int,
        default=DEFAULT_MAX_REDIRECTS,
        metavar="N",
        help="redirect hops to follow, 0 to record only the first response (default: %(default)s)",
    )
    status.add_argument(
        "--status-expect",
        default="200",
        metavar="CODES",
        help="statuses treated as OK, comma separated; 2xx-style wildcards allowed "
        "(default: %(default)s)",
    )
    status.add_argument(
        "--status-concurrency",
        type=int,
        default=DEFAULT_STATUS_CONCURRENCY,
        metavar="N",
        help="parallel status checks (default: %(default)s)",
    )
    status.add_argument(
        "--fail-on-status",
        action="store_true",
        help="exit 1 when any target's status check is not OK",
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

    secman = parser.add_argument_group(
        "secman upload",
        "Push findings into a SecMan instance (https://github.com/schmalle/secman). "
        "Findings become vulnerabilities on the asset named after the target's host, "
        "under a stable synthetic ID, so re-scanning updates rows instead of "
        "duplicating them.",
    )
    secman.add_argument(
        "--secman-upload",
        action="store_true",
        help="upload this scan's findings to SecMan when it finishes",
    )
    secman.add_argument(
        "--secman-upload-report",
        metavar="PATH",
        help="upload the findings of an existing report.json and exit (no scan)",
    )
    secman.add_argument(
        "--secman-dry-run",
        action="store_true",
        help="show exactly what would be uploaded without writing anything",
    )
    secman.add_argument(
        "--secman-transport",
        choices=("http", "mcp"),
        default="http",
        help="REST API or MCP endpoint (default: %(default)s)",
    )
    secman.add_argument(
        "--secman-url",
        default=None,
        metavar="URL",
        help=f"SecMan base URL (default: $SECMAN_URL or {DEFAULT_BACKEND_URL})",
    )
    secman.add_argument(
        "--secman-token",
        default=None,
        metavar="JWT",
        help="existing SecMan JWT for http transport (default: $SECMAN_TOKEN)",
    )
    secman.add_argument(
        "--secman-username",
        default=None,
        help="SecMan login for http transport (default: $SECMAN_USERNAME)",
    )
    secman.add_argument(
        "--secman-password",
        default=None,
        help="SecMan password for http transport (default: $SECMAN_PASSWORD)",
    )
    secman.add_argument(
        "--secman-api-key",
        default=None,
        metavar="KEY",
        help="MCP API key, sent as X-MCP-API-Key (default: $SECMAN_MCP_API_KEY)",
    )
    secman.add_argument(
        "--secman-user-email",
        default=None,
        metavar="EMAIL",
        help="MCP delegated user, sent as X-MCP-User-Email (default: $SECMAN_MCP_USER_EMAIL)",
    )
    secman.add_argument(
        "--secman-min-severity",
        choices=("critical", "high", "medium", "low", "info"),
        default="medium",
        help="lowest severity worth uploading (default: %(default)s)",
    )
    secman.add_argument(
        "--secman-owner",
        default=DEFAULT_OWNER,
        metavar="NAME",
        help="owner recorded on assets SecMan auto-creates (default: %(default)s)",
    )
    secman.add_argument(
        "--secman-id-prefix",
        default=DEFAULT_ID_PREFIX,
        metavar="PREFIX",
        help="prefix for the synthetic vulnerability IDs (default: %(default)s)",
    )
    secman.add_argument(
        "--secman-asset-name",
        default=None,
        metavar="NAME",
        help="file every finding under this asset instead of the target's hostname",
    )
    secman.add_argument(
        "--secman-allow-existing",
        action="store_true",
        help="re-send findings SecMan already holds instead of skipping them",
    )
    secman.add_argument(
        "--secman-timeout",
        type=float,
        default=DEFAULT_TIMEOUT_S,
        metavar="SECONDS",
        help="SecMan request timeout (default: %(default)s)",
    )
    secman.add_argument(
        "--secman-insecure",
        action="store_true",
        help="ignore TLS certificate errors when talking to SecMan",
    )
    secman.add_argument(
        "--secman-fail-on-error",
        action="store_true",
        help="exit non-zero when any finding could not be uploaded",
    )
    secman.add_argument(
        "--secman-status-findings",
        action="store_true",
        help="also upload a vulnerability for targets whose status check is not OK",
    )
    secman.add_argument(
        "--secman-status-severity",
        choices=("auto", "critical", "high", "medium", "low", "info"),
        default="auto",
        help="severity for status findings; auto uses the built-in mapping (default: %(default)s)",
    )
    secman.add_argument(
        "--secman-register-assets",
        action="store_true",
        help="register every scanned host as a SecMan asset, even without findings "
        "(http transport needs the ADMIN role)",
    )
    secman.add_argument(
        "--secman-asset-type",
        default=DEFAULT_ASSET_TYPE,
        metavar="TYPE",
        help="asset type recorded on registered assets (default: %(default)s)",
    )

    db = parser.add_argument_group(
        "database",
        "Optionally mirror the status-check results into MariaDB. Needs the "
        "driver: pip install 'secman-visual-check[db]'. See db/install.sh for "
        "the schema and a least-privilege database user.",
    )
    db.add_argument(
        "--db-store",
        action="store_true",
        help="store status-check results in MariaDB (default: $SECMAN_DB_STORE)",
    )
    db.add_argument(
        "--db-url",
        default=None,
        metavar="URL",
        help="mysql://user:pass@host:3306/dbname, overriding the individual "
        "--db-* flags (default: $SECMAN_DB_URL)",
    )
    db.add_argument("--db-host", default=None, help="default: $SECMAN_DB_HOST or 127.0.0.1")
    db.add_argument("--db-port", type=int, default=None, help="default: $SECMAN_DB_PORT or 3306")
    db.add_argument("--db-user", default=None, help="default: $SECMAN_DB_USER")
    db.add_argument("--db-password", default=None, help="default: $SECMAN_DB_PASSWORD")
    db.add_argument(
        "--db-name",
        default=None,
        help=f"default: $SECMAN_DB_NAME or {DEFAULT_DB_NAME}",
    )
    db.add_argument(
        "--db-table-prefix",
        default=DEFAULT_TABLE_PREFIX,
        metavar="PREFIX",
        help="table name prefix (default: %(default)s)",
    )
    db.add_argument(
        "--db-fail-on-error",
        action="store_true",
        help="exit non-zero when the database write fails",
    )
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


def parse_status_list(value: str) -> tuple[int, ...]:
    """Parse ``--status-expect``: ``200``, ``200,401`` or a wildcard like ``2xx``."""
    codes: set[int] = set()
    for raw in value.split(","):
        item = raw.strip().lower()
        if not item:
            continue
        if len(item) == 3 and item[0].isdigit() and item[1:] == "xx":
            base = int(item[0]) * 100
            if not 100 <= base <= 500:
                raise argparse.ArgumentTypeError(f"invalid status wildcard {raw.strip()!r}")
            codes.update(range(base, base + 100))
            continue
        if not item.isdigit():
            raise argparse.ArgumentTypeError(
                f"invalid status {raw.strip()!r}; expected e.g. 200, 200,401 or 2xx"
            )
        code = int(item)
        if not 100 <= code <= 599:
            raise argparse.ArgumentTypeError(f"status {code} is outside 100-599")
        codes.add(code)
    if not codes:
        raise argparse.ArgumentTypeError("--status-expect needs at least one status code")
    return tuple(sorted(codes))


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

    # Inherits the browser's timeout, user agent, headers, basic auth and
    # --insecure, so the pre-check presents itself as the same client.
    status_check = StatusCheckOptions.from_capture(
        capture,
        enabled=args.status_check,
        method=args.status_method,
        timeout_s=args.status_timeout,
        max_redirects=max(0, args.status_max_redirects),
        expect_statuses=parse_status_list(args.status_expect),
        max_concurrency=max(1, args.status_concurrency),
    )

    return ScanConfig(
        output_dir=output_dir,
        capture=capture,
        status_check=status_check,
        analyzer=analyzer,
        categories=categories,
        concurrency=max(1, args.concurrency),
        ai_concurrency=max(1, args.ai_concurrency),
        respect_robots=args.respect_robots,
        fail_on=None if args.fail_on == "none" else Severity(args.fail_on),
    )


def build_secman_options(args: argparse.Namespace) -> SecmanOptions:
    """Resolve the SecMan flags against the environment, raising ValueError if unusable."""
    options = SecmanOptions(
        transport=args.secman_transport,
        base_url=(args.secman_url or os.environ.get("SECMAN_URL") or DEFAULT_BACKEND_URL),
        dry_run=args.secman_dry_run,
        token=args.secman_token or os.environ.get("SECMAN_TOKEN"),
        username=args.secman_username or os.environ.get("SECMAN_USERNAME"),
        password=args.secman_password or os.environ.get("SECMAN_PASSWORD"),
        # Deliberately not SECMAN_API_KEY: that one is the vision model's key.
        api_key=args.secman_api_key or os.environ.get("SECMAN_MCP_API_KEY"),
        user_email=args.secman_user_email or os.environ.get("SECMAN_MCP_USER_EMAIL"),
        min_severity=Severity(args.secman_min_severity),
        owner=args.secman_owner,
        id_prefix=args.secman_id_prefix,
        asset_name=args.secman_asset_name,
        allow_existing=args.secman_allow_existing,
        timeout=args.secman_timeout,
        verify_tls=not args.secman_insecure,
        status_findings=args.secman_status_findings,
        status_severity=(
            None
            if args.secman_status_severity == "auto"
            else Severity(args.secman_status_severity)
        ),
        register_assets=args.secman_register_assets,
        asset_type=args.secman_asset_type,
    )
    options.validate()
    return options


def build_db_options(args: argparse.Namespace) -> DbOptions:
    """Resolve the database flags against the environment, raising ValueError if unusable."""
    enabled = args.db_store or _env_flag("SECMAN_DB_STORE")
    url = args.db_url or os.environ.get("SECMAN_DB_URL")
    overrides = {
        "enabled": enabled,
        "table_prefix": args.db_table_prefix,
        "fail_on_error": args.db_fail_on_error,
    }
    if url:
        options = DbOptions.from_url(url, **overrides)
    else:
        options = DbOptions(
            host=args.db_host or os.environ.get("SECMAN_DB_HOST") or "127.0.0.1",
            port=args.db_port or int(os.environ.get("SECMAN_DB_PORT") or 3306),
            user=args.db_user or os.environ.get("SECMAN_DB_USER") or "",
            password=args.db_password or os.environ.get("SECMAN_DB_PASSWORD") or "",
            database=args.db_name or os.environ.get("SECMAN_DB_NAME") or DEFAULT_DB_NAME,
            **overrides,
        )
    options.validate()
    return options


def _env_flag(name: str) -> bool:
    return (os.environ.get(name) or "").strip().lower() in ("1", "true", "yes", "on")


def _run_secman_upload(report, options: SecmanOptions, fail_on_error: bool) -> int:
    """Upload a report's findings and turn the result into an exit code."""
    try:
        summary = upload_findings(report, options)
    except SecmanError as exc:
        print(f"error: SecMan upload failed: {exc}", file=sys.stderr)
        return EXIT_ERROR
    write_upload_report(summary)
    if (summary.failures or summary.asset_failures) and fail_on_error:
        return EXIT_ERROR
    return EXIT_OK


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
        prefix = f"{result.status_check.label} | " if result.status_check else ""
        print(f"[{done}/{total}] {result.url} -> {prefix}{state}", file=sys.stderr, flush=True)

    return hook


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    upload_requested = args.secman_upload or args.secman_upload_report
    if upload_requested:
        try:
            secman_options = build_secman_options(args)
        except ValueError as exc:
            # Fail before the scan: a ten-minute crawl should not end on a typo
            # in the credentials.
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_ERROR
    else:
        secman_options = None

    try:
        db_options = build_db_options(args)
    except ValueError as exc:
        # Same rule as the SecMan credentials: fail before the scan, not after it.
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    # Uploading a stored report is a standalone mode; there is nothing to scan.
    if args.secman_upload_report:
        try:
            stored = load_report_json(args.secman_upload_report)
        except SecmanError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_ERROR
        assert secman_options is not None
        return _run_secman_upload(stored, secman_options, args.secman_fail_on_error)

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

    db_status = EXIT_OK
    if db_options.enabled:
        summary = store_report(report, db_options)
        write_db_report(summary)
        if summary.error and db_options.fail_on_error:
            db_status = EXIT_ERROR

    upload_status = EXIT_OK
    if secman_options is not None:
        upload_status = _run_secman_upload(
            report, secman_options, args.secman_fail_on_error
        )

    if config.fail_on is not None and report.max_severity.rank >= config.fail_on.rank:
        if any(f.severity.rank >= config.fail_on.rank for r in report.results for f in r.findings):
            return EXIT_FINDINGS
    if args.fail_on_status and report.status_failures:
        return EXIT_FINDINGS
    return upload_status or db_status


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
