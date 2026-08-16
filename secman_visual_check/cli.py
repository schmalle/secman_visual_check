"""Command line interface for the visual exposure scanner."""

from __future__ import annotations

import argparse
import asyncio
import io
import os
import sys
from pathlib import Path
from typing import Sequence

from . import __version__
from .analyzer import DEFAULT_BASE_URL, DEFAULT_MODEL, AnalyzerError, AnalyzerOptions
from .capture import CaptureOptions
from .categories import load_categories
from .config import ScanConfig
from .mailer import DEFAULT_SUBJECT_PREFIX
from .mailer import DEFAULT_TIMEOUT_S as MAIL_TIMEOUT_S
from .mailer import TRANSPORTS, MailOptions, send_report, write_mail_report
from .models import ScanResult, Severity
from .reporting import (
    should_colorize,
    write_console_report,
    write_csv_report,
    write_html_report,
    write_json_report,
    write_stats_report,
)
from .db import (
    DEFAULT_DB_NAME,
    DEFAULT_TABLE_PREFIX,
    DatabaseError,
    DbOptions,
    parse_flag,
    set_flags,
    store_report,
    write_db_report,
    write_flag_report,
)
from .plan import ScanPlan, write_plan
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
from .secrets import BINARY_ENV as PASS_CLI_ENV
from .secrets import DEFAULT_BINARY as DEFAULT_PASS_CLI
from .secrets import DEFAULT_TIMEOUT_S as PASS_CLI_TIMEOUT_S
from .secrets import SCHEME as SECRET_SCHEME
from .secrets import SecretError, SecretResolver, redact
from .status import DEFAULT_CHECKSUM_MAX_BYTES
from .status import DEFAULT_CONCURRENCY as DEFAULT_STATUS_CONCURRENCY
from .status import DEFAULT_MAX_REDIRECTS
from .status import DEFAULT_TIMEOUT_S as DEFAULT_STATUS_TIMEOUT_S
from .status import StatusCheckOptions
from .targets import TargetError, load_targets, normalize_url

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
    out.add_argument("--csv", metavar="PATH", help="CSV report path (default: DIR/report.csv)")
    out.add_argument(
        "--stats",
        metavar="PATH",
        help="statistics report path (default: DIR/statistics.txt)",
    )
    out.add_argument("--no-json", action="store_true", help="skip the JSON report")
    out.add_argument("--no-html", action="store_true", help="skip the HTML report")
    out.add_argument("--no-csv", action="store_true", help="skip the CSV report")
    out.add_argument("--no-stats", action="store_true", help="skip the statistics report")
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
        "--no-visual-check",
        dest="visual_check",
        action="store_false",
        default=True,
        help="skip the browser entirely — no screenshots, no analysis. Leaves a "
        "pure status/checksum check that needs no Chromium installed",
    )
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
        "--allow-private-redirects",
        action="store_true",
        help="do not block a target's redirect (or, for the browser capture, an "
        "iframe) to a private/loopback/link-local address on a different host "
        "than the target itself. Off by default: a compromised or malicious "
        "target could otherwise redirect the scanner at internal "
        "infrastructure or cloud metadata endpoints (e.g. 169.254.169.254)",
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
    checksum = status.add_mutually_exclusive_group()
    checksum.add_argument(
        "--status-checksum",
        dest="status_checksum",
        action="store_true",
        default=True,
        help="hash the response body of targets that answer as expected, so a "
        "later run can tell 'still up' from 'still up and unchanged'. On by "
        "default; the flag is kept so existing scripts keep working",
    )
    checksum.add_argument(
        "--no-status-checksum",
        dest="status_checksum",
        action="store_false",
        help="do not fetch bodies — the status check then costs one HEAD per "
        "target and cannot detect content changes",
    )
    status.add_argument(
        "--status-checksum-max-bytes",
        type=int,
        default=DEFAULT_CHECKSUM_MAX_BYTES,
        metavar="N",
        help="stop hashing a body after this many bytes (default: %(default)s)",
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
    run.add_argument(
        "--dry-run",
        action="store_true",
        help="resolve everything — targets, credentials, every stage — then print "
        "the plan and exit without writing, sending or uploading anything. Add "
        "-q to print only the resolved target URLs",
    )

    secrets = parser.add_argument_group(
        "secrets",
        "Any credential this tool accepts — API keys, tokens, database and SMTP "
        "passwords — "
        f"may be given as a {SECRET_SCHEME}vault/item/field reference instead of "
        "the secret itself; the value is fetched from Proton Pass through "
        "pass-cli before the scan starts. Values that are not references are "
        "used verbatim, so nothing changes unless you opt in.",
    )
    secrets.add_argument(
        "--pass-cli-binary",
        default=None,
        metavar="PATH",
        help=f"Proton Pass CLI to invoke (default: ${PASS_CLI_ENV} or {DEFAULT_PASS_CLI})",
    )
    secrets.add_argument(
        "--pass-cli-timeout",
        type=float,
        default=PASS_CLI_TIMEOUT_S,
        metavar="SECONDS",
        help="how long to wait for one pass-cli call (default: %(default)s)",
    )
    secrets.add_argument(
        "--no-pass-cli",
        dest="pass_cli",
        action="store_false",
        default=True,
        help=f"refuse {SECRET_SCHEME} references instead of resolving them, for "
        "hosts where shelling out to a password manager is not wanted",
    )

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

    mail = parser.add_argument_group(
        "email",
        "Send the result as an email styled like SecMan's own notifications. "
        "Transports: plain SMTP, Microsoft 365 (Graph sendMail) and AWS SES.",
    )
    mail.add_argument(
        "--mail",
        action="store_true",
        help="email the results when the scan finishes (default: $SECMAN_MAIL)",
    )
    mail.add_argument(
        "--mail-transport",
        choices=TRANSPORTS,
        default=None,
        help="how to send (default: $SECMAN_MAIL_TRANSPORT or smtp)",
    )
    mail.add_argument(
        "--mail-from",
        default=None,
        metavar="ADDRESS",
        help="sender address (default: $SECMAN_MAIL_FROM)",
    )
    mail.add_argument(
        "--mail-from-name",
        default="SecMan Visual Check",
        metavar="NAME",
        help="sender display name (default: %(default)s)",
    )
    mail.add_argument(
        "--mail-to",
        action="append",
        default=[],
        metavar="ADDRESS",
        help="recipient, repeatable (default: $SECMAN_MAIL_TO, comma separated)",
    )
    mail.add_argument(
        "--mail-subject-prefix",
        default=DEFAULT_SUBJECT_PREFIX,
        metavar="TEXT",
        help="prepended to the subject (default: %(default)s)",
    )
    mail.add_argument(
        "--mail-always",
        action="store_true",
        help="send even when nothing is wrong; by default a clean run sends nothing",
    )
    mail.add_argument(
        "--mail-dry-run",
        action="store_true",
        help="render the message and print the subject without delivering it",
    )
    mail.add_argument(
        "--mail-dashboard-url",
        default=None,
        metavar="URL",
        help="linked from the email's call-to-action button",
    )
    mail.add_argument(
        "--mail-timeout",
        type=float,
        default=MAIL_TIMEOUT_S,
        metavar="SECONDS",
        help="delivery timeout (default: %(default)s)",
    )
    mail.add_argument("--mail-smtp-host", default=None, help="default: $SECMAN_MAIL_SMTP_HOST")
    mail.add_argument(
        "--mail-smtp-port", type=int, default=None, help="default: $SECMAN_MAIL_SMTP_PORT or 587"
    )
    mail.add_argument("--mail-smtp-user", default=None, help="default: $SECMAN_MAIL_SMTP_USER")
    mail.add_argument(
        "--mail-smtp-password", default=None, help="default: $SECMAN_MAIL_SMTP_PASSWORD"
    )
    mail.add_argument(
        "--mail-smtp-no-tls",
        dest="mail_smtp_tls",
        action="store_false",
        default=True,
        help="do not issue STARTTLS",
    )
    mail.add_argument(
        "--mail-smtp-ssl", action="store_true", help="connect with implicit TLS (port 465)"
    )
    mail.add_argument(
        "--mail-tenant-id", default=None, metavar="ID", help="default: $SECMAN_MAIL_TENANT_ID"
    )
    mail.add_argument(
        "--mail-client-id", default=None, metavar="ID", help="default: $SECMAN_MAIL_CLIENT_ID"
    )
    mail.add_argument(
        "--mail-client-secret",
        default=None,
        metavar="SECRET",
        help="default: $SECMAN_MAIL_CLIENT_SECRET",
    )
    mail.add_argument(
        "--mail-aws-region",
        default=None,
        metavar="REGION",
        help="SES region (default: $SECMAN_MAIL_AWS_REGION or $AWS_REGION)",
    )
    mail.add_argument(
        "--mail-aws-profile",
        default=None,
        metavar="NAME",
        help="named AWS profile to resolve SES credentials from (default: $AWS_PROFILE)",
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
    db.add_argument(
        "--db-set-flag",
        action="append",
        default=[],
        metavar="URL=FLAG",
        help="flag a URL as OK, NEW or NOT_CHECKED and exit (no scan). Repeatable. "
        "OK is the operator's verdict and is never set by a scan; it is cleared "
        "automatically when the URL's content checksum changes",
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


def parse_flag_assignments(raw: list[str]) -> list[tuple[str, str]]:
    """Parse ``--db-set-flag URL=FLAG`` into ``[(normalised url, canonical flag)]``.

    Split on the *last* ``=`` so query strings survive: ``?a=b=OK`` means the URL
    is ``?a=b`` and the flag is ``OK``.
    """
    assignments: list[tuple[str, str]] = []
    for item in raw:
        url, sep, flag = item.rpartition("=")
        if not sep or not url.strip() or not flag.strip():
            raise argparse.ArgumentTypeError(
                f"invalid --db-set-flag {item!r}; expected URL=FLAG, e.g. "
                "https://example.com/=OK"
            )
        try:
            normalised = normalize_url(url.strip())
        except TargetError as exc:
            raise argparse.ArgumentTypeError(f"invalid --db-set-flag {item!r}: {exc}") from exc
        try:
            assignments.append((normalised, parse_flag(flag)))
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"invalid --db-set-flag {item!r}: {exc}") from exc
    return assignments


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


def build_secret_resolver(args: argparse.Namespace) -> SecretResolver:
    """The one resolver a run uses, so a reference is fetched once, not per flag."""
    return SecretResolver(
        binary=(
            args.pass_cli_binary or os.environ.get(PASS_CLI_ENV) or DEFAULT_PASS_CLI
        ),
        timeout=max(0.1, args.pass_cli_timeout),
        enabled=args.pass_cli,
    )


def build_config(
    args: argparse.Namespace, resolver: SecretResolver | None = None
) -> ScanConfig:
    """Turn parsed arguments into a ScanConfig, raising ValueError on bad input.

    Raises :class:`SecretError` when a credential is a ``pass://`` reference that
    cannot be resolved — before the browser is launched, like every other
    credential check.
    """
    resolver = resolver or SecretResolver()
    width, height = parse_viewport(args.viewport)
    output_dir = Path(args.output_dir)

    headers = {
        name: resolver.resolve(value, what=f"--header {name!r}") or ""
        for name, value in parse_headers(args.header).items()
    }

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
        extra_headers=headers,
        basic_auth=parse_basic_auth(
            resolver.resolve_pair(args.basic_auth, what="--basic-auth")
        ),
        storage_state=args.storage_state,
        browser_channel=args.browser_channel,
        executable_path=args.browser_executable,
        block_private_redirects=not args.allow_private_redirects,
    )

    categories = load_categories(args.categories_file)

    analyzer: AnalyzerOptions | None = None
    # No browser means no screenshot, and the model has nothing to look at.
    if not args.no_ai and args.visual_check:
        instructions = args.instructions or ""
        if args.instructions_file:
            extra = Path(args.instructions_file).read_text(encoding="utf-8")
            instructions = f"{instructions}\n{extra}".strip()
        api_key = (
            resolver.resolve(
                args.api_key
                or os.environ.get("OPENROUTER_API_KEY")
                or os.environ.get("SECMAN_API_KEY"),
                what="--api-key",
            )
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
        checksum=args.status_checksum,
        checksum_max_bytes=max(0, args.status_checksum_max_bytes),
        block_private_redirects=not args.allow_private_redirects,
    )

    if not args.visual_check and not status_check.enabled:
        raise ValueError(
            "--no-visual-check and --no-status-check together leave nothing to do"
        )

    # Database mode depends on it: the stored checksum is what makes change
    # detection possible, and there is nowhere else to keep one. Turning it off
    # would leave the flag lifecycle silently broken, so say so instead.
    if not args.status_checksum and (args.db_store or _env_flag("SECMAN_DB_STORE")):
        raise ValueError(
            "--no-status-checksum cannot be combined with --db-store: the stored "
            "checksum is what makes change detection possible"
        )

    return ScanConfig(
        output_dir=output_dir,
        visual_check=args.visual_check,
        capture=capture,
        status_check=status_check,
        analyzer=analyzer,
        categories=categories,
        concurrency=max(1, args.concurrency),
        ai_concurrency=max(1, args.ai_concurrency),
        respect_robots=args.respect_robots,
        fail_on=None if args.fail_on == "none" else Severity(args.fail_on),
    )


def build_secman_options(
    args: argparse.Namespace, resolver: SecretResolver | None = None
) -> SecmanOptions:
    """Resolve the SecMan flags against the environment, raising ValueError if unusable."""
    resolver = resolver or SecretResolver()
    options = SecmanOptions(
        transport=args.secman_transport,
        base_url=(args.secman_url or os.environ.get("SECMAN_URL") or DEFAULT_BACKEND_URL),
        dry_run=args.secman_dry_run,
        token=resolver.resolve(
            args.secman_token or os.environ.get("SECMAN_TOKEN"), what="--secman-token"
        ),
        username=args.secman_username or os.environ.get("SECMAN_USERNAME"),
        password=resolver.resolve(
            args.secman_password or os.environ.get("SECMAN_PASSWORD"),
            what="--secman-password",
        ),
        # Deliberately not SECMAN_API_KEY: that one is the vision model's key.
        api_key=resolver.resolve(
            args.secman_api_key or os.environ.get("SECMAN_MCP_API_KEY"),
            what="--secman-api-key",
        ),
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


def build_db_options(
    args: argparse.Namespace, resolver: SecretResolver | None = None
) -> DbOptions:
    """Resolve the database flags against the environment, raising ValueError if unusable."""
    resolver = resolver or SecretResolver()
    enabled = args.db_store or _env_flag("SECMAN_DB_STORE")
    # The whole DSN can be one reference: the password inside it would otherwise
    # be the single worst thing to have on a command line.
    url = resolver.resolve(
        args.db_url or os.environ.get("SECMAN_DB_URL"), what="--db-url"
    )
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
            password=resolver.resolve(
                args.db_password or os.environ.get("SECMAN_DB_PASSWORD"),
                what="--db-password",
            )
            or "",
            database=args.db_name or os.environ.get("SECMAN_DB_NAME") or DEFAULT_DB_NAME,
            **overrides,
        )
    options.validate()
    return options


def build_mail_options(
    args: argparse.Namespace, resolver: SecretResolver | None = None
) -> MailOptions:
    """Resolve the email flags against the environment, raising ValueError if unusable."""
    resolver = resolver or SecretResolver()
    recipients = list(args.mail_to)
    if not recipients:
        recipients = [
            address.strip()
            for address in (os.environ.get("SECMAN_MAIL_TO") or "").split(",")
            if address.strip()
        ]
    options = MailOptions(
        enabled=args.mail or _env_flag("SECMAN_MAIL"),
        transport=(
            args.mail_transport or os.environ.get("SECMAN_MAIL_TRANSPORT") or "smtp"
        ),
        sender=args.mail_from or os.environ.get("SECMAN_MAIL_FROM") or "",
        sender_name=args.mail_from_name,
        recipients=recipients,
        subject_prefix=args.mail_subject_prefix,
        always=args.mail_always,
        timeout=args.mail_timeout,
        dry_run=args.mail_dry_run,
        smtp_host=args.mail_smtp_host or os.environ.get("SECMAN_MAIL_SMTP_HOST") or "",
        smtp_port=args.mail_smtp_port
        or int(os.environ.get("SECMAN_MAIL_SMTP_PORT") or 587),
        smtp_user=args.mail_smtp_user or os.environ.get("SECMAN_MAIL_SMTP_USER") or "",
        smtp_password=(
            resolver.resolve(
                args.mail_smtp_password or os.environ.get("SECMAN_MAIL_SMTP_PASSWORD"),
                what="--mail-smtp-password",
            )
            or ""
        ),
        smtp_tls=args.mail_smtp_tls,
        smtp_ssl=args.mail_smtp_ssl,
        tenant_id=args.mail_tenant_id or os.environ.get("SECMAN_MAIL_TENANT_ID") or "",
        client_id=args.mail_client_id or os.environ.get("SECMAN_MAIL_CLIENT_ID") or "",
        client_secret=(
            resolver.resolve(
                args.mail_client_secret or os.environ.get("SECMAN_MAIL_CLIENT_SECRET"),
                what="--mail-client-secret",
            )
            or ""
        ),
        aws_region=(
            args.mail_aws_region
            or os.environ.get("SECMAN_MAIL_AWS_REGION")
            or os.environ.get("AWS_REGION")
            or ""
        ),
        aws_profile=args.mail_aws_profile or os.environ.get("AWS_PROFILE") or "",
    )
    options.validate()
    return options


def _env_flag(name: str) -> bool:
    return (os.environ.get(name) or "").strip().lower() in ("1", "true", "yes", "on")


def _emit(writer, *args, secrets: Sequence[str] = (), **kwargs) -> None:
    """Run a report writer, then scrub resolved secrets out of what it printed.

    Every one of these writers echoes text from somewhere else — a SecMan error
    body, a database driver's message. A backend that rejects a credential by
    quoting it back must not get it into the console output or a CI log, so the
    output goes through a buffer on its way to stdout rather than straight to it.
    """
    buffer = io.StringIO()
    writer(*args, stream=buffer, **kwargs)
    sys.stdout.write(redact(buffer.getvalue(), secrets))


def _run_secman_upload(
    report, options: SecmanOptions, fail_on_error: bool, secrets: Sequence[str] = ()
) -> int:
    """Upload a report's findings and turn the result into an exit code."""
    try:
        summary = upload_findings(report, options)
    except SecmanError as exc:
        print(f"error: SecMan upload failed: {redact(str(exc), secrets)}", file=sys.stderr)
        return EXIT_ERROR
    _emit(write_upload_report, summary, secrets=secrets)
    if (summary.failures or summary.asset_failures) and fail_on_error:
        return EXIT_ERROR
    return EXIT_OK


def _progress_hook(quiet: bool, secrets: Sequence[str] = ()):
    """Per-target progress line, printed live as the scan runs.

    Unlike every other writer, this one runs *before* the final reports (and
    their own redaction) exist, straight to stderr — a resolved secret
    reflected into `result.error`/`load_error` (e.g. a `--basic-auth pass://`
    credential a backend echoed back) would otherwise reach a terminal or CI
    log unredacted before the scan even finishes. Route it through the same
    `redact()` every other writer uses.
    """

    def hook(result: ScanResult, done: int, total: int) -> None:
        if quiet:
            return
        if result.skipped_reason:
            state = f"skipped ({result.skipped_reason})"
        elif result.error:
            state = f"error: {redact(result.error, secrets)}"
        elif result.capture and result.capture.load_error:
            state = f"load failed: {redact(result.capture.load_error, secrets)}"
        else:
            state = result.max_severity.value
        prefix = f"{result.status_check.label} | " if result.status_check else ""
        print(f"[{done}/{total}] {result.url} -> {prefix}{state}", file=sys.stderr, flush=True)

    return hook


def _report_outputs(args: argparse.Namespace, config: ScanConfig) -> list[tuple[str, Path]]:
    """The files a run would write, in the order it would write them."""
    outputs: list[tuple[str, Path]] = []
    if config.visual_check:
        outputs.append(("screenshots", config.screenshot_dir))
    for name, flag, override, filename in (
        ("json", args.no_json, args.json, "report.json"),
        ("html", args.no_html, args.html, "report.html"),
        ("csv", args.no_csv, args.csv, "report.csv"),
        ("statistics", args.no_stats, args.stats, "statistics.txt"),
    ):
        if not flag:
            outputs.append((name, Path(override) if override else config.output_dir / filename))
    return outputs


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # One switch, applied before anything is built: a dry run must not be able
    # to write through a stage that was never told about it.
    if args.dry_run:
        args.secman_dry_run = True
        args.mail_dry_run = True

    resolver = build_secret_resolver(args)

    upload_requested = args.secman_upload or args.secman_upload_report
    try:
        # Fail before the scan: a ten-minute crawl should not end on a typo in
        # the credentials, nor on a pass:// reference that names nothing.
        secman_options = (
            build_secman_options(args, resolver) if upload_requested else None
        )
        db_options = build_db_options(args, resolver)
        mail_options = build_mail_options(args, resolver)
    except (ValueError, SecretError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    # Flagging URLs is a standalone command; there is nothing to scan.
    if args.db_set_flag:
        try:
            assignments = parse_flag_assignments(args.db_set_flag)
        except argparse.ArgumentTypeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_ERROR
        # Reuse the same credential rules as a storing run, whether or not
        # --db-store was passed.
        db_options.enabled = True
        try:
            db_options.validate()
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_ERROR
        if args.dry_run:
            # Deliberately offline. Reading the current flags would make a nicer
            # preview, but it would also mean a dry run of a two-line command
            # needs a reachable database and an installed driver.
            write_plan(
                ScanPlan(
                    action=f"set URL flags in {db_options.dsn}",
                    secrets=resolver.resolved,
                    notes=[
                        "Would set:\n"
                        + "\n".join(f"  {flag:<12} {url}" for url, flag in assignments)
                    ],
                )
            )
            return EXIT_OK
        try:
            changes = set_flags(assignments, db_options)
        except (ValueError, DatabaseError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_ERROR
        write_flag_report(changes)
        return EXIT_OK

    # Uploading a stored report is a standalone mode; there is nothing to scan.
    if args.secman_upload_report:
        try:
            stored = load_report_json(args.secman_upload_report)
        except SecmanError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_ERROR
        assert secman_options is not None
        return _run_secman_upload(
            stored, secman_options, args.secman_fail_on_error, resolver.values
        )

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

    try:
        config = build_config(args, resolver)
    except (argparse.ArgumentTypeError, ValueError, OSError, SecretError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.dry_run:
        if args.quiet:
            # The original --dry-run output, kept verbatim so scripts that pipe
            # the target list into something else keep working.
            for url in targets:
                print(url)
            return EXIT_OK
        write_plan(
            ScanPlan(
                targets=targets,
                config=config,
                outputs=_report_outputs(args, config),
                db=db_options,
                mail=mail_options,
                secman=secman_options,
                secrets=resolver.resolved,
            )
        )
        return EXIT_OK

    if not args.quiet:
        if not config.visual_check:
            workers = f"{config.status_check.max_concurrency} status worker(s)"
            mode = "no browser (status check only)"
        else:
            workers = f"{config.concurrency} browser worker(s)"
            mode = "capture only" if config.analyzer is None else config.analyzer.model
        print(
            f"Scanning {len(targets)} target(s) with {workers}; analysis: {mode}",
            file=sys.stderr,
        )

    try:
        report = asyncio.run(
            run_scan(
                targets,
                config,
                progress=_progress_hook(args.quiet, secrets=resolver.values),
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
        statistics=not args.no_stats,
        secrets=resolver.values,
    )

    if not args.no_json:
        path = Path(args.json) if args.json else config.output_dir / "report.json"
        write_json_report(report, path, include_raw=args.include_raw, secrets=resolver.values)
        print(f"\nJSON report: {path}")
    if not args.no_html:
        path = Path(args.html) if args.html else config.output_dir / "report.html"
        write_html_report(
            report, path, embed_images=not args.link_images, secrets=resolver.values
        )
        print(f"HTML report: {path}")
    if not args.no_csv:
        path = Path(args.csv) if args.csv else config.output_dir / "report.csv"
        write_csv_report(report, path, secrets=resolver.values)
        print(f"CSV report: {path}")
    if not args.no_stats:
        path = Path(args.stats) if args.stats else config.output_dir / "statistics.txt"
        write_stats_report(report, path, secrets=resolver.values)
        print(f"Statistics: {path}")

    db_status = EXIT_OK
    flag_changes: list = []
    if db_options.enabled:
        summary = store_report(report, db_options)
        _emit(write_db_report, summary, secrets=resolver.values)
        flag_changes = summary.flag_changes
        if summary.error and db_options.fail_on_error:
            db_status = EXIT_ERROR

    if mail_options.enabled:
        # After the database, so the email can report which URLs are new or
        # changed — that is the part a human actually wants mailed.
        mail_summary = send_report(
            report,
            mail_options,
            flag_changes=flag_changes,
            dashboard_url=args.mail_dashboard_url,
            secrets=resolver.values,
        )
        _emit(write_mail_report, mail_summary, secrets=resolver.values)

    upload_status = EXIT_OK
    if secman_options is not None:
        upload_status = _run_secman_upload(
            report, secman_options, args.secman_fail_on_error, resolver.values
        )

    if config.fail_on is not None and report.max_severity.rank >= config.fail_on.rank:
        if any(f.severity.rank >= config.fail_on.rank for r in report.results for f in r.findings):
            return EXIT_FINDINGS
    if args.fail_on_status and report.status_failures:
        return EXIT_FINDINGS
    return upload_status or db_status


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
