"""Console, JSON, HTML, CSV and statistics rendering of a ScanReport."""

from __future__ import annotations

import base64
import csv
import html
import json
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any, Sequence, TextIO

from .models import (
    STATUS_STATES,
    Analysis,
    Finding,
    PageCapture,
    ScanReport,
    ScanResult,
    Severity,
    UrlStatus,
)
from .secrets import redact

SEVERITY_COLORS = {
    Severity.CRITICAL: "\033[1;97;41m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[1;33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[90m",
}
RESET = "\033[0m"

SEVERITY_HEX = {
    Severity.CRITICAL: "#b3103c",
    Severity.HIGH: "#d9480f",
    Severity.MEDIUM: "#b7860b",
    Severity.LOW: "#1c7ed6",
    Severity.INFO: "#6b7280",
}

STATUS_COLORS = {
    "ok": "\033[32m",
    "redirect": "\033[36m",
    "redirect_broken": "\033[1;33m",
    "unexpected_status": "\033[1;33m",
    "client_error": "\033[1;31m",
    "server_error": "\033[1;31m",
    "unreachable": "\033[1;97;41m",
    "unknown": "\033[90m",
}

STATUS_HEX = {
    "ok": "#2f9e44",
    "redirect": "#1c7ed6",
    "redirect_broken": "#b7860b",
    "unexpected_status": "#b7860b",
    "client_error": "#d9480f",
    "server_error": "#b3103c",
    "unreachable": "#b3103c",
    "unknown": "#6b7280",
}

#: Order the status summary is printed in — most alarming last is unhelpful in a
#: terminal, so it reads best-to-worst.
STATUS_DISPLAY_ORDER = (
    "ok",
    "redirect",
    "redirect_broken",
    "unexpected_status",
    "client_error",
    "server_error",
    "unreachable",
    "unknown",
)


# --------------------------------------------------------------------------- #
# Secret redaction — applied before any renderer below sees the report
# --------------------------------------------------------------------------- #

#: A resolved credential can legitimately end up inside report content: a
#: target that reflects request headers (e.g. a rejected Basic-Auth password
#: passed via ``--basic-auth pass://vault/item/password``) back in its body
#: or error page puts it in ``capture.text_excerpt``/``load_error``, and from
#: there into the screenshot's extracted text, the AI analyzer's summary, and
#: every report format. ``redact_report`` scrubs every such target-influenced
#: text field before a renderer sees it — structural fields (URLs, status
#: codes, timestamps, config echoes like ``model``) are left untouched, since
#: scrubbing those would corrupt the report rather than protect anything.


def _redact_or_none(value: str | None, secrets: Sequence[str]) -> str | None:
    if value is None:
        return None
    return redact(value, secrets)


def _redact_capture(capture: PageCapture | None, secrets: Sequence[str]) -> PageCapture | None:
    if capture is None:
        return None
    return replace(
        capture,
        title=_redact_or_none(capture.title, secrets),
        text_excerpt=redact(capture.text_excerpt, secrets),
        load_error=_redact_or_none(capture.load_error, secrets),
        console_errors=[redact(entry, secrets) for entry in capture.console_errors],
    )


def _redact_status(status: UrlStatus | None, secrets: Sequence[str]) -> UrlStatus | None:
    if status is None:
        return None
    return replace(status, error=_redact_or_none(status.error, secrets))


def _redact_finding(finding: Finding, secrets: Sequence[str]) -> Finding:
    return replace(
        finding,
        category=redact(finding.category, secrets),
        title=redact(finding.title, secrets),
        evidence=redact(finding.evidence, secrets),
        recommendation=redact(finding.recommendation, secrets),
    )


def _redact_analysis(analysis: Analysis | None, secrets: Sequence[str]) -> Analysis | None:
    if analysis is None:
        return None
    return replace(
        analysis,
        summary=redact(analysis.summary, secrets),
        page_type=redact(analysis.page_type, secrets),
        error=_redact_or_none(analysis.error, secrets),
        raw_response=_redact_or_none(analysis.raw_response, secrets),
        findings=[_redact_finding(f, secrets) for f in analysis.findings],
    )


def _redact_result(result: ScanResult, secrets: Sequence[str]) -> ScanResult:
    return replace(
        result,
        error=_redact_or_none(result.error, secrets),
        skipped_reason=_redact_or_none(result.skipped_reason, secrets),
        capture=_redact_capture(result.capture, secrets),
        status_check=_redact_status(result.status_check, secrets),
        analysis=_redact_analysis(result.analysis, secrets),
    )


def redact_report(report: ScanReport, secrets: Sequence[str]) -> ScanReport:
    """Return a copy of ``report`` with every target-influenced text field
    scrubbed of any resolved secret value in ``secrets``.

    A no-op (returns ``report`` itself) when ``secrets`` is empty — the
    common case, and the reason every writer below can call this
    unconditionally without a cost when no credential was ever resolved.
    Shared with ``mailer.build_message``, so the outgoing email body gets the
    same scrubbing as the on-disk reports.
    """
    if not secrets:
        return report
    return replace(report, results=[_redact_result(r, secrets) for r in report.results])


def checksum_summary(status: UrlStatus) -> str:
    """``sha256:1a2b3c4d…  4.2 KB  text/html`` — the short form used everywhere."""
    if not status.content_checksum:
        return ""
    bits = [f"sha256:{status.content_checksum[:12]}"]
    if status.content_length is not None:
        bits.append(human_bytes(status.content_length) + (" (truncated)" if status.content_truncated else ""))
    if status.content_type:
        bits.append(status.content_type.split(";")[0].strip())
    return "  ".join(bits)


def human_bytes(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GB"  # pragma: no cover - unreachable, loop returns first


def _paint(text: str, severity: Severity, color: bool) -> str:
    if not color:
        return text
    return f"{SEVERITY_COLORS[severity]}{text}{RESET}"


def _paint_status(text: str, state: str, color: bool) -> str:
    if not color:
        return text
    return f"{STATUS_COLORS.get(state, '')}{text}{RESET}"


def status_detail(status: UrlStatus) -> str:
    """The parenthesised suffix after a status label, or ``''``."""
    if status.error:
        return status.error
    bits = []
    if status.redirect_count:
        hops = "hop" if status.redirect_count == 1 else "hops"
        bits.append(f"{status.redirect_count} {hops}")
    if not status.ok and status.final_status is not None:
        expected = ", ".join(str(code) for code in status.expected_statuses)
        bits.append(f"expected {expected}")
    if status.elapsed_s:
        bits.append(f"{status.elapsed_s:.2f}s")
    return ", ".join(bits)


def should_colorize(stream: TextIO, force: bool | None = None) -> bool:
    if force is not None:
        return force
    return hasattr(stream, "isatty") and stream.isatty()


def write_console_report(
    report: ScanReport,
    stream: TextIO | None = None,
    color: bool | None = None,
    verbose: bool = False,
    statistics: bool = True,
    secrets: Sequence[str] = (),
) -> None:
    report = redact_report(report, secrets)
    out = stream or sys.stdout
    use_color = should_colorize(out, color)

    print("", file=out)
    print("=" * 72, file=out)
    print(f"Scan finished: {len(report.results)} target(s) in {report.duration_s:.1f}s", file=out)
    if report.model:
        print(f"Model: {report.model}", file=out)
    print("=" * 72, file=out)

    for result in report.results:
        _write_result(result, out, use_color, verbose)

    counts = report.severity_counts()
    print("", file=out)
    print("Findings by severity:", file=out)
    for severity in reversed(list(Severity)):
        label = f"  {severity.value:<9} {counts[severity.value]}"
        print(_paint(label, severity, use_color) if counts[severity.value] else label, file=out)

    if report.status_checked:
        _write_status_summary(report, out, use_color)

    if statistics:
        _write_statistics_summary(report, out)

    failures = report.failed
    if failures:
        print("", file=out)
        print(f"{len(failures)} target(s) could not be captured:", file=out)
        for result in failures:
            reason = result.error or (result.capture.load_error if result.capture else "unknown")
            print(f"  {result.url} — {reason}", file=out)


def _write_statistics_summary(report: ScanReport, out: TextIO) -> None:
    """The derived numbers, deliberately not repeating the two count tables above.

    Rows whose stage never ran are omitted rather than printed as zeros: a
    ``--no-visual-check`` run has nothing to say about captures.
    """
    stats = report_statistics(report)
    targets = stats["targets"]
    if not targets:
        return

    rows: list[tuple[str, str]] = [("targets", f"{targets:>6}")]

    if any(r.capture is not None for r in report.results):
        rows.append(("captured", f"{stats['captured']:>6}  {_pct(stats['captured'], targets)}"))
        if stats["capture_failed"]:
            rows.append(
                ("capture failed", f"{stats['capture_failed']:>6}  {_pct(stats['capture_failed'], targets)}")
            )
        if stats["analysed"]:
            rows.append(("analysed", f"{stats['analysed']:>6}  {_pct(stats['analysed'], targets)}"))
    if stats["skipped"]:
        rows.append(("skipped", f"{stats['skipped']:>6}  {_pct(stats['skipped'], targets)}"))

    rows.append(
        (
            "findings",
            f"{stats['findings_total']:>6}  on {stats['targets_with_findings']} target(s)",
        )
    )

    checked = stats["status_checked"]
    if checked:
        rows.append(
            ("answered HTTP 200", f"{stats['answered_200']:>6}  {_pct(stats['answered_200'], checked)}")
        )
        rows.append(
            (
                "answered another code",
                f"{stats['answered_other']:>6}  {_pct(stats['answered_other'], checked)}",
            )
        )
        if stats["no_response"]:
            rows.append(
                ("no response", f"{stats['no_response']:>6}  {_pct(stats['no_response'], checked)}")
            )
        # Only worth a line when it differs from the plain 200 count above, which
        # happens exactly when --status-expect was widened.
        if stats["status_ok"] != stats["answered_200"]:
            rows.append(
                (
                    "answering as expected",
                    f"{stats['status_ok']:>6}  {_pct(stats['status_ok'], checked)}",
                )
            )
        if stats["checksummed"]:
            rows.append(
                (
                    "checksummed",
                    f"{stats['checksummed']:>6}  {_pct(stats['checksummed'], checked)}"
                    f"  {human_bytes(stats['bytes_hashed'])} hashed",
                )
            )

    print("", file=out)
    print("Statistics:", file=out)
    width = max(len(label) for label, _ in rows)
    for label, value in rows:
        print(f"  {label:<{width}} {value}", file=out)


def _write_status_summary(report: ScanReport, out: TextIO, use_color: bool) -> None:
    counts = report.status_counts()
    print("", file=out)
    print("Status checks:", file=out)
    for state in STATUS_DISPLAY_ORDER:
        count = counts.get(state, 0)
        label = f"  {state:<18} {count}"
        print(_paint_status(label, state, use_color) if count else label, file=out)

    # The states bucket by kind; this says which code was actually returned.
    code_rows = sorted_code_counts(report.status_code_counts())
    if code_rows:
        checked = sum(count for _, count in code_rows)
        print("", file=out)
        print("HTTP status codes:", file=out)
        for code, count in code_rows:
            print(f"  {code_label(code):<18} {count:>6}  {_pct(count, checked)}", file=out)

    problems = report.status_failures
    if not problems:
        return
    print("", file=out)
    print(f"{len(problems)} target(s) did not return an expected status:", file=out)
    for result in problems:
        status = result.status_check
        assert status is not None
        reason = status.error or f"HTTP {status.final_status}"
        print(f"  {result.url} — {reason}", file=out)


def _write_status_line(status: UrlStatus, out: TextIO, use_color: bool) -> None:
    detail = status_detail(status)
    label = _paint_status(status.label, status.state, use_color)
    print(f"  status: {label}" + (f"  ({detail})" if detail else ""), file=out)
    if status.redirect_count:
        for hop in status.chain:
            arrow = f" -> {hop.location}" if hop.location else ""
            print(f"    {hop.status} {hop.url}{arrow}", file=out)
    if status.content_checksum:
        print(f"  content: {checksum_summary(status)}", file=out)


def _write_result(result: ScanResult, out: TextIO, use_color: bool, verbose: bool) -> None:
    severity = result.max_severity
    badge = _paint(f"[{severity.value.upper()}]", severity, use_color)
    print("", file=out)
    print(f"{badge} {result.url}", file=out)

    # Printed before the skip/error returns: a target Chromium could not render
    # still has a real HTTP status, and that is exactly when it is worth seeing.
    if result.status_check is not None:
        _write_status_line(result.status_check, out, use_color)

    if result.skipped_reason:
        print(f"  skipped: {result.skipped_reason}", file=out)
        return
    if result.error:
        print(f"  error: {result.error}", file=out)
        return

    capture = result.capture
    if capture:
        bits = []
        if capture.status is not None:
            bits.append(f"HTTP {capture.status}")
        if capture.title:
            bits.append(f"title={capture.title[:60]!r}")
        if capture.final_url and capture.final_url != result.url:
            bits.append(f"-> {capture.final_url}")
        if bits:
            print(f"  {'  '.join(bits)}", file=out)
        if capture.load_error:
            print(f"  load error: {capture.load_error}", file=out)
        if capture.screenshot_path:
            print(f"  screenshot: {capture.screenshot_path}", file=out)

    analysis = result.analysis
    if analysis is None:
        return
    if analysis.error:
        print(f"  analysis error: {analysis.error}", file=out)
    if analysis.summary:
        print(f"  {analysis.summary}", file=out)
    for finding in analysis.findings:
        marker = _paint(f"  - [{finding.severity.value}]", finding.severity, use_color)
        print(f"{marker} {finding.title}  ({finding.category}, conf {finding.confidence:.2f})", file=out)
        if verbose:
            if finding.evidence:
                print(f"      evidence: {finding.evidence[:300]}", file=out)
            if finding.recommendation:
                print(f"      fix: {finding.recommendation[:300]}", file=out)


def write_json_report(
    report: ScanReport, path: Path, include_raw: bool = False, secrets: Sequence[str] = ()
) -> Path:
    report = redact_report(report, secrets)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report.to_dict(include_raw), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return path


def write_html_report(
    report: ScanReport, path: Path, embed_images: bool = True, secrets: Sequence[str] = ()
) -> Path:
    report = redact_report(report, secrets)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(report, path.parent, embed_images), encoding="utf-8")
    return path


#: One row per target, so a status-only run (no capture, no analysis) is still a
#: full table. Findings are summarised rather than exploded into rows: a target
#: is the unit an operator sorts, filters and assigns.
CSV_COLUMNS = (
    "url",
    "status_state",
    "status_ok",
    "first_status",
    "final_status",
    "final_url",
    "redirect_count",
    "content_checksum",
    "content_length",
    "content_type",
    "http_status",
    "title",
    "screenshot",
    "max_severity",
    "findings",
    "categories",
    "page_type",
    "summary",
    "error",
)

#: Excel and LibreOffice evaluate a cell starting with any of these. Page titles
#: and model summaries are attacker-influenced text, so they are quoted out.
_FORMULA_LEADERS = ("=", "+", "-", "@", "\t", "\r")


def _csv_cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    text = str(value)
    if text.startswith(_FORMULA_LEADERS):
        return "'" + text
    return text


def csv_rows(report: ScanReport) -> list[dict[str, str]]:
    """One dict per target, keyed by :data:`CSV_COLUMNS`."""
    rows = []
    for result in report.results:
        status = result.status_check
        capture = result.capture
        analysis = result.analysis
        findings = result.findings
        error = result.error or result.skipped_reason or (
            capture.load_error if capture else None
        )
        row = {
            "url": result.url,
            "status_state": status.state if status else None,
            "status_ok": status.ok if status else None,
            "first_status": status.first_status if status else None,
            "final_status": status.final_status if status else None,
            "final_url": status.final_url if status else None,
            "redirect_count": status.redirect_count if status else None,
            "content_checksum": status.content_checksum if status else None,
            "content_length": status.content_length if status else None,
            "content_type": status.content_type if status else None,
            "http_status": capture.status if capture else None,
            "title": capture.title if capture else None,
            "screenshot": capture.screenshot_path if capture else None,
            "max_severity": result.max_severity.value,
            "findings": len(findings),
            "categories": ";".join(sorted({f.category for f in findings})),
            "page_type": analysis.page_type if analysis else None,
            "summary": analysis.summary if analysis else None,
            "error": error,
        }
        rows.append({key: _csv_cell(value) for key, value in row.items()})
    return rows


def write_csv_report(report: ScanReport, path: Path, secrets: Sequence[str] = ()) -> Path:
    report = redact_report(report, secrets)
    path.parent.mkdir(parents=True, exist_ok=True)
    # newline="" per the csv module: it writes \r\n itself.
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(csv_rows(report))
    return path


def sorted_code_counts(counts: dict[str, int]) -> list[tuple[str, int]]:
    """Numerically ascending, with the no-response bucket last."""
    codes = sorted((c for c in counts if c != "none"), key=int)
    rows = [(code, counts[code]) for code in codes]
    if counts.get("none"):
        rows.append(("none", counts["none"]))
    return rows


def code_label(code: str) -> str:
    return "no response" if code == "none" else f"HTTP {code}"


def report_statistics(report: ScanReport) -> dict[str, Any]:
    """Aggregate counts for the statistics report, and for anything else that asks."""
    checksummed = 0
    bytes_hashed = 0
    status_ok = 0
    for result in report.results:
        status = result.status_check
        if status is None:
            continue
        if status.ok:
            status_ok += 1
        if status.content_checksum:
            checksummed += 1
            bytes_hashed += status.content_length or 0

    checked = sum(1 for r in report.results if r.status_check is not None)
    code_counts = report.status_code_counts()
    # Split on the literal code, not on the ``ok`` state: --status-expect can
    # make a 401 "expected", and the question here is what the server said.
    answered_200 = code_counts.get("200", 0)
    no_response = code_counts.get("none", 0)
    return {
        "tool_version": report.tool_version,
        "model": report.model,
        "started_at": report.started_at,
        "finished_at": report.finished_at,
        "duration_s": report.duration_s,
        "targets": len(report.results),
        "captured": sum(1 for r in report.results if r.capture and r.capture.ok),
        "capture_failed": len(report.failed),
        "skipped": sum(1 for r in report.results if r.skipped_reason),
        "analysed": sum(1 for r in report.results if r.analysis is not None),
        "targets_with_findings": sum(1 for r in report.results if r.findings),
        "findings_total": sum(len(r.findings) for r in report.results),
        "severity_counts": report.severity_counts(),
        "max_severity": report.max_severity.value,
        "status_checked": checked,
        "status_ok": status_ok,
        "status_failed": len(report.status_failures),
        "status_counts": report.status_counts(),
        "status_code_counts": code_counts,
        "answered_200": answered_200,
        "answered_other": checked - answered_200 - no_response,
        "no_response": no_response,
        "checksummed": checksummed,
        "bytes_hashed": bytes_hashed,
    }


def _pct(count: int, total: int) -> str:
    """A percentage column, blank when there is nothing to divide by."""
    if not total:
        return ""
    return f"{count * 100.0 / total:5.1f}%"


def render_stats(report: ScanReport) -> str:
    stats = report_statistics(report)
    targets = stats["targets"]
    lines = [
        "secman_visual_check — scan statistics",
        "=" * 44,
        "",
        f"Started    {stats['started_at'].isoformat()}",
    ]
    if stats["finished_at"]:
        lines.append(f"Finished   {stats['finished_at'].isoformat()}")
    lines.append(f"Duration   {stats['duration_s']:.1f}s")
    if stats["tool_version"]:
        lines.append(f"Version    {stats['tool_version']}")
    if stats["model"]:
        lines.append(f"Model      {stats['model']}")
    lines += ["", f"Targets    {targets}"]

    # Omitted entirely for --no-visual-check: four zero rows about a stage that
    # never ran read as "everything failed" rather than "not applicable".
    if any(r.capture is not None for r in report.results):
        lines += [
            "",
            "Capture",
            f"  captured          {stats['captured']:>6}  {_pct(stats['captured'], targets)}",
            f"  failed            {stats['capture_failed']:>6}  {_pct(stats['capture_failed'], targets)}",
            f"  skipped           {stats['skipped']:>6}  {_pct(stats['skipped'], targets)}",
            f"  analysed          {stats['analysed']:>6}  {_pct(stats['analysed'], targets)}",
        ]

    lines += ["", "Findings by severity"]
    for severity in reversed(list(Severity)):
        count = stats["severity_counts"][severity.value]
        lines.append(f"  {severity.value:<17} {count:>6}")
    lines += [
        f"  {'total':<17} {stats['findings_total']:>6}",
        "",
        f"  targets with findings {stats['targets_with_findings']:>2}  "
        f"{_pct(stats['targets_with_findings'], targets)}",
        f"  highest severity      {stats['max_severity']}",
    ]

    if stats["status_checked"]:
        checked = stats["status_checked"]
        lines += ["", "Status checks"]
        for state in STATUS_DISPLAY_ORDER:
            count = stats["status_counts"].get(state, 0)
            lines.append(f"  {state:<17} {count:>6}  {_pct(count, checked)}")
        lines.append(f"  {'checked':<17} {checked:>6}")

        lines += ["", "HTTP status codes"]
        for code, count in sorted_code_counts(stats["status_code_counts"]):
            lines.append(f"  {code_label(code):<17} {count:>6}  {_pct(count, checked)}")
        lines += [
            "",
            f"  answered HTTP 200     {stats['answered_200']:>2}  "
            f"{_pct(stats['answered_200'], checked)}",
            f"  answered another code {stats['answered_other']:>2}  "
            f"{_pct(stats['answered_other'], checked)}",
            f"  no response           {stats['no_response']:>2}  "
            f"{_pct(stats['no_response'], checked)}",
            f"  answering as expected {stats['status_ok']:>2}  "
            f"{_pct(stats['status_ok'], checked)}",
            f"  checksummed           {stats['checksummed']:>2}  "
            f"{_pct(stats['checksummed'], checked)}",
            f"  bytes hashed          {human_bytes(stats['bytes_hashed'])}",
        ]

    return "\n".join(lines) + "\n"


def write_stats_report(report: ScanReport, path: Path, secrets: Sequence[str] = ()) -> Path:
    # render_stats only ever prints aggregate counts and structural fields
    # (model, timestamps) — never a target-influenced text field — but the
    # report is still redacted here for the same reason every other writer
    # is: a future stats field must opt into leaking, not opt out of it.
    report = redact_report(report, secrets)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_stats(report), encoding="utf-8")
    return path


def render_html(report: ScanReport, base_dir: Path, embed_images: bool = True) -> str:
    counts = report.severity_counts()
    cards = "".join(
        f'<div class="stat" style="--c:{SEVERITY_HEX[s]}">'
        f'<span class="n">{counts[s.value]}</span>'
        f'<span class="l">{html.escape(s.value)}</span></div>'
        for s in reversed(list(Severity))
    )
    status_cards = ""
    if report.status_checked:
        status_counts = report.status_counts()
        status_cards = '<div class="stats">' + "".join(
            f'<div class="stat" style="--c:{STATUS_HEX[state]}">'
            f'<span class="n">{status_counts.get(state, 0)}</span>'
            f'<span class="l">{html.escape(state.replace("_", " "))}</span></div>'
            for state in STATUS_DISPLAY_ORDER
            if status_counts.get(state, 0)
        ) + "</div>"

    sections = "\n".join(_render_result(r, base_dir, embed_images) for r in report.results)

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Visual exposure scan</title>
<style>
  :root {{ color-scheme: light dark; --bg:#f6f7f9; --fg:#16181d; --card:#fff; --muted:#5c6270; --line:#e2e5ea; }}
  @media (prefers-color-scheme: dark) {{
    :root {{ --bg:#14161a; --fg:#e8eaed; --card:#1d2026; --muted:#9aa1ad; --line:#2c3039; }}
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; padding:2rem 1.25rem 4rem; background:var(--bg); color:var(--fg);
         font:15px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif; }}
  .wrap {{ max-width: 1100px; margin: 0 auto; }}
  h1 {{ font-size:1.6rem; margin:0 0 .25rem; }}
  .meta {{ color:var(--muted); font-size:.9rem; margin-bottom:1.5rem; }}
  .stats {{ display:flex; flex-wrap:wrap; gap:.75rem; margin-bottom:2rem; }}
  .stat {{ background:var(--card); border:1px solid var(--line); border-left:4px solid var(--c);
           border-radius:8px; padding:.6rem 1rem; min-width:110px; }}
  .stat .n {{ display:block; font-size:1.5rem; font-weight:650; color:var(--c); }}
  .stat .l {{ display:block; font-size:.78rem; text-transform:uppercase; letter-spacing:.05em; color:var(--muted); }}
  .result {{ background:var(--card); border:1px solid var(--line); border-radius:10px;
             padding:1.1rem 1.25rem; margin-bottom:1.25rem; overflow:hidden; }}
  .result h2 {{ font-size:1rem; margin:0 0 .5rem; word-break:break-all; }}
  .result h2 a {{ color:inherit; }}
  .badge {{ display:inline-block; padding:.1rem .5rem; border-radius:4px; font-size:.72rem;
            font-weight:700; text-transform:uppercase; color:#fff; margin-right:.5rem; }}
  .kv {{ color:var(--muted); font-size:.85rem; margin:.2rem 0 .75rem; word-break:break-word; }}
  .summary {{ margin:.5rem 0 1rem; }}
  .finding {{ border-left:3px solid var(--c); background:rgba(127,127,127,.07);
              border-radius:0 6px 6px 0; padding:.6rem .85rem; margin:.55rem 0; }}
  .finding h3 {{ font-size:.95rem; margin:0 0 .3rem; }}
  .finding p {{ margin:.25rem 0; font-size:.87rem; }}
  .finding .label {{ color:var(--muted); font-weight:600; }}
  figure {{ margin:1rem 0 0; }}
  figure img {{ max-width:100%; height:auto; border:1px solid var(--line); border-radius:6px; display:block; }}
  figcaption {{ color:var(--muted); font-size:.8rem; margin-top:.35rem; }}
  .error {{ color:#d9480f; font-size:.9rem; }}
  .status {{ display:inline-block; padding:.1rem .5rem; border-radius:4px; font-size:.72rem;
             font-weight:700; text-transform:uppercase; color:#fff; margin-right:.5rem; }}
  .chain {{ list-style:none; padding-left:0; margin:.35rem 0 .75rem;
            font-size:.82rem; color:var(--muted); }}
  .chain li {{ word-break:break-all; padding:.1rem 0; }}
  pre {{ overflow-x:auto; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>Visual exposure scan</h1>
  <div class="meta">
    {len(report.results)} target(s) &middot; {report.duration_s:.1f}s &middot;
    model {html.escape(report.model or "n/a")} &middot;
    started {html.escape(report.started_at.isoformat(timespec="seconds"))}
  </div>
  <div class="stats">{cards}</div>
  {status_cards}
  {sections}
</div>
</body>
</html>
"""


def _render_result(result: ScanResult, base_dir: Path, embed_images: bool) -> str:
    severity = result.max_severity
    color = SEVERITY_HEX[severity]
    url = html.escape(result.url)
    parts = [
        f'<section class="result" style="--c:{color}">',
        f'<h2><span class="badge" style="background:{color}">{severity.value}</span>'
        f'<a href="{url}" rel="noreferrer noopener nofollow">{url}</a></h2>',
    ]

    if result.status_check is not None:
        parts.append(_render_status(result.status_check))

    if result.skipped_reason:
        parts.append(f'<p class="kv">Skipped: {html.escape(result.skipped_reason)}</p>')
    if result.error:
        parts.append(f'<p class="error">Error: {html.escape(result.error)}</p>')

    capture = result.capture
    if capture:
        meta = []
        if capture.status is not None:
            meta.append(f"HTTP {capture.status}")
        if capture.title:
            meta.append(f"title: {html.escape(capture.title)}")
        if capture.final_url and capture.final_url != result.url:
            meta.append(f"redirected to {html.escape(capture.final_url)}")
        if meta:
            parts.append(f'<p class="kv">{" &middot; ".join(meta)}</p>')
        if capture.load_error:
            parts.append(f'<p class="error">Load error: {html.escape(capture.load_error)}</p>')

    analysis = result.analysis
    if analysis:
        if analysis.error:
            parts.append(f'<p class="error">Analysis error: {html.escape(analysis.error)}</p>')
        if analysis.page_type:
            parts.append(f'<p class="kv">Page type: {html.escape(analysis.page_type)}</p>')
        if analysis.summary:
            parts.append(f'<p class="summary">{html.escape(analysis.summary)}</p>')
        for finding in analysis.findings:
            fcolor = SEVERITY_HEX[finding.severity]
            block = [
                f'<div class="finding" style="--c:{fcolor}">',
                f'<h3><span class="badge" style="background:{fcolor}">'
                f"{finding.severity.value}</span>{html.escape(finding.title)}</h3>",
                f'<p class="kv">{html.escape(finding.category)} &middot; '
                f"confidence {finding.confidence:.2f}</p>",
            ]
            if finding.evidence:
                block.append(
                    f'<p><span class="label">Evidence:</span> {html.escape(finding.evidence)}</p>'
                )
            if finding.recommendation:
                block.append(
                    f'<p><span class="label">Recommendation:</span> '
                    f"{html.escape(finding.recommendation)}</p>"
                )
            block.append("</div>")
            parts.append("".join(block))

    if capture and capture.screenshot_path:
        src = _image_src(Path(capture.screenshot_path), base_dir, embed_images)
        if src:
            parts.append(
                f'<figure><img src="{src}" alt="Screenshot of {url}" loading="lazy">'
                f"<figcaption>{html.escape(Path(capture.screenshot_path).name)}</figcaption></figure>"
            )

    parts.append("</section>")
    return "\n".join(parts)


def _render_status(status: UrlStatus) -> str:
    """The status pill plus, when the target redirected, the chain.

    Everything here is remote-controlled — the URL, the ``Location`` header and
    the error text all come off the wire, so every one of them is escaped.
    """
    color = STATUS_HEX.get(status.state, STATUS_HEX["unknown"])
    detail = status_detail(status)
    parts = [
        f'<p class="kv"><span class="status" style="background:{color}">'
        f"{html.escape(status.label)}</span>"
        + (html.escape(detail) if detail else "")
        + "</p>"
    ]
    if status.redirect_count:
        hops = "".join(
            f"<li>{hop.status if hop.status is not None else '?'} {html.escape(hop.url)}"
            + (f" &rarr; {html.escape(hop.location)}" if hop.location else "")
            + "</li>"
            for hop in status.chain
        )
        parts.append(f'<ol class="chain">{hops}</ol>')
    if status.content_checksum:
        parts.append(f'<p class="kv">{html.escape(checksum_summary(status))}</p>')
    return "".join(parts)


def _image_src(path: Path, base_dir: Path, embed: bool) -> str | None:
    if not path.exists():
        return None
    if embed:
        encoded = base64.b64encode(path.read_bytes()).decode("ascii")
        return f"data:image/png;base64,{encoded}"
    try:
        relative = path.resolve().relative_to(base_dir.resolve())
    except ValueError:
        relative = path
    return html.escape(str(relative).replace("\\", "/"))
