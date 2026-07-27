"""Console, JSON and HTML rendering of a ScanReport."""

from __future__ import annotations

import base64
import html
import json
import sys
from pathlib import Path
from typing import TextIO

from .models import ScanReport, ScanResult, Severity

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


def _paint(text: str, severity: Severity, color: bool) -> str:
    if not color:
        return text
    return f"{SEVERITY_COLORS[severity]}{text}{RESET}"


def should_colorize(stream: TextIO, force: bool | None = None) -> bool:
    if force is not None:
        return force
    return hasattr(stream, "isatty") and stream.isatty()


def write_console_report(
    report: ScanReport,
    stream: TextIO | None = None,
    color: bool | None = None,
    verbose: bool = False,
) -> None:
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

    failures = report.failed
    if failures:
        print("", file=out)
        print(f"{len(failures)} target(s) could not be captured:", file=out)
        for result in failures:
            reason = result.error or (result.capture.load_error if result.capture else "unknown")
            print(f"  {result.url} — {reason}", file=out)


def _write_result(result: ScanResult, out: TextIO, use_color: bool, verbose: bool) -> None:
    severity = result.max_severity
    badge = _paint(f"[{severity.value.upper()}]", severity, use_color)
    print("", file=out)
    print(f"{badge} {result.url}", file=out)

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


def write_json_report(report: ScanReport, path: Path, include_raw: bool = False) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report.to_dict(include_raw), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return path


def write_html_report(report: ScanReport, path: Path, embed_images: bool = True) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(report, path.parent, embed_images), encoding="utf-8")
    return path


def render_html(report: ScanReport, base_dir: Path, embed_images: bool = True) -> str:
    counts = report.severity_counts()
    cards = "".join(
        f'<div class="stat" style="--c:{SEVERITY_HEX[s]}">'
        f'<span class="n">{counts[s.value]}</span>'
        f'<span class="l">{html.escape(s.value)}</span></div>'
        for s in reversed(list(Severity))
    )
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
