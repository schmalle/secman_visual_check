"""What a run *would* do — the `--dry-run` mode.

A scan is slow, spends money on model calls, writes files, rows and emails, and
files vulnerabilities in a tracker. All of that is configured from about ninety
flags and two dozen environment variables, and the usual way to find out whether
you got it right is to run it. This module is the other way: it resolves exactly
the same configuration, down to fetching every credential, and then prints the
plan instead of executing it.

The guarantee is narrow and worth stating precisely: **a dry run writes
nothing** — no report file, no screenshot, no database row, no email, no SecMan
vulnerability — and never launches the browser or calls the model. It is not an
offline mode. Resolving a ``pass://`` reference talks to Proton Pass, and a
SecMan dry run with credentials still *reads* from SecMan to tell you which
findings are already filed. Reads are what make the plan worth reading.

The plan is assembled from the very objects the run would use — a
:class:`~secman_visual_check.config.ScanConfig`, the DB, mail and SecMan option
objects — so it cannot drift from what actually happens. Anything printed here
comes from those objects or from ``endpoint``/``dsn`` properties that are
documented never to contain a secret.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence, TextIO

from .config import ScanConfig
from .db import DbOptions
from .mailer import MailOptions
from .secman import SecmanOptions
from .secrets import SecretRef

WIDTH = 72


@dataclass
class ScanPlan:
    """One run, described rather than performed."""

    targets: Sequence[str] = ()
    config: ScanConfig | None = None
    outputs: list[tuple[str, Path]] = field(default_factory=list)
    db: DbOptions | None = None
    mail: MailOptions | None = None
    secman: SecmanOptions | None = None
    #: References resolved while building the plan. Names, never values.
    secrets: Sequence[SecretRef] = ()
    #: Standalone modes describe themselves instead of a scan.
    action: str = "scan"
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "targets": list(self.targets),
            "outputs": {name: str(path) for name, path in self.outputs},
            "secrets": [str(ref) for ref in self.secrets],
            "notes": list(self.notes),
        }


def _stage_lines(config: ScanConfig) -> list[tuple[str, str]]:
    """One line per pipeline stage: is it on, and with what."""
    lines: list[tuple[str, str]] = []

    status = config.status_check
    if status.enabled:
        expected = ",".join(str(code) for code in status.expect_statuses[:6])
        if len(status.expect_statuses) > 6:
            expected += ",…"
        method = {
            "auto": "HEAD, falling back to GET",
            "head": "HEAD",
            "get": "GET",
        }.get(status.method, status.method)
        detail = (
            f"{method}, expect {expected}, "
            f"{status.max_concurrency} worker(s), "
            f"{'checksums on' if status.checksum else 'no checksums'}, "
            f"{status.max_redirects} redirect hop(s)"
        )
        lines.append(("status check", detail))
    else:
        lines.append(("status check", "disabled (--no-status-check)"))

    if config.visual_check:
        capture = config.capture
        shape = "full page" if capture.full_page else "viewport only"
        if capture.full_page and capture.max_capture_height:
            shape += f" (max {capture.max_capture_height}px)"
        lines.append(
            (
                "browser",
                f"{capture.viewport_width}x{capture.viewport_height}, {shape}, "
                f"{config.concurrency} worker(s), {capture.timeout_ms / 1000:g}s timeout",
            )
        )
    else:
        lines.append(("browser", "disabled (--no-visual-check) — no Chromium needed"))

    if config.analyzer is not None:
        analyzer = config.analyzer
        key = "API key set" if analyzer.api_key else "NO API KEY — the run would fail"
        lines.append(
            (
                "analysis",
                f"{analyzer.model} via {analyzer.base_url}, "
                f"{config.ai_concurrency} worker(s), {key}",
            )
        )
    elif config.visual_check:
        lines.append(("analysis", "disabled (--no-ai) — screenshots only"))
    else:
        lines.append(("analysis", "disabled (no browser, so nothing to look at)"))

    if config.content_check:
        inputs = []
        if config.visual_check and config.capture.content_max_chars > 0:
            inputs.append("page text and DOM")
        if status.enabled and status.checksum and status.keep_body_chars > 0:
            inputs.append("raw response body")
        detail = f"{len(config.content_patterns)} pattern(s) over " + (
            ", ".join(inputs) if inputs else "nothing — no input stage keeps content"
        )
        lines.append(("content check", detail))
    else:
        lines.append(("content check", "disabled (--no-content-check)"))

    return lines


def _missing_mail_setting(mail: MailOptions) -> str:
    """What a real send would still refuse over. Empty when it is ready to go."""
    if mail.transport == "smtp" and not mail.smtp_host:
        return "NO SMTP HOST — a real send would fail"
    if mail.transport == "o365" and not (mail.tenant_id and mail.client_id and mail.client_secret):
        return "INCOMPLETE GRAPH CREDENTIALS — a real send would fail"
    if mail.transport == "ses" and not mail.aws_region:
        return "NO AWS REGION — a real send would fail"
    return ""


def _integration_lines(plan: ScanPlan) -> list[tuple[str, str]]:
    lines: list[tuple[str, str]] = []
    if plan.action != "scan":
        # A standalone command touches exactly one thing, named in `action`.
        # Listing the stages it does not use would be noise.
        return lines

    if plan.db is not None and plan.db.enabled:
        lines.append(("database", f"would write status rows to {plan.db.dsn}"))
    else:
        lines.append(("database", "disabled"))

    if plan.mail is not None and plan.mail.enabled:
        when = "always" if plan.mail.always else "only when something is wrong"
        recipients = ", ".join(plan.mail.recipients) or "nobody"
        # A dry run relaxes the transport checks so the plan can be seen without
        # credentials — which makes saying what is still missing its job.
        missing = _missing_mail_setting(plan.mail)
        lines.append(
            (
                "email",
                f"would send via {plan.mail.endpoint} to {recipients} ({when})"
                + (f" — {missing}" if missing else ""),
            )
        )
    else:
        lines.append(("email", "disabled"))

    if plan.secman is not None:
        options = plan.secman
        extras = []
        if not options.has_credentials:
            extras.append("NO CREDENTIALS — a real upload would be refused")
        if options.status_findings:
            extras.append("status failures included")
        if options.register_assets:
            extras.append("assets registered")
        if options.allow_existing:
            extras.append("existing findings re-sent")
        suffix = f" — {', '.join(extras)}" if extras else ""
        lines.append(
            (
                "secman",
                f"would upload findings at {options.min_severity.value} or above to "
                f"{options.base_url} over {options.transport}{suffix}",
            )
        )
    else:
        lines.append(("secman", "disabled"))

    return lines


def write_plan(plan: ScanPlan, stream: TextIO | None = None) -> None:
    """Print the plan. Writes to the stream and nowhere else."""
    out = stream or sys.stdout
    print("=" * WIDTH, file=out)
    print("Dry run — nothing will be written, sent or uploaded", file=out)
    print("=" * WIDTH, file=out)

    if plan.action != "scan":
        print(f"\nAction: {plan.action}", file=out)

    if plan.targets:
        print(f"\nTargets ({len(plan.targets)}):", file=out)
        for url in plan.targets:
            print(f"  {url}", file=out)

    if plan.config is not None:
        print("\nStages:", file=out)
        for name, detail in _stage_lines(plan.config):
            print(f"  {name:<14} {detail}", file=out)

    if plan.outputs:
        print("\nWould write:", file=out)
        for name, path in plan.outputs:
            print(f"  {name:<14} {path}", file=out)

    integrations = _integration_lines(plan)
    if integrations:
        print("\nIntegrations:", file=out)
        for name, detail in integrations:
            print(f"  {name:<14} {detail}", file=out)

    if plan.secrets:
        print("\nSecrets:", file=out)
        for ref in plan.secrets:
            print(f"  resolved       {ref}", file=out)

    for note in plan.notes:
        print(f"\n{note}", file=out)

    print("\nNothing was written. Re-run without --dry-run to execute this plan.", file=out)
