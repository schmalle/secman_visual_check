"""Email the scan result, over Microsoft 365, AWS SES or plain SMTP.

The message is rendered to match SecMan's own notification emails — same
600px layout, the same ``#0d6efd`` header, the same badge palette and footer —
so a visual-check report landing in an inbox next to a SecMan alert reads as
one system rather than two. See ``secman/src/backendng/src/main/resources/
email-templates/`` for the originals.

Named ``mailer`` rather than ``email`` on purpose: the latter would shadow the
standard library package this module itself depends on.
"""

from __future__ import annotations

import html
import smtplib
import ssl
import sys
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.utils import formataddr, parseaddr
from typing import Any, Sequence, TextIO

from .models import ScanReport, Severity

DEFAULT_SUBJECT_PREFIX = "[secman-visual-check]"
DEFAULT_TIMEOUT_S = 30.0
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"

TRANSPORTS = ("smtp", "o365", "ses")

#: SecMan's palette, lifted from its email templates so both systems' mail
#: renders identically.
_SEVERITY_HEX = {
    Severity.CRITICAL: ("#dc3545", "#fff"),
    Severity.HIGH: ("#fd7e14", "#fff"),
    Severity.MEDIUM: ("#ffc107", "#000"),
    Severity.LOW: ("#6c757d", "#fff"),
    Severity.INFO: ("#6c757d", "#fff"),
}
_STATE_HEX = {
    "ok": ("#198754", "#fff"),
    "redirect": ("#0d6efd", "#fff"),
    "redirect_broken": ("#ffc107", "#000"),
    "unexpected_status": ("#ffc107", "#000"),
    "client_error": ("#fd7e14", "#fff"),
    "server_error": ("#dc3545", "#fff"),
    "unreachable": ("#dc3545", "#fff"),
    "unknown": ("#6c757d", "#fff"),
}
_FLAG_HEX = {
    "OK": ("#198754", "#fff"),
    "NEW": ("#0d6efd", "#fff"),
    "NOT_CHECKED": ("#6c757d", "#fff"),
}


class MailError(RuntimeError):
    """Raised when the message cannot be built or delivered."""


@dataclass
class MailOptions:
    """Everything the send needs, resolved from CLI flags and the environment."""

    enabled: bool = False
    transport: str = "smtp"
    sender: str = ""
    sender_name: str = "SecMan Visual Check"
    recipients: list[str] = field(default_factory=list)
    subject_prefix: str = DEFAULT_SUBJECT_PREFIX
    #: Send even when every target came back healthy. Off by default: a daily
    #: check that mails "nothing happened" trains people to filter it.
    always: bool = False
    timeout: float = DEFAULT_TIMEOUT_S
    dry_run: bool = False
    # smtp
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_tls: bool = True
    smtp_ssl: bool = False
    # o365 (Microsoft Graph, client credentials)
    tenant_id: str = ""
    client_id: str = ""
    client_secret: str = ""
    # aws ses
    aws_region: str = ""
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    aws_profile: str = ""

    def validate(self) -> None:
        """Fail fast on unusable configuration, before a scan is started."""
        if not self.enabled:
            return
        if self.transport not in TRANSPORTS:
            raise ValueError(f"unknown email transport {self.transport!r}")
        if not self.sender:
            raise ValueError("--mail-from is required to send email")
        if not self.recipients:
            raise ValueError("--mail-to is required to send email")
        for address in [self.sender, *self.recipients]:
            if "@" not in parseaddr(address)[1]:
                raise ValueError(f"invalid email address {address!r}")
        if self.dry_run:
            return
        if self.transport == "smtp" and not self.smtp_host:
            raise ValueError("--mail-smtp-host is required for the smtp transport")
        if self.transport == "o365" and not (
            self.tenant_id and self.client_id and self.client_secret
        ):
            raise ValueError(
                "the o365 transport needs --mail-tenant-id, --mail-client-id and "
                "--mail-client-secret (or $SECMAN_MAIL_TENANT_ID, "
                "$SECMAN_MAIL_CLIENT_ID, $SECMAN_MAIL_CLIENT_SECRET)"
            )
        if self.transport == "ses" and not self.aws_region:
            raise ValueError(
                "the ses transport needs --mail-aws-region (or $AWS_REGION)"
            )

    @property
    def endpoint(self) -> str:
        """A safe-to-print description of where mail goes. Never a secret."""
        if self.transport == "smtp":
            return f"smtp://{self.smtp_host}:{self.smtp_port}"
        if self.transport == "o365":
            return f"graph:{self.tenant_id or '?'}"
        return f"ses:{self.aws_region or '?'}"


@dataclass
class MailSummary:
    enabled: bool
    transport: str
    endpoint: str
    recipients: list[str] = field(default_factory=list)
    subject: str = ""
    sent: bool = False
    dry_run: bool = False
    error: str | None = None
    skipped_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "transport": self.transport,
            "endpoint": self.endpoint,
            "recipients": list(self.recipients),
            "subject": self.subject,
            "sent": self.sent,
            "dry_run": self.dry_run,
            "error": self.error,
            "skipped_reason": self.skipped_reason,
        }


# --------------------------------------------------------------------------- #
# Rendering — deliberately mirrors SecMan's email templates
# --------------------------------------------------------------------------- #


def build_subject(report: ScanReport, flag_changes: Sequence[Any] = (), prefix: str = "") -> str:
    """A subject that says what happened without needing the body opened."""
    bits: list[str] = []
    failures = len(report.status_failures)
    if failures:
        bits.append(f"{failures} status problem{'s' if failures != 1 else ''}")
    changed = [c for c in flag_changes if getattr(c, "reason", "") == "content changed"]
    if changed:
        bits.append(f"{len(changed)} changed")
    new = [c for c in flag_changes if getattr(c, "is_new_url", False)]
    if new:
        bits.append(f"{len(new)} new")
    findings = sum(report.severity_counts().values())
    if findings:
        bits.append(f"{findings} finding{'s' if findings != 1 else ''}")
    headline = ", ".join(bits) if bits else "all clear"
    scope = f"{len(report.results)} target{'s' if len(report.results) != 1 else ''}"
    subject = f"Visual check: {headline} ({scope})"
    return f"{prefix} {subject}".strip() if prefix else subject


def _badge(text: str, palette: dict, key: Any) -> str:
    background, color = palette.get(key, ("#6c757d", "#fff"))
    return (
        f'<span style="display:inline-block;padding:4px 8px;border-radius:3px;'
        f'font-size:12px;font-weight:bold;background-color:{background};'
        f'color:{color};">{html.escape(text)}</span>'
    )


def render_html_email(
    report: ScanReport,
    flag_changes: Sequence[Any] = (),
    dashboard_url: str | None = None,
) -> str:
    """The HTML body, styled like SecMan's ``new-vulnerability-notification.html``."""
    failures = report.status_failures
    changed = [c for c in flag_changes if getattr(c, "reason", "") == "content changed"]
    new_urls = [c for c in flag_changes if getattr(c, "is_new_url", False)]
    counts = report.status_counts()
    severity_counts = report.severity_counts()

    alert = (
        "Every target answered as expected."
        if not failures and not changed
        else (
            f"<strong>Action Required:</strong> {len(failures)} target(s) did not "
            f"answer as expected and {len(changed)} changed content since the last run."
        )
    )

    status_rows = "".join(
        f"<div style='margin:10px 0;'>{_badge(state.replace('_', ' ').upper(), _STATE_HEX, state)} "
        f"<strong>{counts[state]}</strong> target(s)</div>"
        for state in counts
        if counts[state]
    )
    severity_rows = "".join(
        f"<div style='margin:10px 0;'>{_badge(sev.value.upper(), _SEVERITY_HEX, sev)} "
        f"<strong>{severity_counts[sev.value]}</strong> finding(s)</div>"
        for sev in reversed(list(Severity))
        if severity_counts[sev.value]
    )

    problem_rows = "".join(
        "<tr>"
        f"<td style='padding:12px;text-align:left;border-bottom:1px solid #ddd;"
        f"word-break:break-all;'>{html.escape(r.url)}</td>"
        f"<td style='padding:12px;text-align:left;border-bottom:1px solid #ddd;'>"
        f"{_badge(r.status_check.state.replace('_', ' ').upper(), _STATE_HEX, r.status_check.state)}</td>"
        f"<td style='padding:12px;text-align:left;border-bottom:1px solid #ddd;'>"
        f"{html.escape(r.status_check.error or str(r.status_check.final_status or '-'))}</td>"
        "</tr>"
        for r in failures[:50]
    )
    flag_rows = "".join(
        "<tr>"
        f"<td style='padding:12px;text-align:left;border-bottom:1px solid #ddd;"
        f"word-break:break-all;'>{html.escape(c.url)}</td>"
        f"<td style='padding:12px;text-align:left;border-bottom:1px solid #ddd;'>"
        f"{_badge(c.flag, _FLAG_HEX, c.flag)}</td>"
        f"<td style='padding:12px;text-align:left;border-bottom:1px solid #ddd;'>"
        f"{html.escape(c.reason or '-')}</td>"
        "</tr>"
        for c in list(flag_changes)[:50]
    )

    sections = []
    if status_rows or severity_rows:
        sections.append(
            "<div style='background-color:#fff;padding:15px;border-radius:5px;margin:20px 0;'>"
            "<h3>Summary</h3>" + status_rows + severity_rows + "</div>"
        )
    if problem_rows:
        sections.append(
            "<h3>Targets that did not answer as expected</h3>"
            + _table(("URL", "State", "Detail"), problem_rows)
            + (
                f"<p style='color:#6c757d;font-size:12px;'>Showing the first 50 of "
                f"{len(failures)}.</p>"
                if len(failures) > 50
                else ""
            )
        )
    if flag_rows:
        sections.append(
            "<h3>URL flags</h3>"
            + _table(("URL", "Flag", "Reason"), flag_rows)
            + f"<p style='color:#6c757d;font-size:12px;'>{len(new_urls)} newly added.</p>"
        )
    if not sections:
        sections.append("<p>Nothing to report.</p>")

    cta = (
        "<center><a href='%s' style=\"display:inline-block;background-color:#0d6efd;"
        "color:white;padding:12px 24px;text-decoration:none;border-radius:5px;"
        'margin:20px 0;">Open the dashboard</a></center>' % html.escape(dashboard_url)
        if dashboard_url
        else ""
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Visual Check Results</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;
             max-width: 600px; margin: 0 auto; padding: 20px;">
  <div style="background-color:#0d6efd;color:white;padding:20px;text-align:center;
              border-radius:5px 5px 0 0;">
    <h1 style="margin:0;">Visual Check Results</h1>
  </div>

  <div style="background-color:#f8f9fa;padding:20px;border-radius:0 0 5px 5px;">
    <p>Hello,</p>

    <div style="background-color:#cfe2ff;border-left:4px solid #0d6efd;padding:15px;margin:20px 0;">
      {alert}
    </div>

    <p>
      {len(report.results)} target(s) checked in {report.duration_s:.1f}s
      on {html.escape(report.started_at.isoformat(timespec="seconds"))}.
    </p>

    {"".join(sections)}
    {cta}
  </div>

  <div style="text-align:center;color:#6c757d;font-size:12px;margin-top:30px;
              padding-top:20px;border-top:1px solid #ddd;">
    <p>This is an automated notification from the Security Management System.</p>
    <p>Please do not reply to this email.</p>
  </div>
</body>
</html>
"""


def _table(headers: tuple[str, ...], rows: str) -> str:
    head = "".join(
        "<th style='padding:12px;text-align:left;border-bottom:1px solid #ddd;"
        f"background-color:#e9ecef;font-weight:bold;'>{html.escape(h)}</th>"
        for h in headers
    )
    return (
        "<table style='width:100%;border-collapse:collapse;margin:20px 0;"
        f"background-color:white;'><thead><tr>{head}</tr></thead><tbody>{rows}</tbody></table>"
    )


def render_text_email(
    report: ScanReport,
    flag_changes: Sequence[Any] = (),
    dashboard_url: str | None = None,
) -> str:
    """The plain-text alternative, mirroring SecMan's ``.txt`` templates."""
    lines = [
        "VISUAL CHECK RESULTS",
        "=" * 40,
        "",
        f"{len(report.results)} target(s) checked in {report.duration_s:.1f}s",
        f"Started: {report.started_at.isoformat(timespec='seconds')}",
        "",
    ]

    counts = report.status_counts()
    active = {state: n for state, n in counts.items() if n}
    if active:
        lines.append("Status checks:")
        lines += [f"  {state:<18} {n}" for state, n in active.items()]
        lines.append("")

    severity_counts = {k: v for k, v in report.severity_counts().items() if v}
    if severity_counts:
        lines.append("Findings by severity:")
        lines += [f"  {name:<9} {n}" for name, n in severity_counts.items()]
        lines.append("")

    failures = report.status_failures
    if failures:
        lines.append(f"{len(failures)} target(s) did not answer as expected:")
        for result in failures[:50]:
            status = result.status_check
            detail = status.error or f"HTTP {status.final_status}"
            lines.append(f"  [{status.state}] {result.url} - {detail}")
        if len(failures) > 50:
            lines.append(f"  ... and {len(failures) - 50} more")
        lines.append("")

    if flag_changes:
        lines.append("URL flags:")
        for change in list(flag_changes)[:50]:
            arrow = f"{change.previous} -> {change.flag}" if change.previous else change.flag
            lines.append(f"  [{arrow}] {change.url} ({change.reason})")
        lines.append("")

    if dashboard_url:
        lines += [f"Dashboard: {dashboard_url}", ""]

    lines += [
        "-" * 40,
        "This is an automated notification from the Security Management System.",
        "Please do not reply to this email.",
    ]
    return "\n".join(lines)


def build_message(
    report: ScanReport,
    options: MailOptions,
    flag_changes: Sequence[Any] = (),
    dashboard_url: str | None = None,
) -> EmailMessage:
    """A multipart/alternative message with the text part first, as MIME requires."""
    message = EmailMessage()
    message["Subject"] = build_subject(report, flag_changes, options.subject_prefix)
    message["From"] = (
        formataddr((options.sender_name, options.sender))
        if options.sender_name
        else options.sender
    )
    message["To"] = ", ".join(options.recipients)
    message.set_content(render_text_email(report, flag_changes, dashboard_url))
    message.add_alternative(
        render_html_email(report, flag_changes, dashboard_url), subtype="html"
    )
    return message


# --------------------------------------------------------------------------- #
# Transports
# --------------------------------------------------------------------------- #


class Mailer:
    """Common shape for the three transports."""

    transport = "?"

    def send(self, message: EmailMessage, options: MailOptions) -> None:
        raise NotImplementedError


class SmtpMailer(Mailer):
    """Plain SMTP — the same path SecMan itself uses."""

    transport = "smtp"

    def __init__(self, client: Any = None) -> None:
        self._client = client

    def send(self, message: EmailMessage, options: MailOptions) -> None:
        if self._client is not None:
            self._client.send_message(message)
            return
        try:
            if options.smtp_ssl:
                server = smtplib.SMTP_SSL(
                    options.smtp_host,
                    options.smtp_port,
                    timeout=options.timeout,
                    context=ssl.create_default_context(),
                )
            else:
                server = smtplib.SMTP(
                    options.smtp_host, options.smtp_port, timeout=options.timeout
                )
            with server:
                if options.smtp_tls and not options.smtp_ssl:
                    server.starttls(context=ssl.create_default_context())
                if options.smtp_user:
                    server.login(options.smtp_user, options.smtp_password)
                server.send_message(message)
        except (smtplib.SMTPException, OSError) as exc:
            raise MailError(f"SMTP delivery failed: {_short(exc)}") from exc


class O365Mailer(Mailer):
    """Microsoft 365 via the Graph API.

    Client-credentials flow: the app registration needs the *application*
    permission ``Mail.Send``, and the mailbox named by ``--mail-from`` is the
    one the message is sent as.
    """

    transport = "o365"

    def __init__(self, client: Any = None) -> None:
        self._client = client

    def send(self, message: EmailMessage, options: MailOptions) -> None:
        import httpx

        client = self._client or httpx.Client(timeout=options.timeout)
        owned = self._client is None
        try:
            token = self._token(client, options)
            payload = {
                "message": {
                    "subject": message["Subject"],
                    "body": {"contentType": "HTML", "content": _html_part(message)},
                    "toRecipients": [
                        {"emailAddress": {"address": parseaddr(a)[1]}}
                        for a in options.recipients
                    ],
                },
                "saveToSentItems": False,
            }
            sender = parseaddr(options.sender)[1]
            response = client.post(
                f"{GRAPH_BASE_URL}/users/{sender}/sendMail",
                headers={"Authorization": f"Bearer {token}"},
                json=payload,
            )
            if response.status_code >= 400:
                raise MailError(
                    f"Graph sendMail failed (HTTP {response.status_code}): "
                    f"{_detail(response)}"
                )
        except httpx.HTTPError as exc:
            raise MailError(f"Graph sendMail failed: {_short(exc)}") from exc
        finally:
            if owned:
                client.close()

    @staticmethod
    def _token(client: Any, options: MailOptions) -> str:
        response = client.post(
            f"https://login.microsoftonline.com/{options.tenant_id}/oauth2/v2.0/token",
            data={
                "client_id": options.client_id,
                "client_secret": options.client_secret,
                "scope": GRAPH_SCOPE,
                "grant_type": "client_credentials",
            },
        )
        if response.status_code >= 400:
            raise MailError(
                f"Microsoft token request failed (HTTP {response.status_code}): "
                f"{_detail(response)}"
            )
        try:
            token = response.json().get("access_token")
        except ValueError as exc:
            raise MailError("Microsoft token response was not JSON") from exc
        if not token:
            raise MailError("Microsoft token response carried no access_token")
        return str(token)


class SesMailer(Mailer):
    """AWS SES, through boto3 so credential resolution works the way AWS users expect.

    boto3 already handles profiles, instance roles, IMDS, SSO and the whole
    ``AWS_*`` environment — reimplementing SigV4 here would be a worse copy of
    all of it.
    """

    transport = "ses"

    def __init__(self, client: Any = None) -> None:
        self._client = client

    def send(self, message: EmailMessage, options: MailOptions) -> None:
        client = self._client or self._build_client(options)
        try:
            client.send_raw_email(
                Source=parseaddr(options.sender)[1],
                Destinations=[parseaddr(a)[1] for a in options.recipients],
                RawMessage={"Data": message.as_bytes()},
            )
        except Exception as exc:  # boto3 raises ClientError and friends
            raise MailError(f"SES delivery failed: {_short(exc)}") from exc

    @staticmethod
    def _build_client(options: MailOptions) -> Any:
        if not boto3_available():
            raise MailError(BOTO3_MISSING)
        import boto3

        session_kwargs: dict[str, Any] = {}
        if options.aws_profile:
            session_kwargs["profile_name"] = options.aws_profile
        session = boto3.session.Session(**session_kwargs)
        client_kwargs: dict[str, Any] = {"region_name": options.aws_region}
        if options.aws_access_key_id:
            client_kwargs["aws_access_key_id"] = options.aws_access_key_id
            client_kwargs["aws_secret_access_key"] = options.aws_secret_access_key
        return session.client("ses", **client_kwargs)


BOTO3_MISSING = (
    "boto3 is not installed or cannot be imported. "
    "Run: pip install 'secman-visual-check[aws]'"
)


def boto3_available() -> bool:
    try:
        import boto3  # noqa: F401
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException:
        return False
    return True


def build_mailer(options: MailOptions) -> Mailer:
    if options.transport == "o365":
        return O365Mailer()
    if options.transport == "ses":
        return SesMailer()
    return SmtpMailer()


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


def send_report(
    report: ScanReport,
    options: MailOptions,
    flag_changes: Sequence[Any] = (),
    mailer: Mailer | None = None,
    dashboard_url: str | None = None,
) -> MailSummary:
    """Render and deliver the result email. Never raises.

    A mail problem is reported, not propagated: the scan already succeeded and
    its reports are already on disk.
    """
    summary = MailSummary(
        enabled=options.enabled,
        transport=options.transport,
        endpoint=options.endpoint,
        recipients=list(options.recipients),
        dry_run=options.dry_run,
    )
    if not options.enabled:
        summary.skipped_reason = "not enabled"
        return summary

    quiet_run = not report.status_failures and not flag_changes and not report.failed
    if quiet_run and not options.always:
        summary.skipped_reason = "nothing to report (use --mail-always to send anyway)"
        return summary

    try:
        message = build_message(report, options, flag_changes, dashboard_url)
        summary.subject = str(message["Subject"])
        if options.dry_run:
            return summary
        (mailer or build_mailer(options)).send(message, options)
    except MailError as exc:
        summary.error = str(exc)
        return summary
    except Exception as exc:  # pragma: no cover - defensive
        summary.error = _short(exc)
        return summary

    summary.sent = True
    return summary


def write_mail_report(summary: MailSummary, stream: TextIO | None = None) -> None:
    """Print the mail result in the same shape as the scan's console report."""
    out = stream or sys.stdout
    if not summary.enabled:
        return
    print("", file=out)
    if summary.skipped_reason:
        print(f"Email: skipped — {summary.skipped_reason}", file=out)
        return
    if summary.error:
        print(f"Email: {summary.transport} delivery failed — {summary.error}", file=out)
        return
    recipients = ", ".join(summary.recipients)
    verb = "would send" if summary.dry_run else "sent"
    print(
        f"Email: {verb} via {summary.transport} ({summary.endpoint}) to {recipients}",
        file=out,
    )
    print(f"  subject: {summary.subject}", file=out)


def _html_part(message: EmailMessage) -> str:
    part = message.get_body(preferencelist=("html",))
    if part is None:  # pragma: no cover - build_message always adds one
        return message.get_content()
    return part.get_content()


def _detail(response: Any) -> str:
    try:
        payload = response.json()
    except Exception:
        return str(getattr(response, "text", ""))[:200]
    if isinstance(payload, dict):
        error = payload.get("error")
        if isinstance(error, dict):
            return str(error.get("message") or error)[:200]
        return str(
            payload.get("error_description") or error or payload
        )[:200]
    return str(payload)[:200]


def _short(exc: BaseException) -> str:
    message = str(exc).strip().splitlines()
    first = message[0] if message else ""
    return f"{type(exc).__name__}: {first}"[:300] if first else type(exc).__name__
