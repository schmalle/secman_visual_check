"""Email rendering and the three delivery transports."""

import io

import httpx
import pytest

from secman_visual_check import mailer as mailer_module
from secman_visual_check.db import FlagChange
from secman_visual_check.mailer import (
    MailError,
    MailOptions,
    MailSummary,
    O365Mailer,
    SesMailer,
    SmtpMailer,
    build_mailer,
    build_message,
    build_subject,
    render_html_email,
    render_text_email,
    send_report,
    write_mail_report,
)
from secman_visual_check.models import (
    Analysis,
    Finding,
    ScanReport,
    ScanResult,
    Severity,
    UrlStatus,
)


def status(url, state="ok", **overrides):
    value = UrlStatus(url=url, state=state, first_status=200, final_status=200)
    for key, item in overrides.items():
        setattr(value, key, item)
    return value


def make_report(*results):
    if not results:
        results = (
            ScanResult(url="https://example.com/", status_check=status("https://example.com/")),
            ScanResult(
                url="https://dead.example/",
                status_check=status(
                    "https://dead.example/",
                    state="unreachable",
                    final_status=None,
                    error="ConnectError: Name or service not known",
                ),
            ),
        )
    return ScanReport(results=list(results), model="test/model", tool_version="0.2.0")


def options(**overrides):
    base = {
        "enabled": True,
        "sender": "scanner@example.com",
        "recipients": ["ops@example.com"],
        "smtp_host": "smtp.example.com",
    }
    base.update(overrides)
    return MailOptions(**base)


CHANGES = [
    FlagChange("https://example.com/", "NEW", "OK", "content changed"),
    FlagChange("https://fresh.example/", "NEW", None, "first seen"),
]


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #


def test_subject_summarises_what_happened():
    subject = build_subject(make_report(), CHANGES, prefix="[svc]")

    assert subject.startswith("[svc] Visual check:")
    assert "1 status problem" in subject
    assert "1 changed" in subject
    assert "1 new" in subject
    assert "2 targets" in subject


def test_subject_says_all_clear_when_nothing_happened():
    healthy = make_report(
        ScanResult(url="https://example.com/", status_check=status("https://example.com/"))
    )

    assert "all clear" in build_subject(healthy)


def test_subject_counts_findings():
    result = ScanResult(
        url="https://example.com/",
        status_check=status("https://example.com/"),
        analysis=Analysis(
            risk_level=Severity.CRITICAL,
            summary="s",
            findings=[Finding("unauthenticated_admin", Severity.CRITICAL, "Admin open")],
        ),
    )

    assert "1 finding" in build_subject(make_report(result))


def test_html_uses_secmans_layout_and_palette():
    body = render_html_email(make_report(), CHANGES, dashboard_url="https://secman.example/")

    # The markers that make it read as a SecMan email.
    assert "background-color:#0d6efd" in body  # header
    assert "background-color:#f8f9fa" in body  # content panel
    assert "border-left:4px solid #0d6efd" in body  # alert box
    assert "background-color:#e9ecef" in body  # table head
    assert "#dc3545" in body  # critical/unreachable badge
    assert "This is an automated notification from the Security Management System." in body
    assert "Please do not reply to this email." in body
    assert "max-width: 600px" in body


def test_html_lists_failures_and_flag_changes():
    body = render_html_email(make_report(), CHANGES)

    assert "https://dead.example/" in body
    assert "UNREACHABLE" in body
    assert "ConnectError: Name or service not known" in body
    assert "https://fresh.example/" in body
    assert "content changed" in body
    assert "1 newly added." in body


def test_html_escapes_remote_controlled_text():
    evil = ScanResult(
        url="https://example.com/?q=<script>alert(1)</script>",
        status_check=status(
            "https://example.com/",
            state="client_error",
            final_status=404,
            error='<img src=x onerror="alert(1)">',
        ),
    )

    body = render_html_email(make_report(evil))

    assert "<script>alert(1)</script>" not in body
    assert 'onerror="alert(1)"' not in body
    assert "&lt;script&gt;" in body


def test_html_caps_long_failure_lists():
    many = [
        ScanResult(
            url=f"https://example.com/{i}",
            status_check=status(f"https://example.com/{i}", state="client_error", final_status=404),
        )
        for i in range(60)
    ]

    body = render_html_email(make_report(*many))

    assert "Showing the first 50 of 60." in body
    assert "https://example.com/59" not in body


def test_html_has_a_cta_only_when_a_dashboard_url_is_given():
    assert "Open the dashboard" in render_html_email(make_report(), dashboard_url="https://x/")
    assert "Open the dashboard" not in render_html_email(make_report())


def test_text_alternative_mirrors_the_html():
    body = render_text_email(make_report(), CHANGES)

    assert "VISUAL CHECK RESULTS" in body
    assert "1 target(s) did not answer as expected:" in body
    assert "[unreachable] https://dead.example/" in body
    assert "[OK -> NEW] https://example.com/ (content changed)" in body
    assert "Please do not reply to this email." in body
    assert "<" not in body.replace("<-", "").replace("->", "")


def test_message_is_multipart_with_text_first():
    message = build_message(make_report(), options(), CHANGES)

    assert message["To"] == "ops@example.com"
    assert message["From"] == "SecMan Visual Check <scanner@example.com>"
    assert message.get_body(preferencelist=("plain",)) is not None
    assert message.get_body(preferencelist=("html",)) is not None
    assert "Visual check:" in message["Subject"]


# --------------------------------------------------------------------------- #
# Finding 3 — a target that reflects a resolved secret back (e.g. a rejected
# Basic-Auth password quoted in an error page) must not land in the outgoing
# message body — scrubbed before Mailer.send ever sees it, not just in a
# post-send log line.
# --------------------------------------------------------------------------- #

SECRET = "s3cretPassw0rd"


def make_report_with_secret(secret: str = SECRET) -> ScanReport:
    result = ScanResult(
        url="https://example.com/",
        status_check=status(
            "https://example.com/",
            state="client_error",
            final_status=401,
            error=f"HTTP 401: bad credentials '{secret}'",
        ),
    )
    return make_report(result)


def test_build_message_redacts_a_reflected_secret_from_both_parts():
    message = build_message(make_report_with_secret(), options(), secrets=[SECRET])

    text_body = message.get_body(preferencelist=("plain",)).get_content()
    html_body = message.get_body(preferencelist=("html",)).get_content()

    assert SECRET not in text_body
    assert SECRET not in html_body
    assert "<redacted>" in text_body
    # Redaction happens before HTML-escaping, so the marker's angle brackets
    # are escaped like any other rendered text.
    assert "&lt;redacted&gt;" in html_body


def test_build_message_without_secrets_is_unaffected():
    """The common case — no credential was ever resolved — must not alter
    the rendered message."""
    message = build_message(make_report_with_secret(), options())

    text_body = message.get_body(preferencelist=("plain",)).get_content()
    assert SECRET in text_body


def test_send_report_scrubs_the_secret_before_the_mailer_ever_sees_it():
    """The regression this closes: redaction must happen *before* send(), not
    only in the post-send console summary."""
    fake = FakeSmtp()

    summary = send_report(
        make_report_with_secret(),
        options(),
        mailer=SmtpMailer(client=fake),
        secrets=[SECRET],
    )

    assert summary.sent is True
    sent_message = fake.sent[0]
    text_body = sent_message.get_body(preferencelist=("plain",)).get_content()
    html_body = sent_message.get_body(preferencelist=("html",)).get_content()
    assert SECRET not in text_body
    assert SECRET not in html_body
    assert SECRET not in sent_message.as_string()


# --------------------------------------------------------------------------- #
# Options
# --------------------------------------------------------------------------- #


def test_validate_requires_sender_and_recipients():
    with pytest.raises(ValueError, match="--mail-from"):
        options(sender="").validate()
    with pytest.raises(ValueError, match="--mail-to"):
        options(recipients=[]).validate()


def test_validate_rejects_a_malformed_address():
    with pytest.raises(ValueError, match="invalid email address"):
        options(recipients=["not-an-address"]).validate()


def test_validate_checks_per_transport_credentials():
    with pytest.raises(ValueError, match="--mail-smtp-host"):
        options(smtp_host="").validate()
    with pytest.raises(ValueError, match="--mail-tenant-id"):
        options(transport="o365").validate()
    with pytest.raises(ValueError, match="--mail-aws-region"):
        options(transport="ses").validate()


def test_validate_is_lenient_for_a_dry_run():
    options(transport="o365", dry_run=True).validate()


def test_validate_is_a_no_op_when_disabled():
    MailOptions(enabled=False, transport="nonsense").validate()


def test_endpoint_never_carries_a_secret():
    o365 = options(transport="o365", tenant_id="tid", client_secret="s3cret")
    smtp = options(smtp_password="s3cret")

    assert "s3cret" not in o365.endpoint
    assert "s3cret" not in smtp.endpoint
    assert o365.endpoint == "graph:tid"


def test_build_mailer_picks_the_transport():
    assert isinstance(build_mailer(options()), SmtpMailer)
    assert isinstance(build_mailer(options(transport="o365")), O365Mailer)
    assert isinstance(build_mailer(options(transport="ses")), SesMailer)


# --------------------------------------------------------------------------- #
# Transports
# --------------------------------------------------------------------------- #


class FakeSmtp:
    def __init__(self):
        self.sent = []

    def send_message(self, message):
        self.sent.append(message)


def test_smtp_sends_the_message():
    fake = FakeSmtp()

    SmtpMailer(client=fake).send(build_message(make_report(), options()), options())

    assert len(fake.sent) == 1


def test_o365_fetches_a_token_then_calls_send_mail():
    seen = []

    def handler(request):
        seen.append(str(request.url))
        if "oauth2" in str(request.url):
            return httpx.Response(200, json={"access_token": "tok-123"})
        assert request.headers["authorization"] == "Bearer tok-123"
        return httpx.Response(202)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    opts = options(transport="o365", tenant_id="tid", client_id="cid", client_secret="sec")

    O365Mailer(client=client).send(build_message(make_report(), opts), opts)

    assert "login.microsoftonline.com/tid/oauth2/v2.0/token" in seen[0]
    assert seen[1].endswith("/users/scanner@example.com/sendMail")


def test_o365_sends_html_and_the_recipient_list():
    captured = {}

    def handler(request):
        if "oauth2" in str(request.url):
            return httpx.Response(200, json={"access_token": "t"})
        import json

        captured.update(json.loads(request.content))
        return httpx.Response(202)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    opts = options(
        transport="o365",
        tenant_id="t",
        client_id="c",
        client_secret="s",
        recipients=["a@example.com", "Ops Team <b@example.com>"],
    )

    O365Mailer(client=client).send(build_message(make_report(), opts), opts)

    assert captured["message"]["body"]["contentType"] == "HTML"
    assert "<!DOCTYPE html>" in captured["message"]["body"]["content"]
    assert [r["emailAddress"]["address"] for r in captured["message"]["toRecipients"]] == [
        "a@example.com",
        "b@example.com",
    ]


def test_o365_surfaces_a_token_failure():
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda r: httpx.Response(401, json={"error_description": "bad secret"})
        )
    )
    opts = options(transport="o365", tenant_id="t", client_id="c", client_secret="s")

    with pytest.raises(MailError, match="token request failed"):
        O365Mailer(client=client).send(build_message(make_report(), opts), opts)


def test_o365_surfaces_a_send_failure():
    def handler(request):
        if "oauth2" in str(request.url):
            return httpx.Response(200, json={"access_token": "t"})
        return httpx.Response(403, json={"error": {"message": "no Mail.Send"}})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    opts = options(transport="o365", tenant_id="t", client_id="c", client_secret="s")

    with pytest.raises(MailError, match="no Mail.Send"):
        O365Mailer(client=client).send(build_message(make_report(), opts), opts)


class FakeSes:
    def __init__(self, fail=False):
        self.calls = []
        self.fail = fail

    def send_raw_email(self, **kwargs):
        if self.fail:
            raise RuntimeError("Email address is not verified")
        self.calls.append(kwargs)


def test_ses_sends_the_raw_message():
    fake = FakeSes()
    opts = options(transport="ses", aws_region="eu-central-1")

    SesMailer(client=fake).send(build_message(make_report(), opts), opts)

    call = fake.calls[0]
    assert call["Source"] == "scanner@example.com"
    assert call["Destinations"] == ["ops@example.com"]
    assert b"Visual check:" in call["RawMessage"]["Data"]


def test_ses_wraps_a_client_error():
    opts = options(transport="ses", aws_region="eu-central-1")

    with pytest.raises(MailError, match="SES delivery failed"):
        SesMailer(client=FakeSes(fail=True)).send(build_message(make_report(), opts), opts)


def test_ses_without_boto3_says_which_extra_to_install(monkeypatch):
    monkeypatch.setattr(mailer_module, "boto3_available", lambda: False)
    opts = options(transport="ses", aws_region="eu-central-1")

    with pytest.raises(MailError, match=r"secman-visual-check\[aws\]"):
        SesMailer().send(build_message(make_report(), opts), opts)


def test_boto3_available_treats_a_broken_import_as_missing(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def exploding(name, *args, **kwargs):
        if name == "boto3":
            raise BaseException("broken native dependency")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", exploding)

    assert mailer_module.boto3_available() is False


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


def test_send_report_delivers_and_reports():
    fake = FakeSmtp()

    summary = send_report(make_report(), options(), CHANGES, mailer=SmtpMailer(client=fake))

    assert summary.sent is True
    assert summary.error is None
    assert summary.recipients == ["ops@example.com"]
    assert len(fake.sent) == 1


def test_send_report_is_a_no_op_when_disabled():
    summary = send_report(make_report(), options(enabled=False))

    assert summary.sent is False
    assert summary.skipped_reason == "not enabled"


def test_a_clean_run_sends_nothing_unless_asked():
    healthy = make_report(
        ScanResult(url="https://example.com/", status_check=status("https://example.com/"))
    )
    fake = FakeSmtp()

    quiet = send_report(healthy, options(), mailer=SmtpMailer(client=fake))
    loud = send_report(healthy, options(always=True), mailer=SmtpMailer(client=fake))

    assert quiet.sent is False
    assert "nothing to report" in quiet.skipped_reason
    assert loud.sent is True
    assert len(fake.sent) == 1


def test_a_dry_run_renders_the_subject_without_delivering():
    fake = FakeSmtp()

    summary = send_report(
        make_report(), options(dry_run=True), CHANGES, mailer=SmtpMailer(client=fake)
    )

    assert summary.sent is False
    assert summary.dry_run is True
    assert "Visual check:" in summary.subject
    assert fake.sent == []


def test_a_delivery_failure_is_reported_not_raised():
    class Exploding(SmtpMailer):
        def send(self, message, opts):
            raise MailError("SMTP delivery failed: connection refused")

    summary = send_report(make_report(), options(), CHANGES, mailer=Exploding())

    assert summary.sent is False
    assert "connection refused" in summary.error


def test_write_mail_report_covers_each_outcome():
    def rendered(summary):
        stream = io.StringIO()
        write_mail_report(summary, stream)
        return stream.getvalue()

    assert rendered(MailSummary(enabled=False, transport="smtp", endpoint="x")) == ""
    assert "skipped — not enabled" in rendered(
        MailSummary(enabled=True, transport="smtp", endpoint="x", skipped_reason="not enabled")
    )
    assert "delivery failed — boom" in rendered(
        MailSummary(enabled=True, transport="ses", endpoint="ses:eu", error="boom")
    )
    sent = rendered(
        MailSummary(
            enabled=True,
            transport="o365",
            endpoint="graph:tid",
            recipients=["ops@example.com"],
            subject="Visual check: all clear",
            sent=True,
        )
    )
    assert "sent via o365 (graph:tid) to ops@example.com" in sent
    assert "subject: Visual check: all clear" in sent
