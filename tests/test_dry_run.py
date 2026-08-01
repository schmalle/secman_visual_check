"""The global --dry-run: resolve everything, execute nothing."""

import json

from secman_visual_check.cli import build_parser, main
from secman_visual_check.config import ScanConfig
from secman_visual_check.db import DbOptions
from secman_visual_check.mailer import MailOptions
from secman_visual_check.plan import ScanPlan, write_plan
from secman_visual_check.secman import SecmanOptions


def parse(argv):
    return build_parser().parse_args(argv)


def run(argv, capsys):
    code = main(argv)
    return code, capsys.readouterr()


# --------------------------------------------------------------------------- #
# What the plan says
# --------------------------------------------------------------------------- #


def test_the_plan_lists_targets_stages_and_outputs(capsys, tmp_path):
    code, captured = run(
        ["example.com", "https://example.org/x", "--dry-run", "--no-ai", "-o", str(tmp_path)],
        capsys,
    )
    assert code == 0
    out = captured.out
    assert "Dry run" in out
    assert "https://example.com/" in out and "https://example.org/x" in out
    assert "Targets (2)" in out
    assert "status check" in out and "browser" in out
    assert "disabled (--no-ai)" in out
    assert str(tmp_path / "report.json") in out
    assert str(tmp_path / "screenshots") in out
    assert "Nothing was written" in out


def test_a_dry_run_writes_no_files(tmp_path, capsys):
    code, _ = run(["example.com", "--dry-run", "--no-ai", "-o", str(tmp_path)], capsys)
    assert code == 0
    assert not tmp_path.exists() or list(tmp_path.iterdir()) == []


def test_suppressed_reports_are_not_promised(capsys, tmp_path):
    _, captured = run(
        ["example.com", "--dry-run", "--no-ai", "--no-html", "--no-csv", "-o", str(tmp_path)],
        capsys,
    )
    assert "report.json" in captured.out
    assert "report.html" not in captured.out
    assert "report.csv" not in captured.out


def test_a_browserless_run_promises_no_screenshots(capsys, tmp_path):
    _, captured = run(
        ["example.com", "--dry-run", "--no-visual-check", "-o", str(tmp_path)], capsys
    )
    assert "disabled (--no-visual-check)" in captured.out
    assert "screenshots" not in captured.out


def test_the_plan_names_the_model_and_flags_a_missing_key(capsys, monkeypatch, tmp_path):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("SECMAN_API_KEY", raising=False)
    _, captured = run(["example.com", "--dry-run", "-o", str(tmp_path)], capsys)
    assert "NO API KEY" in captured.out


# --------------------------------------------------------------------------- #
# Integrations are described, never contacted
# --------------------------------------------------------------------------- #


def test_dry_run_makes_the_secman_upload_credential_free(capsys, tmp_path):
    # Without --dry-run this is a usage error: an upload needs a token.
    code, captured = run(
        ["example.com", "--dry-run", "--secman-upload", "--no-ai", "-o", str(tmp_path)],
        capsys,
    )
    assert code == 0
    assert "would upload findings at medium or above" in captured.out
    # …and says what a real run would still be refused over.
    assert "NO CREDENTIALS" in captured.out


def test_dry_run_makes_the_email_credential_free(capsys, tmp_path):
    # The smtp transport normally insists on a host before the scan starts.
    code, captured = run(
        [
            "example.com",
            "--dry-run",
            "--no-ai",
            "-o",
            str(tmp_path),
            "--mail",
            "--mail-from",
            "scanner@example.com",
            "--mail-to",
            "ops@example.com",
        ],
        capsys,
    )
    assert code == 0
    assert "ops@example.com" in captured.out
    assert "only when something is wrong" in captured.out
    assert "NO SMTP HOST" in captured.out


def test_the_database_is_described_without_being_opened(capsys, tmp_path):
    code, captured = run(
        [
            "example.com",
            "--dry-run",
            "--no-ai",
            "-o",
            str(tmp_path),
            "--db-store",
            "--db-user",
            "svc",
            "--db-password",
            "pw",
            "--db-host",
            "db.internal",
        ],
        capsys,
    )
    assert code == 0
    assert "svc@db.internal:3306/secman_visual_check" in captured.out
    # The password is a credential, not a plan detail.
    assert "pw" not in captured.out.replace("password", "")


def test_setting_flags_is_planned_offline(capsys):
    # No database, no driver, no connection — and still a useful answer.
    code, captured = run(
        [
            "--dry-run",
            "--db-set-flag",
            "https://example.com/=OK",
            "--db-user",
            "svc",
        ],
        capsys,
    )
    assert code == 0
    assert "set URL flags" in captured.out
    assert "OK" in captured.out and "https://example.com/" in captured.out


def test_uploading_a_stored_report_stays_a_dry_run(capsys, tmp_path):
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "url": "https://example.com/admin",
                        "analysis": {
                            "findings": [
                                {
                                    "title": "Password list on screen",
                                    "severity": "high",
                                    "category": "credentials",
                                }
                            ]
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    code, captured = run(["--dry-run", "--secman-upload-report", str(report)], capsys)
    assert code == 0
    assert "dry run (nothing written)" in captured.out
    assert "[planned]" in captured.out


# --------------------------------------------------------------------------- #
# A dry run still validates
# --------------------------------------------------------------------------- #


def test_a_broken_option_still_fails_in_a_dry_run(capsys):
    # The point of a dry run is to find this before a ten-minute crawl does.
    code, captured = run(["example.com", "--dry-run", "--viewport", "wide"], capsys)
    assert code == 2
    assert "viewport" in captured.err


def test_an_unusable_target_still_fails_in_a_dry_run(capsys):
    code, captured = run(["ftp://example.com", "--dry-run"], capsys)
    assert code == 2
    assert "error:" in captured.err


def test_an_unresolvable_secret_reference_fails_before_the_scan(capsys, tmp_path):
    code, captured = run(
        [
            "example.com",
            "--dry-run",
            "--no-ai",
            "-o",
            str(tmp_path),
            "--pass-cli-binary",
            str(tmp_path / "definitely-not-installed"),
            "--secman-upload",
            "--secman-token",
            "pass://Infra/SecMan/token",
        ],
        capsys,
    )
    assert code == 2
    assert "--secman-token" in captured.err


def test_a_resolved_reference_is_named_in_the_plan(capsys, tmp_path, monkeypatch):
    stub = tmp_path / "fake-pass-cli"
    stub.write_text("#!/bin/sh\nprintf 'jwt-value\\n'\n", encoding="utf-8")
    stub.chmod(0o755)
    code, captured = run(
        [
            "example.com",
            "--dry-run",
            "--no-ai",
            "-o",
            str(tmp_path / "out"),
            "--pass-cli-binary",
            str(stub),
            "--secman-upload",
            "--secman-token",
            "pass://Infra/SecMan/token",
        ],
        capsys,
    )
    assert code == 0
    assert "pass://Infra/SecMan/token" in captured.out
    # The reference is named; the value it resolved to is not printed.
    assert "jwt-value" not in captured.out


# --------------------------------------------------------------------------- #
# write_plan on its own
# --------------------------------------------------------------------------- #


def test_write_plan_marks_disabled_integrations(capsys, tmp_path):
    write_plan(
        ScanPlan(
            targets=["https://example.com/"],
            config=ScanConfig(output_dir=tmp_path),
            db=DbOptions(),
            mail=MailOptions(),
        )
    )
    out = capsys.readouterr().out
    assert "database       disabled" in out
    assert "email          disabled" in out
    assert "secman         disabled" in out


def test_plan_to_dict_carries_names_not_values(tmp_path):
    plan = ScanPlan(
        targets=["https://example.com/"],
        outputs=[("json", tmp_path / "report.json")],
        secman=SecmanOptions(token="a-real-token"),
    )
    payload = plan.to_dict()
    assert payload["targets"] == ["https://example.com/"]
    assert payload["outputs"]["json"].endswith("report.json")
    assert "a-real-token" not in json.dumps(payload)
