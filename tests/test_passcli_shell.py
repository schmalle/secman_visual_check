"""scripts/passcli.sh — the shell half of the pass:// resolution.

Exercised through bash with a stub pass-cli on PATH, so the operator scripts
that source it are covered by the same suite as everything else. Nothing here
touches a real Proton Pass.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

HELPER = Path(__file__).resolve().parents[1] / "scripts" / "passcli.sh"

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")


def stub_cli(tmp_path: Path, body: str) -> Path:
    """A fake pass-cli, first on PATH."""
    binary = tmp_path / "pass-cli"
    binary.write_text(f"#!/usr/bin/env bash\n{body}\n", encoding="utf-8")
    binary.chmod(0o755)
    return binary


def run_bash(script: str, tmp_path: Path, env: dict | None = None):
    environment = dict(os.environ)
    environment["PATH"] = f"{tmp_path}{os.pathsep}{environment['PATH']}"
    environment.update(env or {})
    return subprocess.run(
        ["bash", "-c", f"set -euo pipefail\nsource {HELPER}\n{script}"],
        capture_output=True,
        text=True,
        env=environment,
        timeout=30,
    )


def recording_cli(tmp_path: Path, value: str = "s3cret") -> Path:
    """A stub that logs its argv to a file — the helper discards its stderr."""
    log = tmp_path / "argv.log"
    stub_cli(tmp_path, f'printf "%s\\n" "$*" >> "{log}"\nprintf "{value}\\n"')
    return log


def test_a_literal_value_is_left_alone(tmp_path):
    stub_cli(tmp_path, 'echo "should not run" >&2; exit 1')
    result = run_bash(
        'DB_PASSWORD=hunter2; secman_resolve_var DB_PASSWORD; printf "%s" "$DB_PASSWORD"',
        tmp_path,
    )
    assert result.returncode == 0
    assert result.stdout == "hunter2"


def test_a_reference_is_resolved(tmp_path):
    log = recording_cli(tmp_path)
    result = run_bash(
        "DB_PASSWORD='pass://Infra/Scanner DB/password'; secman_resolve_var DB_PASSWORD; "
        'printf "%s" "$DB_PASSWORD"',
        tmp_path,
    )
    assert result.returncode == 0
    assert result.stdout == "s3cret"
    argv = log.read_text(encoding="utf-8")
    # The vault and item reached pass-cli with their spaces intact…
    assert "--vault-name Infra" in argv
    assert "Scanner DB" in argv
    # …and the secret never became an argument.
    assert "s3cret" not in argv


def test_the_field_defaults_to_password(tmp_path):
    log = recording_cli(tmp_path)
    result = run_bash("TOKEN='pass://Infra/Bot'; secman_resolve_var TOKEN", tmp_path)
    assert result.returncode == 0
    assert "--field password" in log.read_text(encoding="utf-8")


def test_percent_escapes_are_decoded(tmp_path):
    log = recording_cli(tmp_path)
    result = run_bash(
        "TOKEN='pass://Team%2FOps/CI%20runner/api'; secman_resolve_var TOKEN", tmp_path
    )
    assert result.returncode == 0
    argv = log.read_text(encoding="utf-8")
    assert "--vault-name Team/Ops" in argv
    assert "CI runner" in argv


def test_the_second_spelling_is_tried(tmp_path):
    stub_cli(
        tmp_path,
        'if [[ "$*" == *--item-title* ]]; then exit 2; fi\nprintf "fallback\\n"',
    )
    result = run_bash(
        "TOKEN='pass://V/i/f'; secman_resolve_var TOKEN; printf '%s' \"$TOKEN\"", tmp_path
    )
    assert result.returncode == 0
    assert result.stdout == "fallback"


def test_an_unresolvable_reference_fails_loudly(tmp_path):
    stub_cli(tmp_path, "exit 1")
    result = run_bash("TOKEN='pass://V/i/f'; secman_resolve_var TOKEN", tmp_path)
    assert result.returncode != 0
    assert "could not resolve" in result.stderr
    assert "pass-cli login" in result.stderr


def test_a_reference_with_no_item_is_rejected(tmp_path):
    stub_cli(tmp_path, "printf \"ok\\n\"")
    result = run_bash("TOKEN='pass://Infra'; secman_resolve_var TOKEN", tmp_path)
    assert result.returncode != 0
    assert "missing an item" in result.stderr


def test_a_missing_binary_says_how_to_fix_it(tmp_path):
    result = run_bash(
        "TOKEN='pass://V/i/f'; secman_resolve_var TOKEN",
        tmp_path,
        env={"SECMAN_PASS_CLI": str(tmp_path / "definitely-not-installed")},
    )
    assert result.returncode != 0
    assert "SECMAN_PASS_CLI" in result.stderr


def test_install_sh_resolves_the_password_before_touching_the_database(tmp_path):
    # No mysql on PATH: the script must still get far enough to prove it
    # resolved the reference, and must fail rather than run with the literal.
    stub_cli(tmp_path, 'printf "resolved-pw\\n"')
    install = HELPER.parent.parent / "db" / "install.sh"
    environment = dict(os.environ)
    environment["PATH"] = f"{tmp_path}{os.pathsep}{environment['PATH']}"
    environment["DB_PASSWORD"] = "pass://Infra/Scanner DB/password"
    environment["DB_NAME"] = "not a valid name"
    result = subprocess.run(
        ["bash", str(install)], capture_output=True, text=True, env=environment, timeout=30
    )
    # It got past the DB_PASSWORD check, so the reference resolved to something.
    assert "DB_PASSWORD is required" not in result.stderr
    assert "DB_NAME must be" in result.stderr
