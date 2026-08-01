import subprocess

import pytest

from secman_visual_check.cli import (
    build_config,
    build_db_options,
    build_mail_options,
    build_parser,
    build_secman_options,
)
from secman_visual_check.secrets import (
    DEFAULT_FIELD,
    SecretError,
    SecretRef,
    SecretResolver,
    looks_like_ref,
    parse_ref,
    redact,
)


class FakeCli:
    """Stands in for pass-cli: records argv, answers from a canned table."""

    def __init__(self, answers=None, returncode=0, stderr="", stdout=""):
        #: {(vault, item, field): value}, consulted for the `item view` forms.
        self.answers = answers or {}
        self.returncode = returncode
        self.stderr = stderr
        self.stdout = stdout
        self.calls = []
        #: Argument names this fake pretends not to understand.
        self.unsupported = ()

    def __call__(self, argv, timeout):
        self.calls.append(list(argv))
        if any(flag in argv for flag in self.unsupported):
            return subprocess.CompletedProcess(
                argv, 2, stdout="", stderr="unknown flag\n"
            )
        if self.answers and "view" in argv:
            key = (argv[argv.index("--vault-name") + 1], argv[-3], argv[-1])
            if key in self.answers:
                return subprocess.CompletedProcess(
                    argv, 0, stdout=self.answers[key] + "\n", stderr=""
                )
            return subprocess.CompletedProcess(argv, 1, stdout="", stderr="item not found\n")
        return subprocess.CompletedProcess(
            argv, self.returncode, stdout=self.stdout, stderr=self.stderr
        )


def resolver(fake, **kwargs):
    return SecretResolver(runner=fake, **kwargs)


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #


def test_looks_like_ref():
    assert looks_like_ref("pass://Infra/SecMan/password")
    assert looks_like_ref("  pass://a/b  ")
    assert not looks_like_ref("hunter2")
    assert not looks_like_ref("")
    assert not looks_like_ref(None)


def test_parse_ref_full_and_default_field():
    assert parse_ref("pass://Infra/SecMan bot/token") == SecretRef("Infra", "SecMan bot", "token")
    assert parse_ref("pass://Infra/SecMan bot").field == DEFAULT_FIELD


def test_parse_ref_percent_decodes_and_keeps_slashes_in_the_field():
    ref = parse_ref("pass://Team%2FOps/CI%20runner/custom/field")
    assert ref.vault == "Team/Ops"
    assert ref.item == "CI runner"
    assert ref.field == "custom/field"


@pytest.mark.parametrize("bad", ["pass://", "pass://Infra", "pass:///item/x", "pass://  /x"])
def test_a_broken_reference_is_an_error_not_a_password(bad):
    # Silently treating this as a literal would put "pass://Infra" in an
    # Authorization header and produce a mystifying 401.
    with pytest.raises(SecretError):
        parse_ref(bad)


def test_str_round_trips_for_messages():
    assert str(parse_ref("pass://Infra/Bot/token")) == "pass://Infra/Bot/token"


# --------------------------------------------------------------------------- #
# Resolution
# --------------------------------------------------------------------------- #


def test_a_literal_value_is_passed_through_untouched():
    fake = FakeCli()
    assert resolver(fake).resolve("hunter2") == "hunter2"
    assert resolver(fake).resolve(None) is None
    assert fake.calls == []


def test_a_reference_is_resolved_through_the_cli():
    fake = FakeCli({("Infra", "SecMan", "password"): "s3cret"})
    assert resolver(fake).resolve("pass://Infra/SecMan/password") == "s3cret"
    assert fake.calls[0][:2] == ["pass-cli", "item"]
    assert "--vault-name" in fake.calls[0]


def test_the_secret_never_appears_in_argv():
    fake = FakeCli({("Infra", "SecMan", "password"): "s3cret"})
    resolver(fake).resolve("pass://Infra/SecMan/password")
    assert all("s3cret" not in arg for call in fake.calls for arg in call)


def test_the_same_reference_is_fetched_once():
    fake = FakeCli({("Infra", "SecMan", "password"): "s3cret"})
    one = resolver(fake)
    assert one.resolve("pass://Infra/SecMan") == "s3cret"
    assert one.resolve("pass://Infra/SecMan/password") == "s3cret"
    assert len(fake.calls) == 1
    assert [str(r) for r in one.resolved] == ["pass://Infra/SecMan/password"]


def test_a_second_reference_reuses_the_spelling_that_worked():
    # pass-cli's flags have moved between releases; once one form answers, the
    # others are not tried again for the rest of the run.
    fake = FakeCli(
        {("V", "a", "password"): "one", ("V", "b", "password"): "two"},
    )
    fake.unsupported = ("--item-title",)
    one = resolver(fake)
    assert one.resolve("pass://V/a") == "one"
    first_round = len(fake.calls)
    assert first_round == 2  # --item-title refused, --item-name accepted
    assert one.resolve("pass://V/b") == "two"
    assert len(fake.calls) == first_round + 1


def test_every_spelling_refusing_reports_all_of_them():
    fake = FakeCli(returncode=1, stderr="not logged in\n")
    with pytest.raises(SecretError) as exc:
        resolver(fake).resolve("pass://V/i/f", what="--secman-token")
    message = str(exc.value)
    assert "--secman-token" in message
    assert "not logged in" in message
    assert "pass://V/i/f" in message


def test_a_missing_binary_says_how_to_fix_it():
    def missing(argv, timeout):
        raise FileNotFoundError(argv[0])

    with pytest.raises(SecretError) as exc:
        SecretResolver(runner=missing).resolve("pass://V/i")
    assert "pass-cli" in str(exc.value)
    assert "--pass-cli-binary" in str(exc.value)


def test_a_missing_binary_does_not_try_the_other_spellings():
    calls = []

    def missing(argv, timeout):
        calls.append(argv)
        raise FileNotFoundError(argv[0])

    with pytest.raises(SecretError):
        SecretResolver(runner=missing).resolve("pass://V/i")
    assert len(calls) == 1


def test_a_timeout_points_at_the_locked_session():
    def slow(argv, timeout):
        raise subprocess.TimeoutExpired(argv, timeout)

    with pytest.raises(SecretError) as exc:
        SecretResolver(runner=slow, timeout=2).resolve("pass://V/i")
    assert "pass-cli login" in str(exc.value)


def test_an_empty_value_is_an_error():
    fake = FakeCli(returncode=0, stdout="\n")
    with pytest.raises(SecretError) as exc:
        resolver(fake).resolve("pass://V/i/nosuchfield")
    assert "empty" in str(exc.value)


def test_trailing_newline_is_stripped_but_inner_whitespace_survives():
    fake = FakeCli(returncode=0, stdout="  pa ss  \n")
    assert resolver(fake).resolve("pass://V/i") == "  pa ss  "


def test_disabled_resolver_refuses_references_but_allows_literals():
    fake = FakeCli()
    off = resolver(fake, enabled=False)
    assert off.resolve("hunter2") == "hunter2"
    with pytest.raises(SecretError) as exc:
        off.resolve("pass://V/i", what="--db-password")
    assert "--no-pass-cli" in str(exc.value)
    assert fake.calls == []


def test_a_custom_binary_is_invoked():
    fake = FakeCli(returncode=0, stdout="v\n")
    resolver(fake, binary="/opt/bin/pass-cli").resolve("pass://V/i")
    assert fake.calls[0][0] == "/opt/bin/pass-cli"


# --------------------------------------------------------------------------- #
# Pairs and redaction
# --------------------------------------------------------------------------- #


def test_resolve_pair_handles_the_password_half():
    fake = FakeCli(returncode=0, stdout="s3cret\n")
    assert resolver(fake).resolve_pair("admin:pass://V/i") == "admin:s3cret"


def test_resolve_pair_handles_a_whole_reference():
    # pass:// contains the very colon a USER:PASS pair splits on, so the whole
    # value has to be tested first.
    fake = FakeCli(returncode=0, stdout="admin:s3cret\n")
    assert resolver(fake).resolve_pair("pass://V/i/login") == "admin:s3cret"


def test_resolve_pair_leaves_a_literal_pair_alone():
    fake = FakeCli()
    assert resolver(fake).resolve_pair("admin:hunter2") == "admin:hunter2"
    assert fake.calls == []


def test_redact_replaces_resolved_values():
    assert redact("rejected token s3cretvalue", ["s3cretvalue"]) == "rejected token <redacted>"


def test_redact_leaves_short_values_alone():
    # Masking every "ab" would mangle unrelated text without hiding anything.
    assert redact("a table of abc", ["ab"]) == "a table of abc"


def test_values_are_available_for_redaction_but_resolved_is_names_only():
    fake = FakeCli(returncode=0, stdout="s3cret\n")
    one = resolver(fake)
    one.resolve("pass://V/i")
    assert one.values == ["s3cret"]
    assert all("s3cret" not in str(ref) for ref in one.resolved)


# --------------------------------------------------------------------------- #
# Every credential flag goes through the resolver
# --------------------------------------------------------------------------- #


def parse(argv):
    return build_parser().parse_args(argv)


def test_secman_credentials_accept_references():
    fake = FakeCli(returncode=0, stdout="s3cret\n")
    options = build_secman_options(
        parse(["--secman-upload", "--secman-token", "pass://Infra/SecMan/token"]),
        resolver(fake),
    )
    assert options.token == "s3cret"


def test_mcp_credentials_accept_references():
    fake = FakeCli(returncode=0, stdout="mcp-key\n")
    options = build_secman_options(
        parse(
            [
                "--secman-upload",
                "--secman-transport",
                "mcp",
                "--secman-api-key",
                "pass://Infra/SecMan/api-key",
                "--secman-user-email",
                "ops@example.com",
            ]
        ),
        resolver(fake),
    )
    assert options.api_key == "mcp-key"


def test_a_whole_database_url_can_be_a_reference():
    # The password inside a DSN is the single worst thing to leave on a command
    # line, so the DSN itself has to be referenceable.
    fake = FakeCli(returncode=0, stdout="mysql://svc:pw@db.internal:3306/checks\n")
    options = build_db_options(
        parse(["--db-store", "--db-url", "pass://Infra/Scanner DB/dsn"]), resolver(fake)
    )
    assert (options.host, options.user, options.database) == ("db.internal", "svc", "checks")


def test_the_database_password_can_be_a_reference():
    fake = FakeCli(returncode=0, stdout="pw\n")
    options = build_db_options(
        parse(["--db-store", "--db-user", "svc", "--db-password", "pass://Infra/DB/password"]),
        resolver(fake),
    )
    assert options.password == "pw"
    assert "pw" not in options.dsn  # dsn is documented as safe to print


def test_the_smtp_password_can_be_a_reference():
    fake = FakeCli(returncode=0, stdout="smtp-pw\n")
    options = build_mail_options(
        parse(
            [
                "--mail",
                "--mail-from",
                "a@example.com",
                "--mail-to",
                "b@example.com",
                "--mail-smtp-host",
                "smtp.example.com",
                "--mail-smtp-password",
                "pass://Infra/SMTP/password",
            ]
        ),
        resolver(fake),
    )
    assert options.smtp_password == "smtp-pw"


def test_the_model_api_key_and_headers_can_be_references(tmp_path):
    fake = FakeCli(returncode=0, stdout="sk-resolved\n")
    config = build_config(
        parse(
            [
                "https://example.com",
                "-o",
                str(tmp_path),
                "--api-key",
                "pass://Infra/OpenRouter/key",
                "-H",
                "Authorization: pass://Infra/Target/bearer",
            ]
        ),
        resolver(fake),
    )
    assert config.analyzer is not None
    assert config.analyzer.api_key == "sk-resolved"
    assert config.capture.extra_headers["Authorization"] == "sk-resolved"


def test_basic_auth_resolves_only_the_password_half(tmp_path):
    fake = FakeCli(returncode=0, stdout="s3cret\n")
    config = build_config(
        parse(
            [
                "https://example.com",
                "-o",
                str(tmp_path),
                "--no-ai",
                "--basic-auth",
                "admin:pass://Infra/Target/password",
            ]
        ),
        resolver(fake),
    )
    assert config.capture.basic_auth == ("admin", "s3cret")
    assert config.status_check.basic_auth == ("admin", "s3cret")


def test_option_builders_work_without_a_resolver(tmp_path):
    # Every builder is called directly in tests and scripts; a literal value
    # must never need one.
    options = build_db_options(parse(["--db-store", "--db-user", "svc", "--db-password", "pw"]))
    assert options.password == "pw"
