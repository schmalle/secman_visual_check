"""Resolve ``pass://`` references through the Proton Pass CLI.

Every credential this tool accepts — API keys, JWTs, SMTP and database
passwords — may be written as a *reference* instead of the secret itself::

    --secman-token 'pass://Infra/SecMan automation/password'

The reference names a vault, an item and a field; the value is fetched by
shelling out to ``pass-cli`` (https://protonpass.github.io/pass-cli/) just
before the scan starts. Nothing else changes: a value that is not a reference
is passed through untouched, so existing scripts and environments keep working
and the dependency stays entirely optional.

Two properties are worth keeping if this file is touched:

* **Values never reach argv.** Only the reference is passed to ``pass-cli``, and
  only ``pass-cli`` writes the secret — to a pipe we read. A password given on a
  command line is visible to every process on the host; a reference is not.
* **Values never reach the reports.** :class:`SecretResolver` records which
  references it resolved, never what they resolved to, and
  :func:`redact` scrubs a resolved value out of any text before it is printed.

``pass-cli``'s command surface has moved between releases, so resolution tries
the known spellings in order and remembers the one that worked
(:data:`STRATEGIES`). A failure reports every spelling it attempted, because the
useful message — "not logged in" — can come from any of them.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from typing import Callable, Sequence
from urllib.parse import unquote

#: Reference scheme. Chosen by Proton Pass, not by us.
SCHEME = "pass://"
DEFAULT_BINARY = "pass-cli"
#: A reference may omit the field; an item's password is what is almost always
#: wanted, and it is what ``pass-cli`` itself defaults to.
DEFAULT_FIELD = "password"
DEFAULT_TIMEOUT_S = 30.0

#: Env var holding the binary to invoke, for a pass-cli that is not on PATH.
BINARY_ENV = "SECMAN_PASS_CLI"


class SecretError(RuntimeError):
    """Raised when a ``pass://`` reference cannot be turned into a value."""


@dataclass(frozen=True)
class SecretRef:
    """A parsed ``pass://vault/item/field`` reference.

    Safe to print: it names a secret, it is not one.
    """

    vault: str
    item: str
    field: str = DEFAULT_FIELD

    def __str__(self) -> str:
        return f"{SCHEME}{self.vault}/{self.item}/{self.field}"


def looks_like_ref(value: str | None) -> bool:
    return bool(value) and str(value).strip().startswith(SCHEME)


def parse_ref(value: str) -> SecretRef:
    """Parse ``pass://vault/item[/field]``.

    Segments are percent-decoded, so a vault or item whose name contains ``/``
    can be written ``%2F``. The field is taken as the whole remainder, so a
    custom field name containing a slash needs no escaping.

    Raises :class:`SecretError` for anything that starts with the scheme but is
    not a usable reference — a typo in a credential must be loud, never a
    password that happens to begin with ``pass://``.
    """
    body = str(value).strip()[len(SCHEME) :]
    if not body:
        raise SecretError(f"{value!r} is not a usable secret reference; expected {SCHEME}vault/item/field")
    vault, _, rest = body.partition("/")
    item, sep, raw_field = rest.partition("/")
    vault, item = unquote(vault).strip(), unquote(item).strip()
    if not vault or not item:
        raise SecretError(
            f"{value!r} is missing a vault or item; expected {SCHEME}vault/item/field"
        )
    chosen = unquote(raw_field).strip() if sep else ""
    return SecretRef(vault=vault, item=item, field=chosen or DEFAULT_FIELD)


# --------------------------------------------------------------------------- #
# Talking to pass-cli
# --------------------------------------------------------------------------- #

#: How to ask ``pass-cli`` for one field, most specific spelling first. Releases
#: have disagreed on ``--item-title`` vs ``--item-name`` and on whether a
#: reference can be handed over whole, so all three are tried once and the
#: winner is cached for the rest of the run.
STRATEGIES: tuple[tuple[str, Callable[[SecretRef], list[str]]], ...] = (
    (
        "item view --item-title",
        lambda ref: [
            "item",
            "view",
            "--vault-name",
            ref.vault,
            "--item-title",
            ref.item,
            "--field",
            ref.field,
        ],
    ),
    (
        "item view --item-name",
        lambda ref: [
            "item",
            "view",
            "--vault-name",
            ref.vault,
            "--item-name",
            ref.item,
            "--field",
            ref.field,
        ],
    ),
    ("read", lambda ref: ["read", str(ref)]),
)


def _run(argv: Sequence[str], timeout: float) -> subprocess.CompletedProcess:
    """One ``pass-cli`` invocation. No shell, so nothing here is word-split."""
    return subprocess.run(  # noqa: S603 - argv is a list; there is no shell
        list(argv),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _first_line(text: str) -> str:
    for line in (text or "").splitlines():
        if line.strip():
            return line.strip()[:200]
    return ""


@dataclass
class SecretResolver:
    """Resolves references, once each, through ``pass-cli``.

    Construct one per run and hand it to every option builder, so a reference
    used by two flags costs one ``pass-cli`` call and one prompt.
    """

    binary: str = DEFAULT_BINARY
    timeout: float = DEFAULT_TIMEOUT_S
    #: ``False`` refuses references instead of resolving them, for hosts where
    #: shelling out is not wanted. A literal value still passes through.
    enabled: bool = True
    #: Swappable for tests: same contract as :func:`_run`.
    runner: Callable[[Sequence[str], float], subprocess.CompletedProcess] = _run

    _cache: dict[SecretRef, str] = field(default_factory=dict, repr=False)
    _strategy: str | None = field(default=None, repr=False)
    _resolved: list[SecretRef] = field(default_factory=list, repr=False)

    @property
    def resolved(self) -> list[SecretRef]:
        """References resolved so far, in first-seen order. Never their values."""
        return list(self._resolved)

    @property
    def values(self) -> list[str]:
        """Every resolved value, for :func:`redact`. Not for printing."""
        return list(self._cache.values())

    def resolve(self, value: str | None, *, what: str = "value") -> str | None:
        """Return ``value``, or the secret it references.

        ``what`` names the flag in error messages (``"--secman-token"``), so a
        failure says which credential could not be fetched.
        """
        if value is None or not looks_like_ref(value):
            return value
        try:
            ref = parse_ref(value)
        except SecretError as exc:
            raise SecretError(f"{what}: {exc}") from None
        if not self.enabled:
            raise SecretError(
                f"{what} is the secret reference {ref}, but --no-pass-cli was given"
            )
        if ref in self._cache:
            return self._cache[ref]
        try:
            secret = self._fetch(ref)
        except SecretError as exc:
            raise SecretError(f"{what}: {exc}") from None
        self._cache[ref] = secret
        self._resolved.append(ref)
        return secret

    def resolve_pair(self, value: str | None, *, what: str = "value") -> str | None:
        """Resolve a ``USER:PASS`` pair, where either half may be a reference.

        ``--basic-auth`` is the awkward case: the whole option can be one
        reference to an item holding ``user:pass``, or the password half alone
        can be — and ``pass://`` contains the very colon the pair splits on.
        Resolving the whole value first settles it.
        """
        if value is None:
            return None
        if looks_like_ref(value):
            return self.resolve(value, what=what)
        user, sep, secret = str(value).partition(":")
        if not sep:
            return value
        return f"{user}:{self.resolve(secret, what=what)}"

    def _fetch(self, ref: SecretRef) -> str:
        attempts: list[tuple[str, str]] = []
        ordered = [s for s in STRATEGIES if s[0] == self._strategy] or list(STRATEGIES)
        for name, build in ordered:
            argv = [self.binary, *build(ref)]
            try:
                completed = self.runner(argv, self.timeout)
            except FileNotFoundError:
                # No point trying the other spellings: the binary is absent.
                raise SecretError(
                    f"cannot resolve {ref}: {self.binary!r} was not found. Install the "
                    "Proton Pass CLI (https://protonpass.github.io/pass-cli/), or point "
                    f"--pass-cli-binary / ${BINARY_ENV} at it"
                ) from None
            except subprocess.TimeoutExpired:
                raise SecretError(
                    f"cannot resolve {ref}: {self.binary} did not answer within "
                    f"{self.timeout:g}s. An unlocked session is needed — try "
                    "'pass-cli login' first"
                ) from None
            except OSError as exc:
                raise SecretError(f"cannot resolve {ref}: {self.binary} failed to start: {exc}") from None

            if completed.returncode == 0:
                secret = (completed.stdout or "").strip("\r\n")
                if not secret:
                    raise SecretError(
                        f"{ref} resolved to an empty value — check the field name"
                    )
                # Remember the spelling this pass-cli understands.
                self._strategy = name
                return secret
            attempts.append((name, _first_line(completed.stderr) or _first_line(completed.stdout)))

        detail = "; ".join(f"{name}: {message or 'no output'}" for name, message in attempts)
        raise SecretError(f"cannot resolve {ref}: {self.binary} refused every form ({detail})")


def redact(text: str, secrets: Sequence[str]) -> str:
    """Replace resolved values with a marker.

    Last line of defence for text that is about to be printed — a backend that
    echoes a rejected credential back in its error body must not put it in a
    report. Short values are left alone: masking every occurrence of a two-
    character string mangles unrelated text without hiding anything.
    """
    out = text or ""
    for secret in secrets:
        if secret and len(secret) >= 4:
            out = out.replace(secret, "<redacted>")
    return out
