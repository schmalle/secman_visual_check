# Credentials from Proton Pass

Every credential this tool accepts can be written as a *reference* to an item in
a Proton Pass vault instead of the secret itself. The value is fetched through
[`pass-cli`](https://protonpass.github.io/pass-cli/) just before the scan
starts, so no password has to live in a shell history, a CI variable, a
`docker run -e`, or a `.env` file you keep meaning to delete.

It is entirely opt-in. A value that is not a reference is used exactly as
before, and nothing in this document changes anything for a setup that does not
use it. `pass-cli` is not a dependency of the package — it is only ever invoked
if you actually write a reference.

## The reference syntax

```
pass://<vault>/<item>/<field>
```

- **vault** — the vault's name or share ID.
- **item** — the item's title or ID.
- **field** — `password`, `username`, `email`, `note`, or the name of a custom
  field. Optional; it defaults to `password`.

Names with spaces work as-is, as long as the whole reference is quoted for your
shell. `%2F` lets a vault or item name contain a slash; the field is taken as
the whole remainder, so a custom field name containing a slash needs no
escaping.

```bash
'pass://Infra/SecMan automation/password'   # explicit field
'pass://Infra/SecMan automation'            # same thing — password is the default
'pass://Infra/SecMan automation/api-key'    # a custom field
'pass://Team%2FOps/CI runner/token'         # vault literally named "Team/Ops"
```

## Using it

Log in once, then pass references anywhere a credential is expected:

```bash
pass-cli login

python -m secman_visual_check -f targets.txt \
  --api-key 'pass://Infra/OpenRouter/api-key' \
  --secman-upload \
  --secman-token 'pass://Infra/SecMan automation/token'
```

Environment variables work too — a reference is resolved wherever the value
comes from, so an exported default is as good as a flag:

```bash
export SECMAN_DB_URL='pass://Infra/Scanner DB/dsn'
python -m secman_visual_check --db-store -f targets.txt
```

Check it before you rely on it. A dry run resolves every credential and then
stops, so a wrong vault name costs a second instead of a failed nightly job:

```bash
python -m secman_visual_check --dry-run -f targets.txt \
  --secman-upload --secman-token 'pass://Infra/SecMan automation/token'
```

The plan lists every reference it resolved — by name, never by value.

## Where references are accepted

| Flag | Environment variable |
| --- | --- |
| `--api-key` | `OPENROUTER_API_KEY`, `SECMAN_API_KEY` |
| `-H/--header` (the value) | — |
| `--basic-auth` (whole value, or the password half) | — |
| `--secman-token` | `SECMAN_TOKEN` |
| `--secman-password` | `SECMAN_PASSWORD` |
| `--secman-api-key` | `SECMAN_MCP_API_KEY` |
| `--db-url` (the whole DSN) | `SECMAN_DB_URL` |
| `--db-password` | `SECMAN_DB_PASSWORD` |
| `--mail-smtp-password` | `SECMAN_MAIL_SMTP_PASSWORD` |
| `--mail-client-secret` | `SECMAN_MAIL_CLIENT_SECRET` |

`--basic-auth` is the one with a wrinkle, because `pass://` contains the very
colon a `USER:PASS` pair splits on. Both forms work:

```bash
--basic-auth 'alice:pass://Infra/Internal portal/password'  # password half
--basic-auth 'pass://Infra/Internal portal/login'           # one item holding "alice:s3cret"
```

## Tuning it

| Flag | Effect |
| --- | --- |
| `--pass-cli-binary PATH` | The `pass-cli` to invoke, if it is not on `PATH`. Also `$SECMAN_PASS_CLI`. |
| `--pass-cli-timeout SECONDS` | How long to wait for one call (default 30). A locked session is the usual reason for a slow one. |
| `--no-pass-cli` | Refuse references instead of resolving them. Literal values still work. For hosts where shelling out to a password manager is not wanted. |

## Shell scripts

`scripts/passcli.sh` is the same resolution for the operator scripts in this
repository. Source it and pass any variable that may hold a credential through
`secman_resolve_var`:

```bash
source scripts/passcli.sh
secman_resolve_var DB_PASSWORD
```

`db/install.sh` already does this for `DB_PASSWORD` and `DB_ROOT_PASSWORD`, so
the database can be created without its password ever being typed:

```bash
DB_PASSWORD='pass://Infra/Scanner DB/password' db/install.sh
```

The helper honours `$SECMAN_PASS_CLI` and `$SECMAN_PASS_CLI_TIMEOUT`.

## What it does with the secret

- **It never reaches a command line.** Only the *reference* is passed to
  `pass-cli`; the value comes back through a pipe. A password given as
  `--db-password s3cret` is visible to every process on the host for as long as
  the scan runs — a reference is not.
- **It never reaches a report.** The JSON, HTML, CSV and console output carry
  the reference's name at most. Text that comes back from a backend — a SecMan
  error body, a database driver's message — is scrubbed of resolved values
  before it is printed, so a service that rejects a credential by quoting it
  back cannot put it in a CI log.
- **It is fetched once per run.** Two flags pointing at the same item cost one
  `pass-cli` call and one unlock prompt.

## When it goes wrong

Resolution failures are fatal and happen *before* the scan, alongside every
other credential check — the point is that a ten-minute crawl never ends on a
typo. The message names the flag and the reference.

| Message | Cause |
| --- | --- |
| `'pass-cli' was not found` | Not installed, or not on `PATH`. Install it, or point `--pass-cli-binary` / `$SECMAN_PASS_CLI` at it. |
| `pass-cli did not answer within 30s` | Usually a locked session waiting on an unlock that never comes. Run `pass-cli login` first, or raise `--pass-cli-timeout`. |
| `pass-cli refused every form (…)` | The vault, item or field does not exist — or you are not logged in. The message quotes what `pass-cli` itself said. |
| `resolved to an empty value` | The item exists but the field is empty. Check the field name. |
| `is missing a vault or item` | A malformed reference. This is deliberately an error rather than a literal: a password of `pass://Infra` would fail three steps later with a baffling 401. |

`pass-cli`'s command surface has changed between releases, so resolution tries
each known spelling (`item view --item-title`, `item view --item-name`,
`read <ref>`) and remembers whichever one answered. If all of them fail, the
error quotes what each attempt said.

## In CI

A pipeline that already has a machine credential does not need this — keep
using the environment variable. It earns its keep where a human's vault is the
source of truth: a laptop, a jump host, an on-call runbook, or an operator
script like `db/install.sh` that is run by hand a few times a year.

For an unattended runner, `pass-cli` needs a non-interactive session; see the
[Proton Pass CLI documentation](https://protonpass.github.io/pass-cli/) for how
that is set up on your plan. Without one, `--no-pass-cli` makes the refusal
explicit rather than letting a job hang on an unlock prompt.
