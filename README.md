# secman_visual_check

Checker for web pages.

Give it a URL (or a list of them). It loads each page in a headless browser,
takes a screenshot, and asks a vision model whether the page exposes content
that should not be reachable — credentials, unauthenticated admin panels,
directory listings, personal data, stack traces, and so on. Before the browser
opens a target it also asks a plain HTTP client what the URL actually answers:
200, a redirect (and where to), an error, or nothing at all — see
[Status and redirect checks](#status-and-redirect-checks).

You get a console summary, a machine-readable JSON report, and a self-contained
HTML report with the screenshots embedded. Findings can also be pushed straight
into [SecMan](https://github.com/schmalle/secman) — see
[Uploading findings to SecMan](#uploading-findings-to-secman) — and status
results can be mirrored into MariaDB, see [db/README.md](db/README.md).

Every credential can be handed over as a Proton Pass reference rather than the
secret itself (see [Credentials from Proton Pass](#credentials-from-proton-pass)),
and `--dry-run` resolves the whole configuration and prints what a run *would*
do without touching anything (see [Dry runs](#dry-runs)).

> **Scan only systems you own or are explicitly authorised to test.** The tool
> loads pages and sends screenshots to a third-party model provider; both are
> actions you need permission for.

## Install

Python 3.10+.

```bash
pip install -r requirements.txt
playwright install chromium          # one-time browser download
```

Or install the package itself (adds a `secman-visual-check` command):

```bash
pip install -e .
playwright install chromium
```

### Homebrew Python (macOS)

Homebrew's Python is an *externally managed* environment ([PEP 668](https://peps.python.org/pep-0668/)),
so a bare `pip install` into it is refused:

```
error: externally-managed-environment
× This environment is externally managed
```

Use a virtual environment. This is the recommended setup on macOS:

```bash
brew install python              # if you do not already have it
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/playwright install chromium
```

Then run the tool through that interpreter — either directly, or with the venv
activated:

```bash
.venv/bin/python -m secman_visual_check https://example.com

# …or activate once per shell and drop the prefix
source .venv/bin/activate
python -m secman_visual_check https://example.com
```

Installing the package (`pip install -e .`) additionally puts a
`secman-visual-check` command on the venv's path, so `.venv/bin/secman-visual-check`
works without the `-m` form.

Two Homebrew-specific notes:

- **Do not** reach for `pip install --break-system-packages`. It writes into the
  interpreter Homebrew manages, and a later `brew upgrade python` can remove or
  replace what you installed.
- Chromium is downloaded by `playwright install` into `~/Library/Caches/ms-playwright`,
  not by Homebrew, and it is tied to the Playwright version in the venv. Re-run
  `playwright install chromium` after upgrading Playwright. To use a browser you
  already have instead, point `$SECMAN_BROWSER_EXECUTABLE` at it — or skip the
  browser entirely with `--no-visual-check`.

## Quick start

```bash
export OPENROUTER_API_KEY=sk-or-...

# One URL
python -m secman_visual_check https://example.com/admin

# A list, into a chosen output directory
python -m secman_visual_check -f examples/urls.txt -o ./scan-2026-07-27

# Screenshots only, no model calls and no API key needed
python -m secman_visual_check --no-ai https://example.com

# No browser at all — just check what each URL answers
python -m secman_visual_check --no-visual-check -f examples/urls.txt
```

Targets come from the command line, from one or more files (`-f`, repeatable),
or from stdin (`--stdin`). A target file is one URL per line; blank lines and
`#` comments are ignored, a missing scheme defaults to `https://`, and
duplicates are dropped:

```
# examples/urls.txt
https://example.com/admin
example.com/backup/          # scheme optional, trailing comments fine
```

Output lands in `scan-output/` by default:

```
scan-output/
├── screenshots/0001-example.com-admin-3f9a2c1b04.png
├── report.json        machine-readable, the full detail
├── report.html        self-contained, screenshots embedded
├── report.csv         one row per target, for a spreadsheet
└── statistics.txt     the aggregate numbers
```

All four are written by default; `--no-json`, `--no-html`, `--no-csv` and
`--no-stats` each drop one, and `--json`, `--html`, `--csv` and `--stats` take an
explicit path.

## Reports

### CSV

`report.csv` is **one row per target**, not per finding — a target is the unit
you sort, filter and assign, and the row is still complete when a run produced
no findings at all:

| column | |
| --- | --- |
| `url` | the target as scanned |
| `status_state`, `status_ok`, `first_status`, `final_status`, `final_url`, `redirect_count` | the HTTP status check |
| `content_checksum`, `content_length`, `content_type` | the body hash, when one was taken |
| `http_status`, `title`, `screenshot` | what the browser saw, blank under `--no-visual-check` |
| `max_severity`, `findings`, `categories` | the verdict: worst severity, how many findings, and the distinct categories, `;`-separated |
| `page_type`, `summary` | the model's description of the page |
| `error` | load error, scan error, or `robots.txt` skip reason |

Cells beginning `=`, `+`, `-` or `@` are prefixed with `'`, so a page title or a
model summary cannot become a live formula when the file is opened in Excel or
LibreOffice.

### Statistics

The aggregate numbers are printed at the end of every run and written to
`statistics.txt`:

```
Statistics:
  targets                    4
  findings                   0  on 0 target(s)
  answering as expected      2   50.0%
  checksummed                2   50.0%  891.1 KB hashed
```

The console block shows what the two count tables above it do not; the file adds
the full per-severity and per-state breakdown with percentages, plus the run's
timing, version and model. Rows for a stage that never ran are omitted rather
than printed as zeros — a `--no-visual-check` run says nothing about captures,
because "0 captured" would read as failure rather than as *not applicable*.

`--no-stats` suppresses both the file and the console block.

## Doing less: `--no-ai` and `--no-visual-check`

A full run does three things per target: an HTTP status check, a screenshot, and
a model call. Two flags switch the expensive halves off, and they stack from the
outside in:

| Mode | Status check | Screenshot | Model call | Needs |
| --- | --- | --- | --- | --- |
| default | yes | yes | yes | Chromium + API key |
| `--no-ai` | yes | yes | no | Chromium |
| `--no-visual-check` | yes | no | no | neither |

The content check runs in every mode: on the page text and DOM when the browser
ran, on the raw response body when only the status check did. A `--no-ai` or
`--no-visual-check` run therefore still produces findings for a leaked key, a
served `.env` or a stack trace — deterministic ones, tagged
`"source": "content"`.

`--no-status-check` turns off the remaining probe; combining it with
`--no-visual-check` leaves nothing to do and is rejected with exit code `2`.

### `--no-ai` — screenshots without a verdict

Captures every page and writes the reports, but never calls the model. No API
key is needed, nothing leaves the machine, and the run costs nothing:

```bash
python -m secman_visual_check --no-ai -f examples/urls.txt -o ./evidence
```

```
Scanning 12 target(s) with 4 browser worker(s); analysis: capture only

[INFO] https://example.com/backup/
  status: 200 ok  (0.12s)
  HTTP 200  title='Index of /backup'
  screenshot: evidence/screenshots/0002-example.com-backup-3f9a2c1b04.png
```

Results carry `analysis: null` in `report.json`, and the HTML report is a
screenshot contact sheet. Use it to grab evidence for a human to review, to
sanity-check `--viewport`, `--max-height` or `--storage-state` before paying for
a real run, or in CI where an API key is not available.

Because there are no findings, `--fail-on` can never trip — pair it with
`--fail-on-status` if you still want the run to gate:

```bash
python -m secman_visual_check --no-ai --fail-on-status -f targets.txt --quiet
```

### `--no-visual-check` — no browser at all

Skips the Chromium *launch*, not just the screenshot, so this works on a host
where Playwright's browser was never installed — a small CI image, a container,
a jump host:

```bash
python -m secman_visual_check --no-visual-check -f examples/urls.txt
```

```
Scanning 12 target(s) with 8 status worker(s); analysis: no browser (status check only)

[INFO] https://example.com/admin
  status: 200 ok  (0.06s)
```

What remains is a fast uptime and redirect checker. It fans out over
`--status-concurrency` (8 by default, independent of `-c`) and finishes a
few hundred URLs in seconds. Typical uses:

```bash
# Uptime gate: fail the pipeline when anything stops answering as expected
python -m secman_visual_check --no-visual-check --fail-on-status -f targets.txt

# Change detection: mirror the body hashes into MariaDB
python -m secman_visual_check --no-visual-check --db-store -f targets.txt

# Redirect audit: record the first response verbatim and do not follow it
python -m secman_visual_check --no-visual-check --status-max-redirects 0 -f targets.txt
```

`capture` and `analysis` are both `null` in `report.json`; `status_check` is
fully populated. Screenshots are absent, so `--link-images` and `--include-raw`
have nothing to act on.

## Status and redirect checks

Every target gets an HTTP status check before the browser touches it. It runs on
by default and needs no configuration:

```
[2/4] http://old.example.com/ -> 301->200 redirect (1 hop) | info

[INFO] http://old.example.com/
  status: 301->200 redirect  (1 hop, 0.34s)
    301 http://old.example.com/ -> /new
    200 https://old.example.com/new
```

This is a **separate request**, not a reuse of the browser's navigation. The
browser follows redirects internally, answers from its cache, runs service
workers and honours storage state, so it can only ever tell you where a target
*ended up*. The check walks the chain by hand with redirects disabled, so the
first response — and every `Location` after it — is recorded verbatim. That is
what a non-browser client actually sees. Both statuses appear side by side in
the report; a divergence between them is itself worth looking at.

Each target ends in one state:

| state | meaning |
| --- | --- |
| `ok` | answered an expected status (200 by default), no redirects |
| `redirect` | redirected, and the end of the chain was expected |
| `redirect_broken` | redirect loop, hop cap reached, or a `Location` that cannot be followed |
| `unexpected_status` | a 1xx/2xx nobody asked for, e.g. 204 where 200 was expected |
| `client_error` | 4xx |
| `server_error` | 5xx |
| `unreachable` | DNS, TLS, connection or timeout failure |

```bash
# Treat 401 as healthy too — an authenticated endpoint should refuse anonymous callers
python -m secman_visual_check --status-expect 200,401 https://api.example.com/private

# Record the first response and do not follow it
python -m secman_visual_check --status-max-redirects 0 http://example.com

# Fail the build when anything is not answering as expected
python -m secman_visual_check --fail-on-status -f urls.txt

# Turn it off
python -m secman_visual_check --no-status-check https://example.com
```

### Content checksums

**On by default.** Every target that answers as expected has its body hashed
with sha256, so a later run can tell *still up* from *still up and unchanged*:

```
[INFO] https://example.com/admin
  status: 200 ok  (0.12s)
  content: sha256:1a2b3c4d5e6f  4.2 KB  text/html
```

Only healthy targets are hashed — a 404's error page changes for reasons nobody
wants to be alerted about. Bodies are streamed, never buffered whole, and capped
at `--status-checksum-max-bytes` (5 MiB).

The cost is one extra `GET` per healthy target, since the walk itself only needs
`HEAD`. That is real: a 900 KB homepage takes roughly 0.2s to hash where the
bare status check took 0.05s. Turn it off when you only care whether a target
answers:

```bash
python -m secman_visual_check --no-status-checksum -f urls.txt
```

`--no-status-checksum` cannot be combined with `--db-store` — the stored
checksum is what drives change detection and the `NEW`/`OK` flag lifecycle, so
the combination is rejected with exit code `2` rather than silently storing
nothing. `--status-checksum` still exists and is now a no-op, so existing
scripts and cron entries keep working.

### Skipping the browser

`--no-visual-check` reduces a run to exactly this check — no Chromium, no model
calls. See [Doing less](#doing-less---no-ai-and---no-visual-check).

```bash
python -m secman_visual_check --no-visual-check -f urls.txt
```

Full reference: [docs/STATUS_CHECK.md](docs/STATUS_CHECK.md).

## Tracking URLs over time

With `--db-store`, every URL carries a flag between runs:

| flag | meaning |
| --- | --- |
| `NEW` | never reviewed — or reviewed once and changed since |
| `OK` | reviewed and unchanged since. Only an operator sets this |
| `NOT_CHECKED` | known, but the last run reached no verdict |

The scanner never writes `OK`: it can tell you a URL answers and that its
content has not moved, not that somebody looked at it and was happy. You do
that:

```bash
python -m secman_visual_check --db-set-flag https://example.com/admin=OK
```

And the tool takes it back when the evidence expires — **when a URL's checksum
changes, its flag returns to `NEW`**, because an `OK` verdict describes the
content that was reviewed and cannot outlive it. Each URL also records when it
was first seen, when its content last changed, and when it was last checked.

A run that cannot reach a URL drops it from `OK` to `NOT_CHECKED`, but never
touches a `NEW` one — that still needs review — and never overrides a flag an
operator set, since one unreachable run is not evidence against a human
decision.

See [db/README.md](db/README.md) for the schema and the install script.

## Emailing the results

```bash
python -m secman_visual_check --mail \
  --mail-from scanner@example.com --mail-to ops@example.com \
  --mail-transport o365 --mail-tenant-id ... --mail-client-id ... --mail-client-secret ... \
  -f urls.txt
```

Three transports: `smtp` (default), `o365` (Microsoft Graph `sendMail`, client
credentials, needs the `Mail.Send` application permission) and `ses` (AWS SES
via boto3 — `pip install 'secman-visual-check[aws]'`, credentials resolved the
normal AWS way). The message is HTML with a plain-text alternative, styled to
match SecMan's own notification emails so both land in an inbox looking like
one system.

By default a clean run sends nothing — `--mail-always` overrides that, and
`--mail-dry-run` renders the message and prints the subject without delivering
it. When database mode is on, the email also reports which URLs are new and
which changed.

## What it looks at

The definition of "critical content" is data, not code. The built-in categories
live in `secman_visual_check/categories.py`:

| Category | Default severity |
| --- | --- |
| `exposed_credentials` — passwords, API keys, tokens, private keys | critical |
| `unauthenticated_admin` — admin panel reachable without login | critical |
| `database_or_ops_console` — phpMyAdmin, Kibana, Jenkins, Grafana… | critical |
| `malicious_or_defaced` — defacement, phishing, injected spam | critical |
| `personal_data` — PII, payment, health or HR data | high |
| `internal_documents` — confidential documents, contracts, runbooks | high |
| `directory_listing` — "Index of /" file listings | high |
| `backup_or_source_disclosure` — dumps, `.env`, raw source | high |
| `debug_output` — stack traces, `phpinfo()`, env dumps | high |
| `infrastructure_disclosure` — internal hostnames, versions, IPs | medium |
| `open_api_surface` — Swagger UI, GraphQL playground | medium |
| `default_or_placeholder_page` — untouched default/setup pages | low |
| `error_page` — plain 4xx/5xx pages | info |

Replace the whole set with your own definition:

```bash
python -m secman_visual_check --categories-file examples/categories.json https://example.com
```

Or keep the defaults and add site-specific guidance:

```bash
python -m secman_visual_check \
  --instructions "The cookie banner and the 'Employees only' footer link are expected. Ignore them." \
  https://example.com
```

### The content check — what the page *contains*

The model judges what a page shows. A second, deterministic check judges what
it contains: a fixed set of patterns is run over the rendered text, the DOM
after scripts ran, and the raw response body the status check already
downloaded, and every match becomes a finding tagged `"source": "content"`.
It needs no model and no API key, is on by default, and is what still finds a
private key in an HTML comment, a `DB_PASSWORD=` on line 900 of a page cut off
by `--max-height`, or an AWS key on a `--no-ai` run.

| Looks for | Category | Severity |
| --- | --- | --- |
| Private keys, AWS/GitHub/Slack/Stripe/Google keys, JWTs, connection strings and URLs with passwords | `exposed_credentials` | critical / high |
| `.env` secrets, a served `.git/config` | `backup_or_source_disclosure` | critical / high |
| `password = …` and `Bearer …` in visible text (guarded against labels and placeholders) | `exposed_credentials` | high |
| IBANs and payment card numbers with valid check digits; bulk email lists | `personal_data` | high / medium |
| Stack traces, Django debug pages, `phpinfo()`, Spring actuator dumps | `debug_output` | high |
| `Index of /` listings | `directory_listing` | high |
| Private IP addresses, server version banners | `infrastructure_disclosure` | medium / low |

One finding per pattern per page, secrets redacted to four characters in the
evidence, loose patterns restricted to visible text so minified scripts do not
flood the report. Extend or replace the set with `--content-patterns-file`
(see `examples/content-patterns.json`); turn it off with `--no-content-check`.
Full pattern list, sources and file format in
[docs/CONTENT_CHECK.md](docs/CONTENT_CHECK.md).

## Choosing a model

Any vision-capable model on an OpenAI-compatible endpoint works. The default is
OpenRouter:

```bash
python -m secman_visual_check --model anthropic/claude-sonnet-4.5 https://example.com
python -m secman_visual_check --model openai/gpt-4o             https://example.com
python -m secman_visual_check --model google/gemini-2.5-flash   https://example.com
```

Model slugs change; check <https://openrouter.ai/models?modality=text+image-%3Etext>
for the current list and pin one with `--model` or `SECMAN_MODEL`.

To use a different provider, point `--base-url` at any OpenAI-compatible
`/chat/completions` endpoint (vLLM, LiteLLM, Ollama, Azure OpenAI, …):

```bash
python -m secman_visual_check \
  --base-url http://localhost:11434/v1 --model qwen2.5vl --api-key ollama \
  https://example.com
```

The request uses `response_format: json_schema` to force a structured verdict.
Models that reject it are automatically retried with `json_object` and then with
no constraint at all — the reply is parsed leniently either way. Force a level
with `--structured-output {json_schema,json_object,none}`.

### Environment variables

| Variable | Purpose |
| --- | --- |
| `OPENROUTER_API_KEY` / `SECMAN_API_KEY` | API key (`--api-key` wins) |
| `SECMAN_MODEL` | Default model slug |
| `SECMAN_BASE_URL` | Default API base URL |
| `SECMAN_BROWSER_EXECUTABLE` | Path to an existing Chromium binary |
| `SECMAN_PASS_CLI` | Proton Pass CLI binary, if it is not on `PATH` (`--pass-cli-binary` wins) |

## Scanning pages behind a login

```bash
# Basic auth
python -m secman_visual_check --basic-auth alice:s3cret https://internal.example/

# A bearer token or any other header (repeatable)
python -m secman_visual_check -H "Authorization: Bearer $TOKEN" https://internal.example/

# A saved Playwright session (cookies + localStorage)
python -m secman_visual_check --storage-state ./auth.json https://internal.example/
```

To produce `auth.json`, log in once with Playwright and call
`context.storage_state(path="auth.json")`.

## CI use

`--fail-on` turns the scan into a gate. The process exits `1` when any finding
reaches the given severity, `0` when it does not, and `2` on a usage or
configuration error.

```bash
python -m secman_visual_check -f targets.txt --fail-on critical --quiet
```

Use `--fail-on none` to always exit `0`, and `--dry-run -q` to print the
resolved, de-duplicated target list without touching the network.

`--fail-on` answers "was anything found". `--fail-on-unevaluated` answers the
other question a gate needs: "was every target actually looked at". Every
result records an `evaluation` state — `analysed`, `captured`, `status_only`
for a target that got through every stage the run asked for; `analysis_failed`,
`capture_failed`, `skipped`, `error` for one that did not — and the flag exits
`1` when any target is in the second group. The console, JSON, CSV, HTML and
statistics reports all carry the state, and unevaluated targets are listed with
the reason. See [docs/COVERAGE.md](docs/COVERAGE.md).

```bash
python -m secman_visual_check -f targets.txt --fail-on high --fail-on-unevaluated --quiet
```

## Dry runs

`--dry-run` resolves exactly the configuration a real run would use — including
fetching every credential — and then prints the plan instead of executing it.

```bash
python -m secman_visual_check -f targets.txt --dry-run \
  --secman-upload --db-store --mail --mail-to ops@example.com
```

```
========================================================================
Dry run — nothing will be written, sent or uploaded
========================================================================

Targets (2):
  https://example.com/
  https://example.org/admin

Stages:
  status check   HEAD, falling back to GET, expect 200, 8 worker(s), checksums on, 10 redirect hop(s)
  browser        1440x900, full page (max 4000px), 4 worker(s), 30s timeout
  analysis       anthropic/claude-sonnet-4.5 via https://openrouter.ai/api/v1, 3 worker(s), API key set

Would write:
  screenshots    scan-output/screenshots
  json           scan-output/report.json
  html           scan-output/report.html
  csv            scan-output/report.csv
  statistics     scan-output/statistics.txt

Integrations:
  database       would write status rows to svc@db.internal:3306/secman_visual_check
  email          would send via smtp://smtp.example.com:587 to ops@example.com (only when something is wrong)
  secman         would upload findings at medium or above to https://secman.internal over http

Nothing was written. Re-run without --dry-run to execute this plan.
```

A dry run writes nothing — no report, no screenshot, no database row, no email,
no SecMan vulnerability — and never launches Chromium or calls the model. It
still *validates* everything a real run validates, and says in the plan where a
relaxed check would have stopped a real run (`NO API KEY`, `NO SMTP HOST`,
`NO CREDENTIALS`).

It applies to the standalone commands too:

```bash
# Exactly what would be filed in SecMan, from an earlier report
python -m secman_visual_check --dry-run --secman-upload-report scan-output/report.json

# What a flag change would do — offline, no database needed
python -m secman_visual_check --dry-run --db-set-flag 'https://example.com/=OK' --db-user svc

# Just the resolved target list, one per line
python -m secman_visual_check -f targets.txt --dry-run -q
```

`--dry-run` implies `--secman-dry-run` and `--mail-dry-run`; those two are
narrower and suppress one integration's writes while the scan itself runs for
real. Full reference: [docs/DRY_RUN.md](docs/DRY_RUN.md).

## Credentials from Proton Pass

Any credential — API keys, tokens, database and SMTP passwords — can be written
as a reference to an item in a Proton Pass vault instead of the secret itself.
The value is fetched through [`pass-cli`](https://protonpass.github.io/pass-cli/)
before the scan starts:

```
pass://<vault>/<item>/<field>       # field is optional and defaults to "password"
```

```bash
pass-cli login

python -m secman_visual_check -f targets.txt \
  --api-key 'pass://Infra/OpenRouter/api-key' \
  --secman-upload \
  --secman-token 'pass://Infra/SecMan automation/token'
```

Environment variables carry references too, so an exported default works the
same way:

```bash
export SECMAN_DB_URL='pass://Infra/Scanner DB/dsn'
python -m secman_visual_check --db-store -f targets.txt
```

This is entirely opt-in: a value that is not a reference is used verbatim, and
`pass-cli` is only ever invoked if you actually write one. It is not a
dependency of the package.

The secret never reaches a command line — only the reference is passed to
`pass-cli` — and never reaches a report: text coming back from a backend is
scrubbed of resolved values before it is printed. A reference that cannot be
resolved is a hard error *before* the scan, like every other credential check.

`--pass-cli-binary PATH` (or `$SECMAN_PASS_CLI`) points at a `pass-cli` that is
not on `PATH`; `--pass-cli-timeout` bounds one call; `--no-pass-cli` refuses
references outright for hosts where shelling out to a password manager is not
wanted.

The shell scripts do the same. `db/install.sh` resolves `DB_PASSWORD` and
`DB_ROOT_PASSWORD`, so the database can be created without the password ever
being typed:

```bash
DB_PASSWORD='pass://Infra/Scanner DB/password' db/install.sh
```

Full reference, including where references are accepted and what each error
means: [docs/PASS_CLI.md](docs/PASS_CLI.md).

## Uploading findings to SecMan

Findings can be pushed straight into a [SecMan](https://github.com/schmalle/secman)
instance, over its REST API or its MCP endpoint:

```bash
# Show what would be uploaded — no credentials, no network, no writes
python -m secman_visual_check --secman-upload --secman-dry-run https://example.com

# Scan and upload over the REST API
export SECMAN_URL=https://secman.internal
export SECMAN_USERNAME=scanner-bot SECMAN_PASSWORD=...
python -m secman_visual_check --secman-upload -f targets.txt

# Same, over MCP
export SECMAN_MCP_API_KEY=sk-... SECMAN_MCP_USER_EMAIL=you@company.com
python -m secman_visual_check --secman-upload --secman-transport mcp -f targets.txt

# Upload a report from an earlier run, without rescanning
python -m secman_visual_check --secman-upload-report scan-output/report.json
```

Each finding becomes a vulnerability on the asset named after the target's host,
under a synthetic ID derived from the page and the finding's category:

```
SECMAN-VISUAL-EXPOSED-CREDENTIALS-90eb9ade62
```

That ID is deliberately independent of the model's wording, which is rephrased on
every run. Scanning the same page twice therefore lands on the same ID, and
**duplicates are suppressed in three layers**: findings that collapse to one SecMan
row are merged before sending, findings SecMan already holds are skipped, and
anything that still arrives hits SecMan's own `(asset, cve)` upsert. A failure of
the middle layer is reported and non-fatal — the upsert still prevents duplication.

`--secman-dry-run` writes nothing. Without credentials it goes fully offline and
just prints the payloads; with credentials it still performs the read-only
existence check, so it can tell you which findings are already there. Credentials
are validated *before* the scan starts, so a typo fails immediately rather than
after a long crawl.

Severity maps onto SecMan's four levels (`info` folds into `LOW`), and
`--secman-min-severity` (default `medium`) decides what is worth uploading at all.

| Flag | Effect |
| --- | --- |
| `--secman-upload`, `--secman-upload-report PATH` | Upload this scan, or an earlier `report.json` |
| `--secman-dry-run` | Print the payloads, write nothing |
| `--secman-transport {http,mcp}` | REST API (default) or MCP endpoint |
| `--secman-url`, `--secman-timeout`, `--secman-insecure` | Where SecMan is and how to reach it |
| `--secman-token` / `--secman-username`+`--secman-password` | http auth: an existing JWT, or a login |
| `--secman-api-key`, `--secman-user-email` | mcp auth: `X-MCP-API-Key` and `X-MCP-User-Email` |
| `--secman-min-severity`, `--secman-owner`, `--secman-id-prefix`, `--secman-asset-name` | How findings are mapped |
| `--secman-allow-existing` | Re-send findings SecMan already holds |
| `--secman-fail-on-error` | Exit non-zero when an upload fails |
| `--secman-status-findings`, `--secman-status-severity` | Also upload targets whose status check failed |
| `--secman-register-assets`, `--secman-asset-type` | Put every scanned host in SecMan's asset inventory |

Environment defaults: `SECMAN_URL`, `SECMAN_TOKEN`, `SECMAN_USERNAME`,
`SECMAN_PASSWORD`, `SECMAN_MCP_API_KEY`, `SECMAN_MCP_USER_EMAIL`. Note that
`SECMAN_API_KEY` is the *vision model's* key and is not used for uploads.

Full reference, including the ID scheme, the permissions each transport needs and
troubleshooting: [docs/SECMAN_UPLOAD.md](docs/SECMAN_UPLOAD.md).

## Options worth knowing

| Flag | Effect |
| --- | --- |
| `-c/--concurrency`, `--ai-concurrency` | Parallel page loads (4) and model calls (3). Capture and analysis are pipelined, so a slow model call does not stall the browser. The screenshot step itself is serialised — Chromium splices content between tabs when several capture at once. |
| `--viewport 1440x900`, `--viewport-only` | Window size; capture just the fold instead of the full page. |
| `--max-height 4000` | Clamp full-page screenshots. Infinite-scroll pages otherwise produce enormous images that waste vision tokens. `0` disables the clamp. |
| `--timeout`, `--wait-until`, `--settle` | Navigation budget, completion signal, and extra settle time for lazy content. |
| `--insecure` | Ignore TLS certificate errors (common on internal hosts). |
| `--allow-private-redirects` | Off by default: a target's redirect (status check, or its `robots.txt` fetch under `--respect-robots`) or navigation/iframe (browser capture) to a private/loopback/link-local address on a *different* host than the target is blocked, and `--basic-auth`/`-H` headers are only ever sent to the target's own host — a compromised or malicious target should not be able to redirect the scanner at internal infrastructure or cloud metadata endpoints (e.g. `169.254.169.254`), or collect credentials meant for a different site. Pass this flag only when you deliberately scan through a redirector that lands on your own internal infrastructure. |
| `--respect-robots` | Skip URLs the origin's `robots.txt` disallows. Off by default: you are scanning your own assets. |
| `--no-json`, `--no-html`, `--no-csv`, `--no-stats` | Drop one of the four default reports. `--json/--html/--csv/--stats PATH` relocate them. |
| `--link-images` | Link screenshots from the HTML report instead of embedding them, for large scans. |
| `--include-raw` | Keep the raw model replies in the JSON report, for debugging prompts. |
| `--no-content-check`, `--content-patterns-file PATH`, `--content-max-chars N` | The deterministic pattern check of page text, DOM and raw body for credentials, personal data and debug output: turn it off, extend or replace its patterns, cap how much content it reads. See [docs/CONTENT_CHECK.md](docs/CONTENT_CHECK.md). |
| `--fail-on-unevaluated` | Exit 1 when any target did not get through every stage the run asked for. See [docs/COVERAGE.md](docs/COVERAGE.md). |
| `--no-visual-check` | Skip the browser entirely: no screenshots, no model calls, no Chromium needed. |
| `--no-status-check` | Skip the HTTP status/redirect pre-check. |
| `--no-status-checksum`, `--status-checksum-max-bytes` | Body hashing of healthy targets is on by default; turn it off, or cap how much of a body is read. |
| `--status-expect 200,401`, `--status-max-redirects`, `--status-method`, `--status-timeout`, `--status-concurrency` | Tune the status check. See [docs/STATUS_CHECK.md](docs/STATUS_CHECK.md). |
| `--fail-on-status` | Exit 1 when any target's status check is not OK. |
| `--db-store`, `--db-url`, `--db-*` | Mirror the status results into MariaDB. See [db/README.md](db/README.md). |
| `--db-set-flag URL=FLAG` | Flag a URL as `OK`, `NEW` or `NOT_CHECKED` and exit. |
| `--mail`, `--mail-transport`, `--mail-to`, `--mail-*` | Email the results over SMTP, Microsoft 365 or AWS SES. |
| `--dry-run` | Resolve everything, print the plan, execute nothing. `-q` narrows it to the target list. See [docs/DRY_RUN.md](docs/DRY_RUN.md). |
| `--pass-cli-binary`, `--pass-cli-timeout`, `--no-pass-cli` | Where to find the Proton Pass CLI that resolves `pass://` credentials, how long to wait for it, or refuse references outright. See [docs/PASS_CLI.md](docs/PASS_CLI.md). |
| `-v/--verbose` | Print evidence and remediation for every finding. |

Full list: `python -m secman_visual_check --help`.

## JSON report shape

```json
{
  "tool": "secman_visual_check",
  "model": "anthropic/claude-sonnet-4.5",
  "target_count": 2,
  "severity_counts": {"critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0},
  "status_counts": {"ok": 1, "redirect": 1, "redirect_broken": 0,
                    "unexpected_status": 0, "client_error": 0, "server_error": 0,
                    "unreachable": 0, "unknown": 0},
  "evaluation_counts": {"analysed": 2, "analysis_failed": 0, "captured": 0, "capture_failed": 0,
                        "status_only": 0, "skipped": 0, "error": 0},
  "unevaluated_count": 0,
  "max_severity": "critical",
  "results": [
    {
      "url": "https://example.com/backup/",
      "evaluation": "analysed",
      "evaluated": true,
      "max_severity": "critical",
      "status_check": {
        "state": "ok",
        "ok": true,
        "method": "HEAD",
        "first_status": 200,
        "final_status": 200,
        "final_url": "https://example.com/backup/",
        "redirect_count": 0,
        "expected_statuses": [200],
        "chain": [{"url": "https://example.com/backup/", "status": 200, "location": null,
                   "elapsed_s": 0.021}],
        "content_checksum": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "content_length": 4321,
        "content_type": "text/html",
        "content_truncated": false,
        "error": null,
        "elapsed_s": 0.021,
        "checked_at": "2026-07-29T09:14:02.113000+00:00"
      },
      "capture": {"status": 200, "title": "Index of /backup", "screenshot_path": "..."},
      "content_check": {"sources": ["text", "html", "body"], "chars_scanned": 3812,
                        "matches": 1, "findings": 1},
      "analysis": {
        "risk_level": "critical",
        "page_type": "directory listing",
        "summary": "Directory index exposing a database dump and a .env file.",
        "findings": [
          {
            "category": "exposed_credentials",
            "severity": "critical",
            "title": "Database password rendered in page",
            "evidence": "DB_PASSWORD=hunt...",
            "recommendation": "Rotate the credential and remove the file.",
            "confidence": 0.9,
            "source": "model"
          },
          {
            "category": "backup_or_source_disclosure",
            "severity": "critical",
            "title": "Environment file secret rendered in page",
            "evidence": "DB_PASSWORD=hunt… — in page text",
            "recommendation": "Block access to .env and similar files at the web server, then rotate every value in it.",
            "confidence": 0.9,
            "source": "content"
          }
        ]
      }
    }
  ]
}
```

Pages that fail to load still appear, with `capture.load_error` set — and with
their `status_check` intact, since it runs before the browser and does not
depend on it. A page that only rendered the browser's own error screen is never
sent to the model. `status_check` is `null` when the check is disabled or the
target was skipped by `robots.txt`.

`evaluation` says how far each target got through the stages the run asked for
and `evaluated` whether it got through all of them ([docs/COVERAGE.md](docs/COVERAGE.md)).
`content_check` records what the pattern check searched, even when nothing
matched; its findings sit beside the model's with `"source": "content"`
([docs/CONTENT_CHECK.md](docs/CONTENT_CHECK.md)). `content_check` is `null`
when the check is off or no stage produced content for the target.

## How it fits together

| Module | Responsibility |
| --- | --- |
| `targets.py` | Parse, normalise and de-duplicate URLs |
| `capture.py` | Playwright: navigate, screenshot, extract title/text/status |
| `status.py` | HTTP status/redirect pre-check and body checksum |
| `categories.py` | The policy — what counts as critical content |
| `prompts.py` | System prompt, user prompt, and the response JSON schema |
| `analyzer.py` | OpenAI-compatible vision call, retries, lenient JSON parsing |
| `content.py` | Deterministic pattern check of page text, DOM and raw body for confidential data |
| `scanner.py` | Pipelines capture → analysis → content check with independent concurrency limits; records each target's evaluation state |
| `reporting.py` | Console, JSON, HTML, CSV and statistics output |
| `secman.py` | Maps findings onto SecMan vulnerabilities; HTTP and MCP upload |
| `db.py` | Optional MariaDB mirror: status history, URL flags, change tracking |
| `mailer.py` | Result email over SMTP, Microsoft 365 or AWS SES |
| `secrets.py` | Resolves `pass://` credentials through the Proton Pass CLI |
| `plan.py` | `--dry-run`: what a run would do, rendered from the same options |
| `cli.py` | Argument parsing and exit codes |

## Caveats

- The model reads a screenshot. It can miss content behind a click or rendered
  after `--settle` elapses. Content below the `--max-height` clamp and text the
  browser never paints — comments, scripts — are covered by the content check,
  which is pattern matching and carries its own confidence values.
- A target the run could not evaluate is reported as such, not as clean. Gate on
  `--fail-on-unevaluated` when the list is the promise.
- Verdicts are probabilistic. Treat findings as a triage queue, not a control.
  Every finding carries a `confidence`; the evidence string tells you what the
  model actually saw.
- Screenshots of exposed pages contain the exposed data. Treat the output
  directory as sensitive.

## Tests

```bash
pip install pytest
python -m pytest
```

The suite covers URL handling, prompt construction, the model-response parser,
the analyzer's HTTP behaviour (retries, schema downgrade, auth failures) against
a mocked transport, scanner orchestration and per-target coverage accounting,
the content check's patterns and their false-positive guards, report rendering,
and the SecMan upload — ID stability, the three de-duplication layers, dry-run behaviour, and
both transports against a mocked backend. `pass://` resolution is covered on
both sides — the Python resolver against a fake `pass-cli`, and
`scripts/passcli.sh` through bash against a stub binary — and `--dry-run` is
checked to validate everything while writing nothing. It does not require a
browser, an API key, a Proton Pass account or a SecMan instance.
