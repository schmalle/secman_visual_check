# Uploading findings to SecMan

`secman_visual_check` can push its findings into a [SecMan](https://github.com/schmalle/secman)
instance, either through SecMan's REST API or through its MCP endpoint. Re-running
a scan updates the rows it already created instead of piling up duplicates.

- [Quick start](#quick-start)
- [How a finding becomes a SecMan vulnerability](#how-a-finding-becomes-a-secman-vulnerability)
- [Duplicate suppression](#duplicate-suppression)
- [Dry-run mode](#dry-run-mode)
- [Transports](#transports)
- [Status findings and asset registration](#status-findings-and-asset-registration)
- [All options](#all-options)
- [Exit codes](#exit-codes)
- [Troubleshooting](#troubleshooting)

## Quick start

```bash
# See what would be uploaded — no credentials, no network, no writes
python -m secman_visual_check --secman-upload --secman-dry-run https://example.com

# Scan and upload over the REST API
export SECMAN_URL=https://secman.internal
export SECMAN_USERNAME=scanner-bot SECMAN_PASSWORD=...
python -m secman_visual_check --secman-upload -f targets.txt

# Same, over MCP
export SECMAN_MCP_API_KEY=sk-... SECMAN_MCP_USER_EMAIL=you@company.com
python -m secman_visual_check --secman-upload --secman-transport mcp -f targets.txt

# Upload the findings of a scan you already ran
python -m secman_visual_check --secman-upload-report scan-output/report.json
```

`--secman-upload-report` is a standalone mode: it reads a `report.json` written by
an earlier run, uploads its findings and exits. No targets, no browser, no model
calls — useful for re-sending after a SecMan outage, or for uploading a report
produced on a machine that has no route to SecMan.

## How a finding becomes a SecMan vulnerability

SecMan tracks vulnerabilities as `(asset, vulnerabilityId, criticality)`. A visual
exposure finding is not a CVE, so it is mapped like this:

| SecMan field | Value |
| --- | --- |
| `hostname` | the target URL's host, lowercased, without port (override with `--secman-asset-name`) |
| `cve` | a stable synthetic ID — see below |
| `criticality` | the finding's severity, mapped onto SecMan's four levels |
| `daysOpen` | `0` |
| `owner` | `--secman-owner` (default `secman-visual-check`), used when SecMan auto-creates the asset |

Severity maps as `critical → CRITICAL`, `high → HIGH`, `medium → MEDIUM`,
`low → LOW`, `info → LOW`. SecMan has no informational level, so `info` lands on
`LOW`; by default `--secman-min-severity medium` means neither is uploaded at all.

### The synthetic vulnerability ID

```
SECMAN-VISUAL-EXPOSED-CREDENTIALS-90eb9ade62
└── prefix ──┘└──── category ────┘└─ digest ─┘
```

The digest is the first 10 hex characters of
`sha256(host + port + path + query + "|" + category)`.

What goes into it matters:

- **Host, port, path and query are included**, so the same class of exposure on
  two different pages produces two rows — which is what you want, since they are
  fixed separately.
- **The model's wording is deliberately excluded.** Titles, evidence and summaries
  are regenerated on every scan and drift between runs. Hashing them would mint a
  new ID each time and turn every re-scan into a fresh set of duplicates.

The consequence is that the ID is *stable*: scan the same page twice and the
second run resolves to the same `(asset, cve)` pair, which SecMan upserts.

Change the prefix with `--secman-id-prefix` if you want to distinguish scanners,
environments or teams. Note that the prefix is also what the MCP transport filters
on when checking for existing findings, so keep it consistent across runs.

## Duplicate suppression

Duplicates are prevented in three independent layers, so no single failure
reintroduces them:

1. **Within one upload.** Findings that collapse to the same
   `(hostname, vulnerability ID)` are merged before anything is sent, keeping the
   highest severity of the group. The model regularly emits two findings in the
   same category for one page, and those are a single SecMan row.
2. **Against the backend.** Before writing, SecMan is asked which IDs the target
   assets already hold; anything already present is reported as `skipped` and
   never sent. Pass `--secman-allow-existing` to re-send anyway (this refreshes
   the row rather than adding one).
3. **Inside SecMan.** Whatever does get sent goes through SecMan's own
   `(asset, cve)` upsert, which updates the matching row instead of inserting.

Layer 3 is the reason a failure in layer 2 is not fatal. If the pre-check query
fails — permissions, a timeout, an unexpected response — the upload continues and
the run says so:

```
  could not pre-check for existing findings (...); relied on SecMan's own
  (asset, cve) upsert instead
```

Nothing duplicates in that case; you just lose the `skipped` accounting and pay
for the writes.

The existing-ID lookup asks for excepted findings too. SecMan's default view hides
vulnerabilities covered by an active exception — if the lookup used that default,
a finding somebody had explicitly excepted would look absent and be re-uploaded on
every single run.

## Dry-run mode

`--secman-dry-run` performs **no writes**. Reads are still allowed, which makes the
dry run more informative when credentials are available:

| | with credentials | without credentials |
| --- | --- | --- |
| Connects to SecMan | yes (read-only) | no |
| Checks what already exists | yes | no |
| Item status | `planned` or `skipped` | `planned` |

Both forms print the full payload for every finding — asset, vulnerability ID,
criticality, source URL, category and title — so you can confirm the mapping before
writing anything into your inventory.

Credentials are optional for a dry run and required otherwise. Validation happens
**before the scan starts**, so a credential typo fails in a second rather than
after a ten-minute crawl. Any of them may be a `pass://vault/item/field`
reference resolved through the Proton Pass CLI — see
[PASS_CLI.md](PASS_CLI.md).

Note that `--dry-run` is the wider flag: it plans the *whole* run — targets,
stages, report files, database, email and this upload — and executes none of it.
`--secman-dry-run` scans normally and only suppresses the upload. `--dry-run`
implies `--secman-dry-run`, so `--dry-run --secman-upload-report report.json`
prints exactly this payload list without writing. See
[DRY_RUN.md](DRY_RUN.md).

## Transports

### `--secman-transport http` (default)

Talks to `POST /api/vulnerabilities/cli-add`, and reads
`GET /api/vulnerabilities/current` for the duplicate pre-check. The account needs
the `ADMIN` or `VULN` role.

Two ways to authenticate:

```bash
# Log in; SecMan returns the JWT in the secman_auth cookie, which is replayed
python -m secman_visual_check --secman-upload \
  --secman-username scanner-bot --secman-password ... https://example.com

# Or present a JWT you already hold
python -m secman_visual_check --secman-upload --secman-token "$JWT" https://example.com
```

An MFA-enabled account cannot complete the login flow non-interactively — the run
stops with a message saying so. Use an automation account without MFA, or obtain a
JWT out of band and pass `--secman-token`.

### `--secman-transport mcp`

Talks to SecMan's MCP endpoint (`POST /mcp`, JSON-RPC 2.0): `initialize`, then
`tools/call` for `add_vulnerability`, and `get_vulnerabilities` for the duplicate
pre-check.

```bash
python -m secman_visual_check --secman-upload --secman-transport mcp \
  --secman-url https://secman.internal \
  --secman-api-key sk-... --secman-user-email you@company.com \
  https://example.com
```

Both headers are mandatory on SecMan's side: `X-MCP-API-Key` authenticates the key
and `X-MCP-User-Email` names the delegated user. Effective permissions are the
intersection of the API key's permissions and the delegated user's role, so the key
needs write permission *and* the user needs `ADMIN` or `VULN`. Delegation must also
be enabled on the key itself.

`--secman-url` takes the backend root for both transports; `/mcp` is appended
automatically, and a URL that already ends in `/mcp` is left alone.

## Status findings and asset registration

Two opt-in extras, both driven by the
[status check](STATUS_CHECK.md) rather than by the model.

### `--secman-status-findings`

A target that does not answer as expected becomes an ordinary vulnerability, so
it rides the same de-duplication, existing-ID pre-check and dry-run paths as
everything else. Healthy targets — `ok` and `redirect` — produce nothing.

| status state | category | severity |
| --- | --- | --- |
| `unreachable` | `unreachable` | high |
| `server_error` (5xx) | `unexpected_status` | high |
| `client_error` (4xx) | `unexpected_status` | medium |
| `unexpected_status` (unasked-for 1xx/2xx) | `unexpected_status` | medium |
| `redirect_broken` | `broken_redirect` | medium |

IDs come from the same `vulnerability_id()` as every other finding, so they are
stable across runs by construction:
`SECMAN-VISUAL-UNREACHABLE-<hash>`, `SECMAN-VISUAL-UNEXPECTED-STATUS-<hash>`.
`--secman-min-severity` still applies; `--secman-status-severity` overrides the
whole table with one value.

```bash
python -m secman_visual_check --secman-upload --secman-status-findings \
  --secman-min-severity medium -f urls.txt
```

### `--secman-register-assets`

Puts every scanned host in SecMan's asset inventory, whether or not it has
findings — useful when the scan *is* the discovery step.

- **http transport** uses `PUT /api/assets/import`, SecMan's idempotent upsert
  for external scanners: it matches on name, merges, and preserves
  operator-set fields, so re-scanning never mints a second asset. It requires
  the **ADMIN** role; without it each registration is reported as `failed` and
  the findings upload continues regardless.
- **mcp transport** uses the `create_asset` tool, which is not an upsert, so a
  rejection naming an existing asset is reported as `skipped`.

One row per distinct host, not per page. The asset is named after the host
(or `--secman-asset-name`), owned by `--secman-owner`, typed by
`--secman-asset-type`, with the first URL seen on that host recorded as its URI.

Output looks like:

```
  [created] asset example.com  https://example.com/admin
      asset id 41

SecMan: 2 created, 0 updated, 0 planned, 0 skipped, 0 failed
  assets: 1 created
```

Note that findings alone already cause SecMan to auto-create assets from the
`owner` field on `cli-add`. `--secman-register-assets` is for the hosts that
have *no* findings and would otherwise never appear.

## All options

| Flag | Environment | Default | Effect |
| --- | --- | --- | --- |
| `--secman-upload` | | off | Upload this scan's findings when it finishes |
| `--secman-upload-report PATH` | | | Upload an existing `report.json` and exit |
| `--secman-dry-run` | | off | Print what would be sent; write nothing |
| `--secman-transport {http,mcp}` | | `http` | Which endpoint to use |
| `--secman-url URL` | `SECMAN_URL` | `http://localhost:8080` | SecMan base URL |
| `--secman-token JWT` | `SECMAN_TOKEN` | | Existing JWT (http) |
| `--secman-username` | `SECMAN_USERNAME` | | Login (http) |
| `--secman-password` | `SECMAN_PASSWORD` | | Password (http) |
| `--secman-api-key KEY` | `SECMAN_MCP_API_KEY` | | `X-MCP-API-Key` (mcp) |
| `--secman-user-email EMAIL` | `SECMAN_MCP_USER_EMAIL` | | `X-MCP-User-Email` (mcp) |
| `--secman-min-severity` | | `medium` | Lowest severity worth uploading |
| `--secman-owner NAME` | | `secman-visual-check` | Owner for assets SecMan auto-creates |
| `--secman-id-prefix PREFIX` | | `SECMAN-VISUAL` | Prefix of the synthetic IDs |
| `--secman-asset-name NAME` | | | File everything under one asset |
| `--secman-allow-existing` | | off | Re-send findings SecMan already holds |
| `--secman-timeout SECONDS` | | `30` | Per-request timeout |
| `--secman-insecure` | | off | Ignore TLS errors (internal CAs) |
| `--secman-fail-on-error` | | off | Exit non-zero if any upload or asset registration failed |
| `--secman-status-findings` | | off | Also upload targets whose status check is not OK |
| `--secman-status-severity` | | `auto` | Severity for status findings; `auto` uses the mapping below |
| `--secman-register-assets` | | off | Register every scanned host as an asset (http needs ADMIN) |
| `--secman-asset-type TYPE` | | `Web Service` | Asset type recorded on registered assets |

`SECMAN_API_KEY` is **not** used here — that variable is the vision model's API
key. The MCP key has its own variable, `SECMAN_MCP_API_KEY`.

## Exit codes

Upload results fold into the tool's existing exit codes:

- `0` — scan clean and upload fine.
- `1` — `--fail-on` matched a finding. This takes precedence: a scan that found
  something critical exits `1` whether or not the upload succeeded.
- `2` — a usage or configuration error, an upload that could not start at all
  (bad credentials, unreachable backend), or — with `--secman-fail-on-error` —
  a run in which at least one individual finding failed to upload.

Without `--secman-fail-on-error`, individual failures are reported in the summary
and counted, but do not change the exit code. Individual failures never abort the
run: each remaining finding is still attempted.

## Troubleshooting

**`SecMan requires MFA for this account`** — the login endpoint answered
`mfaRequired`. Use an automation account without MFA, or pass `--secman-token`.

**`HTTP 401` / `403` on upload** — the account is missing `ADMIN` or `VULN`. On
MCP, check the API key's permissions, that delegation is enabled on the key, and
that the delegated user carries the role: effective permission is the intersection
of the two.

**`MCP tools/call error: DELEGATION_HEADER_REQUIRED`** — `--secman-user-email` was
not set. SecMan requires it on every `tools/call`.

**Findings keep reappearing as new rows** — something in the ID inputs is moving
between runs. The usual causes are a changing `--secman-id-prefix`, or targets
whose URLs carry a per-run value in the query string (a session token, a cache
buster). The path and query are part of the ID by design.

**Everything comes back `updated` and nothing is `skipped`** — the pre-check
lookup is failing; look for the `could not pre-check` line in the summary. Nothing
is being duplicated, but the account may lack read access to
`/api/vulnerabilities/current` or to the `get_vulnerabilities` tool.

**Nothing is uploaded at all** — the default `--secman-min-severity medium` drops
`low` and `info` findings. The summary line reports how many were held back.
