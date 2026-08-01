# Dry runs

A scan is slow, spends money on model calls, writes four report files and a
directory of screenshots, mirrors rows into MariaDB, sends email, and files
vulnerabilities in SecMan. All of that is configured from about ninety flags and
two dozen environment variables, and the usual way to find out whether you got
it right is to run it and see.

`--dry-run` is the other way. It resolves exactly the configuration a real run
would use — including fetching every credential — and then prints the plan
instead of executing it.

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

Secrets:
  resolved       pass://Infra/SecMan automation/token

Nothing was written. Re-run without --dry-run to execute this plan.
```

## What it guarantees

**A dry run writes nothing.** No report file, no screenshot, no output
directory, no database row, no email, no SecMan vulnerability. It also never
launches Chromium and never calls the model, so it costs nothing and needs no
browser installed.

**It is not an offline mode.** Two things still reach the network, and both are
reads:

- Resolving a `pass://` reference talks to Proton Pass through `pass-cli`. That
  is the point — a reference that names nothing should fail here rather than at
  three in the morning. See [PASS_CLI.md](PASS_CLI.md).
- `--dry-run --secman-upload-report` asks SecMan which findings it already
  holds, so the plan can tell `planned` from `skipped`. Drop the credentials, or
  pass `--secman-allow-existing`, to keep it fully offline.

## What it validates

Everything a real run validates, in the same order and before anything happens:

- every URL parses and normalises, and the de-duplicated list is what you meant;
- the viewport, status list, headers, category file and instructions file are
  usable;
- every credential resolves, including `pass://` references;
- the combinations that cannot work are refused (`--no-visual-check` with
  `--no-status-check`, `--no-status-checksum` with `--db-store`);
- the transports have what they need — and where a dry run relaxes a check so
  the plan can be seen without credentials, it says so in the plan itself
  (`NO SMTP HOST`, `NO CREDENTIALS`, `NO API KEY`).

Exit codes are the usual ones: `0` when the plan is printed, `2` when the
configuration is unusable.

## Just the target list

`--dry-run -q` prints the resolved, de-duplicated URLs and nothing else, one per
line — the original behaviour of the flag, kept for scripts that pipe it
somewhere:

```bash
python -m secman_visual_check -f targets.txt --stdin --dry-run -q | wc -l
```

## The other modes

`--dry-run` applies to the standalone commands too.

**Uploading a stored report** runs SecMan's own dry run, which prints the exact
payload for every finding:

```bash
python -m secman_visual_check --dry-run --secman-upload-report scan-output/report.json
```

Each finding comes back as `planned` (would be written), `skipped` (SecMan
already holds it) or `failed`. See
[SECMAN_UPLOAD.md](SECMAN_UPLOAD.md) for what the synthetic IDs mean.

**Setting URL flags** prints what would change and exits:

```bash
python -m secman_visual_check --dry-run --db-set-flag 'https://example.com/=OK' --db-user svc
```

This one is deliberately offline. Reading the current flags first would make a
nicer preview, but it would also mean a dry run of a two-line command needs a
reachable database and an installed driver.

## Related flags

`--secman-dry-run` and `--mail-dry-run` are narrower: they suppress *one*
integration's writes while the scan itself runs for real. They are still there
and still useful — `--mail-dry-run` renders the message and prints the subject
so you can see what a real alert would look like against real findings.
`--dry-run` implies both.

| Flag | Scan runs? | Writes reports? | Writes to the integration? |
| --- | --- | --- | --- |
| `--dry-run` | no | no | no |
| `--secman-dry-run` | yes | yes | no |
| `--mail-dry-run` | yes | yes | no (renders and prints the subject) |
