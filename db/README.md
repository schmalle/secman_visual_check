# MariaDB storage for status checks

Optional. Reports are files; this is what you query when you want to ask
"which hosts started answering 500 this week" without grepping a pile of JSON.

Nothing here is needed to run a scan. If the database is unreachable or the
driver is missing, the scan still succeeds and prints one line saying the write
was skipped.

## Install

```bash
pip install 'secman-visual-check[db]'          # pulls in PyMySQL
DB_PASSWORD='choose-one' db/install.sh          # creates db, user and schema
```

`install.sh` connects as an administrative user (`DB_ROOT_USER`, default `root`)
to create the database and apply the schema, then creates an application user
holding **`SELECT, INSERT, UPDATE, DELETE` only** — no DDL, so the scanner
cannot alter or drop the tables it writes to.

Environment it reads: `DB_ROOT_USER`, `DB_ROOT_PASSWORD`, `DB_HOST`, `DB_PORT`,
`DB_NAME`, `DB_USER`, `DB_PASSWORD` (required), `DB_USER_HOST`, `TABLE_PREFIX`.

To apply the schema by hand instead:

```bash
mysql -u root -p secman_visual_check < db/schema.sql
```

## Connecting

Either a URL or the individual flags; each has an environment fallback.

| flag | environment | default |
| --- | --- | --- |
| `--db-store` | `SECMAN_DB_STORE` | off |
| `--db-url` | `SECMAN_DB_URL` | |
| `--db-host` | `SECMAN_DB_HOST` | `127.0.0.1` |
| `--db-port` | `SECMAN_DB_PORT` | `3306` |
| `--db-user` | `SECMAN_DB_USER` | |
| `--db-password` | `SECMAN_DB_PASSWORD` | |
| `--db-name` | `SECMAN_DB_NAME` | `secman_visual_check` |
| `--db-table-prefix` | | `svc_` |
| `--db-fail-on-error` | | off |

```bash
export SECMAN_DB_URL='mysql://secman_visual:pw@127.0.0.1:3306/secman_visual_check'
secman-visual-check --db-store https://example.com
```

Credentials are resolved and validated *before* the scan starts, so a typo costs
a second rather than a ten-minute crawl. By default a failed write is reported
and the exit code is unaffected; `--db-fail-on-error` makes it exit non-zero.

`--db-password` and `--db-url` accept a `pass://vault/item/field` reference
instead of the secret, resolved through the Proton Pass CLI — the DSN in
particular is worth keeping off a command line, since it carries the password
inside it. `db/install.sh` resolves `DB_PASSWORD` and `DB_ROOT_PASSWORD` the
same way. See [../docs/PASS_CLI.md](../docs/PASS_CLI.md).

```bash
export SECMAN_DB_URL='pass://Infra/Scanner DB/dsn'
DB_PASSWORD='pass://Infra/Scanner DB/password' db/install.sh
```

## URL flags and change tracking

Beyond the per-run log, the database carries a **current state** for every URL:
a review flag, the last content checksum, and three dates.

| flag | meaning |
| --- | --- |
| `NEW` | never reviewed — or reviewed once and changed since |
| `OK` | reviewed and unchanged since. Only an operator sets this |
| `NOT_CHECKED` | known, but the last run reached no verdict |

The scanner never writes `OK`. It can tell you a URL answers and that its
content has not moved; it cannot tell you somebody looked at the page and was
happy. That is an operator's call:

```bash
secman-visual-check --db-set-flag https://example.com/admin=OK
secman-visual-check --db-set-flag https://a.example/=OK --db-set-flag https://b.example/=NEW
```

The flag spelling is forgiving — `ok`, `NOT CHECKED` and `not-checked` all
work. This is a standalone command: no scan runs, and it uses the same `--db-*`
credentials as a storing run.

**A changed checksum clears the flag.** When a URL's body hash differs from the
stored one, the flag goes back to `NEW` and `last_changed_at` moves. An `OK`
verdict describes the content that was reviewed, so it cannot outlive that
content — this is the whole point of storing the checksum.

The other transitions are deliberately conservative:

- A run that reaches no verdict (unreachable, robots-skipped, status check off)
  drops a URL from `OK` to `NOT_CHECKED` — but **never** touches a `NEW` one.
  `NEW` already means "needs review", and one unreachable run is no reason to
  drop it off the queue.
- A flag an operator set is **not** downgraded by an unreachable run either.
  A human decision outlives a transient outage. Only a real content change
  overrides it.
- An unreachable run never erases the last known checksum, so the next
  successful run compares against the last content actually seen.

Dates, all on `svc_url_state`:

| column | meaning |
| --- | --- |
| `first_seen_at` | initial addition. Never moves |
| `last_changed_at` | when the content checksum last differed |
| `last_checked_at` | when the URL was last looked at |
| `change_count` | how many times the content has changed |

Checksums are computed by default, so `--db-store` needs no extra flag. Only
targets that answered as expected are hashed — see
[../docs/STATUS_CHECK.md](../docs/STATUS_CHECK.md). `--no-status-checksum` is
rejected in database mode: without a checksum the flag lifecycle above could
never notice a change.

## Schema

Four tables, all `InnoDB` / `utf8mb4`, related by `ON DELETE CASCADE`:

- **`svc_scan_run`** — one row per invocation. `run_uuid` is derived from the
  run's own contents, so storing the same report twice is a duplicate-key error
  rather than a silent second copy.
- **`svc_url_status`** — one row per checked target: `state`, `is_ok`,
  `first_status` (the raw, un-followed response), `final_status`, `final_url`,
  `redirect_count`, `error`, plus `browser_status` — what Chromium saw — so a
  divergence between the two clients is visible in SQL.
- **`svc_redirect_hop`** — one row per hop, with the raw `Location` header.
- **`svc_url_state`** — one row per URL, carried across runs: the flag, who set
  it, the content checksum, and the dates above. `svc_url_status` is the log;
  this is the current state.

`url_hash` (sha256 of the URL) exists because a 2048-character URL cannot be
indexed; join or filter on it rather than on `url`.

## Queries

Everything that is not currently OK, most recent first:

```sql
SELECT url, state, first_status, final_status, error, checked_at
FROM svc_url_status
WHERE is_ok = 0
ORDER BY checked_at DESC;
```

Targets whose status changed between the last two runs:

```sql
SELECT s.url, s.final_status, p.final_status AS previous
FROM svc_url_status s
JOIN svc_url_status p ON p.url_hash = s.url_hash AND p.run_id = s.run_id - 1
WHERE s.final_status <> p.final_status;
```

Everything that needs review — newly discovered or changed since it was
approved:

```sql
SELECT url, flag, first_seen_at, last_changed_at, change_count
FROM svc_url_state
WHERE flag = 'NEW'
ORDER BY last_changed_at DESC;
```

URLs that changed in the last week:

```sql
SELECT url, change_count, last_changed_at
FROM svc_url_state
WHERE last_changed_at > NOW() - INTERVAL 7 DAY
ORDER BY last_changed_at DESC;
```

Where a host redirects to:

```sql
SELECT s.url, h.hop_index, h.status_code, h.location
FROM svc_url_status s
JOIN svc_redirect_hop h ON h.status_id = s.id
WHERE s.hostname = 'example.com'
ORDER BY s.checked_at DESC, h.hop_index;
```

## Retention

Deleting a run cascades to its status rows and hops:

```sql
DELETE FROM svc_scan_run WHERE started_at < NOW() - INTERVAL 90 DAY;
```

`svc_url_state` is deliberately **not** cascaded from a run: it is the inventory,
not the log, and pruning history should not lose which URLs were approved. Drop
URLs you no longer track explicitly:

```sql
DELETE FROM svc_url_state WHERE last_checked_at < NOW() - INTERVAL 180 DAY;
```
