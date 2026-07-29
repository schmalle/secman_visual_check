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

## Schema

Three tables, all `InnoDB` / `utf8mb4`, related by `ON DELETE CASCADE`:

- **`svc_scan_run`** — one row per invocation. `run_uuid` is derived from the
  run's own contents, so storing the same report twice is a duplicate-key error
  rather than a silent second copy.
- **`svc_url_status`** — one row per checked target: `state`, `is_ok`,
  `first_status` (the raw, un-followed response), `final_status`, `final_url`,
  `redirect_count`, `error`, plus `browser_status` — what Chromium saw — so a
  divergence between the two clients is visible in SQL.
- **`svc_redirect_hop`** — one row per hop, with the raw `Location` header.

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
