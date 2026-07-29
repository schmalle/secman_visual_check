# Status and redirect checks

Every target gets an HTTP status check before the browser opens it: does the URL
answer **200**, does it **redirect** (and where to), or is it broken? The result
appears on screen, in `report.json`, in `report.html`, and optionally in SecMan
and MariaDB.

It is on by default. `--no-status-check` turns it off and restores the previous
output exactly.

## Why a separate request

The scanner already navigates each target with Playwright, and `capture.status`
records what came back. That number is not the same thing:

- The browser **follows redirects internally**. Only the final response
  survives; the 301 that got you there, and its `Location`, are gone.
- The browser uses its **cache**, runs **service workers**, and honours
  `--storage-state`, so it may not touch the network the way a plain client does.
- A **HEAD/GET difference** — a server that answers HEAD with 405 while GET
  returns 200 — is invisible through a browser.
- When navigation fails outright, `capture.status` is `None`. The site may still
  be answering perfectly well; Chromium just refused to render it.

So the check is its own request, made with `httpx` and redirects **disabled**,
then walked hop by hop. Both numbers appear in the report side by side. A
divergence between them is a finding in its own right: it usually means a
service worker, a cache, or a client-side redirect is in play.

## How the walk works

1. Issue the first request. Default method is `HEAD`; if the server answers
   400, 403, 405, 406 or 501 — statuses that say more about HEAD support than
   about the resource — that hop is retried with `GET`. The GET is streamed and
   abandoned as soon as the headers arrive, so no body is ever downloaded.
2. Record a hop: the URL, the status, and the raw `Location` header exactly as
   sent (it may be relative).
3. If the status is 301/302/303/307/308 and a `Location` is present, resolve it
   against the current URL and repeat. A `303` turns the rest of the walk into a
   `GET`, per RFC 9110.
4. Stop on: a non-redirect status, a missing `Location`, the hop cap
   (`--status-max-redirects`, default 10), a URL already visited (a loop), or a
   `Location` that is not `http(s)`.

Transport failures — DNS, TLS, connection refused, timeout — are recorded, never
raised. A dead host is a result, not a crash.

## States

| state | meaning | `ok` |
| --- | --- | --- |
| `ok` | final status is expected, no redirects | ✔ |
| `redirect` | final status is expected, reached via ≥1 redirect | ✔ |
| `redirect_broken` | loop, hop cap reached, missing or unusable `Location` | ✘ |
| `unexpected_status` | a 1xx/2xx that was not expected, e.g. 204 where 200 was asked for | ✘ |
| `client_error` | final status is 4xx | ✘ |
| `server_error` | final status is 5xx | ✘ |
| `unreachable` | transport failure, or not an HTTP(S) URL | ✘ |
| `unknown` | the check did not run | ✘ |

`ok` is defined purely as *final status ∈ expected statuses*, so
`--status-expect 200,401` makes a 401 healthy without touching any code.

## Flags

| flag | default | what it does |
| --- | --- | --- |
| `--no-status-check` | on | skip the check entirely |
| `--status-method {auto,head,get}` | `auto` | `auto` = HEAD with a GET fallback; the others pin the method |
| `--status-timeout SECONDS` | `15.0` | per-request timeout |
| `--status-max-redirects N` | `10` | hops to follow; `0` records the first response and stops |
| `--status-expect CODES` | `200` | comma-separated statuses treated as OK; `2xx`-style wildcards allowed |
| `--status-concurrency N` | `8` | parallel checks, independent of `--concurrency` |
| `--fail-on-status` | off | exit 1 when any target's check is not OK |

The check inherits the browser's identity so both requests look like one client:
`--timeout`, `--user-agent`, `-H/--header`, `--basic-auth` and `--insecure` all
apply to it. `--status-timeout` overrides `--timeout` for the check alone.

Targets skipped by `--respect-robots` are not checked either — "do not touch
this URL" means all of it.

## Output

Progress line (stderr), one per finished target:

```
[1/4] https://example.com/admin -> 200 ok | critical
[2/4] http://old.example.com/ -> 301->200 redirect | info
[3/4] https://example.com/gone -> 404 client_error | load failed: net::ERR_HTTP_RESPONSE_CODE_FAILURE
[4/4] https://dead.example/ -> unreachable | error: ConnectError
```

Console report, per target — printed even when the target was skipped or the
browser failed, because that is when it matters most:

```
[INFO] http://old.example.com/
  status: 301->200 redirect  (1 hop, 0.34s)
    301 http://old.example.com/ -> /new
    200 http://old.example.com/new
  HTTP 200  -> http://old.example.com/new
```

and a summary block:

```
Status checks:
  ok                 8
  redirect           2
  redirect_broken    0
  unexpected_status  0
  client_error       1
  server_error       0
  unreachable        1
  unknown            0

2 target(s) did not return an expected status:
  https://example.com/gone — HTTP 404
  https://dead.example/ — ConnectError: Name or service not known
```

The HTML report shows a coloured status pill per target, the redirect chain as
an ordered list, and a row of status cards next to the severity cards.

## JSON

Added under each result as `status_check`, plus a top-level `status_counts`.
Both are additive — nothing that existed before changed shape.

```json
"status_check": {
  "url": "http://old.example.com/",
  "state": "redirect",
  "ok": true,
  "method": "HEAD",
  "first_status": 301,
  "final_status": 200,
  "final_url": "http://old.example.com/new",
  "redirect_count": 1,
  "expected_statuses": [200],
  "chain": [
    {"url": "http://old.example.com/", "status": 301, "location": "/new", "elapsed_s": 0.081},
    {"url": "http://old.example.com/new", "status": 200, "location": null, "elapsed_s": 0.263}
  ],
  "error": null,
  "elapsed_s": 0.344,
  "checked_at": "2026-07-29T09:14:02.113000+00:00"
}
```

`status_check` is `null` when the check was disabled or the target was skipped.
Reports written before this feature simply do not have the key; every consumer
in this repo tolerates its absence.

## Exit codes

Unchanged, with one addition:

| code | meaning |
| --- | --- |
| 0 | nothing to report |
| 1 | a finding at or above `--fail-on`, **or** — with `--fail-on-status` — a target whose status check is not OK |
| 2 | the scan or an upload failed |

The findings gate is evaluated first, so an exit code of 1 does not on its own
tell you which gate fired; the console report does.

## Sending status results onward

- **SecMan** — `--secman-status-findings` turns failed checks into
  vulnerabilities, and `--secman-register-assets` puts every scanned host in the
  asset inventory. See [SECMAN_UPLOAD.md](SECMAN_UPLOAD.md).
- **MariaDB** — `--db-store` mirrors every check into a queryable database. See
  [../db/README.md](../db/README.md).
