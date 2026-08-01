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
   (`--status-max-redirects`, default 10), a URL already visited (a loop), a
   `Location` that is not `http(s)`, or — on by default — a `Location` that
   resolves to a private/loopback/link-local address on a **different host**
   than the target (`--allow-private-redirects` opts back in; see below).

Transport failures — DNS, TLS, connection refused, timeout — are recorded, never
raised. A dead host is a result, not a crash.

A target's `Location` is followed wherever it points, but `--basic-auth` and
`-H`/`--header` credentials are only ever attached to a request that stays on
the target's own host — never to a redirect hop that lands elsewhere, and
never to the body fetch a checksum performs against the final URL. A
compromised or malicious target should not be able to redirect the scanner at
internal infrastructure or cloud metadata endpoints (e.g. `169.254.169.254`)
and collect whatever credentials were configured for a completely different
site.

## States

| state | meaning | `ok` |
| --- | --- | --- |
| `ok` | final status is expected, no redirects | ✔ |
| `redirect` | final status is expected, reached via ≥1 redirect | ✔ |
| `redirect_broken` | loop, hop cap reached, missing/unusable `Location`, or a redirect blocked as a likely SSRF target | ✘ |
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
| `--allow-private-redirects` | off | allow a redirect to a private/loopback/link-local address on a different host than the target, and let `--basic-auth`/`-H` credentials follow a cross-host redirect. Also applies to the browser capture's navigation/iframe handling. |
| `--status-method {auto,head,get}` | `auto` | `auto` = HEAD with a GET fallback; the others pin the method |
| `--status-timeout SECONDS` | `15.0` | per-request timeout |
| `--status-max-redirects N` | `10` | hops to follow; `0` records the first response and stops |
| `--status-expect CODES` | `200` | comma-separated statuses treated as OK; `2xx`-style wildcards allowed |
| `--status-concurrency N` | `8` | parallel checks, independent of `--concurrency` |
| `--no-status-checksum` | on | body hashing of targets that answer as expected is on by default; this turns it off. Rejected together with `--db-store` |
| `--status-checksum-max-bytes N` | `5242880` | stop hashing a body after this many bytes |
| `--fail-on-status` | off | exit 1 when any target's check is not OK |

The check inherits the browser's identity so both requests look like one client:
`--timeout`, `--user-agent`, `-H/--header`, `--basic-auth` and `--insecure` all
apply to it. `--status-timeout` overrides `--timeout` for the check alone.

Targets skipped by `--respect-robots` are not checked either — "do not touch
this URL" means all of it.

## Content checksums

On by default. After the walk settles, the body of the final response is
streamed and hashed with sha256 — one more request than the walk itself needs,
since the walk is happy with `HEAD`.

Only targets that answered as **expected** are hashed. A 404's error page, a
maintenance splash, a rate-limit notice — those change constantly and for
reasons nobody wants to be alerted about, so hashing them would produce a change
feed of pure noise.

- The body is streamed and discarded chunk by chunk; nothing is buffered whole.
- Past `--status-checksum-max-bytes` (5 MiB) hashing stops and the result is
  marked `content_truncated`. A change checker should not download an ISO to
  notice that a heading moved.
- An empty body records `content_length: 0` and **no** checksum — "no content"
  is a different fact from "content that happens to be empty".
- If the body read fails, the status verdict still stands; only the checksum is
  lost, and the reason is appended to `error`.

On screen:

```
[INFO] https://example.com/admin
  status: 200 ok  (0.12s)
  content: sha256:1a2b3c4d5e6f  4.2 KB  text/html
```

The checksum is what makes [URL change tracking](../db/README.md) possible: it
is the difference between "this URL still answers" and "this URL still answers
*and nobody changed it*".

### Turning it off

`--no-status-checksum` drops the body request, leaving one `HEAD` per target.
Worth it for a large uptime-only sweep — hashing a 900 KB page costs about 0.2s
against 0.05s for the bare check — and pointless otherwise.

```bash
python -m secman_visual_check --no-visual-check --no-status-checksum -f urls.txt
```

It is rejected together with `--db-store` (exit code `2`): the stored checksum
is what drives change detection, so a database run without one would keep a flag
lifecycle that can never notice a change.

`--status-checksum` is still accepted and now does nothing, so scripts written
against the old opt-in behaviour keep working.

## Skipping the browser

`--no-visual-check` skips Chromium entirely — no launch, no screenshot, no model
call. The launch is the expensive part, so this is not a small saving, and the
run works on a host with no browser installed at all:

```bash
python -m secman_visual_check --no-visual-check -f urls.txt
```

The banner says so:

```
Scanning 3 target(s) with 8 status worker(s); analysis: no browser (status check only)
```

`--no-visual-check` together with `--no-status-check` leaves nothing to do, and
is rejected before the scan starts.

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
  "content_checksum": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "content_length": 4321,
  "content_type": "text/html",
  "content_truncated": false,
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
- **MariaDB** — `--db-store` mirrors every check into a queryable database, and
  turns the checksum into per-URL change tracking. See
  [../db/README.md](../db/README.md).
- **Email** — `--mail` sends the result to an inbox. See [EMAIL.md](EMAIL.md).
