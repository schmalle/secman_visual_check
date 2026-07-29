# Emailing the results

`--mail` sends the scan result to an inbox when the run finishes. Three
transports are supported: plain **SMTP**, **Microsoft 365** through the Graph
API, and **AWS SES**.

```bash
python -m secman_visual_check --mail \
  --mail-from scanner@example.com --mail-to ops@example.com \
  --mail-smtp-host smtp.example.com \
  -f urls.txt
```

## What it looks like

The message is `multipart/alternative` — HTML with a plain-text fallback — and
is styled to match SecMan's own notification emails: the same 600px layout, the
`#0d6efd` header, the `#f8f9fa` content panel, the `#cfe2ff` alert box, the
same table and badge palette, and the same footer wording. A visual-check report
landing next to a SecMan alert should read as one system, not two. The
originals live in `secman/src/backendng/src/main/resources/email-templates/`.

The subject says what happened without needing the body opened:

```
[secman-visual-check] Visual check: 2 status problems, 1 changed, 1 new, 1 finding (12 targets)
[secman-visual-check] Visual check: all clear (12 targets)
```

The body carries a summary of status states and finding severities, a table of
targets that did not answer as expected, and — when database mode is on — a
table of URL flag changes, so "what is new and what moved" is the part that
actually reaches a human.

## When it sends

**By default a clean run sends nothing.** A daily check that mails "nothing
happened" trains people to filter it, and then it is not a notification any
more. Mail goes out when a target failed its status check, when a URL's content
changed, when a URL is newly discovered, or when a capture failed.

- `--mail-always` sends regardless, for the "prove the job still runs" case.
- `--mail-dry-run` renders the message and prints the subject without
  delivering it.

Delivery is fail-soft: if the mail server is down, the failure is printed and
the scan's exit code is unaffected. The reports are already on disk; losing the
notification should not turn a successful scan into a failed one.

Credentials are resolved and validated **before the scan starts**, so a typo
costs a second rather than a ten-minute crawl.

## Transports

### `--mail-transport smtp` (default)

Standard library `smtplib`; the same path SecMan itself uses. STARTTLS by
default, `--mail-smtp-ssl` for implicit TLS on port 465, `--mail-smtp-no-tls`
to disable it for a local relay.

```bash
python -m secman_visual_check --mail \
  --mail-from scanner@example.com --mail-to ops@example.com \
  --mail-smtp-host smtp.example.com --mail-smtp-port 587 \
  --mail-smtp-user scanner --mail-smtp-password "$SMTP_PASSWORD" \
  -f urls.txt
```

### `--mail-transport o365`

Microsoft Graph `POST /v1.0/users/{sender}/sendMail`, authenticated with the
OAuth2 client-credentials flow. No extra dependency — it rides on `httpx`,
which is already required.

The app registration needs the **application** permission `Mail.Send` (granted
with admin consent), and `--mail-from` must be a mailbox in the tenant — that
is the mailbox the message is sent as.

```bash
export SECMAN_MAIL_TENANT_ID=... SECMAN_MAIL_CLIENT_ID=... SECMAN_MAIL_CLIENT_SECRET=...
python -m secman_visual_check --mail --mail-transport o365 \
  --mail-from scanner@contoso.com --mail-to ops@contoso.com \
  -f urls.txt
```

Messages are sent with `saveToSentItems: false`, so a service mailbox does not
accumulate a copy of every run.

### `--mail-transport ses`

AWS SES `SendRawEmail`, through **boto3**:

```bash
pip install 'secman-visual-check[aws]'
python -m secman_visual_check --mail --mail-transport ses \
  --mail-aws-region eu-central-1 \
  --mail-from scanner@example.com --mail-to ops@example.com \
  -f urls.txt
```

boto3 rather than hand-rolled SigV4 on purpose: it already handles named
profiles, instance roles, IMDS, SSO and the whole `AWS_*` environment, and a
reimplementation here would be a worse copy of all of it. Credentials resolve
the normal AWS way — `--mail-aws-profile`, `AWS_PROFILE`, `AWS_REGION`, an
instance role, whatever you already use. The sender address (or its domain) must
be verified in SES, and a sandboxed account can only send to verified
recipients.

If boto3 is not installed, the send is reported as a failure naming the extra to
install; the scan itself still succeeds.

## Options

| flag | environment | default |
| --- | --- | --- |
| `--mail` | `SECMAN_MAIL` | off |
| `--mail-transport {smtp,o365,ses}` | `SECMAN_MAIL_TRANSPORT` | `smtp` |
| `--mail-from ADDRESS` | `SECMAN_MAIL_FROM` | |
| `--mail-from-name NAME` | | `SecMan Visual Check` |
| `--mail-to ADDRESS` (repeatable) | `SECMAN_MAIL_TO` (comma separated) | |
| `--mail-subject-prefix TEXT` | | `[secman-visual-check]` |
| `--mail-always` | | off |
| `--mail-dry-run` | | off |
| `--mail-dashboard-url URL` | | |
| `--mail-timeout SECONDS` | | `30` |
| `--mail-smtp-host` | `SECMAN_MAIL_SMTP_HOST` | |
| `--mail-smtp-port` | `SECMAN_MAIL_SMTP_PORT` | `587` |
| `--mail-smtp-user` | `SECMAN_MAIL_SMTP_USER` | |
| `--mail-smtp-password` | `SECMAN_MAIL_SMTP_PASSWORD` | |
| `--mail-smtp-no-tls`, `--mail-smtp-ssl` | | STARTTLS on |
| `--mail-tenant-id` | `SECMAN_MAIL_TENANT_ID` | |
| `--mail-client-id` | `SECMAN_MAIL_CLIENT_ID` | |
| `--mail-client-secret` | `SECMAN_MAIL_CLIENT_SECRET` | |
| `--mail-aws-region` | `SECMAN_MAIL_AWS_REGION`, `AWS_REGION` | |
| `--mail-aws-profile` | `AWS_PROFILE` | |

`--mail-dashboard-url` becomes the call-to-action button in the HTML body —
point it at your SecMan instance.

## Secrets

Passwords, client secrets and AWS keys can be passed as flags, but the
environment variables above are the better route: flags show up in process
listings and shell history. Nothing secret is ever printed — the console line
names the transport and endpoint only:

```
Email: sent via o365 (graph:contoso-tenant-id) to ops@contoso.com
  subject: [secman-visual-check] Visual check: 1 status problem (12 targets)
```
