# Content check: confidential data in what the page contains

The vision model judges what a page **shows**. The content check judges what it
**contains**. It runs a fixed set of regular expressions over the text the
browser rendered, the DOM after scripts ran, and the raw response body the
status check already downloaded, and turns matches into ordinary findings tagged
`"source": "content"`. It is on by default, needs no model and no API key, and
runs on every target the earlier stages produced content for.

- [Why a second check](#why-a-second-check)
- [What is searched](#what-is-searched)
- [Built-in patterns](#built-in-patterns)
- [How matches become findings](#how-matches-become-findings)
- [Extending or replacing the patterns](#extending-or-replacing-the-patterns)
- [Options](#options)
- [Limits](#limits)

## Why a second check

A screenshot cannot see:

- **HTML comments, inline scripts and data attributes.** `<!-- admin: hunter2 -->`
  never paints. Neither does an API key in a `<script>` block.
- **Anything below the `--max-height` clamp.** A 40,000-pixel page is cut at
  4,000 by default; a key on line 900 is off-screen.
- **Anything at all when there is no model.** `--no-ai` and `--no-visual-check`
  runs produced no findings before this check existed, and a model that is down
  or answers unusably left the page with none either.

The content check closes those gaps deterministically. It is not a replacement
for the model — a login form that gates nothing, an admin panel, a defaced
page are judgements about what a visitor sees — but it is the part of the
assessment that is reproducible, cheap, and independent of any provider.

## What is searched

| Source | Comes from | Available when |
| --- | --- | --- |
| `text` | `body.innerText` after the page settled | browser ran and the page rendered |
| `html` | `page.content()` — the live DOM serialised | browser ran and the page rendered |
| `body` | the first bytes of the response the status check hashed | status check on, checksum on, text-like content type |

Each is capped at `--content-max-chars` (default 500,000 characters) and kept in
memory only. None of them is written to any report; the JSON report keeps the
`text_excerpt` it always had. Binary bodies (images, PDFs, archives) are never
retained: only `text/*`, JSON, JavaScript, XML, YAML and form-encoded types are.

Every pattern declares which sources it may see. Patterns with a recognisable
format — an AWS key, a private-key header, a connection string — run on all
three. Loose patterns — `password = …`, a bearer token, a stack trace — run on
visible text only, because minified JavaScript is full of `password:` and
would otherwise flood the report.

## Built-in patterns

| id | Category | Severity | Sources | What it matches |
| --- | --- | --- | --- | --- |
| `private_key_block` | `exposed_credentials` | critical | all | `-----BEGIN … PRIVATE KEY-----` |
| `aws_access_key_id` | `exposed_credentials` | critical | all | `AKIA…` / `ASIA…` access key IDs |
| `aws_secret_access_key` | `exposed_credentials` | critical | all | `aws_secret_access_key = <40 chars>` |
| `github_token` | `exposed_credentials` | critical | all | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_` |
| `slack_token` | `exposed_credentials` | critical | all | `xoxb-`, `xoxp-`, … |
| `google_api_key` | `exposed_credentials` | high | all | `AIza…` |
| `stripe_secret_key` | `exposed_credentials` | critical | all | `sk_live_`, `sk_test_`, `rk_live_`, `rk_test_` |
| `openai_style_key` | `exposed_credentials` | high | all | `sk-…`, `sk-proj-…`, `sk-ant-…`, `sk-or-v1-…` |
| `jwt` | `exposed_credentials` | high | all | three base64url segments starting `eyJ` |
| `connection_string_with_password` | `exposed_credentials` | critical | all | `mysql://user:pass@host`, `postgres://`, `mongodb://`, `redis://`, `amqp://`, `jdbc:` |
| `url_with_credentials` | `exposed_credentials` | high | all | `https://user:pass@host` |
| `dotenv_secret` | `backup_or_source_disclosure` | critical | all | `DB_PASSWORD=`, `DATABASE_URL=`, `APP_KEY=`, `SECRET_KEY=`, … at line start |
| `git_config` | `backup_or_source_disclosure` | high | all | `[core]` + `repositoryformatversion` — a served `.git/config` |
| `password_assignment` | `exposed_credentials` | high | text | `password = …`, `api_key: …`, `client_secret=…` with a plausible value |
| `bearer_token` | `exposed_credentials` | high | text | `Bearer <token>` |
| `iban` | `personal_data` | high | text | IBAN with a valid mod-97 check |
| `payment_card` | `personal_data` | high | text | 13–19 digit card number with a valid Luhn check and a known prefix |
| `email_list` | `personal_data` | medium | text | ten or more distinct email addresses on one page |
| `private_ip` | `infrastructure_disclosure` | medium | text | RFC 1918 addresses |
| `server_banner` | `infrastructure_disclosure` | low | text | `Apache/2.4.41`, `nginx/1.18.0`, `PHP/8.1.2`, … |
| `stack_trace` | `debug_output` | high | text | Python tracebacks, Java `at …(File.java:12)`, PHP fatals and warnings, .NET exceptions, Node stack frames |
| `django_debug_page` | `debug_output` | high | text | the Django `DEBUG = True` footer |
| `phpinfo` | `debug_output` | high | text | `phpinfo()` output |
| `spring_actuator_env` | `debug_output` | high | text, body | Spring Boot `/actuator/env` JSON |
| `directory_index` | `directory_listing` | high | text | `Index of /`, `Parent Directory` |

The `password_assignment` pattern is the loosest, and it is guarded: the value
must be on the same line as the label, at least eight characters, contain a
digit or a symbol, and not look like a placeholder (`********`, `${VAR}`,
`<redacted>`, `changeme`) or code (`e.target.value`). `Password:` followed by a
form field or a "Forgot password?" link does not match.

## How matches become findings

- **One finding per pattern per page.** A page listing forty private addresses
  yields one `infrastructure_disclosure` finding whose evidence says `(+39
  more)`, not forty rows — in the report, and in SecMan.
- **Secrets are redacted in the evidence** the same way the model is asked to
  redact them: the first four characters survive, the rest is `…`. Where the
  pattern isolates a value after a label, the label survives and the value does
  not: `DB_PASSWORD=hunt…`. Markers that are not themselves secrets — a
  private-key header, `Index of /` — are quoted.
- **Findings merge into the page's analysis.** They sit beside the model's
  findings, tagged `source: "content"`, and the page's `risk_level` is raised
  to the worst of them. Every consumer sees them the same way it sees the
  model's: `--fail-on`, the severity counts, the CSV, the email, the SecMan
  upload. When there was no model verdict — `--no-ai`, `--no-visual-check`, or
  a failed call — a bare analysis is created around them with
  `"model": "content-check"`.
- **The scope is recorded even when nothing matched.** Each result carries a
  `content_check` object saying which sources were available, how many
  characters were read and how many patterns matched, so "no content finding"
  and "nothing was checked" are different facts in the report.

```json
"content_check": {"sources": ["text", "html", "body"], "chars_scanned": 48213, "matches": 1, "findings": 1},
"analysis": {
  "findings": [
    {
      "category": "exposed_credentials",
      "severity": "critical",
      "title": "AWS access key ID in page content",
      "evidence": "AKIA… — in page HTML",
      "recommendation": "Rotate the credential and remove it from the page.",
      "confidence": 0.9,
      "source": "content"
    }
  ]
}
```

## Extending or replacing the patterns

`--content-patterns-file PATH` takes a JSON file. A bare list is appended to
the built-ins; an object `{"replace": true, "patterns": [...]}` starts from
nothing. An entry whose `id` matches a built-in replaces that one pattern, so a
single severity or regex can be tuned without restating the set.

```json
[
  {
    "id": "internal_marker",
    "category": "internal_documents",
    "severity": "high",
    "title": "Internal-only banner on a public page",
    "regex": "(?i)\\binternal use only\\b",
    "recommendation": "Gate the page behind authentication.",
    "confidence": 0.7,
    "secret": false,
    "sources": ["text"],
    "min_matches": 1
  }
]
```

| Field | Required | Meaning |
| --- | --- | --- |
| `id` | yes | Stable name; overrides a built-in with the same id |
| `category` | yes | A category id — built-in or from `--categories-file` — or anything else |
| `title` | yes | The finding's headline |
| `regex` | yes | Python `re` syntax; use inline flags such as `(?i)` and `(?m)` |
| `severity` | no | `critical`, `high`, `medium` (default), `low`, `info` |
| `recommendation` | no | Remediation text carried on the finding |
| `confidence` | no | 0–1, default 0.7 |
| `secret` | no | Redact the match in the evidence (default `false`) |
| `sources` | no | Any of `text`, `html`, `body`; default all three |
| `min_matches` | no | Report only when at least this many distinct matches were found |

A regex that does not compile, an unknown source, a missing required field or
an empty resulting set is a configuration error, reported before the scan
starts and exit code `2`. See `examples/content-patterns.json`.

## Options

| Flag | Default | Effect |
| --- | --- | --- |
| `--no-content-check` | off | Skip the check entirely. Also stops the browser and the status check from keeping content in memory. |
| `--content-patterns-file PATH` | | Extend or replace the built-in patterns |
| `--content-max-chars N` | `500000` | Cap on each of the three sources, per target |

The `body` source depends on the status check's checksum fetch, so
`--no-status-checksum` and `--no-status-check` both remove it; the browser
sources remain.

## Limits

- **It is pattern matching.** Confidence values are honest: `0.9` for an AWS
  key ID with its fixed prefix, `0.55` for `password = …`. Treat lower
  confidences as a triage queue.
- **It reads what was fetched, not what exists.** Content behind a click, a
  scroll trigger or a second request is not searched.
- **Redaction is shallow.** Four characters of a secret survive in the
  evidence. Reports and the SecMan upload never carry more than that, but the
  screenshot still shows whatever the page showed — treat the output directory
  as sensitive, as before.
- **A resolved `pass://` credential reflected by the target** is still scrubbed
  by `redact()` before any report is written, exactly as for model findings.
