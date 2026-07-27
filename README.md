# secman_visual_check

Checker for web pages.

Give it a URL (or a list of them). It loads each page in a headless browser,
takes a screenshot, and asks a vision model whether the page exposes content
that should not be reachable — credentials, unauthenticated admin panels,
directory listings, personal data, stack traces, and so on. You get a console
summary, a machine-readable JSON report, and a self-contained HTML report with
the screenshots embedded. Findings can also be pushed straight into
[SecMan](https://github.com/schmalle/secman) — see
[Uploading findings to SecMan](#uploading-findings-to-secman).

> **Scan only systems you own or are explicitly authorised to test.** The tool
> loads pages and sends screenshots to a third-party model provider; both are
> actions you need permission for.

## Install

```bash
pip install -r requirements.txt
playwright install chromium          # one-time browser download
```

Or install the package itself (adds a `secman-visual-check` command):

```bash
pip install -e .
playwright install chromium
```

Python 3.10+.

## Quick start

```bash
export OPENROUTER_API_KEY=sk-or-...

# One URL
python -m secman_visual_check https://example.com/admin

# A list, into a chosen output directory
python -m secman_visual_check -f examples/urls.txt -o ./scan-2026-07-27

# Screenshots only, no model calls and no API key needed
python -m secman_visual_check --no-ai https://example.com
```

Output lands in `scan-output/` by default:

```
scan-output/
├── screenshots/0001-example.com-admin-3f9a2c1b04.png
├── report.json
└── report.html
```

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

Use `--fail-on none` to always exit `0`, and `--dry-run` to print the resolved,
de-duplicated target list without touching the network.

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
| `--respect-robots` | Skip URLs the origin's `robots.txt` disallows. Off by default: you are scanning your own assets. |
| `--link-images` | Link screenshots from the HTML report instead of embedding them, for large scans. |
| `--include-raw` | Keep the raw model replies in the JSON report, for debugging prompts. |
| `-v/--verbose` | Print evidence and remediation for every finding. |

Full list: `python -m secman_visual_check --help`.

## JSON report shape

```json
{
  "tool": "secman_visual_check",
  "model": "anthropic/claude-sonnet-4.5",
  "target_count": 2,
  "severity_counts": {"critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0},
  "max_severity": "critical",
  "results": [
    {
      "url": "https://example.com/backup/",
      "max_severity": "critical",
      "capture": {"status": 200, "title": "Index of /backup", "screenshot_path": "..."},
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
            "confidence": 0.9
          }
        ]
      }
    }
  ]
}
```

Pages that fail to load still appear, with `capture.load_error` set. A page that
only rendered the browser's own error screen is never sent to the model.

## How it fits together

| Module | Responsibility |
| --- | --- |
| `targets.py` | Parse, normalise and de-duplicate URLs |
| `capture.py` | Playwright: navigate, screenshot, extract title/text/status |
| `categories.py` | The policy — what counts as critical content |
| `prompts.py` | System prompt, user prompt, and the response JSON schema |
| `analyzer.py` | OpenAI-compatible vision call, retries, lenient JSON parsing |
| `scanner.py` | Pipelines capture → analysis with independent concurrency limits |
| `reporting.py` | Console, JSON and HTML output |
| `secman.py` | Maps findings onto SecMan vulnerabilities; HTTP and MCP upload |
| `cli.py` | Argument parsing and exit codes |

## Caveats

- The model reads a screenshot. It can miss content below the `--max-height`
  clamp, behind a click, or rendered after `--settle` elapses.
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
a mocked transport, scanner orchestration, report rendering, and the SecMan
upload — ID stability, the three de-duplication layers, dry-run behaviour, and
both transports against a mocked backend. It does not require a browser, an API
key or a SecMan instance.
