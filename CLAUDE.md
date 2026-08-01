# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Setup

Homebrew Python is externally managed (PEP 668), so `pip install` into it fails.
Work in a virtualenv — `.venv` is gitignored:

```bash
python -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/playwright install chromium     # one-time, ~150 MB
```

Run everything through `.venv/bin/python`. Optional extras: `[db]` (PyMySQL),
`[aws]` (boto3 for SES). Both are deliberately outside `[dev]` so the
"driver is missing" degradation paths stay exercised in CI.

## Commands

```bash
.venv/bin/python -m pytest                            # full suite
.venv/bin/python -m pytest tests/test_status_check.py  # one file
.venv/bin/python -m pytest -k "checksum"               # one pattern
.venv/bin/python -m secman_visual_check https://example.com
```

The suite needs no browser, API key, database or SecMan instance — every
external boundary is mocked. CI (`.github/workflows/tests.yml`) runs
`pytest -q` on Python 3.10 and 3.12; those are the real floor and ceiling.
There is no linter or formatter configured.

Scans write four reports to `scan-output/` by default — `report.json`,
`report.html`, `report.csv`, `statistics.txt` — each suppressible with
`--no-json` / `--no-html` / `--no-csv` / `--no-stats`. The directory is
gitignored. Exit codes: `0` clean, `1` a finding reached `--fail-on` (or
`--fail-on-status` tripped), `2` usage or configuration error.

## Architecture

A four-stage pipeline over a list of URLs. `cli.py` parses arguments into a
single `ScanConfig`, `scanner.run_scan` executes it, and everything downstream
consumes one `ScanReport`.

```
secrets.py ─→ (every credential, before anything runs)

targets.py → status.py ─┐
                        ├→ scanner.py → reporting.py / db.py / mailer.py / secman.py
            capture.py → analyzer.py

plan.py ←── the same options, described instead of executed (--dry-run)
```

**Two independent probes per target, deliberately not merged.** `status.py`
makes a plain HTTP request with redirects disabled and walks the chain by hand;
`capture.py` drives Chromium. They disagree on purpose — the browser follows
redirects internally, answers from cache and runs service workers, so it only
ever shows where a target *ended up*. Both land in the report side by side.
The status check runs first and outside the capture semaphore, so a status is
known even when Chromium then dies on the page.

**Every optional stage degrades rather than aborts.** `--no-visual-check` skips
the Chromium *launch*, not just the screenshot (a status-only run must work on
a host with no browser). `--no-ai` captures without model calls. A missing
PyMySQL or boto3 is reported, not raised. Transport failures inside the
analyzer become `Analysis.error`; only configuration problems raise
`AnalyzerError` and abort the run.

**Credentials are validated before the scan, never after.** `main()` builds the
SecMan, DB and mail options up front so a ten-minute crawl cannot end on a typo.
Resolving a `pass://` reference happens in the same pass, for the same reason.
Preserve that ordering when adding a stage.

**`--dry-run` writes nothing and validates everything.** It builds the identical
option objects a real run would, then hands them to `plan.py` to describe. A new
stage that writes must either be represented in the plan or be unreachable from
the dry-run path — the guarantee is worth more than the feature.

### Stage notes

- `scanner.py` pipelines capture and analysis under two semaphores
  (`concurrency`, `ai_concurrency`) so a slow model call never stalls the
  browser. Inside `capture.py`, the screenshot step itself holds a lock:
  Chromium splices content between tabs when several full-page captures run at
  once.
- `analyzer.py` targets any OpenAI-compatible `/chat/completions`. It asks for
  `response_format: json_schema` and steps down to `json_object`, then to no
  constraint, when a model rejects it — `_lower_mode` keeps concurrent requests
  from cascading a single 400 all the way down. Replies are parsed leniently
  (`extract_json` scans for a balanced object through markdown fences), and a
  page is never reported below the severity of its own worst finding.
- `categories.py` is the policy layer: what counts as critical content is data,
  fully replaceable via `--categories-file`. Editing detection behaviour usually
  means editing categories or `prompts.py`, not the analyzer.
- `capture.PageCapture.worth_analyzing` gates model spend — a screenshot of
  Chromium's own `chrome-error://` page is never sent.
- `status.py` hashes a body only when the target answered an *expected* status
  (`--status-expect`, default 200); a 404's error page changes for reasons
  nobody wants alerts about. `content_checksum = None` means "not computed" and
  is a different fact from a checksum of zero bytes. Hashing is **on by
  default** and costs one extra GET per healthy target on top of the walk's
  HEAD; `--no-status-checksum` opts out and is rejected alongside `--db-store`.
  `--status-checksum` is retained as a no-op for compatibility.
- `db.py` (MariaDB, opt-in via `--db-store`) keeps a per-URL review flag across
  runs. The scanner only ever writes `NEW`
  and `NOT_CHECKED`; `OK` is an operator statement, set via `--db-set-flag`.
  A changed checksum resets the flag to `NEW` — an `OK` verdict describes
  reviewed content and cannot outlive it. An unreachable run never erases a
  known checksum and never demotes `NEW`.
- `secman.py` maps findings onto SecMan vulnerabilities under a synthetic ID
  derived from page + category, deliberately independent of the model's
  wording so reruns land on the same row. Duplicate suppression has three
  layers (merge before send, skip what SecMan already holds, SecMan's own
  `(asset, cve)` upsert); the middle layer failing is non-fatal by design.
  MCP transport requires the `X-MCP-User-Email` header.
- `reporting.py` renders five ways from one `ScanReport`. The CSV is one row
  per *target* (a status-only run must still produce a full table), and every
  cell goes through `_csv_cell`, which prefixes `=`/`+`/`-`/`@` with `'` so
  attacker-influenced titles and model summaries cannot become spreadsheet
  formulas. `report_statistics()` is the single source of the aggregate numbers
  for both the console block and `statistics.txt`; both omit rows for a stage
  that never ran rather than printing zeros.
- `secrets.py` resolves `pass://vault/item/field` through `pass-cli`, and is the
  only place that shells out. Two invariants: the secret never reaches argv
  (only the reference is passed, the value comes back on a pipe), and it never
  reaches printed output — `redact()` scrubs resolved values out of anything
  echoed back from a backend, applied via `cli._emit`. `pass-cli`'s flags have
  moved between releases, so `STRATEGIES` tries each known spelling and caches
  whichever answered; `scripts/passcli.sh` mirrors the same chain for shell
  scripts and is exercised through bash in `tests/test_passcli_shell.py`.
- `plan.py` renders `--dry-run`. It reads the real option objects rather than
  the argparse namespace, so the plan cannot drift from what a run would do.
- `models.py` holds the dataclasses every stage shares. `ScanReport`'s
  `severity_counts()` counts *findings*; a result's `max_severity` falls back
  to `INFO` when there are none, so a clean page prints `[INFO]` against a
  table of zeros. That is correct, not a bug.

## Conventions

- Standard library plus `playwright` and `httpx` only. Heavy or optional
  dependencies are imported lazily inside the function that needs them
  (`import httpx` inside `__aenter__`, `from playwright.async_api import ...`
  inside `BrowserCapturer.__aenter__`) so `--no-visual-check` and `--no-ai`
  stay honest.
- Async throughout, with `contextlib.AsyncExitStack` in `run_scan` opening only
  the stages a given configuration actually needs.
- Every dataclass carrying report state defines `to_dict()`; the JSON report is
  the public contract and `tests/test_models_and_reporting.py` pins its shape.
- Comments explain *why* a non-obvious choice was made (the screenshot lock,
  the separate status probe, the mode downgrade). Match that when touching
  those paths.
- User-facing docs live in `README.md` with deep references in `docs/` and
  `db/`. A new flag belongs in the README options table and in its topic doc.
- Any new credential flag goes through `SecretResolver.resolve()` and gets a row
  in `docs/PASS_CLI.md`; a flag that reads a secret straight out of the
  namespace is a bug, not a shortcut.
