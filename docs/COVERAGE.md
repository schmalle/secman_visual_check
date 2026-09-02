# Coverage: was every endpoint evaluated?

A scan that says "no findings" can mean two things: every page was looked at
and nothing was exposed, or a page was never looked at. The reports used to
leave that to the reader — a target the browser could not load printed the same
`[INFO]` badge as a clean one, and a model call that failed left a page with no
findings and no flag. This document describes how a run now accounts for every
target it was given.

## The evaluation state

Every result carries an `evaluation` state and a derived `evaluated` boolean.
The state encodes what the run **asked for** as well as what happened, so the
boolean is exact: `evaluated` means "every stage this run promised ran to
completion for this target".

| `evaluation` | `evaluated` | Meaning |
| --- | --- | --- |
| `analysed` | yes | The model returned a usable verdict for the screenshot |
| `captured` | yes | Screenshot taken; no model was requested (`--no-ai`) |
| `status_only` | yes | No browser was requested (`--no-visual-check`); the status check ran |
| `analysis_failed` | no | The model was asked and failed, or answered unusably twice |
| `capture_failed` | no | The browser produced no usable screenshot (timeout, network error, Chromium's own error page) |
| `skipped` | no | Skipped before any stage ran — `--respect-robots` said no |
| `error` | no | An unexpected exception stopped the pipeline for this target |

Two consequences worth spelling out:

- A **status-only run that found a host unreachable did evaluate it** — the
  check ran and produced a verdict. Whether that verdict is acceptable is
  `--fail-on-status`'s question, not coverage's.
- A page with **content-check findings but no model verdict** is
  `analysis_failed` or `captured`, not `analysed`. The findings are real and
  are reported; the page was still not judged the way the run promised.

Results built outside the scanner — a hand-assembled report, a loader — have an
empty state and are neither evaluated nor unevaluated; they never trip the gate.

## Where it shows

**Console.** An unevaluated target says so before anything else about it, and
the summary lists them with the reason:

```
[INFO] https://api.example/internal/
  status: 200 ok  (0.31s)
  not evaluated: analysis failed
  HTTP 200  title='Internal API'
  screenshot: scan-output/screenshots/0003-api.example-internal-9f2a1c0b4e.png
  analysis error: HTTP 502: upstream connect error

2 target(s) were not evaluated:
  https://api.example/internal/ — analysis failed (analysis error: HTTP 502: upstream connect error)
  https://old.example/ — skipped (disallowed by robots.txt)
```

The statistics block gains `evaluated` and `not evaluated` rows.

**JSON.** `evaluation_counts` and `unevaluated_count` at the top level;
`evaluation` and `evaluated` on every result.

**CSV.** `evaluation` and `evaluated` columns.

**HTML.** An "evaluated / not evaluated" card pair, and a red pill on each
unevaluated result.

**statistics.txt.** A `Coverage` block.

**Email.** The subject counts them (`2 not evaluated`), the body lists them,
and an unevaluated target is enough to send the mail — a run that did not look
at something is not a quiet run.

## The gate

```bash
python -m secman_visual_check -f targets.txt --fail-on high --fail-on-unevaluated
```

`--fail-on-unevaluated` exits `1` when any target is unevaluated. It sits
beside `--fail-on` and `--fail-on-status`; the exit code is `1` when any of the
three trips, `2` for configuration errors, `0` otherwise. Use it in CI when the
promise is "every endpoint on this list was looked at", which is a different
promise from "nothing was found".

Note that `--respect-robots` skips count as unevaluated. If a robots-excluded
URL should not fail the gate, take it off the list rather than relaxing the
gate: the list is the promise.

## What the scanner does to keep coverage high

- The **status check runs first and outside the browser's concurrency
  slot**, so a target has a status even when Chromium then dies on it.
- A **model reply with no parseable JSON is re-requested once** before the
  target is recorded as `analysis_failed`. Transport errors were already
  retried with backoff; this covers the model answering in prose.
- The **content check runs regardless of the model's outcome**, so a failed
  call still yields the deterministic findings the page's text supports.
- **Nothing aborts the run.** A failure in any stage is recorded on the target
  and the next target proceeds. `--fail-on-unevaluated` is how the failure
  becomes a build failure.
