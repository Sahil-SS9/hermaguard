# Hermaguard Benchmark

Score-only. It does **not** run HermaGuard (that's a skill, not a binary). Your
harness produces a `--json` report per bug; this scores it against ground truth.

## Layout

- `bugs/<id>/` — the original corpus: 25 cases, one planted bug each. `code/app.py`
  (fixture, **no answer-key comments**), `pre.diff` (the change that introduced it),
  `ground-truth.json` (the finding a correct review should surface: `file`, `classes`,
  plus a `symbol` and `region` that locate it). This corpus is frozen.
- `extended/<id>/` — cases the original corpus cannot express (scorer 3 only):
  - `L*` **clean lookalikes**: code that looks like a bug at a glance and is not
    (`kind: "clean"`, no expected findings).
  - `T*` **repaired twins**: a corpus bug after its fix (`twin_of` names the original).
  - `M*` **multi-file / multi-defect** cases: the same filename in two directories, and
    two independent defects in one change.
- `results/<id>.json` — a harness's review output for that case. The committed ones are
  a **reference run**, see below, pinned to scorer 1 by `results/MANIFEST.json`.

## Run

```bash
python3 benchmark.py --bugs bugs --results results --output results/report.html
python3 benchmark.py --lint-corpus --bugs bugs        # ground truth the scorer cannot grade
python3 benchmark.py --bugs bugs --results my-run/ --scorer-version 3 --summary-json counts.json
```

## Scorer versions

Every score records the version it was produced under; results are never silently
re-scored. Resolution order: `--scorer-version`, then a `scorer_version` field in the
result file, then `results/MANIFEST.json`, then the current version (3).

| | Matching | Notes |
|---|---|---|
| 1 | original keyword scorer | ground-truth classes ignored, basename match. Scores the committed reference run. |
| 2 | class intersection + **basename** | a blank file on either side passed. Frozen. |
| 3 | class intersection + **exact normalised repo-relative path** + a symbol, region or outcome locator | a blank, absolute or escaping path never matches; line numbers may move (`line_tolerance`, default 3) but a different file never matches; a second report of a credited root cause is a duplicate, not a false positive |

Under version 3 the fixture layout prefix `code/` is stripped, so a harness that ran from
the case directory still matches; a basename on its own does not.

### Incomplete runs are not clean runs

Under version 3 a result is **incomplete** (ungraded, never a true negative) when it has
`run_ok: false`, an `error`, a `status` of `interrupted`/`timeout`/`partial`/`crashed`, no
`findings` list, or zero findings **without** evidence that checks ran. Evidence is a
non-empty `checks_completed` list, or a `coverage` array with at least one `clean` /
`finding` / `not_applicable` row and none `not_checked` / `inconclusive`.

### What is reported, separately

Defects found / missed / expected-but-in-an-incomplete-run (these always add up to the
expected total); extra findings and duplicates on defect cases; clean controls correctly
clear / wrongly accused (cases and findings); incomplete runs with reasons. Recall is
shown both over every expected defect and over graded cases only, so dropping cases from
the denominator is visible. Time, turns and cost (`usage: {seconds, turns, cost_usd}`)
are summarised on their own line and never enter the score. There is no quota for
findings: a reviewer that flags everything gets full recall and is penalised on the
controls.

## Reference run (committed in `results/`)

A single `claude-opus-4-8` harness reviewed the 5 fixtures. **Not blind:** the
corpus was authored and reviewed by the same agent, so recall here is an upper
bound. The corpus exists for blind runs by any harness, seed bugs authored by
someone other than the reviewer for an independent number.

| | Recall | Precision | F1 |
|---|---|---|---|
| 5 bugs (scorer 1) | 100% | 90% | 93.3% |

Read the denominator: only 5 of the 25 cases were ever run. Over all 25 expected defects
the same run is 5 found, 0 missed, 20 not run (20% recall over all, 100% over graded).
These five files carry no `classes`, `line` or `symbol`, so scorers 2 and 3 cannot credit
them; re-run a harness to get results scorer 3 can grade.

The one sub-100% precision (bug 001) is a real out-of-ground-truth finding (an
unclosed DB connection), not a hallucination. Each result file carries a
`provenance` block (model, mode, blind flag).
