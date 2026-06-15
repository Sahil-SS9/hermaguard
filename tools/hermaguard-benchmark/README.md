# Hermaguard Benchmark

Score-only. It does **not** run HermaGuard (that's a skill, not a binary). Your
harness produces a `--json` report per bug; this scores it against ground truth.

## Layout

- `bugs/<id>/` — one case per planted bug: `code/app.py` (fixture, **no answer-key
  comments**), `pre.diff` (the change that introduced it), `ground-truth.json`
  (the findings a correct review should surface).
- `results/<id>.json` — a harness's review output for that bug (the shape the
  scorer reads). The committed ones are a **reference run**, see below.

## Run

```bash
python3 benchmark.py --bugs bugs --results results --output results/report.html
```

## Reference run (committed in `results/`)

A single `claude-opus-4-8` harness reviewed the 5 fixtures. **Not blind:** the
corpus was authored and reviewed by the same agent, so recall here is an upper
bound. The corpus exists for blind runs by any harness, seed bugs authored by
someone other than the reviewer for an independent number.

| | Recall | Precision | F1 |
|---|---|---|---|
| 5 bugs | 100% | 90% | 93.3% |

The one sub-100% precision (bug 001) is a real out-of-ground-truth finding (an
unclosed DB connection), not a hallucination. Each result file carries a
`provenance` block (model, mode, blind flag).
