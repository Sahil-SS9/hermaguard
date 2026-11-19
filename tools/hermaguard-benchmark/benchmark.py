#!/usr/bin/env python3
"""
Hermaguard Benchmark — Score HermaGuard against known bug dataset.

The benchmark does NOT run HermaGuard itself (it's a skill, not a binary).
Instead, it scores JSON output that any harness produces.

Usage:
    # 1. Run HermaGuard via your harness, capture JSON output per bug
    #    (e.g., Claude Code: claude -p "/hermaguard --json" > results/bug-001.json)
    #    (e.g., Codex CLI: codex exec --prompt "/hermaguard --json" > results/bug-001.json)
    #    (e.g., Hermes Agent: run skill, save JSON output)

    # 2. Score the results against ground truth
    benchmark.py --score --results results/ --bugs bugs/ --output report.html

    # 3. Score a single bug
    benchmark.py --score --result results/bug-001.json --bug bugs/001-sql-injection

The neutral path: any harness emits the --json report, then benchmark.py --score
against ground truth. No assumption about which CLI or framework runs HermaGuard.

Scorer versions (a result keeps the version it was scored under):
    1  original keyword scorer      - ground-truth classes ignored, basename file match
    2  class + basename scorer      - class intersection, basename match, blank file passes
    3  strict scorer (the default)  - class intersection AND exact normalised repo-relative
                                      path AND a symbol / region / outcome locator. A blank
                                      path never matches. No output and no completed checks
                                      is INCOMPLETE, never a true negative.
Pin a version with --scorer-version, a `scorer_version` field in a result file, or a
results/MANIFEST.json. The committed reference results are pinned to version 1.

Besides the defect corpus (bugs/), an optional extended/ directory holds clean
lookalikes, repaired twins and multi-file cases (version 3 only). Counts are reported
separately: defects found / missed, clean code wrongly accused, incomplete runs.
"""

import argparse
import json
import os
import posixpath
import re
import statistics
import sys
from datetime import datetime
from pathlib import Path

VERSION = "2.0.0"
CURRENT_SCORER_VERSION = 3
SCORER_NOTES = {
    1: "original keyword scorer (classes ignored, basename file match)",
    2: "class intersection + basename file match (blank file passes)",
    3: "class + exact repo-relative path + locator; incomplete runs are never true negatives",
}
INCOMPLETE_STATUSES = {"interrupted", "timeout", "timed_out", "crashed", "partial", "incomplete", "aborted"}
DEFAULT_LINE_TOLERANCE = 3


def discover_bugs(bugs_dir: str) -> list:
    """Find all bug directories containing ground-truth.json."""
    bugs = []
    for entry in sorted(Path(bugs_dir).iterdir()):
        if entry.is_dir() and (entry / "ground-truth.json").exists():
            bugs.append(str(entry))
    return bugs


def load_bug(bug_dir: str) -> dict:
    """Load a bug's ground truth and metadata."""
    gt_path = os.path.join(bug_dir, "ground-truth.json")
    readme_path = os.path.join(bug_dir, "README.md")

    with open(gt_path) as f:
        gt = json.load(f)

    readme = ""
    if os.path.exists(readme_path):
        with open(readme_path) as f:
            readme = f.read()

    return {
        "id": os.path.basename(bug_dir),
        "title": gt.get("title", os.path.basename(bug_dir)),
        "description": gt.get("description", ""),
        "severity": gt.get("severity", "UNKNOWN"),
        "category": gt.get("category", "unknown"),
        "expected_findings": gt.get("findings", []),
        "kind": gt.get("kind", "bug"),                 # "bug" | "clean"
        "control_type": gt.get("control_type"),        # lookalike | repaired_twin
        "twin_of": gt.get("twin_of"),
        "repo_root": gt.get("repo_root", "code"),
        "pre_diff": os.path.join(bug_dir, "pre.diff"),
        "post_diff": os.path.join(bug_dir, "post.diff"),
        "repo_path": os.path.join(bug_dir, "repo"),
        "readme": readme,
    }


def _file_matches(exp_file: str, found_file: str) -> bool:
    """Deterministic file match on basename. Empty either side = pass-through."""
    if not exp_file or not found_file:
        return True
    return os.path.basename(exp_file) == os.path.basename(found_file)


def _class_matches(exp: dict, fnd: dict) -> bool:
    """Deterministic class match: both sides carry `classes` and they intersect."""
    exp_classes = exp.get("classes") or []
    fnd_classes = fnd.get("classes") or []
    if not exp_classes or not fnd_classes:
        return False  # not class-matchable — caller falls back to keywords
    return bool(set(exp_classes) & set(fnd_classes))


def _score_legacy(bug: dict, run_info: dict, scorer_version: int = 2) -> dict:
    """Scorer versions 1 and 2 (frozen). Score a run against ground truth.

    Matching is two-tier and deterministic:
      Tier 1 (preferred): class-based — ground truth entries carry `classes`
      (CWE/HG ids) and findings carry `classes`; a match requires a non-empty
      class intersection AND a basename file match. No thresholds, no fuzzy
      scores. Identical inputs always produce identical results.
      Tier 2 (legacy fallback): keyword overlap for old results that predate
      the classes field. Threshold fixed at 0.3, severity boost 1.3 — kept ONLY
      for backward compatibility; new ground truth must carry classes.
    """
    expected = bug.get("expected_findings", [])
    if scorer_version == 1:
        # Original keyword scorer: ignore ground-truth classes entirely.
        expected = [{k: v for k, v in e.items() if k != "classes"} for e in expected]
    found = run_info.get("findings", [])

    matched_expected = set()
    matched_found = set()
    matches = []
    match_modes = {"class": 0, "keyword": 0}

    for i, exp in enumerate(expected):
        # ---- Tier 1: deterministic class match ----
        if exp.get("classes"):
            for j, fnd in enumerate(found):
                if j in matched_found:
                    continue
                if _class_matches(exp, fnd) and _file_matches(exp.get("file", ""), fnd.get("file", "")):
                    matched_expected.add(i)
                    matched_found.add(j)
                    match_modes["class"] += 1
                    matches.append({
                        "expected_id": f"EXP-{i+1}",
                        "found_id": fnd.get("id", f"HG-{j+1}"),
                        "mode": "class",
                        "matched_classes": sorted(set(exp["classes"]) & set(fnd.get("classes") or [])),
                        "expected_severity": exp.get("severity", "?"),
                        "found_severity": fnd.get("severity", "?"),
                        "expected_file": exp.get("file", "?"),
                        "found_file": fnd.get("file", "?"),
                    })
                    break
            continue  # class-carrying entries never fall through to keywords

        # ---- Tier 2: legacy keyword fallback ----
        exp_text = f"{exp.get('file','')} {exp.get('trigger','')} {exp.get('description','')}".lower()
        best_score = 0
        best_j = -1

        for j, fnd in enumerate(found):
            if j in matched_found:
                continue
            fnd_text = f"{fnd.get('file','')} {fnd.get('trigger_condition','')} {fnd.get('consequence','')}".lower()

            # Simple keyword overlap score
            exp_words = set(exp_text.split())
            fnd_words = set(fnd_text.split())
            if not exp_words or not fnd_words:
                continue
            overlap = len(exp_words & fnd_words) / min(len(exp_words), len(fnd_words))

            # Boost: same severity
            if exp.get("severity") == fnd.get("severity"):
                overlap *= 1.3

            if overlap > best_score:
                best_score = overlap
                best_j = j

        if best_score > 0.3 and best_j >= 0:  # threshold for a "match"
            matched_expected.add(i)
            matched_found.add(best_j)
            matched_fnd = found[best_j]
            match_modes["keyword"] += 1
            matches.append({
                "expected_id": f"EXP-{i+1}",
                "found_id": matched_fnd.get("id", f"HG-{best_j+1}"),
                "mode": "keyword",
                "score": round(best_score, 2),
                "expected_severity": exp.get("severity", "?"),
                "found_severity": matched_fnd.get("severity", "?"),
                "expected_file": exp.get("file", "?"),
                "found_file": matched_fnd.get("file", "?"),
            })

    total_expected = len(expected)
    total_found = len(found)
    true_positives = len(matched_expected)
    false_negatives = total_expected - true_positives
    false_positives = total_found - len(matched_found)

    precision = round(true_positives / total_found * 100, 1) if total_found > 0 else 0
    recall = round(true_positives / total_expected * 100, 1) if total_expected > 0 else 0
    f1 = round(2 * precision * recall / (precision + recall), 1) if (precision + recall) > 0 else 0

    # Severity accuracy
    severity_matches = 0
    for m in matches:
        if m["expected_severity"] == m["found_severity"]:
            severity_matches += 1
    severity_accuracy = round(severity_matches / len(matches) * 100, 1) if matches else 0

    return {
        "bug_id": bug["id"],
        "bug_title": bug["title"],
        "bug_severity": bug["severity"],
        "bug_category": bug["category"],
        "expected_findings": total_expected,
        "found_findings": total_found,
        "true_positives": true_positives,
        "false_negatives": false_negatives,
        "false_positives": false_positives,
        "precision_pct": precision,
        "recall_pct": recall,
        "f1_score": f1,
        "severity_accuracy_pct": severity_accuracy,
        "matches": matches,
        "match_modes": match_modes,
        # A result file without an explicit run_ok flag is treated as a
        # completed run (backward compat) UNLESS it carries an error key —
        # a crashed run must never be scored as OK.
        "run_ok": bool(run_info.get("run_ok", not run_info.get("error"))),
        "run_error": run_info.get("error"),
        "scorer_version": scorer_version,
        "kind": "bug",
        "graded": bool(run_info.get("run_ok", not run_info.get("error"))),
        "duplicates": 0,
        "false_accusations": 0,
        "incomplete_reason": None if run_info.get("run_ok", not run_info.get("error")) else "run not ok",
        "usage": run_info.get("usage"),
    }


# ---------------------------------------------------------------------------
# Scorer version 3: strict location, controls, incomplete runs
# ---------------------------------------------------------------------------

def normalise_path(path, repo_root=None) -> str:
    """Normalise a reported path to a repo-relative posix path ('' if unusable).

    Absolute paths and paths that climb out of the repo are unusable. A leading
    `repo_root/` (the fixture layout, `code/`) is stripped so a harness that ran
    from the case directory still matches. Basenames alone are NOT enough.
    """
    text = str(path or "").strip().replace("\\", "/")
    if not text or text.startswith("/") or re.match(r"^[A-Za-z]:/", text):
        return ""
    norm = posixpath.normpath(text)
    if norm in (".", "..") or norm.startswith("../"):
        return ""
    if repo_root:
        prefix = repo_root.strip("/") + "/"
        if norm.startswith(prefix):
            norm = norm[len(prefix):]
    return norm


def _to_int(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def finding_lines(fnd: dict):
    """(start, end) from `line`, `line_start` or `line_range` ('42' or '42-58'), else None."""
    rng = fnd.get("line_range")
    if isinstance(rng, str) and rng.strip():
        parts = re.split(r"\s*[-:]\s*", rng.strip())
        start = _to_int(parts[0])
        end = _to_int(parts[1]) if len(parts) > 1 else start
        if start is not None:
            return start, end if end is not None else start
    for key in ("line", "line_start"):
        n = _to_int(fnd.get(key))
        if n is not None:
            return n, n
    return None


def finding_text(fnd: dict) -> str:
    keys = ("trigger_condition", "consequence", "recommendation", "message", "title", "description")
    return " ".join(str(fnd.get(k, "")) for k in keys).lower()


def locator_status(exp: dict, fnd: dict):
    """True / False if the expected entry names a locator, None if it names none."""
    checks = []
    symbol = exp.get("symbol")
    if symbol:
        text = finding_text(fnd) + " " + str(fnd.get("symbol", "")).lower()
        checks.append(fnd.get("symbol") == symbol
                      or re.search(r"\b" + re.escape(symbol.lower()) + r"\b", text) is not None)
    region = exp.get("region")
    if isinstance(region, dict) and _to_int(region.get("start")) is not None:
        start = _to_int(region["start"])
        end = _to_int(region.get("end")) if _to_int(region.get("end")) is not None else start
        tol = _to_int(exp.get("line_tolerance"))
        tol = DEFAULT_LINE_TOLERANCE if tol is None else tol
        lines = finding_lines(fnd)
        checks.append(lines is not None and lines[0] <= end + tol and lines[1] >= start - tol)
    words = exp.get("outcome_keywords")
    if isinstance(words, list) and words:
        text = finding_text(fnd)
        checks.append(any(str(w).lower() in text for w in words))
    return any(checks) if checks else None


def strict_match(exp: dict, fnd: dict, repo_root=None) -> bool:
    exp_path = normalise_path(exp.get("file"), repo_root)
    fnd_path = normalise_path(fnd.get("file"), repo_root)
    if not exp_path or not fnd_path or exp_path != fnd_path:
        return False
    if not _class_matches(exp, fnd):
        return False
    return locator_status(exp, fnd) is not False


def run_completion(run_info: dict, findings: list):
    """(complete, reason). Absence of output is never evidence of a clean run."""
    if run_info.get("error"):
        return False, f"run reported an error: {str(run_info['error'])[:100]}"
    if run_info.get("run_ok") is False:
        return False, "run_ok is false"
    status = str(run_info.get("status", "")).lower()
    if status in INCOMPLETE_STATUSES:
        return False, f"run status is {status}"
    if not isinstance(run_info.get("findings"), list):
        return False, "result has no findings list (no output)"
    if findings:
        return True, None
    checks = run_info.get("checks_completed")
    if isinstance(checks, list) and checks:
        return True, None
    cov = run_info.get("coverage")
    if isinstance(cov, list) and cov:
        rows = [c for c in cov if isinstance(c, dict)]
        if any(c.get("status") in ("clean", "finding", "not_applicable") for c in rows) \
                and not any(c.get("status") in ("not_checked", "inconclusive") for c in rows):
            return True, None
    return False, "no findings and no completed checks recorded: no output is not a clean result"


def incomplete_score(bug: dict, reason: str, run_info: dict = None, scorer_version: int = 3) -> dict:
    expected = bug.get("expected_findings", [])
    return {
        "bug_id": bug["id"], "bug_title": bug["title"], "bug_severity": bug["severity"],
        "bug_category": bug["category"], "kind": bug.get("kind", "bug"),
        "control_type": bug.get("control_type"), "scorer_version": scorer_version,
        "graded": False, "run_ok": False, "run_error": reason, "incomplete_reason": reason,
        "outcome": "incomplete",
        "expected_findings": len(expected) if bug.get("kind", "bug") == "bug" else 0,
        "found_findings": len((run_info or {}).get("findings") or []) if isinstance((run_info or {}).get("findings"), list) else 0,
        "true_positives": 0, "false_positives": 0, "false_negatives": 0,
        "duplicates": 0, "false_accusations": 0,
        "precision_pct": 0, "recall_pct": 0, "f1_score": 0, "severity_accuracy_pct": 0,
        "matches": [], "match_modes": {"class": 0, "keyword": 0},
        "usage": (run_info or {}).get("usage"),
    }


def _score_strict(bug: dict, run_info: dict) -> dict:
    kind = bug.get("kind", "bug")
    expected = bug.get("expected_findings", [])
    raw = run_info.get("findings")
    found = [f for f in raw if isinstance(f, dict)] if isinstance(raw, list) else []
    complete, reason = run_completion(run_info, found)
    if not complete:
        return incomplete_score(bug, reason, run_info)
    repo_root = bug.get("repo_root", "code")

    base = {
        "bug_id": bug["id"], "bug_title": bug["title"], "bug_severity": bug["severity"],
        "bug_category": bug["category"], "kind": kind, "control_type": bug.get("control_type"),
        "scorer_version": 3, "graded": True, "run_ok": True, "run_error": None,
        "incomplete_reason": None, "found_findings": len(found), "usage": run_info.get("usage"),
        "partial_coverage": any(isinstance(c, dict) and c.get("status") in ("not_checked", "inconclusive")
                                for c in (run_info.get("coverage") or [])),
    }
    if kind == "clean":
        return dict(base, outcome="falsely_accused" if found else "clean_ok", expected_findings=0,
                    true_positives=0, false_positives=0, false_negatives=0, duplicates=0,
                    false_accusations=len(found), precision_pct=0, recall_pct=0, f1_score=0,
                    severity_accuracy_pct=0, matches=[], match_modes={"class": 0, "keyword": 0},
                    accusations=[{"found_id": f.get("id", f"HG-{i+1}"), "file": f.get("file", "?"),
                                  "classes": f.get("classes") or []} for i, f in enumerate(found)])

    for i, exp in enumerate(expected):
        if not normalise_path(exp.get("file"), repo_root) or not exp.get("classes"):
            return incomplete_score(bug, f"ground-truth entry {i+1} needs a repo-relative file and classes "
                                          "for scorer 3", run_info)

    matched_expected, matched_found, matches = set(), set(), []
    for i, exp in enumerate(expected):
        for j, fnd in enumerate(found):
            if j in matched_found or not strict_match(exp, fnd, repo_root):
                continue
            matched_expected.add(i)
            matched_found.add(j)
            matches.append({
                "expected_id": f"EXP-{i+1}", "found_id": fnd.get("id", f"HG-{j+1}"), "mode": "strict",
                "matched_classes": sorted(set(exp["classes"]) & set(fnd.get("classes") or [])),
                "expected_severity": exp.get("severity", "?"), "found_severity": fnd.get("severity", "?"),
                "expected_file": exp.get("file", "?"), "found_file": fnd.get("file", "?"),
                "locator": "symbol/region/outcome" if locator_status(exp, fnd) else "path+class",
            })
            break

    duplicates = 0
    for j, fnd in enumerate(found):
        if j in matched_found:
            continue
        if any(strict_match(expected[i], fnd, repo_root) for i in matched_expected):
            duplicates += 1  # a second report of a root cause already credited
    false_positives = len(found) - len(matched_found) - duplicates
    tp = len(matched_expected)
    fn = len(expected) - tp
    counted = tp + false_positives
    precision = round(tp / counted * 100, 1) if counted else 0
    recall = round(tp / len(expected) * 100, 1) if expected else 0
    f1 = round(2 * precision * recall / (precision + recall), 1) if (precision + recall) else 0
    sev_ok = sum(1 for m in matches if m["expected_severity"] == m["found_severity"])
    outcome = "found_all" if tp == len(expected) else ("found_some" if tp else "missed")
    return dict(base, outcome=outcome, expected_findings=len(expected), true_positives=tp,
                false_positives=false_positives, false_negatives=fn, duplicates=duplicates,
                false_accusations=0, precision_pct=precision, recall_pct=recall, f1_score=f1,
                severity_accuracy_pct=round(sev_ok / len(matches) * 100, 1) if matches else 0,
                matches=matches, match_modes={"class": 0, "keyword": 0, "strict": tp})


def resolve_scorer_version(run_info: dict, override=None, default=None) -> int:
    """override (CLI) > the result's own `scorer_version` > default (manifest) > current."""
    for candidate in (override, (run_info or {}).get("scorer_version"), default):
        try:
            v = int(candidate)
        except (TypeError, ValueError):
            continue
        if v in SCORER_NOTES:
            return v
    return CURRENT_SCORER_VERSION


def score_run(bug: dict, run_info: dict, scorer_version=None) -> dict:
    """Score one run. The version used is recorded in the result as `scorer_version`."""
    version = resolve_scorer_version(run_info, scorer_version)
    if version >= 3:
        return _score_strict(bug, run_info)
    if bug.get("kind", "bug") == "clean":
        return incomplete_score(bug, "clean controls need scorer version 3", run_info, version)
    return _score_legacy(bug, run_info, version)


def _median(values):
    values = [v for v in values if isinstance(v, (int, float))]
    return round(statistics.median(values), 3) if values else None


def summarise(scores: list) -> dict:
    """Separate counts. found + missed + ungraded always equals expected_total."""
    defects = [s for s in scores if s.get("kind", "bug") == "bug"]
    controls = [s for s in scores if s.get("kind") == "clean"]
    graded_defects = [s for s in defects if s.get("graded", s.get("run_ok"))]
    expected_total = sum(s["expected_findings"] for s in defects)
    found = sum(s["true_positives"] for s in graded_defects)
    missed = sum(s["false_negatives"] for s in graded_defects)
    ungraded = sum(s["expected_findings"] for s in defects if s not in graded_defects)
    graded_controls = [s for s in controls if s.get("graded")]
    usage = [s["usage"] for s in scores if isinstance(s.get("usage"), dict)]
    return {
        "scorer_versions": sorted({s.get("scorer_version", 2) for s in scores}),
        "cases_total": len(scores),
        "cases_graded": len(graded_defects) + len(graded_controls),
        "cases_incomplete": sum(1 for s in scores if not s.get("graded", s.get("run_ok"))),
        "defects": {
            "cases": len(defects), "expected": expected_total, "found": found, "missed": missed,
            "ungraded_in_incomplete_runs": ungraded,
            "recall_all_pct": round(found / expected_total * 100, 1) if expected_total else None,
            "recall_graded_pct": round(found / (found + missed) * 100, 1) if (found + missed) else None,
            "extra_findings": sum(s["false_positives"] for s in graded_defects),
            "duplicate_findings": sum(s.get("duplicates", 0) for s in graded_defects),
        },
        "controls": {
            "cases": len(controls), "graded": len(graded_controls),
            "clean_ok": sum(1 for s in graded_controls if s["outcome"] == "clean_ok"),
            "wrongly_accused": sum(1 for s in graded_controls if s["outcome"] == "falsely_accused"),
            "false_accusation_findings": sum(s["false_accusations"] for s in graded_controls),
            "incomplete": len(controls) - len(graded_controls),
        },
        "incomplete": [{"id": s["bug_id"], "kind": s.get("kind", "bug"), "reason": s.get("incomplete_reason") or s.get("run_error")}
                       for s in scores if not s.get("graded", s.get("run_ok"))],
        "usage_not_scored": {
            "runs_with_usage": len(usage),
            "seconds_median": _median([u.get("seconds") for u in usage]),
            "turns_median": _median([u.get("turns") for u in usage]),
            "cost_usd_total": round(sum(u.get("cost_usd", 0) or 0 for u in usage), 4) if usage else None,
        },
    }


def lint_corpus(bug_dirs: list) -> list:
    """Problems in ground truth that make scorer 3 unable to grade a case."""
    problems = []
    for d in bug_dirs:
        bug = load_bug(d)
        if bug["kind"] == "clean":
            if bug["expected_findings"]:
                problems.append(f"{bug['id']}: clean case lists expected findings")
            continue
        for i, e in enumerate(bug["expected_findings"]):
            if not normalise_path(e.get("file"), bug["repo_root"]):
                problems.append(f"{bug['id']}[{i}]: no usable repo-relative file")
            if not e.get("classes"):
                problems.append(f"{bug['id']}[{i}]: no classes")
            if not (e.get("symbol") or e.get("region") or e.get("outcome_keywords")):
                problems.append(f"{bug['id']}[{i}]: no symbol, region or outcome_keywords")
    return problems


def generate_report(scores: list, output_path: str):
    """Generate HTML benchmark report."""
    total_bugs = len(scores)
    summary = summarise(scores)
    ok_runs = [s for s in scores if s.get("graded", s["run_ok"]) and s.get("kind", "bug") == "bug"]
    avg_precision = round(sum(s["precision_pct"] for s in ok_runs) / len(ok_runs), 1) if ok_runs else 0
    avg_recall = round(sum(s["recall_pct"] for s in ok_runs) / len(ok_runs), 1) if ok_runs else 0
    avg_f1 = round(sum(s["f1_score"] for s in ok_runs) / len(ok_runs), 1) if ok_runs else 0
    avg_severity = round(sum(s["severity_accuracy_pct"] for s in ok_runs) / len(ok_runs), 1) if ok_runs else 0

    total_fp = sum(s["false_positives"] for s in ok_runs)
    total_fn = sum(s["false_negatives"] for s in ok_runs)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HermaGuard Benchmark — {datetime.now().strftime('%d/%m/%Y')}</title>
<style>
  :root {{ color-scheme: dark; }}
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ background:#11100f; color:#f5f5f4; font-family:system-ui,sans-serif; line-height:1.6; padding:2rem; }}
  h1 {{ color:#fbbf24; font-size:1.5rem; margin-bottom:0.5rem; }}
  .subtitle {{ color:#a8a29e; font-size:0.9rem; margin-bottom:2rem; }}
  .summary {{ display:flex; gap:1.5rem; margin:1.5rem 0; flex-wrap:wrap; }}
  .stat {{ background:#1c1a18; border:1px solid #34302c; border-radius:6px; padding:1rem 1.25rem; }}
  .stat-value {{ font-size:1.5rem; font-weight:700; color:#fbbf24; }}
  .stat-label {{ font-size:0.8rem; color:#a8a29e; }}
  .good {{ color:#22c55e; }} .warn {{ color:#fbbf24; }} .bad {{ color:#ef4444; }}
  table {{ width:100%; border-collapse:collapse; margin:1.5rem 0; }}
  th, td {{ padding:0.6rem 0.8rem; text-align:left; border-bottom:1px solid #34302c; }}
  th {{ color:#a8a29e; font-size:0.85rem; font-weight:600; }}
  td {{ font-size:0.9rem; }}
  .bug-title {{ max-width:300px; }}
  .match {{ color:#22c55e; }} .miss {{ color:#ef4444; }}
  .error-row {{ background:#3b1111; }}
  h2 {{ color:#fbbf24; margin:2rem 0 1rem; padding-bottom:0.5rem; border-bottom:1px solid #34302c; }}
  .footer {{ margin-top:3rem; padding-top:1rem; border-top:1px solid #34302c; color:#78716c; font-size:0.8rem; }}
</style>
</head>
<body>

<h1>HermaGuard Benchmark</h1>
<div class="subtitle">{datetime.now().strftime('%d/%m/%Y %H:%M')} · {total_bugs} bugs · v{VERSION}</div>

<div class="summary">
  <div class="stat"><div class="stat-value">{avg_f1}<span style="font-size:0.8rem">%</span></div><div class="stat-label">Avg F1 Score</div></div>
  <div class="stat"><div class="stat-value">{avg_recall}<span style="font-size:0.8rem">%</span></div><div class="stat-label">Avg Recall</div></div>
  <div class="stat"><div class="stat-value">{avg_precision}<span style="font-size:0.8rem">%</span></div><div class="stat-label">Avg Precision</div></div>
  <div class="stat"><div class="stat-value">{avg_severity}<span style="font-size:0.8rem">%</span></div><div class="stat-label">Severity Accuracy</div></div>
  <div class="stat"><div class="stat-value">{total_fp}</div><div class="stat-label">False Positives</div></div>
  <div class="stat"><div class="stat-value">{total_fn}</div><div class="stat-label">False Negatives</div></div>
</div>

<h2>Separate counts</h2>
<p class="subtitle">Scorer version(s): {', '.join(str(v) for v in summary['scorer_versions'])}. Found + missed + ungraded always equals expected. Averages above are over graded defect cases only; incomplete runs are listed below, never counted as clean or as true negatives.</p>
<div class="summary">
  <div class="stat"><div class="stat-value good">{summary['defects']['found']}</div><div class="stat-label">Defects found (of {summary['defects']['expected']})</div></div>
  <div class="stat"><div class="stat-value bad">{summary['defects']['missed']}</div><div class="stat-label">Defects missed</div></div>
  <div class="stat"><div class="stat-value warn">{summary['defects']['ungraded_in_incomplete_runs']}</div><div class="stat-label">Expected defects in incomplete runs</div></div>
  <div class="stat"><div class="stat-value bad">{summary['controls']['wrongly_accused']}</div><div class="stat-label">Clean cases wrongly accused (of {summary['controls']['cases']})</div></div>
  <div class="stat"><div class="stat-value">{summary['controls']['clean_ok']}</div><div class="stat-label">Clean cases correctly clear</div></div>
  <div class="stat"><div class="stat-value warn">{summary['cases_incomplete']}</div><div class="stat-label">Incomplete / ungraded runs</div></div>
  <div class="stat"><div class="stat-value">{summary['defects']['extra_findings']}</div><div class="stat-label">Extra findings on defect cases</div></div>
  <div class="stat"><div class="stat-value">{summary['defects']['duplicate_findings']}</div><div class="stat-label">Duplicate reports (not penalised)</div></div>
</div>
{''.join(f"<p class='miss'>Incomplete: {i['id']} ({i['kind']}) - {str(i['reason'])[:120]}</p>" for i in summary['incomplete'])}
{(f"<p class='subtitle'>Usage, not part of the score: {summary['usage_not_scored']['runs_with_usage']} run(s), median {summary['usage_not_scored']['seconds_median']}s, median {summary['usage_not_scored']['turns_median']} turns, total cost ${summary['usage_not_scored']['cost_usd_total']}</p>") if summary['usage_not_scored']['runs_with_usage'] else ''}

<h2>Results by Bug</h2>
<table>
<tr><th>Bug</th><th>Severity</th><th>Expected</th><th>Found</th><th>TP</th><th>FP</th><th>FN</th><th>Precision</th><th>Recall</th><th>F1</th><th>Sev Acc</th></tr>
"""

    for s in scores:
        if not s["run_ok"]:
            html += f"""<tr class="error-row"><td class="bug-title">{s['bug_title'][:60]}</td>
<td>-</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td><td colspan="4">INCOMPLETE: {str(s.get('run_error') or 'Unknown')[:100]}</td></tr>\n"""
            continue

        if s.get("kind") == "clean":
            verdict = "wrongly accused" if s["outcome"] == "falsely_accused" else "correctly clear"
            cls = "miss" if s["outcome"] == "falsely_accused" else "match"
            html += f"""<tr><td class="bug-title">{s['bug_title'][:60]} <em>({s.get('control_type') or 'control'})</em></td>
<td>none</td><td>0</td><td>{s['found_findings']}</td><td colspan="7" class="{cls}">{verdict}: {s['false_accusations']} finding(s) reported</td></tr>\n"""
            continue

        pcls = "good" if s["precision_pct"] >= 70 else ("warn" if s["precision_pct"] >= 40 else "bad")
        rcls = "good" if s["recall_pct"] >= 70 else ("warn" if s["recall_pct"] >= 40 else "bad")
        fcls = "good" if s["f1_score"] >= 70 else ("warn" if s["f1_score"] >= 40 else "bad")

        html += f"""<tr>
<td class="bug-title">{s['bug_title'][:60]}</td>
<td>{s['bug_severity']}</td>
<td>{s['expected_findings']}</td>
<td>{s['found_findings']}</td>
<td class="match">{s['true_positives']}</td>
<td class="miss">{s['false_positives']}</td>
<td class="miss">{s['false_negatives']}</td>
<td class="{pcls}">{s['precision_pct']}%</td>
<td class="{rcls}">{s['recall_pct']}%</td>
<td class="{fcls}">{s['f1_score']}%</td>
<td>{s['severity_accuracy_pct']}%</td>
</tr>\n"""

    html += "</table>\n"

    # Detailed matches for each bug
    html += "<h2>Match Details</h2>\n"
    for s in scores:
        if not s["run_ok"] or s.get("kind") == "clean":
            continue
        html += f"<h3>{s['bug_title'][:80]} ({s['bug_severity']})</h3>\n"
        if s["matches"]:
            html += "<table><tr><th>Expected</th><th>Found</th><th>Sev Match</th><th>Score</th></tr>\n"
            for m in s["matches"]:
                sev_match = "✓" if m["expected_severity"] == m["found_severity"] else "✗"
                html += f"""<tr><td>{m['expected_file']} ({m['expected_severity']})</td>
<td>{m['found_file'][:50]} ({m['found_severity']})</td><td>{sev_match}</td><td>{m.get('score', m.get('mode', '-'))}</td></tr>\n"""
            html += "</table>\n"
        else:
            html += "<p class='miss'>No matches — all findings missed or all expected bugs not found.</p>\n"

        if s.get("matches"):
            # Unmatched expected (FN)
            matched_exp_ids = {m["expected_id"] for m in s["matches"]}
            unmatched_exp = s.get("expected_findings_count", s["expected_findings"]) - len(matched_exp_ids)
            if unmatched_exp > 0:
                html += f"<p class='miss'>{unmatched_exp} expected bug{'s' if unmatched_exp > 1 else ''} not found (false negative).</p>\n"

    html += f"""<div class="footer">
HermaGuard Benchmark v{VERSION} · Generated {datetime.now().isoformat()}
</div>
</body></html>"""

    with open(output_path, "w") as f:
        f.write(html)

    print(f"Report written to {output_path}")
    return output_path


def _load_manifest_version(results_dir: str):
    path = os.path.join(results_dir, "MANIFEST.json")
    try:
        with open(path) as f:
            return json.load(f).get("scorer_version")
    except (OSError, ValueError):
        return None


def main():
    parser = argparse.ArgumentParser(description="HermaGuard Benchmark — score JSON output against ground truth")
    parser.add_argument("--bugs", default="bugs/", help="Path to bugs directory")
    parser.add_argument("--extended", help="Extended corpus (clean lookalikes, repaired twins, multi-file cases). "
                                           "Default: <bugs>/../extended if present. Scorer 3 only.")
    parser.add_argument("--bug", help="Score a single bug by path")
    parser.add_argument("--results", default="results/", help="Directory containing per-bug JSON result files")
    parser.add_argument("--result", help="Single result JSON file (use with --bug)")
    parser.add_argument("--output", default="report.html", help="HTML report output path")
    parser.add_argument("--scorer-version", type=int, choices=sorted(SCORER_NOTES),
                        help="Force a scorer version (default: the result's own field, then "
                             "results/MANIFEST.json, then the current version)")
    parser.add_argument("--summary-json", help="Also write the separate counts as JSON")
    parser.add_argument("--lint-corpus", action="store_true",
                        help="Report ground-truth entries scorer 3 cannot grade, then exit")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")

    args = parser.parse_args()

    if args.bug and args.result:
        # Single bug mode
        bug = load_bug(args.bug)
        with open(args.result) as f:
            run_info = json.load(f)
        s = score_run(bug, run_info, args.scorer_version)
        status = "✓" if s["run_ok"] else "✗"
        print(f"  {status} {bug['title'][:60]} — P:{s['precision_pct']}% R:{s['recall_pct']}% F1:{s['f1_score']}% (scorer {s['scorer_version']})")
        return

    bugs = discover_bugs(args.bugs)
    if not bugs:
        print(f"No bugs found in {args.bugs}")
        sys.exit(1)

    extended_dir = args.extended
    if extended_dir is None:
        guess = os.path.join(os.path.dirname(os.path.normpath(args.bugs)), "extended")
        extended_dir = guess if os.path.isdir(guess) else None
    extended = discover_bugs(extended_dir) if extended_dir else []

    if args.lint_corpus:
        problems = lint_corpus(bugs + extended)
        for pr in problems:
            print(f"  problem: {pr}")
        print(f"{len(bugs) + len(extended)} case(s) checked, {len(problems)} problem(s)")
        sys.exit(1 if problems else 0)

    manifest_version = _load_manifest_version(args.results)
    print(f"Found {len(bugs)} bug(s)" + (f" + {len(extended)} extended case(s)" if extended else ""))

    scores = []
    skipped_extended = False
    for bug_dir in bugs + extended:
        bug = load_bug(bug_dir)
        is_extended = bug_dir in extended
        result_path = os.path.join(args.results, f"{bug['id']}.json")
        run_info = None
        if os.path.exists(result_path):
            try:
                with open(result_path) as f:
                    run_info = json.load(f)
            except ValueError:
                run_info = None
        version = resolve_scorer_version(run_info or {}, args.scorer_version, manifest_version)
        if is_extended and version < 3:
            skipped_extended = True
            continue  # legacy scorers cannot grade controls; keep their denominators unchanged

        if run_info is not None:
            s = score_run(bug, run_info, version)
        else:
            reason = f"No results file at {result_path}"
            s = incomplete_score(bug, reason, None, version) if version >= 3 else {
                "bug_id": bug["id"], "bug_title": bug["title"],
                "bug_severity": bug["severity"], "bug_category": bug["category"],
                "run_ok": False, "run_error": reason, "graded": False, "kind": "bug",
                "scorer_version": version, "incomplete_reason": reason,
                "precision_pct": 0, "recall_pct": 0, "f1_score": 0,
                "expected_findings": len(bug["expected_findings"]), "found_findings": 0,
                "true_positives": 0, "false_positives": 0, "false_negatives": 0,
                "duplicates": 0, "false_accusations": 0,
                "severity_accuracy_pct": 0, "matches": [],
            }
        scores.append(s)
        if s["run_ok"]:
            if s.get("kind") == "clean":
                print(f"  ✓ {bug['title'][:60]} — {s['outcome']} (scorer {s['scorer_version']})")
            else:
                print(f"  ✓ {bug['title'][:60]} — P:{s['precision_pct']}% R:{s['recall_pct']}% F1:{s['f1_score']}% (scorer {s['scorer_version']})")
        else:
            print(f"  ✗ {bug['title'][:60]} — INCOMPLETE: {s.get('incomplete_reason')} (scorer {s['scorer_version']})")
    if skipped_extended:
        print("  (extended cases skipped: they need scorer version 3)")

    # Generate report. --output is taken literally (path doubling bug fixed);
    # create the parent dir so an explicit path like results/report.html works.
    report_path = args.output
    parent = os.path.dirname(report_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    generate_report(scores, report_path)

    summary = summarise(scores)
    if args.summary_json:
        with open(args.summary_json, "w") as f:
            json.dump(summary, f, indent=2)
    d, c = summary["defects"], summary["controls"]
    print(f"\nScorer version(s): {summary['scorer_versions']}")
    print(f"Defects: {d['found']} found, {d['missed']} missed, {d['ungraded_in_incomplete_runs']} in incomplete runs "
          f"(of {d['expected']} expected; recall {d['recall_all_pct']}% over all, {d['recall_graded_pct']}% over graded)")
    if c["cases"]:
        print(f"Controls: {c['clean_ok']} correctly clear, {c['wrongly_accused']} wrongly accused "
              f"({c['false_accusation_findings']} finding(s)), {c['incomplete']} incomplete (of {c['cases']})")
    print(f"Incomplete / ungraded runs: {summary['cases_incomplete']} of {summary['cases_total']}")
    ok = [s for s in scores if s["run_ok"] and s.get("kind", "bug") == "bug"]
    if ok:
        avg_f1 = round(sum(s["f1_score"] for s in ok) / len(ok), 1)
        print(f"Graded defect runs: {len(ok)}, avg F1: {avg_f1}%")
    elif not summary["cases_graded"]:
        print("All runs lack usable results. Run HermaGuard via your harness first, then score.")
        print("Example: run '/hermaguard --json' under any harness, save output to results/<bug-id>.json")

    print(f"Report: {report_path}")


if __name__ == "__main__":
    main()
