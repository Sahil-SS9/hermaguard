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
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

VERSION = "1.0.0"


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


def score_run(bug: dict, run_info: dict) -> dict:
    """Score a run against ground truth.

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
    }


def generate_report(scores: list, output_path: str):
    """Generate HTML benchmark report."""
    total_bugs = len(scores)
    ok_runs = [s for s in scores if s["run_ok"]]
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

<h2>Results by Bug</h2>
<table>
<tr><th>Bug</th><th>Severity</th><th>Expected</th><th>Found</th><th>TP</th><th>FP</th><th>FN</th><th>Precision</th><th>Recall</th><th>F1</th><th>Sev Acc</th></tr>
"""

    for s in scores:
        if not s["run_ok"]:
            html += f"""<tr class="error-row"><td class="bug-title">{s['bug_title'][:60]}</td>
<td>-</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td><td colspan="4">ERROR: {s.get('run_error','Unknown')[:100]}</td></tr>\n"""
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
        if not s["run_ok"]:
            continue
        html += f"<h3>{s['bug_title'][:80]} ({s['bug_severity']})</h3>\n"
        if s["matches"]:
            html += "<table><tr><th>Expected</th><th>Found</th><th>Sev Match</th><th>Score</th></tr>\n"
            for m in s["matches"]:
                sev_match = "✓" if m["expected_severity"] == m["found_severity"] else "✗"
                html += f"""<tr><td>{m['expected_file']} ({m['expected_severity']})</td>
<td>{m['found_file'][:50]} ({m['found_severity']})</td><td>{sev_match}</td><td>{m['score']}</td></tr>\n"""
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


def main():
    parser = argparse.ArgumentParser(description="HermaGuard Benchmark — score JSON output against ground truth")
    parser.add_argument("--bugs", default="bugs/", help="Path to bugs directory")
    parser.add_argument("--bug", help="Score a single bug by path")
    parser.add_argument("--results", default="results/", help="Directory containing per-bug JSON result files")
    parser.add_argument("--result", help="Single result JSON file (use with --bug)")
    parser.add_argument("--output", default="report.html", help="HTML report output path")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")

    args = parser.parse_args()

    if args.bug and args.result:
        # Single bug mode
        bug = load_bug(args.bug)
        with open(args.result) as f:
            run_info = json.load(f)
        s = score_run(bug, run_info)
        status = "✓" if s["run_ok"] else "✗"
        print(f"  {status} {bug['title'][:60]} — P:{s['precision_pct']}% R:{s['recall_pct']}% F1:{s['f1_score']}%")
        return

    bugs = discover_bugs(args.bugs)
    if not bugs:
        print(f"No bugs found in {args.bugs}")
        sys.exit(1)

    print(f"Found {len(bugs)} bug(s)")

    scores = []
    for bug_dir in bugs:
        bug = load_bug(bug_dir)
        result_path = os.path.join(args.results, f"{bug['id']}.json")

        if os.path.exists(result_path):
            with open(result_path) as f:
                run_info = json.load(f)
            s = score_run(bug, run_info)
            scores.append(s)
            status = "✓" if s["run_ok"] else "✗"
            print(f"  {status} {bug['title'][:60]} — P:{s['precision_pct']}% R:{s['recall_pct']}% F1:{s['f1_score']}%")
        else:
            scores.append({
                "bug_id": bug["id"], "bug_title": bug["title"],
                "bug_severity": bug["severity"], "bug_category": bug["category"],
                "run_ok": False, "run_error": f"No results file at {result_path}",
                "precision_pct": 0, "recall_pct": 0, "f1_score": 0,
                "expected_findings": len(bug["expected_findings"]), "found_findings": 0,
                "true_positives": 0, "false_positives": 0, "false_negatives": len(bug["expected_findings"]),
                "severity_accuracy_pct": 0, "matches": [],
            })

    # Generate report. --output is taken literally (path doubling bug fixed);
    # create the parent dir so an explicit path like results/report.html works.
    report_path = args.output
    parent = os.path.dirname(report_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    generate_report(scores, report_path)

    ok = [s for s in scores if s["run_ok"]]
    if ok:
        avg_f1 = round(sum(s["f1_score"] for s in ok) / len(ok), 1)
        print(f"\nOverall: {len(ok)}/{len(scores)} runs OK, avg F1: {avg_f1}%")
    else:
        print(f"\nAll runs lack result files. Run HermaGuard via your harness first, then score.")
        print(f"Example: run '/hermaguard --json' under any harness, save output to results/<bug-id>.json")

    print(f"Report: {report_path}")


if __name__ == "__main__":
    main()
