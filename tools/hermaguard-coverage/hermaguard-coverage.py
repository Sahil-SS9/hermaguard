#!/usr/bin/env python3
"""
Hermaguard Coverage — The accountability layer.

Every Hermaguard report must account for every applicable bug class:
each class gets exactly one status — finding / clean / not_applicable.
Anything else is a coverage gap and fails the check.

Why: an adversarial review that silently skips bug classes is theatre.
This tool makes coverage measurable and CI-enforceable.

Class registry:
  - The 2024 MITRE CWE Top 25 (verified against cwe.mitre.org,
    2024_top25_list.html, fetched 2026-08-14).
  - Plus CWE-362 (race), CWE-404 (resource leak), CWE-754 (exception
    handling) — outside the Top 25 but core to the skill's own checklists.
  - Plus 4 Hermaguard-native classes the skill claims to check that CWE
    does not model (async rejection, degenerate handlers, state
    transitions, partial writes).

Usage:
    # Registry integrity (CI self-check)
    hermaguard-coverage.py --self-check

    # Emit the applicable-class ledger for a diff's file set
    hermaguard-coverage.py --files "src/a.py,src/b.ts" --ledger ledger.json

    # Validate a report's coverage against the ledger
    hermaguard-coverage.py --check-report report.json --ledger ledger.json

    # One-shot: build ledger and check in a single call
    hermaguard-coverage.py --files "src/a.py" --check-report report.json

Exit codes: 0 = full coverage or self-check OK; 1 = coverage gaps;
2 = usage/IO error.
"""

import argparse
import json
import sys
from pathlib import Path

VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

# Language sets used by applicability rules.
MEMORY_UNSAFE = {".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".zig"}
RUST = {".rs"}  # memory classes apply only via `unsafe` blocks; hint-only
WEB_FRONTEND = {".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte"}
ALL_CODE = MEMORY_UNSAFE | RUST | WEB_FRONTEND | {
    ".py", ".go", ".java", ".kt", ".rb", ".php", ".cs", ".swift", ".scala",
}

# 2024 CWE Top 25 in rank order (MITRE, verified 2026-08-14) + 3 extras.
# status: "always" | lang-rule
# lang_rule: (applicable_exts, na_reason)
CLASSES = [
    # --- 2024 CWE Top 25, rank order ---
    {"id": "CWE-79",  "name": "Cross-site Scripting (XSS)", "rank": 1,  "status": "always"},
    {"id": "CWE-787", "name": "Out-of-bounds Write", "rank": 2,  "status": "lang",
     "applicable": MEMORY_UNSAFE, "na": "memory-unsafe class N/A for this language"},
    {"id": "CWE-89",  "name": "SQL Injection", "rank": 3,  "status": "always"},
    {"id": "CWE-352", "name": "Cross-Site Request Forgery (CSRF)", "rank": 4,  "status": "always"},
    {"id": "CWE-22",  "name": "Path Traversal", "rank": 5,  "status": "always"},
    {"id": "CWE-125", "name": "Out-of-bounds Read", "rank": 6,  "status": "lang",
     "applicable": MEMORY_UNSAFE, "na": "memory-unsafe class N/A for this language"},
    {"id": "CWE-78",  "name": "OS Command Injection", "rank": 7,  "status": "always"},
    {"id": "CWE-416", "name": "Use After Free", "rank": 8,  "status": "lang",
     "applicable": MEMORY_UNSAFE, "na": "memory-unsafe class N/A for this language"},
    {"id": "CWE-862", "name": "Missing Authorization", "rank": 9,  "status": "always"},
    {"id": "CWE-434", "name": "Unrestricted Upload of Dangerous Type", "rank": 10, "status": "always"},
    {"id": "CWE-94",  "name": "Code Injection", "rank": 11, "status": "always"},
    {"id": "CWE-20",  "name": "Improper Input Validation", "rank": 12, "status": "always"},
    {"id": "CWE-77",  "name": "Command Injection", "rank": 13, "status": "always"},
    {"id": "CWE-287", "name": "Improper Authentication", "rank": 14, "status": "always"},
    {"id": "CWE-269", "name": "Improper Privilege Management", "rank": 15, "status": "always"},
    {"id": "CWE-502", "name": "Deserialization of Untrusted Data", "rank": 16, "status": "always"},
    {"id": "CWE-200", "name": "Exposure of Sensitive Information", "rank": 17, "status": "always"},
    {"id": "CWE-863", "name": "Incorrect Authorization", "rank": 18, "status": "always"},
    {"id": "CWE-918", "name": "Server-Side Request Forgery (SSRF)", "rank": 19, "status": "always"},
    {"id": "CWE-119", "name": "Improper Restriction of Memory Buffer", "rank": 20, "status": "lang",
     "applicable": MEMORY_UNSAFE, "na": "memory-unsafe class N/A for this language"},
    {"id": "CWE-476", "name": "NULL Pointer Dereference", "rank": 21, "status": "always",
     "hint": "null/None/undefined deref in any language"},
    {"id": "CWE-798", "name": "Use of Hard-coded Credentials", "rank": 22, "status": "always"},
    {"id": "CWE-190", "name": "Integer Overflow or Wraparound", "rank": 23, "status": "always",
     "hint": "numeric overflow/precision in any language"},
    {"id": "CWE-400", "name": "Uncontrolled Resource Consumption", "rank": 24, "status": "always"},
    {"id": "CWE-306", "name": "Missing Authentication for Critical Function", "rank": 25, "status": "always"},
    # --- Extras: outside Top 25, core to the skill's stated checklist ---
    {"id": "CWE-362", "name": "Race Condition (TOCTOU)", "rank": None, "status": "always"},
    {"id": "CWE-404", "name": "Improper Resource Shutdown/Release", "rank": None, "status": "always"},
    {"id": "CWE-754", "name": "Improper Check for Exceptional Conditions", "rank": None, "status": "always"},
    # --- Hermaguard-native: claimed by the skill, not modelled by CWE ---
    {"id": "HG-ASYNC", "name": "Unhandled async rejection / async race", "rank": None, "status": "always"},
    {"id": "HG-DEGENERATE", "name": "Degenerate handler (empty catch, placeholder return)", "rank": None, "status": "always"},
    {"id": "HG-STATE", "name": "State-transition gap (loading→error, before→after auth)", "rank": None, "status": "always"},
    {"id": "HG-PARTIAL-WRITE", "name": "Partial write / non-atomic update (missing transaction)", "rank": None, "status": "always"},
]

VALID_STATUSES = {"finding", "clean", "not_applicable"}

# ---------------------------------------------------------------------------
# Registry integrity
# ---------------------------------------------------------------------------

def self_check() -> list:
    """Validate registry invariants. Returns list of error strings."""
    errors = []
    ids = [c["id"] for c in CLASSES]
    if len(ids) != len(set(ids)):
        errors.append("duplicate class ids in registry")
    names = [c["name"] for c in CLASSES]
    if len(names) != len(set(names)):
        errors.append("duplicate class names in registry")
    cwe_ids = sorted([i for i in ids if i.startswith("CWE-")], key=lambda x: int(x[4:]))
    top25 = [c for c in CLASSES if c.get("rank") and 1 <= c["rank"] <= 25]
    if len(top25) != 25:
        errors.append(f"expected 25 ranked Top-25 entries, found {len(top25)}")
    ranks = sorted(c["rank"] for c in top25)
    if ranks != list(range(1, 26)):
        errors.append(f"Top-25 ranks not exactly 1..25: {ranks}")
    for c in CLASSES:
        if c["status"] not in ("always", "lang"):
            errors.append(f"{c['id']}: bad status {c['status']}")
        if c["status"] == "lang":
            if "applicable" not in c or "na" not in c or not c["applicable"]:
                errors.append(f"{c['id']}: lang rule missing applicable/na")
    # 2024 Top 25 exact-ID membership (verified against MITRE).
    expected_2024 = {
        "CWE-79", "CWE-787", "CWE-89", "CWE-352", "CWE-22", "CWE-125",
        "CWE-78", "CWE-416", "CWE-862", "CWE-434", "CWE-94", "CWE-20",
        "CWE-77", "CWE-287", "CWE-269", "CWE-502", "CWE-200", "CWE-863",
        "CWE-918", "CWE-119", "CWE-476", "CWE-798", "CWE-190", "CWE-400",
        "CWE-306",
    }
    got = {c["id"] for c in top25}
    if got != expected_2024:
        errors.append(f"Top-25 ID set mismatch: missing={expected_2024 - got} extra={got - expected_2024}")
    return errors


# ---------------------------------------------------------------------------
# Ledger construction
# ---------------------------------------------------------------------------

def build_ledger(files: list) -> dict:
    """Given changed file paths, return the applicable-class ledger.

    A class is applicable if status=always, or its language rule matches
    at least one changed file's extension. Rust gets memory classes as
    hint-only (unsafe blocks) — still applicable, hint attached.
    """
    exts = set()
    has_rust = False
    for f in files:
        ext = Path(f).suffix.lower()
        if ext:
            exts.add(ext)
        if ext == ".rs":
            has_rust = True

    ledger = {
        "version": VERSION,
        "files": sorted(files),
        "classes": [],
    }
    for c in CLASSES:
        if c["status"] == "always":
            entry = {"id": c["id"], "name": c["name"], "applicable": True}
            if "hint" in c:
                entry["hint"] = c["hint"]
            ledger["classes"].append(entry)
        else:
            hit = bool(exts & set(c["applicable"]))
            rust_hint = has_rust and c["id"] in ("CWE-787", "CWE-125", "CWE-416", "CWE-119")
            if hit or rust_hint:
                entry = {"id": c["id"], "name": c["name"], "applicable": True}
                if rust_hint and not hit:
                    entry["hint"] = "Rust: applies via unsafe blocks"
                ledger["classes"].append(entry)
            else:
                ledger["classes"].append({
                    "id": c["id"], "name": c["name"],
                    "applicable": False, "default_status": "not_applicable",
                    "reason": c["na"],
                })
    return ledger


# ---------------------------------------------------------------------------
# Report validation
# ---------------------------------------------------------------------------

def check_report(report: dict, ledger: dict) -> dict:
    """Validate that the report accounts for every applicable class.

    The report must carry a `coverage` array where each entry is
    {class_id, status, evidence} with status in VALID_STATUSES.
    Every applicable ledger class must appear exactly once.
    Finding-backed entries are cross-checked: if a class claims
    `finding`, at least one finding in the report must cite it.
    """
    errors = []
    coverage = report.get("coverage")
    if not isinstance(coverage, list):
        return {
            "ok": False,
            "errors": ["report has no `coverage` array — coverage cannot be verified"],
            "accounted": 0, "applicable": 0, "gaps": [c["id"] for c in ledger["classes"] if c["applicable"]],
        }

    seen = {}
    for i, entry in enumerate(coverage):
        if not isinstance(entry, dict):
            errors.append(f"coverage[{i}] is not an object")
            continue
        cid = entry.get("class_id")
        status = entry.get("status")
        if cid is None or status is None:
            errors.append(f"coverage[{i}] missing class_id or status")
            continue
        if status not in VALID_STATUSES:
            errors.append(f"coverage[{i}] ({cid}): invalid status '{status}' (use one of {sorted(VALID_STATUSES)})")
        if cid in seen:
            errors.append(f"class {cid} appears twice in coverage")
        seen[cid] = entry

    applicable = [c for c in ledger["classes"] if c["applicable"]]
    gaps = []
    for c in applicable:
        entry = seen.get(c["id"])
        if entry is None:
            gaps.append(c["id"])
        elif entry.get("status") == "not_applicable":
            # Allowed only with an explicit reason — an applicable class
            # demoted to N/A must say why.
            if not entry.get("reason"):
                errors.append(f"{c['id']}: marked not_applicable without a reason")
        elif entry.get("status") == "finding":
            findings = report.get("findings", [])
            backed = any(
                isinstance(f, dict) and c["id"] in (
                    f.get("classes") or []) for f in findings
            )
            if not backed:
                errors.append(
                    f"{c['id']}: coverage claims 'finding' but no finding cites this class "
                    f"(add `classes: [\"{c['id']}\"]` to the finding)")

    for cid in seen:
        known = {c["id"] for c in CLASSES}
        if cid not in known:
            errors.append(f"coverage cites unknown class {cid}")

    return {
        "ok": not errors and not gaps,
        "errors": errors,
        "accounted": len(applicable) - len(gaps),
        "applicable": len(applicable),
        "gaps": gaps,
    }


def render_table(result: dict, ledger: dict) -> str:
    lines = []
    by_id = {c["id"]: c for c in ledger["classes"]}
    for c in ledger["classes"]:
        if not c["applicable"]:
            lines.append(f"  N/A      {c['id']:16s} {c['name']} — {c.get('reason', '')}")
    cov = result.get("_coverage_map", {})
    for cid, status in cov.items():
        c = by_id.get(cid, {})
        lines.append(f"  {status:8s} {cid:16s} {c.get('name', '?')}")
    return "\n".join(lines) if lines else "  (empty)"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description="Hermaguard coverage accountability layer")
    p.add_argument("--self-check", action="store_true", help="validate registry integrity")
    p.add_argument("--files", help="comma-separated changed file paths")
    p.add_argument("--ledger", help="ledger JSON path (write with --files, read with --check-report)")
    p.add_argument("--check-report", help="report JSON to validate against the ledger")
    p.add_argument("--quiet", action="store_true", help="print only the verdict")
    args = p.parse_args()

    if args.self_check:
        errs = self_check()
        if errs:
            print("SELF-CHECK FAILED:")
            for e in errs:
                print(f"  - {e}")
            return 1
        print(f"self-check OK — {len(CLASSES)} classes "
              f"({len([c for c in CLASSES if c.get('rank')])} CWE Top-25 + "
              f"{len([c for c in CLASSES if not c.get('rank')])} extras)")
        return 0

    if not args.files and not (args.check_report and args.ledger):
        p.error("need --files, or --check-report with --ledger")

    ledger = None
    if args.files:
        files = [f.strip() for f in args.files.split(",") if f.strip()]
        ledger = build_ledger(files)
        if args.ledger:
            Path(args.ledger).write_text(json.dumps(ledger, indent=2))
            if not args.quiet:
                print(f"ledger written: {args.ledger} "
                      f"({sum(1 for c in ledger['classes'] if c['applicable'])} applicable classes)")

    if args.check_report:
        if ledger is None:
            if not args.ledger:
                p.error("--check-report needs --files or --ledger")
            ledger = json.loads(Path(args.ledger).read_text())
        report = json.loads(Path(args.check_report).read_text())
        result = check_report(report, ledger)
        cmap = {e.get("class_id"): e.get("status") for e in report.get("coverage", []) if isinstance(e, dict)}
        result["_coverage_map"] = cmap
        verdict = "PASS" if result["ok"] else "FAIL"
        print(f"coverage {verdict}: {result['accounted']}/{result['applicable']} applicable classes accounted for")
        if result["gaps"]:
            print(f"gaps: {', '.join(result['gaps'])}")
        for e in result["errors"]:
            print(f"error: {e}")
        if not args.quiet:
            print(render_table(result, ledger))
        return 0 if result["ok"] else 1

    if ledger and not args.ledger and not args.quiet:
        print(json.dumps(ledger, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
