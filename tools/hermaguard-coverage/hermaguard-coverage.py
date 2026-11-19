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
import hashlib
import json
import posixpath
import sys
from pathlib import Path

VERSION = "1.1.0"

# Report format version. Reports without `report_version` are LEGACY: they are
# read as before, labelled "evidence not checked", and never upgraded silently.
# Keep in step with REPORT_VERSION in hermaguard-verify.py (a test enforces it).
REPORT_VERSION = 2

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

VALID_STATUSES = {"finding", "clean", "not_applicable", "not_checked", "inconclusive"}
# Statuses that keep a report issuable but stop it clearing a required gate.
UNRESOLVED_STATUSES = {"not_checked", "inconclusive"}

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

def _norm_path(path) -> str:
    """Normalise a repo-relative path for comparison (posix, no ./, no ..)."""
    text = str(path or "").strip().replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    return posixpath.normpath(text) if text else ""


def _scope_paths(scope) -> list:
    """`path` or `path::symbol` entries -> normalised paths."""
    out = []
    for item in scope if isinstance(scope, list) else []:
        if isinstance(item, str) and item.strip():
            out.append(_norm_path(item.split("::", 1)[0]))
    return out


def _resolve_inside(base, rel):
    """Resolve `rel` under `base`; None if absolute or escaping."""
    if base is None or not isinstance(rel, str) or not rel or Path(rel).is_absolute():
        return None
    base = Path(base).resolve()
    target = (base / rel).resolve()
    try:
        target.relative_to(base)
    except ValueError:
        return None
    return target


def _sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _check_clean_evidence(cid, entry, obs_by_id, report, ledger_files, report_dir):
    """Return (errors, warnings) for one v2 `clean` row."""
    errors, warnings = [], []
    ref = entry.get("observations", entry.get("observation"))
    refs = [ref] if isinstance(ref, str) else (ref if isinstance(ref, list) else [])
    refs = [r for r in refs if isinstance(r, str) and r.strip()]
    if not refs:
        return [f"{cid}: marked clean without evidence - cite an observation, "
                "or mark it not_checked / inconclusive"], warnings
    revision = report.get("revision")
    related = False
    for oid in refs:
        obs = obs_by_id.get(oid)
        if obs is None:
            errors.append(f"{cid}: cites unknown observation {oid!r}")
            continue
        if obs.get("revision") != revision:
            errors.append(f"{cid}: observation {oid} is for revision {obs.get('revision')!r}, "
                          f"the report reviews {revision!r} (stale)")
        if not str(obs.get("check") or "").strip():
            errors.append(f"{cid}: observation {oid} does not say which check was performed")
        covers = obs.get("covers")
        if not isinstance(covers, list) or cid not in covers:
            errors.append(f"{cid}: observation {oid} does not cover this class")
        paths = _scope_paths(obs.get("scope"))
        if not paths:
            errors.append(f"{cid}: observation {oid} has no bounded scope (file or file::symbol)")
        elif not set(paths) & ledger_files:
            errors.append(f"{cid}: observation {oid} scope {sorted(set(paths))} is unrelated to the changed files")
        else:
            related = True
            outside = sorted(set(paths) - ledger_files)
            if outside:
                warnings.append(f"{cid}: observation {oid} also names files outside the change: {outside}")
        kind = obs.get("kind", "manual")
        artifact = obs.get("artifact")
        if kind == "tool" and not artifact:
            errors.append(f"{cid}: tool observation {oid} has no artifact")
        if artifact:
            if report_dir is None:
                warnings.append(f"{cid}: artifact for {oid} not verified (no report directory)")
            else:
                resolved = _resolve_inside(report_dir, artifact)
                if resolved is None or not resolved.is_file():
                    errors.append(f"{cid}: artifact {artifact!r} for {oid} is missing or outside the report directory")
                elif not obs.get("artifact_sha256"):
                    errors.append(f"{cid}: artifact {artifact!r} for {oid} has no artifact_sha256")
                elif _sha256_file(resolved) != obs["artifact_sha256"]:
                    errors.append(f"{cid}: artifact {artifact!r} for {oid} has been altered (hash mismatch)")
    if refs and not related and not errors:
        errors.append(f"{cid}: no cited observation relates to the changed files")
    return errors, warnings


def check_report(report: dict, ledger: dict, *, report_dir=None, expect_revision=None,
                 require_evidence: bool = False) -> dict:
    """Validate that the report accounts for every applicable class.

    Each coverage entry is {class_id, status, ...} with status in VALID_STATUSES.
    Every applicable ledger class must appear exactly once.

    Result keys
      issuable  structurally valid and every applicable class accounted for.
                A partial report (some classes not_checked / inconclusive) is
                issuable: its findings stay readable.
      ok        the GATE: issuable AND nothing unresolved (AND, with
                require_evidence, not a legacy report).
      legacy / evidence_checked   see REPORT_VERSION.

    v2 reports must carry `revision` and `observations[]`; a `clean` row must
    cite observations that name the reviewed revision, a bounded scope inside
    the change, the check performed and the class they cover.
    """
    errors, warnings = [], []
    coverage = report.get("coverage")
    version = report.get("report_version")
    legacy = version is None
    if not legacy and version != REPORT_VERSION:
        errors.append(f"unsupported report_version {version!r} (this checker reads {REPORT_VERSION} and legacy)")
    v2 = version == REPORT_VERSION
    base = {"legacy": legacy, "evidence_checked": v2, "unresolved": [], "warnings": warnings}
    if not isinstance(coverage, list):
        errors.append("report has no `coverage` array - coverage cannot be verified")
        return dict(base, ok=False, issuable=False, errors=errors, accounted=0, applicable=0,
                    gaps=[c["id"] for c in ledger["classes"] if c["applicable"]])

    ledger_files = {_norm_path(f) for f in ledger.get("files", [])}
    obs_by_id = {}
    if v2:
        if not str(report.get("revision") or "").strip():
            errors.append("report has no `revision` (the commit or content digest that was reviewed)")
        elif expect_revision and report["revision"] != expect_revision:
            errors.append(f"report reviews revision {report['revision']!r} but {expect_revision!r} "
                          "was expected (stale report)")
        observations = report.get("observations", [])
        if not isinstance(observations, list):
            errors.append("`observations` must be a list")
            observations = []
        for i, obs in enumerate(observations):
            if not isinstance(obs, dict) or not str(obs.get("id") or "").strip():
                errors.append(f"observations[{i}] needs an `id`")
                continue
            if obs["id"] in obs_by_id:
                errors.append(f"observation {obs['id']!r} appears twice")
            obs_by_id[obs["id"]] = obs

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
    gaps, unresolved, clean_unverified = [], [], 0
    findings = report.get("findings", [])
    for c in applicable:
        entry = seen.get(c["id"])
        status = entry.get("status") if entry else None
        if entry is None:
            gaps.append(c["id"])
        elif status == "not_applicable":
            # Allowed only with an explicit reason - an applicable class
            # demoted to N/A must say why.
            if not entry.get("reason"):
                errors.append(f"{c['id']}: marked not_applicable without a reason")
        elif status in UNRESOLVED_STATUSES:
            unresolved.append(c["id"])
            if not str(entry.get("reason") or "").strip():
                errors.append(f"{c['id']}: marked {status} without saying what is unresolved")
        elif status == "finding":
            backers = [f for f in findings if isinstance(f, dict) and c["id"] in (f.get("classes") or [])]
            if not backers:
                errors.append(
                    f"{c['id']}: coverage claims 'finding' but no finding cites this class "
                    f"(add `classes: [\"{c['id']}\"]` to the finding)")
            by_id = {f.get("id"): f for f in findings if isinstance(f, dict)}
            for fid in entry.get("backed_by") or []:
                if fid not in by_id or c["id"] not in (by_id[fid].get("classes") or []):
                    errors.append(f"{c['id']}: backed_by {fid!r} is not a finding that cites this class")
        elif status == "clean":
            if v2:
                e, w = _check_clean_evidence(c["id"], entry, obs_by_id, report, ledger_files, report_dir)
                errors.extend(e)
                warnings.extend(w)
            else:
                clean_unverified += 1

    for cid in seen:
        known = {c["id"] for c in CLASSES}
        if cid not in known:
            errors.append(f"coverage cites unknown class {cid}")

    if legacy and clean_unverified:
        warnings.append(f"legacy report: {clean_unverified} clean row(s) carry no evidence and were NOT checked")
    if legacy and require_evidence:
        errors.append("legacy report: evidence is not checked, and this gate requires it")

    issuable = not errors and not gaps
    return dict(base, ok=issuable and not unresolved, issuable=issuable, errors=errors,
                accounted=len(applicable) - len(gaps), applicable=len(applicable),
                gaps=gaps, unresolved=unresolved)


def render_markdown(result: dict, ledger: dict, report: dict) -> str:
    """The report's `## Coverage Ledger` section, with evidence and gate status."""
    by_id = {c["id"]: c for c in ledger["classes"]}
    entries = {e.get("class_id"): e for e in report.get("coverage", []) if isinstance(e, dict)}
    obs = {o.get("id"): o for o in report.get("observations", []) if isinstance(o, dict)}
    if result.get("legacy"):
        label = "LEGACY report - clean rows and verification labels were not checked against evidence"
    else:
        label = f"evidence checked (report_version {REPORT_VERSION}, revision {report.get('revision')})"
    gate = "PASS" if result["ok"] else ("FAIL - partial report (issuable)" if result["issuable"] else "FAIL - not issuable")
    lines = [f"**Gate:** {gate}. **Evidence:** {label}.", ""]
    if result["unresolved"]:
        lines += [f"**Unresolved (not a clean result):** {', '.join(result['unresolved'])}", ""]
    lines += ["| Class | Name | Status | Evidence |", "|---|---|---|---|"]
    for cid, c in by_id.items():
        e = entries.get(cid)
        if not c["applicable"]:
            lines.append(f"| {cid} | {c['name']} | not_applicable | {c.get('reason', '')} |")
            continue
        if e is None:
            lines.append(f"| {cid} | {c['name']} | MISSING | no coverage row |")
            continue
        st = e.get("status")
        if st == "clean" and not result.get("legacy"):
            refs = e.get("observations", e.get("observation"))
            refs = [refs] if isinstance(refs, str) else (refs or [])
            ev = "; ".join(f"{r}: {obs.get(r, {}).get('check', '?')} @ {', '.join(obs.get(r, {}).get('scope', []))}"
                           for r in refs) or "NO EVIDENCE"
        elif st == "clean":
            ev = "legacy - not checked"
        elif st == "finding":
            ev = ", ".join(e.get("backed_by") or []) or "see findings"
        else:
            ev = e.get("reason", "")
        lines.append(f"| {cid} | {c['name']} | {st} | {ev} |")
    return "\n".join(lines) + "\n"


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
    p.add_argument("--expect-revision", help="revision the report must review (stale reports fail)")
    p.add_argument("--require-evidence", action="store_true",
                   help="fail legacy (version-less) reports: their clean rows carry no evidence")
    p.add_argument("--render-markdown", metavar="PATH",
                   help="write the report's Coverage Ledger section as markdown ('-' = stdout)")
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
        result = check_report(report, ledger,
                              report_dir=Path(args.check_report).resolve().parent,
                              expect_revision=args.expect_revision,
                              require_evidence=args.require_evidence)
        cmap = {e.get("class_id"): e.get("status") for e in report.get("coverage", []) if isinstance(e, dict)}
        result["_coverage_map"] = cmap
        verdict = "PASS" if result["ok"] else "FAIL"
        print(f"coverage {verdict}: {result['accounted']}/{result['applicable']} applicable classes accounted for")
        if result["legacy"]:
            print("LEGACY report: clean rows carry no evidence and were NOT checked")
        if result["unresolved"]:
            print(f"unresolved (not_checked / inconclusive): {', '.join(result['unresolved'])}")
        if not result["ok"] and result["issuable"]:
            print("report is issuable as a PARTIAL report, but it does not clear the gate")
        for w in result["warnings"]:
            print(f"warning: {w}")
        if args.render_markdown:
            md = render_markdown(result, ledger, report)
            if args.render_markdown == "-":
                print(md)
            else:
                Path(args.render_markdown).write_text(md)
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
