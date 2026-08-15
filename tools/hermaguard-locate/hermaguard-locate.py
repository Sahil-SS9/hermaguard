#!/usr/bin/env python3
"""
Hermaguard Locate — hypothesis-driven fault localization pre-pass.

SHERLOC-style (arXiv 2606.24820): SHERLOC pairs a reasoning LLM with compact
repo tools (grep, AST, git blame) to produce actionable fault diagnoses —
not just file paths but the diagnostic context a repair agent needs.
Its SWE-Bench numbers (84.3% acc@1 Lite) show the localization pass is
worth doing BEFORE adversarial review.

This tool is the COMPACT-REPO-TOOLS layer, fully deterministic and stdlib-only:
  1. Churn analysis   — git diff --numstat (fallback: plain diff parsing)
  2. Hotspot scoring  — hunk-level concentration of added lines
  3. Signal mapping   — per-class keyword/pattern hits (SQL, auth, races,
                        deserialization, async, I/O, config) mapped to the
                        hermaguard coverage classes
  4. Hypothesis list  — top-N ranked suspicion points with WHY each was
                        flagged, ready for the review agents to attack

The reasoning loop stays with the review agents (SKILL.md Phase 1): they
receive the hypothesis list as their starting point and attack from known
weak points instead of re-deriving context from scratch.

Usage:
    hermaguard-locate.py --diff <diff-file-or-'-'> --repo <root> [--top N]
    hermaguard-locate.py --files a.py,b.py --repo <root>
    # reads a unified diff from stdin when --diff -

Output JSON: {churn, hotspots, signals, hypothesis, top_files, stats}

Exit 0 always on successful analysis; 2 on input errors.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

VERSION = "1.0.0"

# Signal map: coverage class -> list of (label, regex) triggers.
# These are deliberately conservative: they flag *suspicion*, not findings.
SIGNAL_MAP = [
    ("CWE-89",    "sql-injection",   [r"\b(f-string|format|%)[^\n]*(SELECT|INSERT|UPDATE|DELETE)", r"\bcur(?:sor)?\.execute\(f", r"\.query\(f[^)]*"]),
    ("CWE-79",    "xss",             [r"dangerouslySetInnerHTML", r"innerHTML\s*=", r"v-html", r"\.html\("]),
    ("CWE-22",    "path-traversal",  [r"os\.path\.join\([^)]*(user|filename|name)", r"open\(f?['\"](?!.*\.\.)", r"Path\([^)]*user"]),
    ("CWE-78",    "command-injection", [r"os\.system\(f", r"subprocess\.(run|Popen|call)\([^)]*shell\s*=\s*True", r"subprocess\.(run|Popen|call)\(f"]),
    ("CWE-502",   "deserialization", [r"pickle\.load", r"yaml\.load\(", r"loads?\([^)]*\)\s*#?\s*.*(untrusted|user|request)", r"eval\(f?"]),
    ("CWE-798",   "hardcoded-creds", [r"(password|passwd|secret|api_key|apikey|token)\s*=\s*['\"][^'\"]{6,}['\"]"]),
    ("CWE-362",   "race-toctou",     [r"os\.path\.exists|os\.access", r"(thread|Thread|asyncio\.gather|await asyncio\.(sleep|wait))", r"check[^\n]*then[^\n]*(write|delete|move)", r"\.balance\s*[+\-]=|balance\s*[+\-]=.*if\s"]),
    ("HG-ASYNC",  "async-gap",       [r"await\s+\w+\([^)]*\)\s*\n(?!.*except)", r"\.catch\(", r"async\s+\w+\([^)]*\)\s*\{[^}]*$"]),
    ("CWE-200",   "info-exposure",   [r"traceback\.format_exc", r"print\([^)]*(token|password|secret|key)", r"return\s+str\(e\)"]),
    ("CWE-918",   "ssrf",            [r"requests\.(get|post|put|delete)\([^)]*(url|user)", r"urllib\.request", r"fetch\([^)]*(url|req)"]),
    ("CWE-476",   "null-deref",      [r"\.fetchone\(\)[^\n]*\[0\]", r"row\[0\]", r"\[0\]\s*(\.|$)", r"\bget\([^)]*\)\[0\]"]),
    ("CWE-434",   "unrestricted-upload", [r"\.save\([^)]*(filename|file|name)", r"upload", r"content_type\s*="]),
    ("CWE-306",   "missing-auth",    [r"@app\.route|@router\.(get|post|put|delete)", r"def\s+\w+\([^)]*request\)\s*:"]) ,
    ("HG-PARTIAL-WRITE", "partial-write", [r"\.write\([^)]*\)\s*\n(?!.*(flush|close|commit))", r"(update|insert).*(where|SET)", r"without\s+(transaction|commit)"]),
    ("CWE-400",   "resource-exhaustion", [r"while\s+True", r"recursive", r"\.read\(\)\s*$", r"all\(|any\(", r"\*\s*1000|\*\s*1024"]),
    ("CWE-190",   "integer-overflow", [r"\+=\s*1" , r"max_|min_", r"len\([^)]*\)\s*\+"]),
]

CLASS_SIGNALS: dict = {}
for _cls, _label, _pats in SIGNAL_MAP:
    CLASS_SIGNALS.setdefault(_cls, []).extend((_label, re.compile(p, re.IGNORECASE)) for p in _pats)

# Files never worth hot-spotting (vendored/generated/binary-ish)
IGNORED_SUFFIXES = {".pyc", ".min.js", ".map", ".lock", ".svg", ".png", ".jpg", ".woff", ".woff2"}


def git_numstat(repo: str, files: list) -> dict:
    """Churn per file via git diff --numstat. Returns {path: {added, deleted}}."""
    if not files:
        return {}
    try:
        r = subprocess.run(
            ["git", "-C", repo, "diff", "--numstat", "--"] + list(files),
            capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            return {}
        out = {}
        for line in r.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) == 3 and parts[0].isdigit():
                out[parts[2]] = {"added": int(parts[0]), "deleted": int(parts[1])}
        return out
    except (subprocess.SubprocessError, OSError):
        return {}


def parse_diff(diff_text: str) -> list:
    """Parse a unified diff into per-file added-line spans.
    Returns [{file, hunks: [{start, added_lines: [line_no,...]}]}]"""
    files_out = []
    cur_file = None
    cur_hunk = None
    for raw in diff_text.splitlines():
        if raw.startswith("+++ b/"):
            cur_file = raw[6:]
            files_out.append({"file": cur_file, "hunks": []})
            cur_hunk = None
        elif raw.startswith("@@") and cur_file is not None:
            m = re.search(r"\+(\d+)(?:,(\d+))?", raw)
            if m:
                cur_hunk = {"start": int(m.group(1)), "added_lines": []}
                files_out[-1]["hunks"].append(cur_hunk)
        elif cur_hunk is not None:
            if raw.startswith("+") and not raw.startswith("+++"):
                cur_hunk["added_lines"].append(cur_hunk["start"] + len(cur_hunk["added_lines"]))
            elif raw.startswith("-") and not raw.startswith("---"):
                pass  # deletions shift nothing for added-line numbering
            else:
                cur_hunk["start"] += 1  # context line advances the new-file line
    return [f for f in files_out if f["hunks"]]


def scan_signals(file_path: str, text: str) -> list:
    """Return [{class_id, label, line, snippet}] for every signal hit."""
    hits = []
    if any(file_path.endswith(s) for s in IGNORED_SUFFIXES):
        return hits
    for cls, entries in CLASS_SIGNALS.items():
        for label, rx in entries:
            for m in rx.finditer(text):
                line_no = text[:m.start()].count("\n") + 1
                snippet = text.splitlines()[line_no - 1].strip()[:120]
                hits.append({"class_id": cls, "label": label,
                             "line": line_no, "snippet": snippet})
    return hits


def score_file(path: str, churn: dict, hits: list) -> dict:
    """Hotspot score: churn concentration + unique signal classes."""
    c = churn.get(path, {"added": 0, "deleted": 0})
    classes = {h["class_id"] for h in hits}
    score = min(c["added"] // 5, 5) + min(len(classes) * 2, 10)
    if c["added"] == 0 and not hits:
        score = 0
    suspicion = "HIGH" if score >= 8 else ("MEDIUM" if score >= 4 else "LOW")
    return {
        "path": path,
        "added": c["added"],
        "deleted": c["deleted"],
        "signal_hits": len(hits),
        "signal_classes": sorted(classes),
        "score": score,
        "suspicion": suspicion,
        "top_signals": sorted(hits, key=lambda h: -h["line"])[:5],
    }


def build_hypotheses(scored: list, top_n: int) -> list:
    """Ranked attack list with explicit WHY notes for the review agents."""
    hyps = []
    for s in sorted(scored, key=lambda x: -x["score"])[:top_n]:
        why = []
        if s["added"] >= 10:
            why.append(f"{s['added']} added lines — large change surface")
        if s["signal_classes"]:
            why.append("signal classes: " + ", ".join(s["signal_classes"]))
        if s["deleted"] > s["added"]:
            why.append("net deletion — check for removed guards")
        hyps.append({
            "file": s["path"],
            "suspicion": s["suspicion"],
            "why": why,
            "attack_from": [h["snippet"] for h in s["top_signals"]],
        })
    return hyps


def analyze(files: list, repo: str, top_n: int) -> dict:
    churn = git_numstat(repo, files)
    scored = []
    for f in files:
        p = Path(f)
        if not p.is_file():
            continue
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        hits = scan_signals(f, text)
        scored.append(score_file(f, churn, hits))
    scored = [s for s in scored if s["score"] > 0]
    hypotheses = build_hypotheses(scored, top_n)
    return {
        "tool": "hermaguard-locate",
        "version": VERSION,
        "hypotheses": hypotheses,
        "top_files": [h["file"] for h in hypotheses],
        "stats": {
            "files_scanned": len(files),
            "files_flagged": len(scored),
            "signal_hits_total": sum(s["signal_hits"] for s in scored),
        },
    }


def main():
    p = argparse.ArgumentParser(description="Hermaguard locate pre-pass — fault localization")
    p.add_argument("--diff", help="Unified diff file, or '-' for stdin")
    p.add_argument("--files", help="Comma-separated file paths")
    p.add_argument("--repo", default=".", help="Repo root for git churn (default: cwd)")
    p.add_argument("--top", type=int, default=5, help="Top-N hypotheses (default: 5)")
    p.add_argument("--json", dest="json_out", help="Write output JSON to path")
    args = p.parse_args()

    if not args.diff and not args.files:
        p.error("--diff or --files required")

    if args.diff == "-":
        diff_text = sys.stdin.read()
    elif args.diff:
        diff_text = Path(args.diff).read_text()
    else:
        diff_text = ""

    if args.files:
        files = [f.strip() for f in args.files.split(",") if f.strip()]
    elif diff_text:
        parsed = parse_diff(diff_text)
        files = [f["file"] for f in parsed]
    else:
        p.error("no files resolved")

    out = analyze(files, args.repo, args.top)
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(out, indent=2))
        print(f"locate: {out['stats']['files_flagged']}/{len(files)} files flagged — {args.json_out}")
    else:
        print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
