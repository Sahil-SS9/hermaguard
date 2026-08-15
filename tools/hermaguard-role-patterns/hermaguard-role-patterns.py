#!/usr/bin/env python3
"""
Hermaguard Role-Pattern Scanner — agent-specific SAST rules (built-in).

CLAWAUDIT's finding: generic SAST (Semgrep Pro, CodeQL) catches only
13.8–21.7% of agent-specific vulnerabilities, while agent-specific rule
bundles reach 66.8–75.1% recall. Hermaguard's prescan shells out to
generic tools (bandit, ruff, eslint); this scanner adds the agent-specific
layer that generic tools miss — pattern bundles keyed to the exact bug
classes each hermaguard reviewer role hunts.

Design (deterministic, stdlib-only, zero external deps):
  - Rule bundles: adversarial (injection/auth/deserialization),
    edge-case (races/null/async/resource), blast-radius (I/O, config,
    migration touchpoints).
  - Each rule: {id, agent, class_id, regex, message, severity}.
  - Emits findings in the SAME schema the prescan normalizes to, so the
    rest of the pipeline (dedup, suppression, report) treats them as
    first-class findings: tool = "hermaguard-role-patterns".

Supports both Python and JS/TS targets; rules carry a `langs` list.

Usage:
    hermaguard-role-patterns.py --files a.py,b.ts [--agents adversarial,edge-case]
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

VERSION = "1.0.0"
TOOL_NAME = "hermaguard-role-patterns"

RULES = [
    # ---- adversarial-reviewer: security-focused ----
    {"id": "ADV-001", "agent": "adversarial", "class_id": "CWE-89",  "langs": ["py", "js", "ts"],
     "regex": r"(?:execute|query|raw)\s*\(\s*f[\"']|f[\"'](?:SELECT|INSERT|UPDATE|DELETE)\b[^\"']*\{",
     "severity": "HIGH", "message": "f-string/format interpolation reaches SQL — parameterize"},
    {"id": "ADV-002", "agent": "adversarial", "class_id": "CWE-78",  "langs": ["py"],
     "regex": r"subprocess\.(?:run|Popen|call)\([^)]*shell\s*=\s*True",
     "severity": "HIGH", "message": "shell=True with subprocess — command injection surface"},
    {"id": "ADV-003", "agent": "adversarial", "class_id": "CWE-502", "langs": ["py"],
     "regex": r"pickle\.loads?\(|yaml\.load\s*\([^)]*\)(?!.*Loader)",
     "severity": "CRITICAL", "message": "unsafe deserialization — pickle/yaml.load on untrusted data"},
    {"id": "ADV-004", "agent": "adversarial", "class_id": "CWE-798", "langs": ["py", "js", "ts"],
     "regex": r"(?:password|passwd|secret|api[_-]?key|token)\s*[:=]\s*[\"'][^\"']{8,}[\"']",
     "severity": "HIGH", "message": "hardcoded credential — move to secrets manager"},
    {"id": "ADV-005", "agent": "adversarial", "class_id": "CWE-918", "langs": ["py", "js", "ts"],
     "regex": r"requests\.(?:get|post|put|delete)\([^)]*(?:url|user)|fetch\(\s*(?:url|req)",
     "severity": "MEDIUM", "message": "outbound request from user-influenced URL — SSRF check"},
    {"id": "ADV-006", "agent": "adversarial", "class_id": "CWE-22",  "langs": ["py"],
     "regex": r"os\.path\.join\(\s*(?:user|filename|name)|Path\([^)]*(?:user|filename)",
     "severity": "MEDIUM", "message": "path built from user input — traversal check"},
    # ---- edge-case-hunter: correctness-focused ----
    {"id": "EDG-001", "agent": "edge-case", "class_id": "CWE-476", "langs": ["py"],
     "regex": r"\.fetchone\(\)\s*\[\s*0\s*\]|\.get\([^)]*\)\s*\[\s*0\s*\]",
     "severity": "MEDIUM", "message": "index [0] on possibly-None result — null deref"},
    {"id": "EDG-002", "agent": "edge-case", "class_id": "CWE-362", "langs": ["py"],
     "regex": r"(?:os\.path\.(?:exists|isfile|isdir)|os\.access)\s*\([^)]*\)[\s\S]{0,400}?(?:remove|unlink|rename|write)",
     "severity": "HIGH", "message": "check-then-act pattern — TOCTOU race window"},
    {"id": "EDG-003", "agent": "edge-case", "class_id": "HG-ASYNC", "langs": ["py", "js", "ts"],
     "regex": r"asyncio\.gather\([^)]*\)|Promise\.all\([^)]*\)",
     "severity": "MEDIUM", "message": "concurrent async work — check rejection/exception handling"},
    {"id": "EDG-004", "agent": "edge-case", "class_id": "HG-PARTIAL-WRITE", "langs": ["py"],
     "regex": r"\.write\s*\([^)]*\)\s*\n(?![^\n]*(?:flush|close|commit|with\s+open))",
     "severity": "MEDIUM", "message": "write without visible flush/commit — partial-write risk"},
    {"id": "EDG-005", "agent": "edge-case", "class_id": "CWE-400", "langs": ["py", "js", "ts"],
     "regex": r"while\s+True\s*:|\.read\(\)\s*$",
     "severity": "MEDIUM", "message": "unbounded loop / full-file read — resource exhaustion"},
    {"id": "EDG-006", "agent": "edge-case", "class_id": "CWE-190", "langs": ["py"],
     "regex": r"int\([^)]*\)\s*[+*]|len\([^)]*\)\s*\+",
     "severity": "LOW", "message": "arithmetic on int()/len() — overflow/limit check"},
    # ---- blast-radius-integration: cross-cutting touchpoints ----
    {"id": "BLT-001", "agent": "blast-radius", "class_id": "CWE-200", "langs": ["py", "js", "ts"],
     "regex": r"traceback\.format_exc\(\)|print\(\s*(?:f[\"'])?[^\"']*(?:token|password|secret|key)",
     "severity": "MEDIUM", "message": "sensitive data may be emitted — exposure check"},
    {"id": "BLT-002", "agent": "blast-radius", "class_id": "CWE-400", "langs": ["py", "js", "ts"],
     "regex": r"getenv\([^)]*\)|process\.env\.\w+|environ\.get\([^)]*\)",
     "severity": "LOW", "message": "env/config read — blast radius of config change"},
    {"id": "BLT-003", "agent": "blast-radius", "class_id": "HG-PARTIAL-WRITE", "langs": ["py"],
     "regex": r"ALTER TABLE|DROP COLUMN|ADD COLUMN|CREATE TABLE",
     "severity": "HIGH", "message": "schema migration — check rollback + data integrity"},
    {"id": "BLT-004", "agent": "blast-radius", "class_id": "CWE-306", "langs": ["py", "js", "ts"],
     "regex": r"@app\.(?:route|get|post|put|delete)|@router\.(?:get|post|put|delete)",
     "severity": "LOW", "message": "route endpoint — verify authz/ownership check exists"},
]

RULE_MAP = {r["id"]: r for r in RULES}


def _lang_of(path: str) -> str:
    s = Path(path).suffix.lower().lstrip(".")
    return s if s in ("py", "js", "ts", "jsx", "tsx") else s.split(".")[-1] if s else ""


def scan_files(files: list, agents: list | None = None) -> list:
    """Scan files with role-pattern rules. Returns normalized findings list."""
    active = set(agents) if agents else {"adversarial", "edge-case", "blast-radius"}
    findings = []
    for f in files:
        p = Path(f)
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        lang = _lang_of(f)
        for rule in RULES:
            if rule["agent"] not in active:
                continue
            if lang not in rule["langs"]:
                continue
            rx = re.compile(rule["regex"], re.IGNORECASE)
            for m in rx.finditer(text):
                line_no = text[:m.start()].count("\n") + 1
                findings.append({
                    "tool": TOOL_NAME,
                    "rule_id": rule["id"],
                    "severity": rule["severity"],
                    "file": f,
                    "line": line_no,
                    "message": rule["message"],
                    "category": "security" if rule["agent"] == "adversarial" else "correctness",
                    "agent": rule["agent"],
                    "class_id": rule["class_id"],
                })
    return findings


def main():
    p = argparse.ArgumentParser(description="Hermaguard agent-specific SAST rules")
    p.add_argument("--files", required=True, help="Comma-separated file paths")
    p.add_argument("--agents", help="Comma-separated agents (default: all)")
    p.add_argument("--json", dest="json_out", help="Write findings JSON to path")
    args = p.parse_args()

    files = [f.strip() for f in args.files.split(",") if f.strip()]
    agents = [a.strip() for a in args.agents.split(",")] if args.agents else None
    findings = scan_files(files, agents)

    out = {"tool": TOOL_NAME, "version": VERSION, "findings": findings,
           "stats": {"files_scanned": len(files), "findings": len(findings)}}
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(out, indent=2))
    print(f"role-patterns: {len(findings)} findings from {len(files)} files")
    for f in findings:
        print(f"  [{f['rule_id']}] {f['severity']} {f['file']}:{f['line']} {f['message']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
