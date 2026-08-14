#!/usr/bin/env python3
"""
Hermaguard Pre-Scan — Deterministic static analysis layer.
Runs language-appropriate linters on changed files, normalises output,
feeds structured findings to the LLM review agents.

Usage:
    hermaguard-prescan --files "src/a.py,src/b.ts" --output prescan.json
    hermaguard-prescan --diff "$(git diff --name-only)" --output prescan.json
    hermaguard-prescan --files "src/*.go" --tools bandit,ruff --output /tmp/prescan.json

Output: JSON written to --output path, stdout prints summary stats.
Exit code 0 even when findings found (findings are informational).
Exit code 1 on tool failure (unavailable linter, no files, etc).
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

VERSION = "1.0.0"

# Language detection: extension → list of (tool, command builder)
LANGUAGE_TOOLS = {
    ".py": [
        {
            "name": "bandit",
            "install_hint": "pip install bandit",
            "build_cmd": lambda files, tmpdir: [
                "bandit", "-f", "json", "-q", *files
            ],
            "parse": "_parse_bandit",
        },
        {
            "name": "ruff",
            "install_hint": "pip install ruff",
            "build_cmd": lambda files, tmpdir: [
                "ruff", "check", "--output-format", "json", "--select",
                "B,PLC,PLW,S,A,SIM,C4,PT", *files
            ],
            "parse": "_parse_ruff",
        },
    ],
    ".ts": [
        {
            "name": "eslint",
            "install_hint": "npm install -g eslint @typescript-eslint/parser @typescript-eslint/eslint-plugin",
            "build_cmd": lambda files, tmpdir: _make_eslint_cmd(files, tmpdir, ".ts"),
            "parse": "_parse_eslint",
        },
        {
            "name": "semgrep",
            "install_hint": "pip install semgrep",
            "build_cmd": lambda files, tmpdir: [
                "semgrep", "--config", "p/typescript", "--config", "p/secrets",
                "--json", "--quiet", *files
            ],
            "parse": "_parse_semgrep",
        },
    ],
    ".tsx": [
        {
            "name": "eslint",
            "install_hint": "npm install -g eslint @typescript-eslint/parser @typescript-eslint/eslint-plugin",
            "build_cmd": lambda files, tmpdir: _make_eslint_cmd(files, tmpdir, ".tsx"),
            "parse": "_parse_eslint",
        },
    ],
    ".js": [
        {
            "name": "eslint",
            "install_hint": "npm install -g eslint",
            "build_cmd": lambda files, tmpdir: _make_eslint_cmd(files, tmpdir, ".js"),
            "parse": "_parse_eslint",
        },
    ],
    ".go": [
        {
            "name": "gosec",
            "install_hint": "go install github.com/securego/gosec/v2/cmd/gosec@latest",
            "build_cmd": lambda files, tmpdir: [
                "gosec", "-fmt", "json", "-quiet", *files
            ],
            "parse": "_parse_gosec",
        },
    ],
    ".rs": [
        {
            "name": "clippy",
            "install_hint": "rustup component add clippy",
            "build_cmd": lambda files, tmpdir: [
                "cargo", "clippy", "--message-format", "json", "--", "-W", "clippy::all"
            ],
            "parse": "_parse_cargo",
        },
    ],
    ".java": [
        {
            "name": "semgrep",
            "install_hint": "pip install semgrep",
            "build_cmd": lambda files, tmpdir: [
                "semgrep", "--config", "p/java", "--config", "p/secrets",
                "--json", "--quiet", *files
            ],
            "parse": "_parse_semgrep",
        },
    ],
}

# Generic: semgrep runs on all languages as fallback
GENERIC_TOOLS = [
    {
        "name": "semgrep",
        "install_hint": "pip install semgrep",
        "build_cmd": lambda files, tmpdir: [
            "semgrep", "--config", "p/secrets", "--config", "p/owasp-top-ten",
            "--json", "--quiet", *files
        ],
        "parse": "_parse_semgrep",
    },
]


def _make_eslint_cmd(files, tmpdir, ext):
    """Create a minimal ESLint config file for hermaguard-prescan and return the command."""
    cfg_path = os.path.join(tmpdir, f"eslintrc-{ext.lstrip('.')}.json")
    config = {
        "env": {"es2021": True, "node": True},
        "parser": "@typescript-eslint/parser" if ext in (".ts", ".tsx") else "espree",
        "parserOptions": {"ecmaVersion": "latest"},
        "plugins": ["@typescript-eslint"] if ext in (".ts", ".tsx") else [],
        "rules": {
            "no-unused-vars": "warn",
            "no-undef": "error",
            "no-empty": "error",
            "no-unsafe-optional-chaining": "error",
            "no-unsafe-negation": "error",
            "no-unsafe-finally": "error",
            "no-constant-condition": "error",
            "no-dupe-keys": "error",
            "no-prototype-builtins": "warn",
            "require-atomic-updates": "error",
        },
    }
    with open(cfg_path, "w") as f:
        json.dump(config, f)
    return [
        "eslint", "-c", cfg_path, "-f", "json", "--no-error-on-unmatched-pattern", *files
    ]


# ── Parsers (tool → normalised {tool, rule_id, severity, file, line, message, category}) ──

def _parse_bandit(output: str) -> list:
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return []
    findings = []
    for r in data.get("results", []):
        sev = {"MEDIUM": "MEDIUM", "HIGH": "HIGH"}.get(r.get("issue_severity", "").upper(), "LOW")
        findings.append({
            "tool": "bandit",
            "rule_id": r.get("test_id", ""),
            "severity": sev,
            "file": r.get("filename", ""),
            "line": r.get("line_number", 0),
            "message": r.get("issue_text", ""),
            "category": "security",
        })
    return findings


def _parse_ruff(output: str) -> list:
    findings = []
    for line in output.strip().split("\n"):
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        rule_id = r.get("code", "")
        if rule_id:
            findings.append({
                "tool": "ruff",
                "rule_id": rule_id,
                "severity": "LOW",
                "file": r.get("filename", ""),
                "line": r.get("location", {}).get("row", 0),
                "message": r.get("message", ""),
                "category": "quality",
            })
    return findings


def _parse_eslint(output: str) -> list:
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return []
    findings = []
    for file_entry in data:
        fname = file_entry.get("filePath", "")
        for msg in file_entry.get("messages", []):
            sev_map = {2: "HIGH", 1: "MEDIUM", 0: "LOW"}
            sev = sev_map.get(msg.get("severity", 0), "LOW")
            findings.append({
                "tool": "eslint",
                "rule_id": msg.get("ruleId", "") or "N/A",
                "severity": sev,
                "file": fname,
                "line": msg.get("line", 0),
                "message": msg.get("message", ""),
                "category": "quality",
            })
    return findings


def _parse_semgrep(output: str) -> list:
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return []
    findings = []
    for r in data.get("results", []):
        sev = r.get("extra", {}).get("severity", "WARNING").upper()
        sev_norm = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}.get(sev, "LOW")
        findings.append({
            "tool": "semgrep",
            "rule_id": r.get("check_id", ""),
            "severity": sev_norm,
            "file": r.get("path", ""),
            "line": r.get("start", {}).get("line", 0),
            "message": r.get("extra", {}).get("message", ""),
            "category": "security" if "owasp" in r.get("check_id", "").lower() else "quality",
        })
    return findings


def _parse_gosec(output: str) -> list:
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return []
    findings = []
    for issue in data.get("Issues", []) if isinstance(data, dict) else (data if isinstance(data, list) else []):
        findings.append({
            "tool": "gosec",
            "rule_id": issue.get("rule_id", ""),
            "severity": issue.get("severity", "MEDIUM").upper(),
            "file": issue.get("file", ""),
            "line": int(issue.get("line", 0)),
            "message": issue.get("details", ""),
            "category": "security",
        })
    return findings


def _parse_cargo(output: str) -> list:
    findings = []
    for line in output.strip().split("\n"):
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("reason") != "compiler-message":
            continue
        m = msg.get("message", {})
        if m.get("code") is None:
            continue
        spans = msg.get("spans", [])
        if not spans:
            continue
        findings.append({
            "tool": "clippy",
            "rule_id": m.get("code", {}).get("code", ""),
            "severity": m.get("level", "warning").upper(),
            "file": spans[0].get("file_name", ""),
            "line": spans[0].get("line_start", 0),
            "message": m.get("message", ""),
            "category": "quality",
        })
    return findings


PARSER_MAP = {
    "bandit": _parse_bandit,
    "ruff": _parse_ruff,
    "eslint": _parse_eslint,
    "semgrep": _parse_semgrep,
    "gosec": _parse_gosec,
    "clippy": _parse_cargo,
}


def find_tool(name: str) -> str | None:
    """Return path to tool if it's on PATH, else None.

    Uses shutil.which so the lookup works on Windows as well as POSIX
    (the old `which` subprocess was POSIX-only despite the cross-platform claim).
    """
    found = shutil.which(name)
    if found:
        return found
    # Fall back to common install locations not always on a minimal PATH.
    for path in [f"/usr/local/bin/{name}", f"/usr/bin/{name}", os.path.expanduser(f"~/.local/bin/{name}")]:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def split_files(files_arg: str) -> list:
    """Split comma/space-separated file list into list of paths."""
    # Try comma-separated first, then newline-separated (from git diff --name-only)
    if "," in files_arg:
        return [f.strip() for f in files_arg.split(",") if f.strip()]
    return [f for f in files_arg.strip().split("\n") if f.strip()]


def group_by_extension(files: list, restrict_tools: list | None = None) -> dict:
    """Group files by extension, mapping to available tools.
    Returns {ext: {"files": [...], "tools": [...]}}
    """
    groups = {}
    for f in files:
        ext = Path(f).suffix.lower()
        if not ext:
            continue
        if ext not in groups:
            groups[ext] = {"files": [], "tools": LANGUAGE_TOOLS.get(ext, [])}
        groups[ext]["files"].append(f)

    # Filter tools if --tools flag was passed
    if restrict_tools:
        for ext_data in groups.values():
            ext_data["tools"] = [t for t in ext_data["tools"] if t["name"] in restrict_tools]

    return groups


def run_tool(tool_def: dict, files: list, tmpdir: str) -> tuple[str | None, list]:
    """Run a single tool. Returns (None, [findings]) on success or (error_msg, []) on failure."""
    if not files:
        return f"no files for {tool_def['name']}", []

    tool_path = find_tool(tool_def["name"])
    if not tool_path:
        return f"{tool_def['name']} not installed ({tool_def.get('install_hint', '')})", []

    cmd = tool_def["build_cmd"](files, tmpdir)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return f"{tool_def['name']} timed out", []
    except FileNotFoundError:
        return f"{tool_def['name']} command not found", []

    if result.returncode != 0 and not result.stdout.strip():
        return f"{tool_def['name']} failed: {result.stderr[:200]}", []

    parser_name = tool_def["parse"]
    parser = PARSER_MAP.get(parser_name, lambda x: [])
    try:
        findings = parser(result.stdout.strip())
    except Exception as e:
        return f"{tool_def['name']} parse error: {e}", []

    return None, findings


# ── Suppression rules (compiled from dismissed findings via hermaguard-compile-rules) ──

DEFAULT_RULES_PATHS = [
    ".kensei/hermaguard-rules.yaml",
    "hermaguard-rules.yaml",
]


def load_suppression_rules(path: str | None = None) -> tuple[list, str | None]:
    """Load compiled suppression rules. Returns (rules, source_path_or_None).

    Accepts the exact format hermaguard-compile-rules writes: a JSON-superset
    YAML list of dicts with keys rule_id/pattern/agent/dismissals. Parsing is
    stdlib-only via json per-document; a fallback regex extractor handles
    hand-edited files. Missing file = no rules, never an error.
    """
    candidates = [path] if path else DEFAULT_RULES_PATHS
    for cand in candidates:
        if not cand:
            continue
        try:
            if not os.path.isfile(cand):
                continue
            with open(cand) as f:
                text = f.read()
        except OSError:
            continue
        rules = _parse_rules_text(text)
        if rules:
            return rules, cand
        return [], cand  # file exists but empty of rules
    return [], None


def _parse_rules_text(text: str) -> list:
    """Parse the compile-rules YAML subset with stdlib only."""
    rules = []
    current = {}
    # Try whole-document JSON first (valid when the file is a pure JSON array)
    try:
        data = json.loads(text)
        if isinstance(data, list):
            return [r for r in data if isinstance(r, dict) and r.get("pattern")]
    except json.JSONDecodeError:
        pass
    # Line-oriented parse of the known key set
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("#") or not s.startswith("- ") and not s[:1].isalpha():
            # allow "- rule_id:" item starts and "  key: value" continuations
            if not s.startswith("- ") and not (current and s and ":" in s and not s.startswith("-")):
                continue
        m = re.match(r"^-\s*(rule_id|pattern|agent|dismissals|file_scope):\s*(.*)$", s)
        if m:
            if current:
                rules.append(current)
            current = {m.group(1): _coerce_scalar(m.group(2))}
            continue
        m = re.match(r"^(rule_id|pattern|agent|dismissals|file_scope):\s*(.*)$", s)
        if m and current is not None:
            key = m.group(1)
            val = _coerce_scalar(m.group(2))
            if key == "rule_id" and current:
                rules.append(current)
                current = {}
            current[key] = val
            continue
    if current:
        rules.append(current)
    return [r for r in rules if r.get("pattern")]


def _coerce_scalar(v: str):
    v = v.strip()
    if v.startswith('"') and v.endswith('"') and len(v) >= 2:
        try:
            return json.loads(v)
        except json.JSONDecodeError:
            return v[1:-1]
    if v.startswith("'") and v.endswith("'") and len(v) >= 2:
        return v[1:-1]
    if v.isdigit():
        return int(v)
    return v


def apply_suppression_rules(findings: list, rules: list) -> tuple[list, list]:
    """Filter findings against compiled suppression rules.

    A finding is suppressed when ALL of:
      - rule.pattern (case-insensitive substring) appears in the finding's
        message, AND
      - rule.file_scope is empty or equals the finding's file basename/dir.
    Suppressed findings are dropped from the output and listed in stats.
    Returns (kept_findings, suppressed_findings).
    """
    if not rules:
        return findings, []
    kept, suppressed = [], []
    for f in findings:
        hay = f"{f.get('message', '')} {f.get('rule_id', '')}".lower()
        fname = f.get("file", "")
        dropped = False
        for r in rules:
            pat = str(r.get("pattern", "")).lower()
            if not pat:
                continue
            scope = str(r.get("file_scope", "") or "")
            scope_ok = (not scope) or (scope and (scope in fname or os.path.basename(fname) == os.path.basename(scope)))
            if pat in hay and scope_ok:
                dropped = True
                break
        if dropped:
            suppressed.append(f)
        else:
            kept.append(f)
    return kept, suppressed


def run_prescan(files: list, restrict_tools: list | None = None,
                rules_path: str | None = None) -> dict:
    """Main entry point. Run all applicable tools on given files.
    Returns the output dict.
    """
    groups = group_by_extension(files, restrict_tools)

    # Collect unique tools from matching extensions
    all_exts = []
    for ext, data in groups.items():
        all_exts.extend(data["files"])
    unique_exts = list(groups.keys())

    # Also add generic tools (semgrep) to any non-empty group
    all_tools_run = set()
    all_findings = []
    tools_run = []
    tools_skipped = []

    # Run extension-specific tools
    for ext, g in groups.items():
        for tool in g["tools"]:
            if tool["name"] in all_tools_run:
                continue
            all_tools_run.add(tool["name"])
            path = find_tool(tool["name"])
            if not path:
                tools_skipped.append(tool["name"])
                continue
            tools_run.append(tool["name"])
            err, findings = run_tool(tool, g["files"], tempfile.gettempdir())
            if err:
                # Move from run to skipped with the reason, once (no double-append).
                if tool["name"] in tools_run:
                    tools_run.remove(tool["name"])
                tools_skipped.append(f"{tool['name']} ({err})")
                continue
            all_findings.extend(findings)

    # Run generic tools (semgrep with security rules) on all files by extension, if available
    semgrep_path = find_tool("semgrep")
    if semgrep_path and all_exts:
        # Only run generic semgrep if it hasn't already been run
        if "semgrep" not in all_tools_run:
            all_tools_run.add("semgrep")
            tools_run.append("semgrep")
            err, findings = run_tool(GENERIC_TOOLS[0], all_exts, tempfile.gettempdir())
            if not err:
                all_findings.extend(findings)
            else:
                tools_skipped.append(f"semgrep-generic ({err})")

    # Deduplicate: same (file, line, tool, rule_id) = same finding
    seen = set()
    deduped = []
    for f in all_findings:
        key = (f["file"], f["line"], f["tool"], f["rule_id"])
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    # Apply compiled suppression rules (hermaguard-compile-rules output)
    rules, rules_source = load_suppression_rules(rules_path)
    kept, suppressed = apply_suppression_rules(deduped, rules)

    by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in kept:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1

    return {
        "findings": kept,
        "stats": {
            "tools_run": tools_run,
            "tools_skipped": tools_skipped,
            "total_findings": len(kept),
            "by_severity": by_sev,
            "files_scanned": len(files),
            "suppression_rules_applied": len(rules),
            "suppression_rules_source": rules_source,
            "suppressed_findings": len(suppressed),
            "hermaguard_prescan_version": VERSION,
        },
    }


def main():
    parser = argparse.ArgumentParser(
        description="Hermaguard Pre-Scan — deterministic static analysis before LLM review"
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument(
        "--files",
        help="Comma-separated or newline-separated list of file paths to scan"
    )
    src.add_argument(
        "--diff",
        help="Newline-separated file list, e.g. \"$(git diff --name-only)\". Alias for --files."
    )
    parser.add_argument(
        "--output", required=True,
        help="Path to write JSON output (e.g., /tmp/hermaguard/prescan-abc123.json)"
    )
    parser.add_argument(
        "--tools",
        help="Comma-separated list of tools to restrict to (e.g., 'bandit,ruff'). Default: auto-detect from file extensions."
    )
    parser.add_argument(
        "--rules",
        help="Path to compiled suppression rules (hermaguard-compile-rules output). Default: .kensei/hermaguard-rules.yaml or hermaguard-rules.yaml in cwd."
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {VERSION}"
    )
    args = parser.parse_args()

    files = split_files(args.files or args.diff)
    if not files:
        output = {
            "findings": [],
            "stats": {
                "tools_run": [],
                "tools_skipped": [],
                "total_findings": 0,
                "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
                "files_scanned": 0,
                "hermaguard_prescan_version": VERSION,
            },
        }
    else:
        restrict = [t.strip() for t in args.tools.split(",")] if args.tools else None
        output = run_prescan(files, restrict, rules_path=args.rules)

    # Write output
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)

    # Summary to stdout
    stats = output["stats"]
    print(f"Pre-scan complete: {stats['total_findings']} findings from {stats['files_scanned']} files")
    print(f"  Tools run: {', '.join(stats['tools_run']) if stats['tools_run'] else 'none'}")
    if stats["tools_skipped"]:
        print(f"  Tools skipped: {', '.join(stats['tools_skipped'])}")
    sevs = []
    for s, c in stats["by_severity"].items():
        if c > 0:
            sevs.append(f"{s}: {c}")
    if sevs:
        print(f"  By severity: {', '.join(sevs)}")
    print(f"  Output: {args.output}")

    sys.exit(0)


if __name__ == "__main__":
    main()
