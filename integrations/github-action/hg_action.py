#!/usr/bin/env python3
"""HermaGuard GitHub Action helper.

All values arrive through environment variables, never through shell
interpolation, so a hostile filename or input cannot become a command.

Subcommands
  select   work out which changed files are in scope; write the NUL-delimited
           list the scanner reads with --files-from, plus a JSON manifest.
  report   validate the scanner output, derive one result state, and write the
           PR comment (comment.md) and the exit decision (decision.json) from
           the same data so they can never disagree.
  enforce  exit with the decision recorded by `report`.

Result states: complete, partial, unavailable, out_of_scope.
An empty findings list means "clean" ONLY when the state is complete.
"""
from __future__ import annotations

import fnmatch
import json
import os
import subprocess
import sys
from pathlib import Path

# Extensions the deterministic scanner has tools for (see LANGUAGE_TOOLS in
# tools/hermaguard-prescan/hermaguard-prescan.py).
SCANNABLE_EXTS = {".py", ".ts", ".tsx", ".js", ".go", ".rs", ".java"}
ZERO_SHA = "0" * 40


def parse_patterns(raw: str) -> list[str]:
    """Skip patterns may be separated by newlines or commas (a literal
    backslash-n typed into a YAML default is also accepted)."""
    raw = raw.replace("\\n", "\n")
    out = []
    for chunk in raw.replace(",", "\n").split("\n"):
        chunk = chunk.strip()
        if chunk:
            out.append(chunk)
    return out


def parse_int(raw: str, default: int) -> int:
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def resolve_range(env) -> tuple[str, str]:
    base = env.get("BASE_SHA", "").strip()
    head = env.get("HEAD_SHA", "").strip()
    if not base:
        base = env.get("PUSH_BEFORE", "").strip()
        head = env.get("PUSH_AFTER", "").strip()
    if not base or base == ZERO_SHA:
        base, head = "HEAD~1", "HEAD"
    if not head:
        head = "HEAD"
    return base, head


def git_changed(base: str, head: str) -> list[str]:
    """Changed (not deleted) paths, NUL-safe."""
    proc = subprocess.run(
        ["git", "diff", "-z", "--name-only", "--diff-filter=ACMRT", base, head, "--"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            "git diff failed: " + proc.stderr.decode("utf-8", "replace").strip())
    return [n.decode("utf-8", "surrogateescape")
            for n in proc.stdout.split(b"\0") if n]


def classify(changed: list[str], patterns: list[str], max_files: int) -> dict:
    in_scope, skipped_pattern, not_scannable = [], [], []
    for path in changed:
        if any(fnmatch.fnmatchcase(path, pat) for pat in patterns):
            skipped_pattern.append(path)
        elif Path(path).suffix.lower() in SCANNABLE_EXTS:
            in_scope.append(path)
        else:
            not_scannable.append(path)
    return {
        "changed": changed,
        "in_scope": in_scope,
        "skipped_by_pattern": skipped_pattern,
        "not_scannable": not_scannable,
        "max_files": max_files,
        "over_cap": len(in_scope) > max_files,
    }


def write_output(env, key: str, value: str) -> None:
    target = env.get("GITHUB_OUTPUT")
    if not target:
        return
    if "\n" in value or "\r" in value:
        raise ValueError(f"refusing multi-line value for output {key!r}")
    with open(target, "a", encoding="utf-8") as fh:
        fh.write(f"{key}={value}\n")


def cmd_select(env) -> int:
    work = Path(env.get("RUNNER_TEMP") or ".") / "hermaguard"
    work.mkdir(parents=True, exist_ok=True)
    base, head = resolve_range(env)
    changed = git_changed(base, head)
    manifest = classify(
        changed,
        parse_patterns(env.get("SKIP_PATTERNS", "")),
        parse_int(env.get("MAX_FILES", "50"), 50),
    )
    manifest["base"], manifest["head"] = base, head

    scan_list = [] if manifest["over_cap"] else manifest["in_scope"]
    (work / "files.list").write_bytes(
        b"\0".join(p.encode("utf-8", "surrogateescape") for p in scan_list))
    (work / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=True), encoding="utf-8")

    write_output(env, "changed_count", str(len(changed)))
    write_output(env, "scan_count", str(len(scan_list)))
    write_output(env, "over_cap", "true" if manifest["over_cap"] else "false")
    print(f"changed={len(changed)} in_scope={len(manifest['in_scope'])} "
          f"scan_list={len(scan_list)} over_cap={manifest['over_cap']}")
    return 0


# ---------------------------------------------------------------- report ----

STATES = ("complete", "partial", "unavailable", "out_of_scope")
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
PER_SEVERITY_CAP = 10


def safe(text, limit=200) -> str:
    """Make tool/PR-controlled text inert in a markdown comment."""
    text = " ".join(str(text).split())
    text = text.replace("`", "'").replace("@", "@\u200b").replace("|", "\\|")
    text = text.replace("<", "&lt;").replace(">", "&gt;")
    return text[:limit] + ("..." if len(text) > limit else "")


def normalise_block_on(raw: str) -> tuple[str, str | None]:
    value = (raw or "").strip().upper()
    if value in ("CRITICAL", "HIGH", "NEVER"):
        return value.lower() if value == "NEVER" else value, None
    return "HIGH", f"unrecognised block_on {safe(raw, 40)!r}; treated as HIGH"


def load_report(path: Path, expected_files: list[str]) -> tuple[dict | None, str | None]:
    """Return (report, None) when the scanner output is usable, else (None, why)."""
    if not path.is_file():
        return None, "scanner produced no report file"
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return None, f"report is not valid JSON ({exc.__class__.__name__})"
    if not isinstance(report, dict):
        return None, "report is not a JSON object"
    findings, stats = report.get("findings"), report.get("stats")
    if not isinstance(findings, list) or not isinstance(stats, dict):
        return None, "report is missing `findings` or `stats`"
    if stats.get("state") not in STATES:
        return None, "report has no valid `stats.state` (scanner too old or output corrupted)"
    if not all(isinstance(f, dict) for f in findings):
        return None, "report `findings` contains non-objects"
    listed = report.get("files")
    if isinstance(listed, list) and expected_files:
        got = sorted(r.get("path", "") for r in listed if isinstance(r, dict))
        if got != sorted(expected_files):
            return None, "report does not cover the files that were sent to the scanner"
    return report, None


SEVERITY_ALIASES = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW", "NOTE": "LOW"}


def norm_severity(raw) -> str:
    sev = str(raw or "LOW").upper()
    sev = SEVERITY_ALIASES.get(sev, sev)
    return sev if sev in SEVERITIES else "LOW"


def count_by_severity(findings: list) -> dict:
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[norm_severity(f.get("severity"))] += 1
    return counts


def decide(state: str, counts: dict, block_on: str, prescan_enabled: bool) -> tuple[int, str]:
    if not prescan_enabled:
        return 0, "Not blocking: the pre-scan was disabled by the workflow (prescan_enabled=false)."
    if block_on == "never":
        return 0, "Not blocking: block_on is `never` (advisory only)."
    if state in ("partial", "unavailable"):
        return 1, (f"BLOCKING: the scan is {state}, and block_on={block_on} requires a "
                   "completed scan. A partial or unavailable scan is not a pass.")
    threshold = ("CRITICAL",) if block_on == "CRITICAL" else ("CRITICAL", "HIGH")
    hit = sum(counts[s] for s in threshold)
    if hit:
        return 1, f"BLOCKING: {hit} {'+'.join(threshold)} finding(s) at or above block_on={block_on}."
    if state == "out_of_scope":
        return 0, "Not blocking: nothing in this change is in scope for the deterministic scan. It was NOT reviewed."
    note = (" Note: the bundled scanners do not currently emit CRITICAL; use block_on: HIGH to gate on high-severity findings."
            if block_on == "CRITICAL" else "")
    return 0, f"Not blocking: no {'+'.join(threshold)} findings in a completed scan.{note}"


def render_comment(*, state, reason, manifest, report, counts, decision_text, tool_exit) -> str:
    stats = (report or {}).get("stats", {})
    findings = (report or {}).get("findings", [])
    headline = {
        "complete": "Complete" if not findings else f"Complete - {len(findings)} finding(s)",
        "partial": "PARTIAL - this is not a clean result",
        "unavailable": "UNAVAILABLE - nothing was reliably scanned",
        "out_of_scope": "OUT OF SCOPE - this change was not reviewed",
    }[state]
    scanned = len(manifest["in_scope"]) if not manifest["over_cap"] else 0
    lines = [f"## HermaGuard deterministic pre-scan: {headline}", ""]
    if reason:
        lines += [f"**Why:** {reason}", ""]
    if state == "complete" and not findings:
        lines += [f"No issues found by the deterministic tools in the {scanned} file(s) scanned.", ""]
    lines += [
        "| | |", "|---|---|",
        f"| Changed files | {len(manifest['changed'])} |",
        f"| In scope for the scanner | {len(manifest['in_scope'])} |",
        f"| Sent to the scanner | {scanned} |",
        f"| Examined | {stats.get('files_examined', 0)} |",
        f"| Tools run | {safe(', '.join(stats.get('tools_run', [])) or 'none', 120)} |",
        f"| Tools skipped | {safe('; '.join(stats.get('tools_skipped', [])) or 'none', 240)} |",
        f"| Result state | `{state}` |",
    ]
    if tool_exit not in (None, ""):
        lines.append(f"| Scanner exit code | {safe(tool_exit, 10)} |")
    lines.append("")

    not_scanned = []
    if manifest["over_cap"]:
        not_scanned.append(f"{len(manifest['in_scope'])} in-scope file(s): more than the cap of "
                           f"{manifest['max_files']}, so none were scanned")
    if manifest["not_scannable"]:
        exts = sorted({Path(p).suffix.lower() or "(no extension)" for p in manifest["not_scannable"]})
        not_scanned.append(f"{len(manifest['not_scannable'])} file(s) of types the scanner "
                           f"does not cover ({safe(', '.join(exts), 80)})")
    if manifest["skipped_by_pattern"]:
        not_scanned.append(f"{len(manifest['skipped_by_pattern'])} file(s) matched `skip_patterns`")
    if not_scanned:
        lines += ["**Not scanned:**"] + [f"- {item}" for item in not_scanned] + [""]

    if findings:
        groups = {s: [] for s in SEVERITIES}
        for f in findings:
            groups[norm_severity(f.get("severity"))].append(f)
        for sev in SEVERITIES:
            items = groups[sev]
            if not items:
                continue
            lines.append(f"### {sev} ({len(items)})")
            for f in items[:PER_SEVERITY_CAP]:
                lines.append(f"- `{safe(f.get('file', '?'), 120)}:{safe(f.get('line', '?'), 10)}` - "
                             f"**{safe(f.get('tool', '?'), 30)}** {safe(f.get('message', ''))}")
            if len(items) > PER_SEVERITY_CAP:
                lines.append(f"- ...{len(items) - PER_SEVERITY_CAP} more {sev} finding(s) not shown (cap {PER_SEVERITY_CAP} per severity).")
            lines.append("")
    lines += [f"**Decision:** {decision_text}", "",
              "> CI runs the deterministic pre-scan only. Run `/hermaguard` for the full adversarial review."]
    return "\n".join(lines) + "\n"


def cmd_report(env) -> int:
    work = Path(env.get("RUNNER_TEMP") or ".") / "hermaguard"
    manifest = json.loads((work / "manifest.json").read_text(encoding="utf-8"))
    block_on, block_note = normalise_block_on(env.get("BLOCK_ON", "HIGH"))
    prescan_enabled = env.get("PRESCAN_ENABLED", "true").strip().lower() == "true"
    scan_list = [] if manifest["over_cap"] else manifest["in_scope"]
    tool_exit_path = work / "scan_exit"
    tool_exit = tool_exit_path.read_text().strip() if tool_exit_path.is_file() else None

    report, problem = None, None
    if not prescan_enabled:
        state, reason = "unavailable", "the pre-scan was disabled by the workflow (prescan_enabled=false)"
    elif manifest["over_cap"]:
        state, reason = "partial", (f"{len(manifest['in_scope'])} files exceed the cap of "
                                    f"{manifest['max_files']}; none were scanned")
    elif not scan_list:
        state, reason = "out_of_scope", ("no changed file is a type the deterministic scanner covers"
                                         if manifest["changed"] else "no files changed")
    else:
        report, problem = load_report(work / "prescan.json", scan_list)
        if problem:
            state, reason = "unavailable", problem
        else:
            state = report["stats"]["state"]
            reason = {
                "complete": None,
                "partial": "some files or tools were not examined (see the table)",
                "unavailable": "no tool could examine the files in scope",
                "out_of_scope": "the scanner reports nothing in scope",
            }[state]
    if block_note:
        reason = f"{reason}; {block_note}" if reason else block_note

    findings = report["findings"] if report else []
    counts = count_by_severity(findings)
    code, decision_text = decide(state, counts, block_on, prescan_enabled)
    comment = render_comment(state=state, reason=reason, manifest=manifest, report=report,
                             counts=counts, decision_text=decision_text, tool_exit=tool_exit)
    (work / "comment.md").write_text(comment, encoding="utf-8")
    (work / "decision.json").write_text(json.dumps({
        "state": state, "exit_code": code, "decision": decision_text, "counts": counts,
        "block_on": block_on, "reason": reason}, indent=2), encoding="utf-8")
    summary = env.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(comment)
    write_output(env, "state", state)
    write_output(env, "exit_code", str(code))
    print(f"state={state} exit_code={code}")
    return 0


def cmd_enforce(env) -> int:
    path = Path(env.get("RUNNER_TEMP") or ".") / "hermaguard" / "decision.json"
    try:
        decision = json.loads(path.read_text(encoding="utf-8"))
        code = int(decision["exit_code"])
    except (OSError, ValueError, KeyError):
        print("BLOCKING: no decision was recorded (the report step did not run).")
        return 1
    print(decision.get("decision", ""))
    return code


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    cmds = {"select": cmd_select, "report": cmd_report, "enforce": cmd_enforce}
    if not argv or argv[0] not in cmds:
        print(__doc__)
        return 2
    return cmds[argv[0]](os.environ)


if __name__ == "__main__":
    sys.exit(main())
