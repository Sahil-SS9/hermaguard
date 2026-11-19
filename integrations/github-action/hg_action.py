#!/usr/bin/env python3
"""HermaGuard GitHub Action helper.

All values arrive through environment variables, never through shell
interpolation, so a hostile filename or input cannot become a command.

Subcommands
  select   work out which changed files are in scope; write the NUL-delimited
           list the scanner reads with --files-from, plus a JSON manifest.
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


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] not in {"select"}:
        print(__doc__)
        return 2
    return {"select": cmd_select}[argv[0]](os.environ)


if __name__ == "__main__":
    sys.exit(main())
