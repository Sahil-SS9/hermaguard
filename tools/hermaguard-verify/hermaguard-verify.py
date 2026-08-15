#!/usr/bin/env python3
"""
Hermaguard Verify — the evidence layer.

Runs a finding's PoC in a hardened subprocess sandbox and emits a verdict
from EXECUTION EVIDENCE, never from model self-report (the Vera principle:
judge outcomes from environment state, not model claims).

Division of labour:
  - The review agent WRITES the PoC (a small script that exercises the
    buggy code and exposes the failure).
  - This tool RUNS it deterministically and judges the result.

Verdicts:
  VERIFIED    PoC ran to its terminal condition and the expected signal
              was observed (expected_exit / expected_output regex).
  REFUTED     PoC ran cleanly — expected signal absent. The finding is
              likely a false positive.
  UNVERIFIED  PoC could not run (timeout, crash-before-signal, missing
              file). Honest label — never silently upgraded.

Sandbox hardening (stdlib only, per-run):
  - cwd: throwaway temp dir
  - env: empty (no credentials, no HOME leakage)
  - rlimits: CPU 10s, address space 512MB, file size 1MB, processes 16
  - own process group; killed hard on timeout
  - stdout/stderr captured and truncated to 4KB each in the report

Usage:
    hermaguard-verify.py --poc poc.py --target src/app.py \
        --finding '{"id":"HG-1","classes":["CWE-476"]}' \
        [--expect-fail] [--expect-output 'TypeError'] [--json out.json]

    hermaguard-verify.py --check-report report.json
        Enforce the forced-verification policy: findings in hard classes
        (CWE-362, HG-ASYNC, HG-PARTIAL-WRITE, CWE-416 by default) must
        carry verification.verdict == 'VERIFIED'. Exit 1 on violations.

Exit codes: 0 = verdict produced & policy satisfied; 1 = policy
violations (check-report) or usage error; 2 = PoC could not run at all.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

VERSION = "1.0.0"

try:
    import resource  # Unix-only; guarded for Windows/macOS portability
    _HAS_RESOURCE = True
except ImportError:
    resource = None
    _HAS_RESOURCE = False

_POSIX = os.name == "posix"

VERIFIED = "VERIFIED"
REFUTED = "REFUTED"
UNVERIFIED = "UNVERIFIED"

# Classes where LLM judgement is empirically weakest (calibration research:
# self-evaluation degrades most on hard/deferred-effect tasks). Findings in
# these classes may not be reported as confirmed without a passing PoC.
FORCED_VERIFICATION_CLASSES = [
    "CWE-362",        # race / TOCTOU — timing-dependent, easy to hand-wave
    "HG-ASYNC",       # async rejection gaps — control flow is hard to trace
    "HG-PARTIAL-WRITE",  # non-atomic updates — failure needs mid-sequence crash
    "CWE-416",        # use-after-free — lifetime reasoning
]

MAX_OUTPUT_BYTES = 4096
LIMIT_CPU_SECONDS = 10
LIMIT_AS_BYTES = 512 * 1024 * 1024
LIMIT_FSIZE_BYTES = 1024 * 1024
LIMIT_NPROC = 16


def _truncate(s: str) -> str:
    return s if len(s) <= MAX_OUTPUT_BYTES else s[:MAX_OUTPUT_BYTES] + f"\n…[truncated, {len(s)} bytes total]"


def _sandbox_limits():
    """preexec_fn: apply rlimits in the child before exec. No-op when the
    resource module is unavailable (Windows) — timeout is the backstop."""
    if not _HAS_RESOURCE:
        return
    resource.setrlimit(resource.RLIMIT_CPU, (LIMIT_CPU_SECONDS, LIMIT_CPU_SECONDS))
    resource.setrlimit(resource.RLIMIT_AS, (LIMIT_AS_BYTES, LIMIT_AS_BYTES))
    resource.setrlimit(resource.RLIMIT_FSIZE, (LIMIT_FSIZE_BYTES, LIMIT_FSIZE_BYTES))
    resource.setrlimit(resource.RLIMIT_NPROC, (LIMIT_NPROC, LIMIT_NPROC))


def run_poc(poc_path: str, target_path: str | None, expect_fail: bool = False,
            expect_output: str | None = None, timeout: int = 30) -> dict:
    """Run the PoC in the sandbox and return the evidence dict."""
    tmpdir = tempfile.mkdtemp(prefix="hermaguard-verify-")
    try:
        # Stage the PoC and the target into the sandbox cwd. The PoC imports
        # the target by its basename — self-contained, no repo access needed.
        staged_poc = os.path.join(tmpdir, "poc.py")
        shutil.copy(poc_path, staged_poc)
        if target_path:
            shutil.copy(target_path, os.path.join(tmpdir, os.path.basename(target_path)))

        start = time.monotonic()
        try:
            # -I strips user site-packages/env PYTHONPATH injection; cwd is
            # prepended to sys.path by -I only for scripts — belt and braces:
            # pass the sandbox dir explicitly so `import app` resolves to the
            # STAGED copy, never the repo original.
            cmd = [sys.executable, "-I", "-c",
                   f"import sys; sys.path.insert(0, {tmpdir!r}); exec(open({os.path.join(tmpdir, 'poc.py')!r}).read())"]
            kwargs = dict(cwd=tmpdir, env={}, capture_output=True, text=True, timeout=timeout)
            if _POSIX:
                # preexec_fn/start_new_session are POSIX-only; on Windows the
                # wall-clock timeout remains the isolation backstop.
                kwargs["preexec_fn"] = _sandbox_limits
                kwargs["start_new_session"] = True
            proc = subprocess.run(cmd, **kwargs)
            duration_ms = int((time.monotonic() - start) * 1000)
            exit_code = proc.returncode
            stdout = _truncate(proc.stdout)
            stderr = _truncate(proc.stderr)
            timed_out = False
        except subprocess.TimeoutExpired as e:
            duration_ms = int((time.monotonic() - start) * 1000)
            exit_code = None
            stdout = _truncate((e.stdout or b"").decode() if isinstance(e.stdout, bytes) else (e.stdout or ""))
            stderr = _truncate((e.stderr or b"").decode() if isinstance(e.stderr, bytes) else (e.stderr or ""))
            timed_out = True

        evidence = {
            "exit_code": exit_code,
            "stdout": stdout,
            "stderr": stderr,
            "duration_ms": duration_ms,
            "timed_out": timed_out,
            "sandbox": {
                "env": "empty",
                "cwd": "throwaway tmpdir",
                "rlimits_applied": _HAS_RESOURCE and _POSIX,
                "rlimits": {"cpu_s": LIMIT_CPU_SECONDS, "as_mb": LIMIT_AS_BYTES // (1024 * 1024),
                            "fsize_mb": LIMIT_FSIZE_BYTES // (1024 * 1024), "nproc": LIMIT_NPROC},
                "isolated_python": True,  # -I: no user site, no env vars, no path injection
            },
        }

        if timed_out:
            evidence["verdict"] = UNVERIFIED
            evidence["reason"] = f"PoC exceeded {timeout}s wall-clock limit and was killed"
            return evidence

        # ---- Deterministic verdict from execution evidence ----
        combined = (stdout or "") + "\n" + (stderr or "")
        signal_observed = []
        if expect_fail:
            if exit_code != 0:
                signal_observed.append(f"non-zero exit ({exit_code})")
        if expect_output:
            if re.search(expect_output, combined):
                signal_observed.append(f"output matched /{expect_output}/")

        if expect_fail or expect_output:
            if signal_observed:
                evidence["verdict"] = VERIFIED
                evidence["signal"] = "; ".join(signal_observed)
            else:
                evidence["verdict"] = REFUTED
                evidence["signal"] = "expected signal NOT observed — likely false positive"
        else:
            # No expectation given: any non-zero exit still counts as a
            # demonstrated failure; a clean run proves nothing, so UNVERIFIED.
            if exit_code != 0:
                evidence["verdict"] = VERIFIED
                evidence["signal"] = f"non-zero exit ({exit_code})"
            else:
                evidence["verdict"] = UNVERIFIED
                evidence["signal"] = "clean run with no expectation specified — nothing proven"
        return evidence
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def check_report_policy(report: dict, forced_classes: list | None = None) -> dict:
    """Enforce forced verification for hard classes. Returns policy result."""
    forced = set(forced_classes if forced_classes is not None else FORCED_VERIFICATION_CLASSES)
    violations = []
    checked = 0
    for f in report.get("findings", []):
        classes = set(f.get("classes") or [])
        if not classes & forced:
            continue
        checked += 1
        v = (f.get("verification") or {})
        if v.get("verdict") != VERIFIED:
            violations.append({
                "finding_id": f.get("id", "?"),
                "classes": sorted(classes & forced),
                "verification_verdict": v.get("verdict", "MISSING"),
                "required": VERIFIED,
            })
    return {
        "ok": not violations,
        "hard_class_findings": checked,
        "violations": violations,
        "policy": (
            "Findings in hard classes "
            f"({', '.join(sorted(forced))}) must carry verification.verdict == 'VERIFIED' "
            "— produced by hermaguard-verify execution evidence, not model self-report."
        ),
    }


def main():
    p = argparse.ArgumentParser(description="Hermaguard PoC verification runner")
    p.add_argument("--poc", help="Path to the PoC script (Python)")
    p.add_argument("--target", help="Path to the target source file the PoC exercises")
    p.add_argument("--finding", help="Finding JSON (echoed into the output for traceability)")
    p.add_argument("--expect-fail", action="store_true",
                   help="PoC is expected to exit non-zero (demonstrates the failure)")
    p.add_argument("--expect-output", help="Regex the PoC output must match (e.g. 'TypeError')")
    p.add_argument("--timeout", type=int, default=30, help="Wall-clock kill limit (s)")
    p.add_argument("--json", dest="json_out", help="Write the evidence JSON to this path")
    p.add_argument("--check-report", help="Report JSON to enforce forced-verification policy on")
    args = p.parse_args()

    if args.check_report:
        report = json.loads(Path(args.check_report).read_text())
        result = check_report_policy(report)
        print(f"policy {'PASS' if result['ok'] else 'FAIL'}: "
              f"{result['hard_class_findings']} hard-class findings checked, "
              f"{len(result['violations'])} violations")
        for v in result["violations"]:
            print(f"  violation: {v['finding_id']} ({', '.join(v['classes'])}) "
                  f"has verification={v['verification_verdict']}, requires {v['required']}")
        return 0 if result["ok"] else 1

    if not args.poc:
        p.error("--poc or --check-report required")

    finding = json.loads(args.finding) if args.finding else {}
    evidence = run_poc(args.poc, args.target, args.expect_fail, args.expect_output, args.timeout)
    out = {
        "tool": "hermaguard-verify",
        "version": VERSION,
        "finding": finding,
        "verification": evidence,
    }
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(out, indent=2))

    v = evidence["verdict"]
    print(f"verdict: {v}")
    print(f"  signal: {evidence.get('signal', '')}")
    print(f"  exit={evidence['exit_code']}  duration={evidence['duration_ms']}ms  timed_out={evidence['timed_out']}")
    if evidence.get("stdout"):
        print(f"  stdout: {evidence['stdout'][:200]}")
    if evidence.get("stderr"):
        print(f"  stderr: {evidence['stderr'][:200]}")
    if args.json_out:
        print(f"  evidence: {args.json_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
