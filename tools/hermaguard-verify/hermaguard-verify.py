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
    hermaguard-verify.py --poc poc.py --target src/app.py
        --finding '{"id":"HG-1","classes":["CWE-476"],"file":"src/app.py"}'
        --revision <commit> [--expect-fail] [--expect-output 'TypeError']
        [--json record.json]
        Writes a verification RECORD bound by content hash to the finding id,
        the reviewed revision, the target path and its content digest, the PoC
        digest and the expected result. Stored output is redacted first.

    hermaguard-verify.py --check-report report.json [--evidence-dir DIR]
                         [--repo-root DIR] [--rerun] [--require-evidence]
        Enforce the forced-verification policy: a finding in a hard class
        (CWE-362, HG-ASYNC, HG-PARTIAL-WRITE, CWE-416 by default) counts as
        VERIFIED only if it references a verifier record that exists, is
        unaltered, and matches the finding, revision, target and result. A
        typed-in "VERIFIED" label is not evidence. Unadmitted findings stay in
        the report as UNVERIFIED (or REFUTED); the gate fails. Exit 1 on
        violations. Reports without report_version are LEGACY: read as before,
        labelled "evidence not checked", never certified.

        --rerun re-executes the recorded PoC (opt-in: it runs code) and
        requires the same verdict. The sandbox limits CPU, memory, files and
        processes but does NOT block network access - use it on a runner you
        trust. Records carry a content hash, not a signature: this stops
        copied, stale and edited records, not a forger who can rewrite a
        record AND its hash on the same machine.

Exit codes: 0 = verdict produced & policy satisfied; 1 = policy
violations (check-report) or usage error; 2 = PoC could not run at all.
"""

import argparse
import hashlib
import json
import posixpath
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

VERSION = "1.1.0"

# Report format version; keep in step with hermaguard-coverage.py (tested).
REPORT_VERSION = 2
RECORD_VERSION = 2

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


# ---------------------------------------------------------------------------
# Records: bind a verdict to the finding, revision, target and result
# ---------------------------------------------------------------------------

_REDACTIONS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "[REDACTED PRIVATE KEY]"),
    (re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key|authorization)\b(\s*[=:]\s*)(\S+)"), r"\1\2[REDACTED]"),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{8,}"), "Bearer [REDACTED]"),
]


def redact(text):
    """Strip obvious secrets from captured output before it is stored."""
    if not isinstance(text, str):
        return text
    for pattern, repl in _REDACTIONS:
        text = pattern.sub(repl, text)
    return text


def _norm_path(path):
    text = str(path or "").strip().replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    return posixpath.normpath(text) if text else ""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path) -> str:
    with open(path, "rb") as fh:
        return sha256_bytes(fh.read())


def record_digest(record: dict) -> str:
    """Hash of the record's canonical JSON, excluding the hash field itself."""
    body = {k: v for k, v in record.items() if k != "record_sha256"}
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256_bytes(canon.encode("utf-8"))


def build_record(finding: dict, evidence: dict, *, poc_path, target_path=None, revision=None,
                 symbol=None, expect_fail=False, expect_output=None) -> dict:
    """Assemble the bindable record for one PoC run (redacted, then hashed)."""
    evidence = dict(evidence)
    for key in ("stdout", "stderr"):
        evidence[key] = redact(evidence.get(key, ""))
    binding = {
        "finding_id": finding.get("id"),
        "classes": sorted(finding.get("classes") or []),
        "revision": revision,
        "target": {
            "path": _norm_path(target_path) if target_path else None,
            "sha256": sha256_file(target_path) if target_path and os.path.isfile(target_path) else None,
            "symbol": symbol,
        },
        "poc_path": os.path.basename(poc_path) if poc_path else None,
        "poc_sha256": sha256_file(poc_path) if poc_path and os.path.isfile(poc_path) else None,
        "expected": {"expect_fail": bool(expect_fail), "expect_output": expect_output},
    }
    record = {
        "tool": "hermaguard-verify",
        "version": VERSION,
        "record_version": RECORD_VERSION,
        "finding": finding,
        "binding": binding,
        "verification": evidence,
    }
    record["record_sha256"] = record_digest(record)
    return record


def _resolve_inside(base, rel):
    if base is None or not isinstance(rel, str) or not rel or Path(rel).is_absolute():
        return None
    base = Path(base).resolve()
    target = (base / rel).resolve()
    try:
        target.relative_to(base)
    except ValueError:
        return None
    return target


# Admission statuses (why a verified claim was NOT admitted)
ABSENT, STALE, MISMATCHED, ALTERED = "absent", "stale", "mismatched", "altered"
REFUTED_S, CONTRADICTORY, UNVERIFIED_S, INVALID = "refuted", "contradictory", "unverified", "invalid"


def admit_finding(finding: dict, report: dict, *, evidence_dir=None, repo_root=None,
                  rerun: bool = False) -> tuple:
    """Decide whether this finding's VERIFIED claim is backed by a verifier record.

    Returns (admitted: bool, status: str, detail: str). `status` is "admitted"
    or one of absent / invalid / altered / mismatched / stale / refuted /
    contradictory / unverified.
    """
    ref = finding.get("verification") or {}
    rel, claimed_hash = ref.get("record"), ref.get("record_sha256")
    if not rel or not claimed_hash:
        return False, ABSENT, "no verifier record reference (a bare label is not evidence)"
    path = _resolve_inside(evidence_dir, rel)
    if path is None or not path.is_file():
        return False, ABSENT, f"record {rel!r} not found inside the evidence directory"
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False, INVALID, "record is not valid JSON"
    if not isinstance(record, dict) or record.get("record_version") != RECORD_VERSION \
            or not isinstance(record.get("binding"), dict) or not isinstance(record.get("verification"), dict):
        return False, INVALID, "record is not a version-2 hermaguard-verify record"

    actual = record_digest(record)
    if actual != record.get("record_sha256") or actual != claimed_hash:
        return False, ALTERED, "record content does not match its recorded hash (edited, or a different record)"

    binding = record["binding"]
    verification = record["verification"]
    if binding.get("finding_id") != finding.get("id"):
        return False, MISMATCHED, f"record is for finding {binding.get('finding_id')!r}, not {finding.get('id')!r}"
    forced_hit = set(finding.get("classes") or []) & set(binding.get("classes") or [])
    if not forced_hit:
        return False, MISMATCHED, "record's classes do not include any class the finding claims"
    target = binding.get("target") or {}
    if _norm_path(finding.get("file")) != _norm_path(target.get("path")) or not target.get("path"):
        return False, MISMATCHED, (f"record targets {target.get('path')!r}, "
                                    f"finding is in {finding.get('file')!r}")
    if finding.get("symbol") and target.get("symbol") and finding["symbol"] != target["symbol"]:
        return False, MISMATCHED, "record targets a different symbol"
    if not binding.get("revision"):
        return False, STALE, "record names no revision"
    if binding["revision"] != report.get("revision"):
        return False, STALE, (f"record is for revision {binding['revision']!r}, "
                              f"the report reviews {report.get('revision')!r}")
    if repo_root is not None and target.get("sha256"):
        current = _resolve_inside(repo_root, target["path"])
        if current is None or not current.is_file() or sha256_file(current) != target["sha256"]:
            return False, STALE, "target file content has changed since the record was made"

    verdict = verification.get("verdict")
    if verdict == REFUTED:
        return False, REFUTED_S, "the verifier REFUTED this finding; it cannot be presented as confirmed"
    if verdict != VERIFIED:
        return False, UNVERIFIED_S, f"record verdict is {verdict!r}"
    if (ref.get("verdict") not in (None, VERIFIED)):
        return False, MISMATCHED, "the finding's own label disagrees with the record"
    expected = binding.get("expected") or {}
    exit_code = verification.get("exit_code")
    if expected.get("expect_fail") and not expected.get("expect_output") and exit_code in (0, None):
        return False, CONTRADICTORY, "VERIFIED, but the PoC was expected to fail and exited cleanly"
    if not str(verification.get("signal") or "").strip():
        return False, CONTRADICTORY, "VERIFIED with no observed signal"

    if rerun:
        poc = _resolve_inside(evidence_dir, binding.get("poc_path") or "")
        tgt = _resolve_inside(repo_root, target["path"]) if repo_root is not None else None
        if poc is None or not poc.is_file() or sha256_file(poc) != binding.get("poc_sha256"):
            return False, ABSENT, "rerun requested but the recorded PoC is missing or altered"
        if tgt is None or not tgt.is_file():
            return False, ABSENT, "rerun requested but the target file is not available under --repo-root"
        again = run_poc(str(poc), str(tgt), bool(expected.get("expect_fail")), expected.get("expect_output"))
        if again.get("verdict") != VERIFIED:
            return False, CONTRADICTORY, f"re-running the PoC gave {again.get('verdict')}, not VERIFIED"
    return True, "admitted", "verifier record matches the finding, revision, target and result"


def check_report_policy(report: dict, forced_classes: list | None = None, *, evidence_dir=None,
                        repo_root=None, rerun: bool = False, require_evidence: bool = False) -> dict:
    """Enforce forced verification for hard classes. Returns the policy result.

    v2 reports (report_version 2): a hard-class finding is admitted as VERIFIED
    only through `admit_finding`. Every other hard-class finding keeps its place
    in the report as UNVERIFIED (or REFUTED) and the gate fails.

    Legacy reports (no report_version) keep the old label-only check, are marked
    `legacy` / `evidence_checked: False`, and are never certified: their VERIFIED
    labels were not compared with any record.
    """
    forced = set(forced_classes if forced_classes is not None else FORCED_VERIFICATION_CLASSES)
    version = report.get("report_version")
    legacy = version is None
    errors = []
    if not legacy and version != REPORT_VERSION:
        errors.append(f"unsupported report_version {version!r}")
    if legacy and require_evidence:
        errors.append("legacy report: VERIFIED labels are not checked against records, and this gate requires it")
    violations, findings_out = [], []
    checked = 0
    for f in report.get("findings", []):
        if not isinstance(f, dict):
            continue
        classes = set(f.get("classes") or [])
        if not classes & forced:
            continue
        checked += 1
        v = (f.get("verification") or {})
        if legacy:
            admitted, status, detail = v.get("verdict") == VERIFIED, ("legacy" if v.get("verdict") == VERIFIED else ABSENT), \
                ("label only - not checked against a record" if v.get("verdict") == VERIFIED else "no VERIFIED label")
        else:
            admitted, status, detail = admit_finding(f, report, evidence_dir=evidence_dir,
                                                     repo_root=repo_root, rerun=rerun)
        effective = VERIFIED if admitted else (REFUTED if status == REFUTED_S else UNVERIFIED)
        findings_out.append({"finding_id": f.get("id", "?"), "admitted": admitted, "status": status,
                             "detail": detail, "effective_verdict": effective})
        if not admitted:
            violations.append({
                "finding_id": f.get("id", "?"),
                "classes": sorted(classes & forced),
                "verification_verdict": v.get("verdict", "MISSING"),
                "required": VERIFIED,
                "status": status,
                "detail": detail,
                "effective_verdict": effective,
            })
    return {
        "ok": not violations and not errors,
        "issuable": not errors,
        "legacy": legacy,
        "evidence_checked": not legacy,
        "errors": errors,
        "hard_class_findings": checked,
        "violations": violations,
        "findings": findings_out,
        "policy": (
            "Findings in hard classes "
            f"({', '.join(sorted(forced))}) count as VERIFIED only when they reference a "
            "hermaguard-verify record that matches the finding, revision, target and result. "
            "Otherwise they stay in the report as UNVERIFIED and the gate fails."
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
    p.add_argument("--revision", help="Commit or content digest the finding was reviewed at (recorded in the record)")
    p.add_argument("--symbol", help="Optional symbol the PoC targets (recorded in the record)")
    p.add_argument("--evidence-dir", help="Directory holding the verifier records (default: the report's directory)")
    p.add_argument("--repo-root", help="Repository root, to check the target's content digest and for --rerun")
    p.add_argument("--rerun", action="store_true",
                   help="Re-execute recorded PoCs and require the same verdict (runs code; see --help header)")
    p.add_argument("--require-evidence", action="store_true", help="Fail legacy (version-less) reports")
    args = p.parse_args()

    if args.check_report:
        report = json.loads(Path(args.check_report).read_text())
        evidence_dir = args.evidence_dir or str(Path(args.check_report).resolve().parent)
        result = check_report_policy(report, evidence_dir=evidence_dir, repo_root=args.repo_root,
                                     rerun=args.rerun, require_evidence=args.require_evidence)
        print(f"policy {'PASS' if result['ok'] else 'FAIL'}: "
              f"{result['hard_class_findings']} hard-class findings checked, "
              f"{len(result['violations'])} violations")
        if result["legacy"]:
            print("LEGACY report: VERIFIED labels were NOT checked against verifier records")
        for e in result["errors"]:
            print(f"  error: {e}")
        for v in result["violations"]:
            print(f"  violation: {v['finding_id']} ({', '.join(v['classes'])}) is "
                  f"{v['effective_verdict']} [{v['status']}]: {v['detail']}")
        return 0 if result["ok"] else 1

    if not args.poc:
        p.error("--poc or --check-report required")

    finding = json.loads(args.finding) if args.finding else {}
    evidence = run_poc(args.poc, args.target, args.expect_fail, args.expect_output, args.timeout)
    out = build_record(finding, evidence, poc_path=args.poc, target_path=args.target,
                       revision=args.revision, symbol=args.symbol,
                       expect_fail=args.expect_fail, expect_output=args.expect_output)
    evidence = out["verification"]
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
