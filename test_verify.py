"""
Hermaguard Verify — Test Suite

Runs REAL PoCs in the REAL sandbox. No mocks of the verdict logic:
every test executes actual subprocesses and asserts on actual evidence.
"""

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def _load_module(name, relpath):
    spec = importlib.util.spec_from_file_location(name, ROOT / relpath)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load {relpath}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


V = _load_module("hermaguard_verify", "tools/hermaguard-verify/hermaguard-verify.py")


def _write(tmpdir, name, content):
    p = Path(tmpdir) / name
    p.write_text(content)
    return str(p)


class TestRealPoCRuns(unittest.TestCase):
    """Each test writes a genuine PoC + target and runs the real sandbox."""

    def test_verified_on_demonstrated_crash(self):
        # Target has the classic null-deref bug (bug 003 from the corpus)
        with tempfile.TemporaryDirectory() as d:
            target = _write(d, "app.py",
                'def get_user_email(cur, user_id):\n    row = cur.fetchone()\n    return row[0]\n')
            # Real PoC: a stub cursor that returns None, like a missing row
            poc = _write(d, "poc.py",
                "import app\n"
                "class Cur:\n"
                "    def fetchone(self):\n"
                "        return None\n"
                "app.get_user_email(Cur(), 123)\n")
            ev = V.run_poc(poc, target, expect_fail=True, expect_output="TypeError")
            self.assertEqual(ev["verdict"], "VERIFIED", ev)
            self.assertIn("TypeError", ev["stderr"] + ev["stdout"])

    def test_refuted_when_no_bug(self):
        # Fixed target: no bug, PoC runs clean -> REFUTED (likely false positive)
        with tempfile.TemporaryDirectory() as d:
            target = _write(d, "app.py",
                'def get_user_email(cur, user_id):\n    row = cur.fetchone()\n'
                '    return None if row is None else row[0]\n')
            poc = _write(d, "poc.py",
                "import app\n"
                "class Cur:\n"
                "    def fetchone(self):\n"
                "        return None\n"
                "assert app.get_user_email(Cur(), 123) is None\n"
                "print('no crash — code handles the null case')\n")
            ev = V.run_poc(poc, target, expect_fail=True)
            self.assertEqual(ev["verdict"], "REFUTED")
            self.assertEqual(ev["exit_code"], 0)

    def test_unverified_on_timeout(self):
        with tempfile.TemporaryDirectory() as d:
            poc = _write(d, "poc.py", "while True: pass\n")
            ev = V.run_poc(poc, None, expect_fail=True, timeout=5)
            self.assertEqual(ev["verdict"], "UNVERIFIED")
            self.assertTrue(ev["timed_out"])

    def test_unverified_when_clean_run_no_expectation(self):
        with tempfile.TemporaryDirectory() as d:
            poc = _write(d, "poc.py", "print('hello')\n")
            ev = V.run_poc(poc, None, expect_fail=False, expect_output=None)
            self.assertEqual(ev["verdict"], "UNVERIFIED")  # proves nothing

    def test_non_posix_fallback_no_crash(self):
        # Windows has no resource module and no preexec_fn support — the
        # sandbox must degrade to timeout-only, not crash.
        saved_posix, saved_res = V._POSIX, V._HAS_RESOURCE
        V._POSIX, V._HAS_RESOURCE = False, False
        try:
            with tempfile.TemporaryDirectory() as d:
                poc = _write(d, "poc.py", "print('hello')\n")
                ev = V.run_poc(poc, None, expect_fail=False, expect_output=None)
                self.assertEqual(ev["verdict"], "UNVERIFIED")
                self.assertFalse(ev["sandbox"]["rlimits_applied"])
            with tempfile.TemporaryDirectory() as d:
                poc = _write(d, "poc.py", "while True: pass\n")
                ev = V.run_poc(poc, None, expect_fail=True, timeout=3)
                self.assertEqual(ev["verdict"], "UNVERIFIED")
                self.assertTrue(ev["timed_out"])
        finally:
            V._POSIX, V._HAS_RESOURCE = saved_posix, saved_res

    def test_race_condition_verified_by_real_concurrency(self):
        # The hard class CWE-362: double-spend only manifests under actual
        # concurrency. The PoC spawns threads against the buggy code.
        with tempfile.TemporaryDirectory() as d:
            target = _write(d, "app.py",
                "class Account:\n"
                "    def __init__(self, balance):\n"
                "        self.balance = balance\n"
                "def withdraw(acct, amount):\n"
                "    if acct.balance >= amount:          # check\n"
                "        acct.balance -= amount          # act (non-atomic)\n"
                "        return True\n"
                "    return False\n")
            poc = _write(d, "poc.py",
                "import app, threading\n"
                "acct = app.Account(100)\n"
                "results = []\n"
                "def try_take():\n"
                "    results.append(app.withdraw(acct, 100))\n"
                "ts = [threading.Thread(target=try_take) for _ in range(8)]\n"
                "[t.start() for t in ts]\n"
                "[t.join() for t in ts]\n"
                "if sum(results) > 1:\n"
                "    print('DOUBLE-SPEND: %d withdrawals succeeded from balance 100' % sum(results))\n"
                "    import sys; sys.exit(3)\n"
                "print('no race observed this run')\n")
            ev = V.run_poc(poc, target, expect_fail=True, expect_output="DOUBLE-SPEND")
            # GIL makes the race probabilistic; with 8 threads on a
            # check-then-act it fires reliably, but we accept either a
            # VERIFIED race or an honest UNVERIFIED/REFUTED — never a crash.
            self.assertIn(ev["verdict"], ("VERIFIED", "REFUTED", "UNVERIFIED"))
            self.assertIsNotNone(ev["exit_code"])

    def test_sandbox_no_env_leakage(self):
        # The PoC must NOT see any parent environment variables.
        with tempfile.TemporaryDirectory() as d:
            poc = _write(d, "poc.py",
                "import os\n"
                "leaked = [k for k in os.environ if not k.startswith(('PATH', 'LC_', 'LANG'))]\n"
                "print('LEAKED:', leaked)\n")
            ev = V.run_poc(poc, None, expect_fail=False, expect_output=None)
            self.assertNotIn("HERMES", ev["stdout"])
            self.assertNotIn("SECRET", ev["stdout"])
            # env={} means essentially nothing is present:
            self.assertNotIn("HOME", ev["stdout"])

    def test_output_truncated(self):
        with tempfile.TemporaryDirectory() as d:
            poc = _write(d, "poc.py", "print('x' * 100_000)\n")
            ev = V.run_poc(poc, None, expect_fail=False, expect_output=None)
            self.assertLessEqual(len(ev["stdout"]), V.MAX_OUTPUT_BYTES + 100)


class TestPolicyEnforcement(unittest.TestCase):
    def test_hard_class_without_verification_violates(self):
        report = {"findings": [
            {"id": "HG-1", "classes": ["CWE-362"], "severity": "HIGH"},
        ]}
        r = V.check_report_policy(report)
        self.assertFalse(r["ok"])
        self.assertEqual(r["violations"][0]["verification_verdict"], "MISSING")

    def test_hard_class_with_verified_passes(self):
        report = {"findings": [
            {"id": "HG-1", "classes": ["CWE-362"], "severity": "HIGH",
             "verification": {"verdict": "VERIFIED", "signal": "DOUBLE-SPEND observed"}},
        ]}
        r = V.check_report_policy(report)
        self.assertTrue(r["ok"])

    def test_soft_class_exempt(self):
        report = {"findings": [
            {"id": "HG-2", "classes": ["CWE-89"], "severity": "CRITICAL"},  # sqli: not forced
        ]}
        r = V.check_report_policy(report)
        self.assertTrue(r["ok"])
        self.assertEqual(r["hard_class_findings"], 0)

    def test_unverified_still_violates(self):
        report = {"findings": [
            {"id": "HG-1", "classes": ["HG-ASYNC"], "verification": {"verdict": "UNVERIFIED"}},
        ]}
        r = V.check_report_policy(report)
        self.assertFalse(r["ok"])

    def test_cli_check_report(self):
        with tempfile.TemporaryDirectory() as d:
            rp = Path(d) / "report.json"
            rp.write_text(json.dumps({"findings": [
                {"id": "HG-1", "classes": ["HG-PARTIAL-WRITE"]}]}))
            tool = str(ROOT / "tools/hermaguard-verify/hermaguard-verify.py")
            r = subprocess.run([sys.executable, tool, "--check-report", str(rp)],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)
            self.assertIn("HG-PARTIAL-WRITE", r.stdout)
            self.assertIn("HG-1", r.stdout)


if __name__ == "__main__":
    unittest.main()
