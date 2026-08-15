"""
Hermaguard Packaging — Test Suite

Proves the pip-install path actually works: builds the package into a
throwaway venv and runs every console script. This is the test that stops
'pip install .' from silently shipping broken entry points.
"""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent

CONSOLE_SCRIPTS = [
    "hermaguard-coverage", "hermaguard-locate", "hermaguard-role-patterns",
    "hermaguard-sanitize", "hermaguard-verify", "hermaguard-prescan",
    "hermaguard-compile-rules", "hermaguard-benchmark", "hermaguard-grader",
]

# Tools whose --help/--self-test is the smoke check
SMOKE_FLAG = {
    "hermaguard-coverage": "--self-check",
    "hermaguard-grader": "--self-test",
    "hermaguard-prescan": "--version",
}


class TestPipInstall(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.venv = Path(tempfile.mkdtemp(prefix="hg-pkg-test-"))
        cls.python = cls.venv / "bin/python"
        r = subprocess.run([sys.executable, "-m", "venv", str(cls.venv)],
                           capture_output=True, text=True, timeout=300)
        assert r.returncode == 0, r.stderr
        r = subprocess.run([str(cls.python), "-m", "pip", "install", "-q", str(ROOT)],
                           capture_output=True, text=True, timeout=600)
        assert r.returncode == 0, r.stderr[-2000:]

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.venv, ignore_errors=True)

    def test_all_console_scripts_run(self):
        for script in CONSOLE_SCRIPTS:
            with self.subTest(script=script):
                flag = SMOKE_FLAG.get(script, "--help")
                r = subprocess.run([str(self.venv / "bin" / script), flag],
                                   capture_output=True, text=True, timeout=120)
                # --help returns 0 for argparse tools; grader prints docstring
                # and returns 2 for unknown subcommands but still must not crash
                self.assertIn(
                    r.returncode, (0, 2),
                    f"{script} {flag} failed: rc={r.returncode} stderr={r.stderr[-500:]}")

    def test_installed_tools_are_flat_layout(self):
        # data-files flatten the tree; the loader must handle that layout
        tools_dir = self.venv / "share" / "hermaguard" / "tools"
        self.assertTrue(tools_dir.is_dir())
        pys = list(tools_dir.glob("*.py"))
        self.assertGreaterEqual(len(pys), 9)


if __name__ == "__main__":
    unittest.main()
