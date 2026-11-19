"""Tests for the GitHub Action: injection safety and file hand-off (C0).

The Action's own `run:` blocks are extracted from action.yml and executed in
bash, so these tests exercise what a consumer's runner would execute, not a
re-implementation of it.
"""
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ACTION_DIR = ROOT / "integrations" / "github-action"
ACTION_YML = ACTION_DIR / "action.yml"
SCANNER = ROOT / "tools" / "hermaguard-prescan" / "hermaguard-prescan.py"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def parse_steps(text):
    """Minimal parser for composite-action steps: returns list of dicts with
    name, if, run (dedented block). No PyYAML dependency."""
    lines = text.splitlines()
    steps, cur, i = [], None, 0
    in_steps = False
    while i < len(lines):
        line = lines[i]
        if line.startswith("  steps:"):
            in_steps = True
            i += 1
            continue
        if not in_steps:
            i += 1
            continue
        m = re.match(r"^    - name: (.*)$", line)
        if m:
            cur = {"name": m.group(1).strip(), "run": None, "env_keys": []}
            steps.append(cur)
            i += 1
            continue
        if cur is not None:
            m = re.match(r"^      run: \|\s*$", line)
            if m:
                block = []
                i += 1
                while i < len(lines) and (lines[i].startswith("        ") or lines[i].strip() == ""):
                    block.append(lines[i])
                    i += 1
                strip = min((len(b) - len(b.lstrip()) for b in block if b.strip()), default=0)
                cur["run"] = "\n".join(b[strip:] for b in block) + "\n"
                continue
            m = re.match(r"^      if: (.*)$", line)
            if m:
                cur["if"] = m.group(1)
        i += 1
    return steps


class ActionStaticSafety(unittest.TestCase):
    def test_no_expression_interpolation_inside_run_blocks(self):
        steps = parse_steps(ACTION_YML.read_text())
        runs = [s for s in steps if s["run"]]
        self.assertGreaterEqual(len(runs), 3)
        for s in runs:
            self.assertNotIn("${{", s["run"],
                             f"step {s['name']!r} interpolates an expression into shell")

    def test_no_expression_interpolation_inside_github_script(self):
        text = ACTION_YML.read_text()
        m = re.search(r"script: \|\n(.*?)(?=\n    - name:|\Z)", text, re.S)
        self.assertIsNotNone(m)
        self.assertNotIn("${{", m.group(1))

    def test_scanner_resolved_from_action_distribution_with_py_suffix(self):
        text = ACTION_YML.read_text()
        self.assertIn("$GITHUB_ACTION_PATH/../../tools/hermaguard-prescan/hermaguard-prescan.py", text)
        self.assertNotIn("tools/hermaguard-prescan/hermaguard-prescan ]", text)
        self.assertTrue((ACTION_DIR / ".." / ".." / "tools" / "hermaguard-prescan" / "hermaguard-prescan.py").exists())

    def test_readme_uses_resolvable_action_path(self):
        readme = (ROOT / "README.md").read_text()
        self.assertNotIn("Sahil-SS9/hermaguard@v2", readme)
        self.assertNotIn("Copy `.github/workflows/hermaguard.yml`", readme)
        self.assertIn("Sahil-SS9/hermaguard/integrations/github-action@", readme)
        self.assertIn("pull_request_target", readme)


HOSTILE = [
    "plain.py",
    "has space.py",
    "comma,name.py",
    "-leading-dash.py",
    'quote"d.py',
    "semi;touch PWNED;.py",
    "x$(touch PWNED).py",
    "back`touch PWNED`tick.py",
    "new\nline.py",
]


@unittest.skipUnless(shutil.which("git") and shutil.which("bash"), "needs git and bash")
class SelectStepEndToEnd(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="hg-action-"))
        self.repo = self.tmp / "consumer"
        self.repo.mkdir()
        self.runner_temp = self.tmp / "runner_temp"
        self.runner_temp.mkdir()
        self.out = self.tmp / "github_output"
        self.out.write_text("")
        self.git("init", "-q")
        self.git("config", "user.email", "t@example.invalid")
        self.git("config", "user.name", "t")
        (self.repo / "seed.txt").write_text("seed\n")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "seed")
        self.base = self.git("rev-parse", "HEAD").strip()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.repo, check=True,
                              capture_output=True, text=True).stdout

    def commit_files(self, files):
        for name in files:
            (self.repo / name).write_text("x = 1\n")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "change")
        return self.git("rev-parse", "HEAD").strip()

    def run_select(self, head, **extra):
        step = next(s for s in parse_steps(ACTION_YML.read_text()) if s["name"] == "Select changed files")
        env = {
            "PATH": os.environ["PATH"], "HOME": str(self.tmp),
            "RUNNER_TEMP": str(self.runner_temp), "GITHUB_OUTPUT": str(self.out),
            "GITHUB_ACTION_PATH": str(ACTION_DIR),
            "BASE_SHA": self.base, "HEAD_SHA": head,
            "PUSH_BEFORE": "", "PUSH_AFTER": "",
            "SKIP_PATTERNS": "*.test.*,*.spec.*,*.md", "MAX_FILES": "50",
        }
        env.update(extra)
        return subprocess.run(["bash", "-e", "-c", step["run"]], cwd=self.repo, env=env,
                              capture_output=True, text=True)

    def test_hostile_filenames_never_execute_and_arrive_intact(self):
        head = self.commit_files(HOSTILE)
        proc = self.run_select(head)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse((self.repo / "PWNED").exists(), "command substitution executed")
        self.assertFalse(any(p.name == "PWNED" for p in self.tmp.rglob("PWNED")))

        scanner = _load("prescan_c0", SCANNER)
        listed = scanner.read_files_from(str(self.runner_temp / "hermaguard" / "files.list"))
        self.assertEqual(sorted(listed), sorted(HOSTILE))

    def test_hostile_filenames_do_not_inject_github_outputs(self):
        head = self.commit_files(HOSTILE + ["evil\nscan_count=0.py"])
        proc = self.run_select(head)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        keys = [ln.split("=", 1)[0] for ln in self.out.read_text().splitlines()]
        self.assertEqual(sorted(keys), ["changed_count", "over_cap", "scan_count"])

    def test_scanner_reads_every_name_from_the_list_file(self):
        head = self.commit_files(HOSTILE)
        self.assertEqual(self.run_select(head).returncode, 0)
        report = self.tmp / "prescan.json"
        proc = subprocess.run(
            [sys.executable, str(SCANNER), "--files-from",
             str(self.runner_temp / "hermaguard" / "files.list"), "--output", str(report)],
            cwd=self.repo, capture_output=True, text=True)
        self.assertIn(proc.returncode, (0, 1), proc.stderr)
        data = json.loads(report.read_text())
        self.assertEqual(data["stats"]["files_scanned"], len(HOSTILE))
        self.assertFalse((self.repo / "PWNED").exists())

    def test_hostile_skip_pattern_and_cap_inputs_do_not_execute(self):
        head = self.commit_files(["a.py"])
        proc = self.run_select(head, SKIP_PATTERNS="$(touch PWNED)\n`touch PWNED`",
                               MAX_FILES="1; touch PWNED")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse((self.repo / "PWNED").exists())

    def test_default_skip_patterns_actually_match(self):
        head = self.commit_files(["keep.py", "thing.test.ts", "thing.spec.js", "notes.md"])
        # the Action's declared default, exactly as written in action.yml
        raw = re.search(r"skip_patterns:\n\s+description:.*\n\s+default: '(.*)'", ACTION_YML.read_text()).group(1)
        self.assertEqual(self.run_select(head, SKIP_PATTERNS=raw).returncode, 0)
        man = json.loads((self.runner_temp / "hermaguard" / "manifest.json").read_text())
        self.assertEqual(man["in_scope"], ["keep.py"])
        self.assertIn("thing.test.ts", man["skipped_by_pattern"])

    def test_cap_is_numeric_not_textual(self):
        head = self.commit_files([f"f{i}.py" for i in range(9)])
        self.assertEqual(self.run_select(head, MAX_FILES="50").returncode, 0)
        man = json.loads((self.runner_temp / "hermaguard" / "manifest.json").read_text())
        self.assertFalse(man["over_cap"])
        self.assertEqual(len(man["in_scope"]), 9)


class ScannerFilesFrom(unittest.TestCase):
    def test_space_separated_string_is_not_how_lists_are_passed(self):
        mod = _load("prescan_c0b", SCANNER)
        with tempfile.NamedTemporaryFile("wb", suffix=".list", delete=False) as fh:
            fh.write(b"a b.py\0c,d.py\0")
        try:
            self.assertEqual(mod.read_files_from(fh.name), ["a b.py", "c,d.py"])
        finally:
            os.unlink(fh.name)

    def test_newline_delimited_list_supported(self):
        mod = _load("prescan_c0c", SCANNER)
        with tempfile.NamedTemporaryFile("wb", suffix=".list", delete=False) as fh:
            fh.write(b"a.py\nb.py\n")
        try:
            self.assertEqual(mod.read_files_from(fh.name), ["a.py", "b.py"])
        finally:
            os.unlink(fh.name)


if __name__ == "__main__":
    unittest.main()
