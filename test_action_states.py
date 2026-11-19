"""End-to-end tests for the Action's result states (C1).

Each case builds a clean consumer repo, copies the Action tree to a separate
location (as GitHub does with a pinned download), then runs the Action's real
`run:` blocks in bash in order: select -> pre-scan -> report -> enforce.
Linters are stubs placed first on PATH, so results are deterministic.

Hosted GitHub Actions is NOT exercised here: outputs, the step summary and the
PR comment body are collected locally.
"""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from test_action import ACTION_DIR, ACTION_YML, ROOT, SCANNER, parse_steps

STEPS = {s["name"]: s for s in parse_steps(ACTION_YML.read_text())}

RUFF_STUB = "#!/bin/sh\necho '[]'\nexit 0\n"
# bandit stub: prints the JSON found in $HG_STUB_BANDIT_JSON, or an empty result.
BANDIT_STUB = ('#!/bin/sh\nif [ -n "$HG_STUB_BANDIT_JSON" ]; then cat "$HG_STUB_BANDIT_JSON"; '
               'else echo \'{"results": []}\'; fi\nexit 0\n')

SCANNER_MODES = ("real", "absent", "no_report", "garbage", "fixed")


def tool_on_system(name):
    return any(os.path.isfile(f"{d}/{name}") for d in ("/usr/bin", "/usr/local/bin"))


class Result:
    def __init__(self):
        self.sent = []
        self.comment = ""
        self.summary = ""
        self.state = None
        self.exit_code = -1
        self.enforce_text = ""
        self.scan_ran = False
        self.decision = {}


class ActionHarness(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="hg-e2e-"))
        self.repo = self.tmp / "consumer"
        self.repo.mkdir()
        self.git("init", "-q")
        self.git("config", "user.email", "t@example.invalid")
        self.git("config", "user.name", "t")
        (self.repo / "seed.txt").write_text("seed\n")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "seed")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.stubs = self.tmp / "stubs"
        self.stubs.mkdir()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.repo, check=True,
                              capture_output=True, text=True).stdout

    def make_stub(self, name, body):
        path = self.stubs / name
        path.write_text(body)
        path.chmod(0o755)

    def build_action_tree(self, scanner_mode, fixed_report=None):
        tree = self.tmp / "action_dl"
        shutil.rmtree(tree, ignore_errors=True)
        (tree / "integrations" / "github-action").mkdir(parents=True)
        (tree / "tools" / "hermaguard-prescan").mkdir(parents=True)
        for name in ("action.yml", "hg_action.py"):
            shutil.copy(ACTION_DIR / name, tree / "integrations" / "github-action" / name)
        target = tree / "tools" / "hermaguard-prescan" / "hermaguard-prescan.py"
        if scanner_mode == "real":
            shutil.copy(SCANNER, target)
        elif scanner_mode == "no_report":
            target.write_text("import sys\nsys.exit(0)\n")
        elif scanner_mode == "garbage":
            target.write_text(
                "import sys\nout = sys.argv[sys.argv.index('--output') + 1]\n"
                "open(out, 'w').write('{not json')\nsys.exit(0)\n")
        elif scanner_mode == "fixed":
            target.write_text(
                "import sys, json\nout = sys.argv[sys.argv.index('--output') + 1]\n"
                f"open(out, 'w').write({json.dumps(json.dumps(fixed_report))})\nsys.exit(0)\n")
        # "absent": leave the scanner out entirely
        return tree / "integrations" / "github-action"

    def run_case(self, changed, *, scanner_mode="real", tools=("ruff", "bandit"),
                 block_on="HIGH", max_files="50", skip="*.test.*,*.spec.*,*.md,*.json,*.yaml",
                 prescan_enabled="true", push_event=False, bandit_json=None,
                 fixed_report=None, extra_env=None):
        self.base = self.git("rev-parse", "HEAD").strip()
        shutil.rmtree(self.tmp / "runner_temp", ignore_errors=True)
        for name, content in changed.items():
            target = self.repo / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "change")
        head = self.git("rev-parse", "HEAD").strip()

        for t in tools:
            self.make_stub(t, RUFF_STUB if t == "ruff" else BANDIT_STUB)
        action_dir = self.build_action_tree(scanner_mode, fixed_report)
        runner_temp = self.tmp / "runner_temp"
        runner_temp.mkdir(exist_ok=True)
        out_file, summary_file = self.tmp / "gh_output", self.tmp / "gh_summary"
        out_file.write_text("")
        summary_file.write_text("")
        home = self.tmp / "home"
        home.mkdir(exist_ok=True)
        env = {
            "PATH": f"{self.stubs}:/usr/bin:/bin", "HOME": str(home),
            "RUNNER_TEMP": str(runner_temp), "GITHUB_OUTPUT": str(out_file),
            "GITHUB_STEP_SUMMARY": str(summary_file), "GITHUB_ACTION_PATH": str(action_dir),
            "BASE_SHA": "" if push_event else self.base, "HEAD_SHA": "" if push_event else head,
            "PUSH_BEFORE": self.base if push_event else "", "PUSH_AFTER": head if push_event else "",
            "SKIP_PATTERNS": skip, "MAX_FILES": max_files, "BLOCK_ON": block_on,
            "PRESCAN_ENABLED": prescan_enabled,
        }
        if bandit_json is not None:
            bj = self.tmp / "bandit.json"
            bj.write_text(json.dumps(bandit_json))
            env["HG_STUB_BANDIT_JSON"] = str(bj)
        env.update(extra_env or {})

        def sh(step_name):
            return subprocess.run(["bash", "-c", STEPS[step_name]["run"]], cwd=self.repo,
                                  env=env, capture_output=True, text=True)

        res = Result()
        sel = sh("Select changed files")
        self.assertEqual(sel.returncode, 0, sel.stderr)
        outputs = dict(line.split("=", 1) for line in out_file.read_text().splitlines())
        if outputs["scan_count"] != "0" and prescan_enabled == "true":
            res.scan_ran = True
            scan = sh("Run HermaGuard Pre-Scan")
            self.assertEqual(scan.returncode, 0, "scan step must never hide-fail the job: " + scan.stderr)
        rep = sh("Summarise result and decide")
        self.assertEqual(rep.returncode, 0, rep.stderr)
        enf = sh("Enforce decision")
        hg = runner_temp / "hermaguard"
        files_list = hg / "files.list"
        raw = files_list.read_bytes() if files_list.exists() else b""
        res.sent = [n.decode() for n in raw.split(b"\0") if n]
        res.comment = (hg / "comment.md").read_text()
        res.summary = summary_file.read_text()
        res.decision = json.loads((hg / "decision.json").read_text())
        res.state, res.exit_code = res.decision["state"], enf.returncode
        res.enforce_text = enf.stdout
        # the comment and the exit status must always agree
        self.assertEqual(res.decision["exit_code"], res.exit_code)
        self.assertIn(res.decision["decision"], res.comment)
        return res


class ResultStates(ActionHarness):
    VULN = "import os\nos.system(input())\n"

    def bandit_high(self, filename):
        return {"results": [{"test_id": "B605", "issue_severity": "HIGH", "filename": filename,
                             "line_number": 2, "issue_text": "shell injection"}]}

    def test_complete_with_finding_above_threshold_fails(self):
        r = self.run_case({"a.py": self.VULN, "b.py": "x = 1\n"}, block_on="HIGH",
                          bandit_json=self.bandit_high("a.py"))
        self.assertEqual(sorted(r.sent), ["a.py", "b.py"])
        self.assertEqual((r.state, r.exit_code), ("complete", 1))
        self.assertIn("shell injection", r.comment)
        self.assertIn("BLOCKING", r.comment)

    def test_complete_critical_threshold_with_critical_finding_fails(self):
        files = ["a.py", "b.py"]
        report = {"findings": [{"tool": "x", "rule_id": "R", "severity": "CRITICAL", "file": "a.py",
                                "line": 1, "message": "boom", "category": "security"}],
                  "files": [{"path": p, "status": "examined", "examined_by": ["x"]} for p in files],
                  "stats": {"state": "complete", "tools_run": ["x"], "tools_skipped": [],
                            "scan_complete": True, "files_examined": 2}}
        r = self.run_case({"a.py": "x = 1\n", "b.py": "y = 1\n"}, scanner_mode="fixed", fixed_report=report)
        self.assertEqual((r.state, r.exit_code), ("complete", 1))

    def test_complete_clean_passes_and_may_say_no_issues(self):
        r = self.run_case({"a.py": "x = 1\n", "b.py": "y = 2\n"})
        self.assertEqual((r.state, r.exit_code), ("complete", 0))
        self.assertIn("No issues found by the deterministic tools in the 2 file(s) scanned", r.comment)

    def test_filename_with_space_is_scanned_intact(self):
        r = self.run_case({"has space.py": "x = 1\n"})
        self.assertEqual(r.sent, ["has space.py"])
        self.assertEqual((r.state, r.exit_code), ("complete", 0))

    def test_scanner_not_present_is_unavailable_and_fails(self):
        r = self.run_case({"a.py": "x = 1\n"}, scanner_mode="absent")
        self.assertEqual((r.state, r.exit_code), ("unavailable", 1))
        self.assertNotIn("No issues found", r.comment)
        self.assertIn("scanner produced no report file", r.comment)

    def test_missing_report_is_unavailable(self):
        r = self.run_case({"a.py": "x = 1\n"}, scanner_mode="no_report")
        self.assertEqual((r.state, r.exit_code), ("unavailable", 1))
        self.assertNotIn("No issues found", r.comment)

    def test_invalid_report_is_unavailable(self):
        r = self.run_case({"a.py": "x = 1\n"}, scanner_mode="garbage")
        self.assertEqual((r.state, r.exit_code), ("unavailable", 1))
        self.assertIn("not valid JSON", r.comment)

    def test_report_without_state_is_unavailable(self):
        legacy = {"findings": [], "stats": {"scan_complete": True, "tools_run": ["ruff"], "tools_skipped": []}}
        r = self.run_case({"a.py": "x = 1\n"}, scanner_mode="fixed", fixed_report=legacy)
        self.assertEqual((r.state, r.exit_code), ("unavailable", 1))
        self.assertNotIn("No issues found", r.comment)

    def test_report_for_other_files_is_unavailable(self):
        report = {"findings": [], "files": [{"path": "other.py", "status": "examined", "examined_by": ["ruff"]}],
                  "stats": {"state": "complete", "tools_run": ["ruff"], "tools_skipped": []}}
        r = self.run_case({"a.py": "x = 1\n"}, scanner_mode="fixed", fixed_report=report)
        self.assertEqual((r.state, r.exit_code), ("unavailable", 1))
        self.assertIn("does not cover the files", r.comment)

    @unittest.skipIf(tool_on_system("bandit"), "a system bandit would hide the 'tool missing' case")
    def test_skipped_tool_is_partial_and_fails(self):
        r = self.run_case({"a.py": "x = 1\n"}, tools=("ruff",))
        self.assertEqual((r.state, r.exit_code), ("partial", 1))
        self.assertIn("bandit", r.comment)
        self.assertNotIn("No issues found", r.comment)
        self.assertIn("PARTIAL", r.comment)

    @unittest.skipIf(tool_on_system("bandit"), "a system bandit would hide the 'tool missing' case")
    def test_empty_partial_scan_is_not_clean(self):
        r = self.run_case({"a.py": "x = 1\n"}, tools=("ruff",), block_on="never")
        self.assertEqual((r.state, r.exit_code), ("partial", 0))
        self.assertIn("PARTIAL", r.comment)
        self.assertNotIn("No issues found", r.comment)
        self.assertIn("block_on is `never`", r.comment)

    def test_over_file_cap_is_partial_not_clean(self):
        r = self.run_case({f"f{i}.py": "x = 1\n" for i in range(5)}, max_files="3")
        self.assertEqual(r.sent, [])
        self.assertFalse(r.scan_ran)
        self.assertEqual((r.state, r.exit_code), ("partial", 1))
        self.assertIn("more than the cap of 3", r.comment)
        self.assertNotIn("No issues found", r.comment)

    def test_prose_only_change_is_out_of_scope_not_clean(self):
        r = self.run_case({"README.md": "# hi\n", "docs/guide.txt": "words\n"})
        self.assertFalse(r.scan_ran)
        self.assertEqual((r.state, r.exit_code), ("out_of_scope", 0))
        self.assertIn("not reviewed", r.comment)
        self.assertNotIn("No issues found", r.comment)

    def test_config_only_change_is_never_called_clean(self):
        for name in ("settings.yaml", "pyproject.toml"):
            with self.subTest(name=name):
                r = self.run_case({name: "a: 1\n"})
                self.assertIn(r.state, ("out_of_scope", "partial"))
                self.assertNotIn("No issues found", r.comment)
                self.assertIn("Not scanned", r.comment)

    def test_code_plus_prose_lists_what_was_not_scanned(self):
        r = self.run_case({"a.py": "x = 1\n", "pyproject.toml": "a = 1\n"})
        self.assertEqual((r.state, r.exit_code), ("complete", 0))
        self.assertIn("Not scanned", r.comment)
        self.assertIn(".toml", r.comment)

    def test_push_event_without_pr_number_writes_job_summary(self):
        r = self.run_case({"a.py": "x = 1\n"}, push_event=True)
        self.assertEqual((r.state, r.exit_code), ("complete", 0))
        self.assertIn("HermaGuard deterministic pre-scan", r.summary)
        self.assertIn("github.event.pull_request", STEPS["Post summary as PR comment"]["if"])

    def test_prescan_disabled_is_reported_not_clean(self):
        r = self.run_case({"a.py": "x = 1\n"}, prescan_enabled="false")
        self.assertFalse(r.scan_ran)
        self.assertEqual(r.state, "unavailable")
        self.assertNotIn("No issues found", r.comment)

    def test_default_gate_is_high_and_blocks_a_high_finding(self):
        text = ACTION_YML.read_text()
        self.assertRegex(text, r"block_on:\n(?:.*\n)*?\s+default: 'HIGH'")
        r = self.run_case({"a.py": self.VULN}, bandit_json=self.bandit_high("a.py"))  # harness default = action default
        self.assertEqual((r.state, r.exit_code), ("complete", 1))

    def test_explicit_critical_gate_passes_a_high_finding_and_says_why(self):
        r = self.run_case({"a.py": self.VULN}, block_on="CRITICAL", bandit_json=self.bandit_high("a.py"))
        self.assertEqual((r.state, r.exit_code), ("complete", 0))
        self.assertIn("do not currently emit CRITICAL", r.comment)

    def test_unknown_block_on_fails_closed_to_high_with_note(self):
        r = self.run_case({"a.py": "x = 1\n"}, block_on="bogus")
        self.assertEqual(r.decision["block_on"], "HIGH")
        self.assertIn("unrecognised block_on", r.comment)

    def test_hostile_finding_text_is_inert_in_the_comment(self):
        evil = {"results": [{"test_id": "B1", "issue_severity": "HIGH", "filename": "a.py", "line_number": 1,
                             "issue_text": "ping @everyone `x` <script>alert(1)</script> | pipe"}]}
        r = self.run_case({"a.py": "x = 1\n"}, block_on="HIGH", bandit_json=evil)
        self.assertNotIn("@everyone", r.comment)
        self.assertNotIn("<script>", r.comment)
        self.assertNotIn("`x`", r.comment)

    def test_finding_cap_note_is_accurate(self):
        results = [{"test_id": f"B{i}", "issue_severity": "HIGH", "filename": "a.py", "line_number": i + 1,
                    "issue_text": f"issue {i}"} for i in range(13)]
        r = self.run_case({"a.py": "x = 1\n"}, block_on="never", bandit_json={"results": results})
        self.assertIn("3 more HIGH finding(s) not shown (cap 10 per severity)", r.comment)
        self.assertNotIn("30 more", r.comment)

    def test_dead_inputs_are_gone(self):
        text = ACTION_YML.read_text()
        for dead in ("comment_mode", "min_severity", "hermaguard_args"):
            self.assertNotIn(dead, text)


if __name__ == "__main__":
    unittest.main()
