"""Scanner result-state tests (C1): per-file records and the four states."""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent
SCANNER = ROOT / "tools" / "hermaguard-prescan" / "hermaguard-prescan.py"


def load():
    spec = importlib.util.spec_from_file_location("prescan_state", SCANNER)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["prescan_state"] = mod
    spec.loader.exec_module(mod)
    return mod


class DeriveState(unittest.TestCase):
    mod = load()

    def call(self, **kw):
        base = dict(requested=2, in_scope=2, examined_in_scope=2, missing=0, tools_skipped=[])
        base.update(kw)
        return self.mod.derive_state(**base)

    def test_table(self):
        self.assertEqual(self.call(), "complete")
        self.assertEqual(self.call(requested=0, in_scope=0, examined_in_scope=0), "out_of_scope")
        self.assertEqual(self.call(in_scope=0, examined_in_scope=0), "out_of_scope")
        self.assertEqual(self.call(in_scope=0, examined_in_scope=0, missing=1), "unavailable")
        self.assertEqual(self.call(examined_in_scope=0), "unavailable")
        self.assertEqual(self.call(tools_skipped=["bandit"]), "partial")
        self.assertEqual(self.call(missing=1), "partial")
        self.assertEqual(self.call(examined_in_scope=1), "partial")


class RunPrescanStates(unittest.TestCase):
    mod = load()

    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.addCleanup(self.d.cleanup)

    def mk(self, name, text="x = 1\n"):
        path = os.path.join(self.d.name, name)
        Path(path).write_text(text)
        return path

    def run_with(self, files, *, installed=("ruff", "bandit"), restrict=None, run_err=None):
        ok = mock.Mock(returncode=0, stdout="[]", stderr="")

        def fake_find(name):
            return f"/stub/{name}" if name in installed else None

        def fake_run_tool(tool, fl, tmp):
            if run_err and tool["name"] in run_err:
                return run_err[tool["name"]], []
            return None, []

        with mock.patch.object(self.mod, "find_tool", side_effect=fake_find), \
             mock.patch.object(self.mod, "run_tool", side_effect=fake_run_tool) as rt:
            out = self.mod.run_prescan(files, restrict)
        return out, rt

    def test_complete_has_per_file_records(self):
        a, b = self.mk("a.py"), self.mk("b.py")
        out, _ = self.run_with([a, b])
        st = out["stats"]
        self.assertEqual(st["state"], "complete")
        self.assertTrue(st["scan_complete"])
        self.assertEqual(st["files_examined"], 2)
        self.assertEqual({r["path"]: r["examined_by"] for r in out["files"]},
                         {a: ["bandit", "ruff"], b: ["bandit", "ruff"]})

    def test_missing_file_is_recorded_and_makes_scan_partial(self):
        a = self.mk("a.py")
        ghost = os.path.join(self.d.name, "ghost.py")
        out, _ = self.run_with([a, ghost])
        rec = {r["path"]: r for r in out["files"]}
        self.assertEqual(rec[ghost]["status"], "missing")
        self.assertEqual(out["stats"]["state"], "partial")
        self.assertFalse(out["stats"]["scan_complete"])
        self.assertEqual(out["stats"]["files_missing"], 1)

    def test_space_separated_string_is_one_missing_file_never_a_clean_scan(self):
        # What the old Action sent. It must no longer read as "scanned, nothing found".
        self.mk("a.py"), self.mk("b.py")
        out, _ = self.run_with(["a.py b.py"])
        self.assertEqual(out["stats"]["state"], "unavailable")
        self.assertEqual(out["files"][0]["status"], "missing")

    def test_only_missing_files_is_unavailable(self):
        out, _ = self.run_with([os.path.join(self.d.name, "nope.py")])
        self.assertEqual(out["stats"]["state"], "unavailable")

    def test_readme_only_is_out_of_scope(self):
        out, rt = self.run_with([self.mk("README.md")])
        self.assertEqual(out["stats"]["state"], "out_of_scope")
        self.assertEqual(out["files"][0]["status"], "unsupported")
        self.assertFalse(out["stats"]["scan_complete"])

    def test_unsupported_file_next_to_python_is_reported_not_hidden(self):
        a, rb = self.mk("a.py"), self.mk("tool.rb", "puts 1\n")
        out, _ = self.run_with([a, rb])
        rec = {r["path"]: r for r in out["files"]}
        self.assertEqual(rec[rb]["status"], "unsupported")
        self.assertIn("no tool configured for .rb", rec[rb]["reason"])
        self.assertEqual(out["stats"]["files_unsupported"], 1)
        self.assertEqual(out["stats"]["state"], "complete")  # the in-scope file was fully examined

    def test_tool_missing_is_partial_with_reason(self):
        a = self.mk("a.py")
        out, _ = self.run_with([a], installed=("ruff",))
        self.assertEqual(out["stats"]["state"], "partial")
        self.assertIn("bandit", out["stats"]["tools_skipped"])
        self.assertEqual(out["files"][0]["examined_by"], ["ruff"])

    def test_no_tools_at_all_is_unavailable(self):
        a = self.mk("a.py")
        out, _ = self.run_with([a], installed=())
        self.assertEqual(out["stats"]["state"], "unavailable")
        self.assertEqual(out["files"][0]["status"], "not_examined")
        self.assertIn("not installed", out["files"][0]["reason"])

    def test_tool_error_is_partial(self):
        a = self.mk("a.py")
        out, _ = self.run_with([a], run_err={"bandit": "bandit timed out"})
        self.assertEqual(out["stats"]["state"], "partial")
        self.assertTrue(any("bandit timed out" in s for s in out["stats"]["tools_skipped"]))

    def test_restrict_excludes_other_languages_as_unsupported(self):
        go = self.mk("m.go", "package m\n")
        out, _ = self.run_with([go], restrict=["bandit", "ruff"])
        self.assertEqual(out["stats"]["state"], "out_of_scope")
        self.assertIn("excluded by --tools", out["files"][0]["reason"])

    def test_every_extension_group_gets_its_tool(self):
        # Regression: eslint is configured for .ts, .tsx and .js. Deduping by tool
        # name used to run it for the first group only, silently skipping the rest.
        ts, tsx, js = self.mk("a.ts"), self.mk("b.tsx"), self.mk("c.js")
        out, rt = self.run_with([ts, tsx, js], installed=("eslint", "semgrep"))
        examined = {r["path"]: r["examined_by"] for r in out["files"]}
        for path in (ts, tsx, js):
            self.assertIn("eslint", examined[path], path)
        ran = [(c.args[0]["name"], tuple(sorted(os.path.basename(f) for f in c.args[1])))
               for c in rt.call_args_list]
        self.assertIn(("eslint", ("a.ts",)), ran)
        self.assertIn(("eslint", ("b.tsx",)), ran)
        self.assertIn(("eslint", ("c.js",)), ran)

    def test_tools_flag_is_honoured_for_generic_semgrep(self):
        a = self.mk("a.py")
        out, rt = self.run_with([a], installed=("ruff", "semgrep"), restrict=["ruff"])
        self.assertNotIn("semgrep", [c.args[0]["name"] for c in rt.call_args_list])
        self.assertEqual(out["stats"]["state"], "complete")

    def test_cli_exit_codes_unchanged_and_state_written(self):
        a = self.mk("a.py")
        out_path = os.path.join(self.d.name, "o.json")
        argv = ["hermaguard-prescan", "--files", a, "--output", out_path]
        with mock.patch.object(self.mod, "find_tool", return_value=None), \
             mock.patch.object(sys, "argv", argv), self.assertRaises(SystemExit) as raised:
            self.mod.main()
        self.assertEqual(raised.exception.code, 1)
        data = json.loads(Path(out_path).read_text())
        self.assertEqual(data["stats"]["state"], "unavailable")
        self.assertFalse(data["stats"]["scan_complete"])

    def test_empty_list_cli_writes_out_of_scope(self):
        out_path = os.path.join(self.d.name, "o.json")
        argv = ["hermaguard-prescan", "--files", "", "--output", out_path]
        with mock.patch.object(sys, "argv", argv), self.assertRaises(SystemExit):
            self.mod.main()
        data = json.loads(Path(out_path).read_text())
        self.assertEqual(data["stats"]["state"], "out_of_scope")
        self.assertEqual(data["files"], [])


if __name__ == "__main__":
    unittest.main()
