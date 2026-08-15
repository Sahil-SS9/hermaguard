"""
Hermaguard Coverage — Test Suite

Tests import and call the real tool. No placebo assertions.
Covers: registry integrity, ledger build, report validation (pass/fail),
language rules, CLI round-trip.
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
    sys.modules[name] = mod  # required for dataclasses with from __future__ annotations
    spec.loader.exec_module(mod)
    return mod


COV = _load_module("hermaguard_coverage", "tools/hermaguard-coverage/hermaguard-coverage.py")


def _full_coverage(ledger, finding_class=None):
    """Build a complete coverage array for the given ledger."""
    cov = []
    for c in ledger["classes"]:
        if not c["applicable"]:
            cov.append({"class_id": c["id"], "status": "not_applicable", "reason": c.get("reason", "")})
        elif c["id"] == finding_class:
            cov.append({"class_id": c["id"], "status": "finding"})
        else:
            cov.append({"class_id": c["id"], "status": "clean"})
    return cov


class TestRegistryIntegrity(unittest.TestCase):
    def test_self_check_passes(self):
        self.assertEqual(COV.self_check(), [])

    def test_registry_size(self):
        # 25 CWE Top-25 + 3 CWE extras + 4 Hermaguard-native
        self.assertEqual(len(COV.CLASSES), 32)

    def test_top25_ids_exact(self):
        ranked = [c for c in COV.CLASSES if c.get("rank") and 1 <= c["rank"] <= 25]
        self.assertEqual(len(ranked), 25)
        expected = {"CWE-79","CWE-787","CWE-89","CWE-352","CWE-22","CWE-125","CWE-78",
                    "CWE-416","CWE-862","CWE-434","CWE-94","CWE-20","CWE-77","CWE-287",
                    "CWE-269","CWE-502","CWE-200","CWE-863","CWE-918","CWE-119","CWE-476",
                    "CWE-798","CWE-190","CWE-400","CWE-306"}
        self.assertEqual({c["id"] for c in ranked}, expected)

    def test_top25_ranks_unique(self):
        ranks = [c["rank"] for c in COV.CLASSES if c.get("rank")]
        self.assertEqual(sorted(ranks), list(range(1, 26)))

    def test_registry_mutation_detected(self):
        # Tamper detection: adding a duplicate id must fail self-check
        COV.CLASSES.append({"id": "CWE-89", "name": "dup", "status": "always"})
        try:
            errs = COV.self_check()
            self.assertTrue(any("duplicate" in e for e in errs))
        finally:
            COV.CLASSES.pop()


class TestLedgerBuild(unittest.TestCase):
    def test_python_only(self):
        led = COV.build_ledger(["src/app.py"])
        na = {c["id"] for c in led["classes"] if not c["applicable"]}
        # memory-unsafe classes excluded for Python
        self.assertIn("CWE-787", na)
        self.assertIn("CWE-416", na)
        applicable = {c["id"] for c in led["classes"] if c["applicable"]}
        self.assertIn("CWE-89", applicable)
        self.assertIn("HG-ASYNC", applicable)

    def test_c_files_get_memory_classes(self):
        led = COV.build_ledger(["driver.c"])
        applicable = {c["id"] for c in led["classes"] if c["applicable"]}
        self.assertIn("CWE-787", applicable)
        self.assertIn("CWE-125", applicable)
        self.assertIn("CWE-416", applicable)

    def test_rust_gets_memory_classes_as_hint(self):
        led = COV.build_ledger(["main.rs"])
        by_id = {c["id"]: c for c in led["classes"]}
        self.assertTrue(by_id["CWE-787"]["applicable"])
        self.assertEqual(by_id["CWE-787"].get("hint"), "Rust: applies via unsafe blocks")

    def test_mixed_languages_union(self):
        led = COV.build_ledger(["a.py", "b.ts", "c.go"])
        applicable = {c["id"] for c in led["classes"] if c["applicable"]}
        # union: TS brings nothing memory-unsafe; all still N/A
        self.assertNotIn("CWE-787", applicable)

    def test_files_sorted_in_ledger(self):
        led = COV.build_ledger(["b.py", "a.py"])
        self.assertEqual(led["files"], ["a.py", "b.py"])


class TestReportValidation(unittest.TestCase):
    def setUp(self):
        self.ledger = COV.build_ledger(["src/app.py", "src/handler.ts"])

    def test_full_coverage_passes(self):
        report = {
            "coverage": _full_coverage(self.ledger, finding_class="CWE-89"),
            "findings": [{"id": "HG-1", "classes": ["CWE-89"], "file": "app.py",
                          "severity": "CRITICAL", "trigger_condition": "f-string SQL",
                          "consequence": "injection"}],
        }
        result = COV.check_report(report, self.ledger)
        self.assertTrue(result["ok"], result["errors"])
        self.assertEqual(result["accounted"], result["applicable"])

    def test_missing_coverage_entry_fails(self):
        cov = [e for e in _full_coverage(self.ledger) if e["class_id"] != "CWE-400"]
        result = COV.check_report({"coverage": cov, "findings": []}, self.ledger)
        self.assertFalse(result["ok"])
        self.assertIn("CWE-400", result["gaps"])

    def test_no_coverage_array_fails(self):
        result = COV.check_report({"findings": []}, self.ledger)
        self.assertFalse(result["ok"])
        self.assertIn("no `coverage` array", result["errors"][0])

    def test_finding_claim_without_backing_finding_fails(self):
        cov = _full_coverage(self.ledger, finding_class="CWE-22")
        result = COV.check_report({"coverage": cov, "findings": []}, self.ledger)
        self.assertFalse(result["ok"])
        self.assertTrue(any("no finding cites this class" in e for e in result["errors"]))

    def test_duplicate_class_entry_fails(self):
        cov = _full_coverage(self.ledger)
        cov.append({"class_id": "CWE-89", "status": "clean"})
        result = COV.check_report({"coverage": cov, "findings": []}, self.ledger)
        self.assertFalse(result["ok"])
        self.assertTrue(any("appears twice" in e for e in result["errors"]))

    def test_invalid_status_fails(self):
        cov = _full_coverage(self.ledger)
        for e in cov:
            if e["class_id"] == "HG-STATE":
                e["status"] = "maybe"
        result = COV.check_report({"coverage": cov, "findings": []}, self.ledger)
        self.assertFalse(result["ok"])
        self.assertTrue(any("invalid status" in e for e in result["errors"]))

    def test_na_without_reason_fails(self):
        cov = _full_coverage(self.ledger)
        for e in cov:
            if e["class_id"] == "CWE-89":
                e["status"] = "not_applicable"  # demote without reason
                e.pop("reason", None)
        result = COV.check_report({"coverage": cov, "findings": []}, self.ledger)
        self.assertFalse(result["ok"])
        self.assertTrue(any("without a reason" in e for e in result["errors"]))

    def test_unknown_class_cited_fails(self):
        cov = _full_coverage(self.ledger)
        cov.append({"class_id": "CWE-9999", "status": "clean"})
        result = COV.check_report({"coverage": cov, "findings": []}, self.ledger)
        self.assertFalse(result["ok"])
        self.assertTrue(any("unknown class" in e for e in result["errors"]))


class TestCLI(unittest.TestCase):
    def test_cli_self_check(self):
        r = subprocess.run(
            [sys.executable, str(ROOT / "tools/hermaguard-coverage/hermaguard-coverage.py"), "--self-check"],
            capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("self-check OK", r.stdout)

    def test_cli_round_trip(self):
        with tempfile.TemporaryDirectory() as d:
            led_path = str(Path(d) / "ledger.json")
            rep_ok = str(Path(d) / "ok.json")
            rep_bad = str(Path(d) / "bad.json")

            r = subprocess.run(
                [sys.executable, str(ROOT / "tools/hermaguard-coverage/hermaguard-coverage.py"),
                 "--files", "a.py,b.ts", "--ledger", led_path],
                capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)

            ledger = json.loads(Path(led_path).read_text())
            ok_report = {"coverage": _full_coverage(ledger, "CWE-89"),
                         "findings": [{"id": "HG-1", "classes": ["CWE-89"]}]}
            Path(rep_ok).write_text(json.dumps(ok_report))
            bad_cov = [e for e in ok_report["coverage"] if e["class_id"] != "HG-PARTIAL-WRITE"]
            Path(rep_bad).write_text(json.dumps({"coverage": bad_cov, "findings": []}))

            tool = str(ROOT / "tools/hermaguard-coverage/hermaguard-coverage.py")
            r_ok = subprocess.run([sys.executable, tool, "--check-report", rep_ok, "--ledger", led_path, "--quiet"],
                                  capture_output=True, text=True)
            self.assertEqual(r_ok.returncode, 0, r_ok.stdout + r_ok.stderr)
            r_bad = subprocess.run([sys.executable, tool, "--check-report", rep_bad, "--ledger", led_path, "--quiet"],
                                   capture_output=True, text=True)
            self.assertEqual(r_bad.returncode, 1)
            self.assertIn("HG-PARTIAL-WRITE", r_bad.stdout)


if __name__ == "__main__":
    unittest.main()


def _load_grader():
    return _load_module("hermaguard_grader", "tools/hermaguard-grader/hermaguard_grader.py")


class TestGrader(unittest.TestCase):
    """L0-L6 grader — real oracle behaviour, not just self-test passthrough."""

    @classmethod
    def setUpClass(cls):
        cls.g = _load_grader()

    def test_self_test_corpus_passes(self):
        rc = self.g.self_test()
        self.assertEqual(rc, 0)

    def test_privilege_axis_gives_l5(self):
        f = self.g.grade_finding({"id": "X", "severity": "HIGH",
                                  "harm_axes": {"completed": True, "reversible": False,
                                                "cross_scope": False, "privilege": True}})
        self.assertEqual(f["L_level"], "L5")

    def test_severity_fallback_never_undergrades(self):
        for tier, floor in self.g.SEVERITY_FALLBACK_FLOOR.items():
            f = self.g.grade_finding({"id": "X", "severity": tier})
            self.assertGreaterEqual(self.g._LEVEL_RANK[f["L_level"]],
                                    self.g._LEVEL_RANK[floor], msg=tier)
            self.assertEqual(f["grading_method"], "severity-fallback")

    def test_grading_is_additive(self):
        original = {"id": "X", "severity": "LOW", "keep": "me"}
        f = self.g.grade_finding(dict(original))
        self.assertEqual(f["keep"], "me")
        for k in original:
            self.assertIn(k, f)

    def test_escalation_chain_raises_peak_to_l6(self):
        report = {"findings": [
            {"id": "A", "severity": "HIGH", "harm_axes": {"completed": True, "reversible": True,
                                                          "cross_scope": True, "privilege": False}},   # L4
            {"id": "B", "severity": "CRITICAL", "harm_axes": {"completed": True, "reversible": False,
                                                              "cross_scope": False, "privilege": True}},  # L5
        ]}
        out = self.g.grade_report(report)
        by_id = {f["id"]: f for f in out["findings"]}
        self.assertEqual(by_id["B"]["L_level"], "L6")
        self.assertTrue(out["severity_grading"]["escalation_chain_detected"])

    def test_local_chain_not_raised(self):
        report = {"findings": [
            {"id": "A", "severity": "MEDIUM", "harm_axes": {"completed": True, "reversible": True,
                                                            "cross_scope": False, "privilege": False}},  # L2
            {"id": "B", "severity": "HIGH", "harm_axes": {"completed": True, "reversible": False,
                                                          "cross_scope": False, "privilege": False}},  # L3
        ]}
        out = self.g.grade_report(report)
        self.assertFalse(out["severity_grading"]["escalation_chain_detected"])
        by_id = {f["id"]: f for f in out["findings"]}
        self.assertEqual(by_id["B"]["L_level"], "L3")


def _load_benchmark():
    return _load_module("hermaguard_benchmark", "tools/hermaguard-benchmark/benchmark.py")


class TestBenchmarkDeterministicScoring(unittest.TestCase):
    """Class-based matching replaces fuzzy keyword overlap for new ground truth."""

    @classmethod
    def setUpClass(cls):
        cls.bm = _load_benchmark()
        cls.bug = {
            "id": "999-test", "title": "t", "severity": "HIGH", "category": "security",
            "expected_findings": [
                {"file": "app.py", "trigger": "x", "description": "x", "severity": "HIGH", "classes": ["CWE-89"]},
            ],
        }

    def test_class_match_exact(self):
        run = {"run_ok": True, "findings": [
            {"id": "HG-1", "file": "app.py", "severity": "HIGH", "classes": ["CWE-89", "CWE-20"]},
        ]}
        s = self.bm.score_run(self.bug, run)
        self.assertEqual(s["true_positives"], 1)
        self.assertEqual(s["false_positives"], 0)
        self.assertEqual(s["match_modes"]["class"], 1)

    def test_class_match_requires_file_match(self):
        run = {"run_ok": True, "findings": [
            {"id": "HG-1", "file": "other.py", "severity": "HIGH", "classes": ["CWE-89"]},
        ]}
        s = self.bm.score_run(self.bug, run)
        self.assertEqual(s["true_positives"], 0)
        self.assertEqual(s["false_negatives"], 1)

    def test_no_class_intersection_no_match(self):
        run = {"run_ok": True, "findings": [
            {"id": "HG-1", "file": "app.py", "severity": "HIGH", "classes": ["CWE-22"]},
        ]}
        s = self.bm.score_run(self.bug, run)
        self.assertEqual(s["true_positives"], 0)

    def test_deterministic_identical_inputs(self):
        run = {"run_ok": True, "findings": [
            {"id": "HG-1", "file": "app.py", "severity": "HIGH", "classes": ["CWE-89"]},
            {"id": "HG-2", "file": "app.py", "severity": "MEDIUM", "classes": ["CWE-22"]},
        ]}
        r1 = self.bm.score_run(self.bug, run)
        r2 = self.bm.score_run(self.bug, run)
        self.assertEqual(r1["matches"], r2["matches"])
        self.assertEqual((r1["precision_pct"], r1["recall_pct"]), (r2["precision_pct"], r2["recall_pct"]))

    def test_legacy_keyword_fallback_still_works(self):
        bug_legacy = {
            "id": "998-legacy", "title": "t", "severity": "HIGH", "category": "security",
            "expected_findings": [
                {"file": "app.py", "trigger": "sql injection unparameterised query", "description": "sqli", "severity": "CRITICAL"},
            ],
        }
        run = {"run_ok": True, "findings": [
            {"id": "HG-1", "file": "app.py", "severity": "CRITICAL",
             "trigger_condition": "sql injection unparameterised query", "consequence": "data breach"},
        ]}
        s = self.bm.score_run(bug_legacy, run)
        self.assertEqual(s["true_positives"], 1)
        self.assertEqual(s["match_modes"]["keyword"], 1)

    def test_crashed_run_never_scored_ok(self):
        # Regression: a result file with an error key must not score as OK
        run = {"error": "agent crashed", "findings": []}
        s = self.bm.score_run(self.bug, run)
        self.assertFalse(s["run_ok"])

    def test_missing_run_ok_flag_does_not_crash(self):
        # Regression: result files predating the run_ok flag previously
        # raised KeyError inside score_run, killing the whole benchmark.
        run = {"findings": [
            {"id": "HG-1", "file": "app.py", "severity": "HIGH", "classes": ["CWE-89"]},
        ]}
        s = self.bm.score_run(self.bug, run)
        self.assertTrue(s["run_ok"])  # defaults to completed
        self.assertEqual(s["true_positives"], 1)

    def test_real_corpus_scoring_perfect_and_zero(self):
        import pathlib
        bugs_dir = pathlib.Path("tools/hermaguard-benchmark/bugs")
        # Perfect run against real ground truth -> 100/100/100
        gt = json.loads((bugs_dir / "001-sql-injection/ground-truth.json").read_text())
        bug = {"id": "001", "title": gt["title"], "severity": gt["severity"],
               "category": gt["category"], "expected_findings": gt["findings"]}
        exp = gt["findings"][0]
        run = {"findings": [{"id": "HG-1", "file": exp["file"],
                             "severity": exp["severity"], "classes": exp["classes"]}]}
        s = self.bm.score_run(bug, run)
        self.assertEqual((s["precision_pct"], s["recall_pct"], s["f1_score"]), (100.0, 100.0, 100.0))
        # Wrong-class run -> 0
        run2 = {"findings": [{"id": "HG-1", "file": exp["file"],
                              "severity": exp["severity"], "classes": ["CWE-79"]}]}
        s2 = self.bm.score_run(bug, run2)
        self.assertEqual((s2["precision_pct"], s2["recall_pct"], s2["f1_score"]), (0.0, 0.0, 0.0))

    def test_corpus_integrity(self):
        import pathlib
        bugs_dir = pathlib.Path("tools/hermaguard-benchmark/bugs")
        dirs = sorted([p for p in bugs_dir.iterdir() if p.is_dir()])
        self.assertEqual(len(dirs), 25, f"expected 25 bugs, found {len(dirs)}")
        for d in dirs:
            gt = json.loads((d / "ground-truth.json").read_text())
            self.assertTrue(gt["findings"], f"{d.name}: no findings in ground truth")
            for f in gt["findings"]:
                self.assertIn("classes", f, f"{d.name}: ground truth missing classes")
