"""C4 tests: the benchmark rewards the right thing (scorer version 3).

Result dicts here are synthetic and harmless: no model is run. The corpus under
tools/hermaguard-benchmark is the real shipped one.
"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BENCH_DIR = ROOT / "tools" / "hermaguard-benchmark"
BUGS = BENCH_DIR / "bugs"
EXT = BENCH_DIR / "extended"
RESULTS = BENCH_DIR / "results"
SCRIPT = BENCH_DIR / "benchmark.py"


def _load():
    spec = importlib.util.spec_from_file_location("bench_v3", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["bench_v3"] = mod
    spec.loader.exec_module(mod)
    return mod


BM = _load()


def bug(name, root=BUGS):
    return BM.load_bug(str(root / name))


def finding(file, classes, line=None, **kw):
    f = {"id": kw.pop("id", "HG-1"), "severity": kw.pop("severity", "HIGH"), "file": file, "classes": classes}
    if line is not None:
        f["line"] = line
    f.update(kw)
    return f


def run(findings, **extra):
    return dict({"run_ok": True, "findings": findings}, **extra)


class StrictLocation(unittest.TestCase):
    def test_same_filename_in_a_different_directory_gets_no_credit(self):
        b = bug("M01-same-filename-two-directories", EXT)
        wrong = run([finding("reports/app.py", ["CWE-20"], 2, trigger_condition="refund negative amount")])
        s3 = BM.score_run(b, wrong)
        self.assertEqual((s3["true_positives"], s3["false_negatives"], s3["false_positives"]), (0, 1, 1))
        self.assertEqual(s3["outcome"], "missed")
        # the version-2 scorer credited exactly this mistake
        s2 = BM.score_run(b, wrong, scorer_version=2)
        self.assertEqual(s2["true_positives"], 1)

    def test_correct_directory_is_credited(self):
        b = bug("M01-same-filename-two-directories", EXT)
        s = BM.score_run(b, run([finding("billing/app.py", ["CWE-20"], 3)]))
        self.assertEqual((s["true_positives"], s["outcome"]), (1, "found_all"))

    def test_fixture_layout_prefix_is_accepted_but_basenames_are_not(self):
        b = bug("M01-same-filename-two-directories", EXT)
        self.assertEqual(BM.score_run(b, run([finding("code/billing/app.py", ["CWE-20"], 3)]))["true_positives"], 1)
        self.assertEqual(BM.score_run(b, run([finding("app.py", ["CWE-20"], 3)]))["true_positives"], 0)

    def test_absent_path_never_matches(self):
        b = bug("001-sql-injection")
        for blank in ("", None):
            s = BM.score_run(b, run([finding(blank, ["CWE-89"], 6)]))
            self.assertEqual(s["true_positives"], 0, blank)
        missing = run([{"id": "HG-1", "severity": "HIGH", "classes": ["CWE-89"], "line": 6}])
        self.assertEqual(BM.score_run(b, missing)["true_positives"], 0)
        self.assertEqual(BM.score_run(b, missing, scorer_version=2)["true_positives"], 1)  # the old pass-through

    def test_absolute_and_escaping_paths_never_match(self):
        b = bug("001-sql-injection")
        for bad in ("/srv/repo/app.py", "../app.py", "C:/work/app.py"):
            self.assertEqual(BM.score_run(b, run([finding(bad, ["CWE-89"], 6)]))["true_positives"], 0, bad)
        self.assertEqual(BM.score_run(b, run([finding("./app.py", ["CWE-89"], 6)]))["true_positives"], 1)

    def test_true_match_with_shifted_lines_still_counts(self):
        b = bug("001-sql-injection")  # region 6-7, tolerance 3
        self.assertEqual(BM.score_run(b, run([finding("app.py", ["CWE-89"], 9)]))["true_positives"], 1)
        self.assertEqual(BM.score_run(b, run([finding("app.py", ["CWE-89"], line_range="5-8")]))["true_positives"], 1)

    def test_right_file_and_class_but_far_from_the_region_and_wrong_symbol_is_not_a_match(self):
        b = bug("001-sql-injection")
        far = run([finding("app.py", ["CWE-89"], 40, trigger_condition="something unrelated near the end")])
        self.assertEqual(BM.score_run(b, far)["true_positives"], 0)

    def test_symbol_alone_can_locate_a_finding_without_line_numbers(self):
        b = bug("001-sql-injection")
        s = BM.score_run(b, run([finding("app.py", ["CWE-89"], trigger_condition="get_user_by_name builds SQL from input")]))
        self.assertEqual(s["true_positives"], 1)

    def test_wrong_class_in_the_right_place_is_not_a_match(self):
        self.assertEqual(BM.score_run(bug("001-sql-injection"), run([finding("app.py", ["CWE-79"], 6)]))["true_positives"], 0)


class DuplicatesAndExtras(unittest.TestCase):
    def test_two_reports_of_one_root_cause_credit_once_and_are_not_false_positives(self):
        b = bug("001-sql-injection")
        s = BM.score_run(b, run([finding("app.py", ["CWE-89"], 6, id="HG-1"),
                                 finding("app.py", ["CWE-89"], 7, id="HG-2")]))
        self.assertEqual((s["true_positives"], s["duplicates"], s["false_positives"]), (1, 1, 0))
        self.assertEqual(s["precision_pct"], 100.0)

    def test_unrelated_extra_finding_is_a_false_positive_not_a_duplicate(self):
        b = bug("001-sql-injection")
        s = BM.score_run(b, run([finding("app.py", ["CWE-89"], 6), finding("app.py", ["CWE-404"], 4, id="HG-2")]))
        self.assertEqual((s["true_positives"], s["duplicates"], s["false_positives"]), (1, 0, 1))

    def test_two_defect_case_finding_one_is_partial(self):
        b = bug("M02-two-defects-two-files", EXT)
        one = BM.score_run(b, run([finding("db.py", ["CWE-89"], 2, severity="CRITICAL")]))
        self.assertEqual((one["true_positives"], one["false_negatives"], one["outcome"]), (1, 1, "found_some"))
        both = BM.score_run(b, run([finding("db.py", ["CWE-89"], 2, severity="CRITICAL"),
                                    finding("web.py", ["CWE-306"], 3, id="HG-2")]))
        self.assertEqual((both["true_positives"], both["outcome"]), (2, "found_all"))


class Controls(unittest.TestCase):
    EVIDENCE = {"checks_completed": ["traced every branch", "ran the static checks"]}

    def test_clean_twin_with_completed_checks_is_a_true_negative(self):
        s = BM.score_run(bug("T01-twin-of-001-sql-parameterised", EXT), run([], **self.EVIDENCE))
        self.assertEqual((s["outcome"], s["graded"]), ("clean_ok", True))

    def test_clean_twin_wrongly_accused(self):
        s = BM.score_run(bug("T01-twin-of-001-sql-parameterised", EXT), run([finding("app.py", ["CWE-89"], 6)]))
        self.assertEqual((s["outcome"], s["false_accusations"]), ("falsely_accused", 1))

    def test_lookalike_wrongly_accused(self):
        s = BM.score_run(bug("L02-lookalike-shell-constant", EXT), run([finding("app.py", ["CWE-78"], 4)]))
        self.assertEqual(s["outcome"], "falsely_accused")

    def test_empty_output_without_completed_checks_is_incomplete_not_a_true_negative(self):
        s = BM.score_run(bug("T01-twin-of-001-sql-parameterised", EXT), run([]))
        self.assertEqual((s["outcome"], s["graded"]), ("incomplete", False))
        self.assertIn("not a clean result", s["incomplete_reason"])

    def test_coverage_with_unresolved_rows_does_not_count_as_completed(self):
        cov = [{"class_id": "CWE-89", "status": "clean"}, {"class_id": "CWE-78", "status": "not_checked", "reason": "x"}]
        s = BM.score_run(bug("T01-twin-of-001-sql-parameterised", EXT), run([], coverage=cov))
        self.assertEqual(s["outcome"], "incomplete")
        done = BM.score_run(bug("T01-twin-of-001-sql-parameterised", EXT),
                            run([], coverage=[{"class_id": "CWE-89", "status": "clean"}]))
        self.assertEqual(done["outcome"], "clean_ok")

    def test_defect_case_with_no_output_is_incomplete_not_missed(self):
        s = BM.score_run(bug("001-sql-injection"), run([]))
        self.assertEqual((s["outcome"], s["false_negatives"], s["expected_findings"]), ("incomplete", 0, 1))

    def test_defect_case_completed_with_nothing_found_is_a_miss(self):
        s = BM.score_run(bug("001-sql-injection"), run([], **self.EVIDENCE))
        self.assertEqual((s["outcome"], s["false_negatives"]), ("missed", 1))

    def test_clean_controls_need_scorer_3(self):
        s = BM.score_run(bug("T01-twin-of-001-sql-parameterised", EXT), run([]), scorer_version=2)
        self.assertFalse(s["graded"])


class IncompleteRuns(unittest.TestCase):
    CASES = [
        ("run_ok false", {"run_ok": False, "findings": []}),
        ("error", {"error": "agent crashed", "findings": [{"file": "app.py"}]}),
        ("interrupted status", {"run_ok": True, "status": "interrupted", "findings": []}),
        ("timeout status", {"status": "timeout", "findings": [finding("app.py", ["CWE-89"], 6)]}),
        ("no findings list", {"run_ok": True}),
    ]

    def test_every_interruption_shape_is_incomplete(self):
        b = bug("001-sql-injection")
        for label, result in self.CASES:
            with self.subTest(label):
                s = BM.score_run(b, result)
                self.assertFalse(s["graded"], label)
                self.assertEqual(s["outcome"], "incomplete")
                self.assertEqual(s["true_positives"], 0)

    def test_ground_truth_without_a_usable_path_is_reported_not_silently_passed(self):
        b = dict(bug("001-sql-injection"))
        b["expected_findings"] = [{"file": "", "classes": ["CWE-89"], "symbol": "x"}]
        s = BM.score_run(b, run([finding("app.py", ["CWE-89"], 6)]))
        self.assertEqual(s["outcome"], "incomplete")
        self.assertIn("ground-truth entry 1", s["incomplete_reason"])


class SeparateCountsAndDenominators(unittest.TestCase):
    def test_found_missed_ungraded_always_add_up_to_expected(self):
        scores = [
            BM.score_run(bug("001-sql-injection"), run([finding("app.py", ["CWE-89"], 6)])),
            BM.score_run(bug("002-unsafe-yaml"), run([], checks_completed=["x"])),          # missed
            BM.score_run(bug("003-null-deref"), {"run_ok": False, "findings": []}),         # incomplete
            BM.score_run(bug("M02-two-defects-two-files", EXT), run([finding("db.py", ["CWE-89"], 2)])),  # 1 of 2
        ]
        d = BM.summarise(scores)["defects"]
        self.assertEqual(d["expected"], 5)
        self.assertEqual((d["found"], d["missed"], d["ungraded_in_incomplete_runs"]), (2, 2, 1))
        self.assertEqual(d["found"] + d["missed"] + d["ungraded_in_incomplete_runs"], d["expected"])

    def test_a_smaller_denominator_cannot_improve_the_result_invisibly(self):
        graded_only = [BM.score_run(bug("001-sql-injection"), run([finding("app.py", ["CWE-89"], 6)]))]
        with_gap = graded_only + [BM.score_run(bug("002-unsafe-yaml"), {"run_ok": False, "findings": []})]
        a, b = BM.summarise(graded_only), BM.summarise(with_gap)
        self.assertEqual(a["defects"]["recall_all_pct"], 100.0)
        self.assertEqual(b["defects"]["recall_graded_pct"], 100.0)   # still 100% over what ran ...
        self.assertEqual(b["defects"]["recall_all_pct"], 50.0)       # ... but the gap is in the headline
        self.assertEqual(b["cases_incomplete"], 1)
        self.assertEqual(b["incomplete"][0]["id"], "002-unsafe-yaml")

    def test_control_counts_are_separate_from_defect_counts(self):
        scores = [
            BM.score_run(bug("L01-lookalike-sql-allowlist", EXT), run([], checks_completed=["x"])),
            BM.score_run(bug("L02-lookalike-shell-constant", EXT), run([finding("app.py", ["CWE-78"], 4)])),
            BM.score_run(bug("T01-twin-of-001-sql-parameterised", EXT), run([])),            # incomplete
        ]
        c = BM.summarise(scores)["controls"]
        self.assertEqual((c["cases"], c["clean_ok"], c["wrongly_accused"], c["incomplete"]), (3, 1, 1, 1))
        self.assertEqual(BM.summarise(scores)["defects"]["expected"], 0)

    def test_always_reporting_something_is_now_penalised(self):
        """A reviewer that flags every case scores perfect recall but wrongly accuses every control."""
        scores = []
        for d in sorted(BUGS.iterdir())[:3]:
            b = BM.load_bug(str(d))
            e = b["expected_findings"][0]
            scores.append(BM.score_run(b, run([finding(e["file"], e["classes"], e["region"]["start"])])))
        for d in sorted(EXT.iterdir()):
            b = BM.load_bug(str(d))
            if b["kind"] == "clean":
                scores.append(BM.score_run(b, run([finding("app.py", ["CWE-89"], 1)])))
        s = BM.summarise(scores)
        self.assertEqual(s["defects"]["recall_all_pct"], 100.0)
        self.assertEqual(s["controls"]["wrongly_accused"], 8)
        self.assertEqual(s["controls"]["clean_ok"], 0)

    def test_usage_is_reported_separately_and_does_not_change_the_score(self):
        plain = BM.score_run(bug("001-sql-injection"), run([finding("app.py", ["CWE-89"], 6)]))
        costed = BM.score_run(bug("001-sql-injection"), run([finding("app.py", ["CWE-89"], 6)],
                                                            usage={"seconds": 40, "turns": 5, "cost_usd": 0.25}))
        self.assertEqual({k: plain[k] for k in ("precision_pct", "recall_pct", "f1_score")},
                         {k: costed[k] for k in ("precision_pct", "recall_pct", "f1_score")})
        u = BM.summarise([costed])["usage_not_scored"]
        self.assertEqual((u["seconds_median"], u["turns_median"], u["cost_usd_total"]), (40, 5, 0.25))


class VersionsAndImmutability(unittest.TestCase):
    def test_committed_reference_results_stay_scored_under_version_1(self):
        manifest = json.loads((RESULTS / "MANIFEST.json").read_text())
        self.assertEqual(manifest["scorer_version"], 1)
        tp = fp = fn = 0
        for path in sorted(RESULTS.glob("0*.json")):
            s = BM.score_run(BM.load_bug(str(BUGS / path.stem)), json.loads(path.read_text()), scorer_version=1)
            tp, fp, fn = tp + s["true_positives"], fp + s["false_positives"], fn + s["false_negatives"]
        self.assertEqual((tp, fp, fn), (5, 1, 0))  # the README's 100% recall

    def test_version_2_is_frozen_and_scores_those_results_zero(self):
        for path in sorted(RESULTS.glob("0*.json")):
            s = BM.score_run(BM.load_bug(str(BUGS / path.stem)), json.loads(path.read_text()), scorer_version=2)
            self.assertEqual(s["true_positives"], 0, path.name)

    def test_resolution_order(self):
        r = {"scorer_version": 2}
        self.assertEqual(BM.resolve_scorer_version(r), 2)                 # the result's own field
        self.assertEqual(BM.resolve_scorer_version(r, override=1), 1)     # CLI override wins
        self.assertEqual(BM.resolve_scorer_version({}, default=1), 1)     # manifest
        self.assertEqual(BM.resolve_scorer_version({}), BM.CURRENT_SCORER_VERSION)
        self.assertEqual(BM.resolve_scorer_version({"scorer_version": 99}), BM.CURRENT_SCORER_VERSION)

    def test_every_score_records_the_version_it_was_scored_under(self):
        b = bug("001-sql-injection")
        self.assertEqual(BM.score_run(b, run([]), scorer_version=1)["scorer_version"], 1)
        self.assertEqual(BM.score_run(b, run([]), scorer_version=2)["scorer_version"], 2)
        self.assertEqual(BM.score_run(b, run([finding("app.py", ["CWE-89"], 6)]))["scorer_version"], 3)

    def test_original_corpus_is_unchanged_in_size_and_still_one_finding_each(self):
        dirs = sorted(p for p in BUGS.iterdir() if p.is_dir())
        self.assertEqual(len(dirs), 25)
        for d in dirs:
            self.assertEqual(len(json.loads((d / "ground-truth.json").read_text())["findings"]), 1)


class Corpus(unittest.TestCase):
    def test_shipped_corpus_lints_clean(self):
        dirs = [str(p) for p in sorted(BUGS.iterdir()) + sorted(EXT.iterdir()) if p.is_dir()]
        self.assertEqual(len(dirs), 35)
        self.assertEqual(BM.lint_corpus(dirs), [])

    def test_extended_corpus_composition(self):
        kinds = [BM.load_bug(str(p)) for p in sorted(EXT.iterdir())]
        self.assertEqual(sum(b["kind"] == "clean" for b in kinds), 8)
        self.assertEqual(sum(b["control_type"] == "lookalike" for b in kinds), 4)
        self.assertEqual(sum(b["control_type"] == "repaired_twin" for b in kinds), 4)
        for b in kinds:
            if b["control_type"] == "repaired_twin":
                self.assertTrue((BUGS / b["twin_of"]).is_dir(), b["id"])
            if b["kind"] == "clean":
                self.assertEqual(b["expected_findings"], [])

    def test_lint_flags_ground_truth_that_scorer_3_cannot_grade(self):
        d = Path(tempfile.mkdtemp(prefix="hg-lint-"))
        self.addCleanup(shutil.rmtree, d, True)
        (d / "x").mkdir()
        (d / "x" / "ground-truth.json").write_text(json.dumps({"title": "t", "findings": [
            {"file": "app.py", "classes": ["CWE-89"]}, {"file": "", "classes": []}]}))
        problems = BM.lint_corpus([str(d / "x")])
        self.assertTrue(any("no symbol, region or outcome_keywords" in p for p in problems))
        self.assertTrue(any("no usable repo-relative file" in p for p in problems))
        self.assertTrue(any("no classes" in p for p in problems))


class ReportAndCli(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="hg-bench-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_html_report_no_longer_crashes_on_class_or_strict_matches(self):
        # regression: the report read m['score'], which class-mode matches never had
        scores = [
            BM.score_run(bug("001-sql-injection"), run([finding("app.py", ["CWE-89"], 6)])),
            BM.score_run(bug("002-unsafe-yaml"), run([finding("app.py", ["CWE-502"], 5)]), scorer_version=2),
            BM.score_run(bug("L01-lookalike-sql-allowlist", EXT), run([finding("app.py", ["CWE-89"], 6)])),
            BM.score_run(bug("T01-twin-of-001-sql-parameterised", EXT), run([])),
        ]
        out = self.tmp / "r.html"
        BM.generate_report(scores, str(out))
        html = out.read_text()
        self.assertIn("Separate counts", html)
        self.assertIn("wrongly accused", html)
        self.assertIn("Incomplete: T01-twin-of-001-sql-parameterised", html)

    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True)

    def test_cli_default_scores_committed_results_under_their_pinned_version(self):
        out = self.tmp / "r.html"
        proc = self.run_cli("--bugs", str(BUGS), "--results", str(RESULTS), "--output", str(out),
                            "--summary-json", str(self.tmp / "s.json"))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        summary = json.loads((self.tmp / "s.json").read_text())
        self.assertEqual(summary["scorer_versions"], [1])
        self.assertEqual(summary["defects"]["found"], 5)
        self.assertEqual(summary["defects"]["ungraded_in_incomplete_runs"], 20)
        self.assertEqual(summary["defects"]["recall_all_pct"], 20.0)
        self.assertIn("extended cases skipped", proc.stdout)

    def test_cli_with_scorer_3_grades_defects_controls_and_reports_gaps(self):
        res = self.tmp / "results"
        res.mkdir()
        (res / "001-sql-injection.json").write_text(json.dumps(run([finding("app.py", ["CWE-89"], 6)])))
        (res / "T01-twin-of-001-sql-parameterised.json").write_text(json.dumps(run([], checks_completed=["read it"])))
        (res / "L02-lookalike-shell-constant.json").write_text(json.dumps(run([finding("app.py", ["CWE-78"], 4)])))
        (res / "M02-two-defects-two-files.json").write_text(json.dumps({"run_ok": False, "status": "interrupted", "findings": []}))
        proc = self.run_cli("--bugs", str(BUGS), "--results", str(res), "--output", str(self.tmp / "r.html"),
                            "--scorer-version", "3", "--summary-json", str(self.tmp / "s.json"))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        s = json.loads((self.tmp / "s.json").read_text())
        self.assertEqual(s["scorer_versions"], [3])
        self.assertEqual(s["cases_total"], 35)
        self.assertEqual((s["controls"]["clean_ok"], s["controls"]["wrongly_accused"]), (1, 1))
        self.assertEqual(s["defects"]["found"], 1)
        self.assertEqual(s["defects"]["found"] + s["defects"]["missed"] + s["defects"]["ungraded_in_incomplete_runs"],
                         s["defects"]["expected"])
        self.assertEqual(s["defects"]["expected"], 28)  # 25 corpus + M01 (1) + M02 (2)
        self.assertIn("INCOMPLETE", proc.stdout)
        self.assertIn("Controls:", proc.stdout)

    def test_cli_lint_corpus_passes_on_the_shipped_corpus(self):
        proc = self.run_cli("--lint-corpus", "--bugs", str(BUGS))
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn("35 case(s) checked, 0 problem(s)", proc.stdout)

    def test_single_case_mode_reports_the_scorer_version(self):
        rp = self.tmp / "one.json"
        rp.write_text(json.dumps(run([finding("app.py", ["CWE-89"], 6)])))
        proc = self.run_cli("--bug", str(BUGS / "001-sql-injection"), "--result", str(rp))
        self.assertIn("(scorer 3)", proc.stdout)


if __name__ == "__main__":
    unittest.main()
