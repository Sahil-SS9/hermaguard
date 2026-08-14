"""
Hermaguard Loop Closure — Test Suite

Proves the suppression loop is actually closed end-to-end:
hermaguard-compile-rules emits YAML → hermaguard-prescan loads it →
matching findings are suppressed. No placebo assertions.
"""

import importlib
import importlib.util
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock
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


PRES = _load_module("hermaguard_prescan", "tools/hermaguard-prescan/hermaguard-prescan.py")


class TestRuleParsing(unittest.TestCase):
    def test_parses_compile_rules_output_format(self):
        # Exact format hermaguard-compile-rules writes (json.dumps pattern)
        text = (
            "# Hermaguard Suppression Rules\n"
            "- rule_id: HG-SUPPRESS-001\n"
            '  pattern: "loose equality on status check"\n'
            "  agent: edge_case\n"
            "  dismissals: 3\n"
            "\n"
            "- rule_id: HG-SUPPRESS-002\n"
            '  pattern: "harmless getattr default"\n'
            "  agent: adversarial\n"
            "  dismissals: 4\n"
        )
        rules = PRES._parse_rules_text(text)
        self.assertEqual(len(rules), 2)
        self.assertEqual(rules[0]["pattern"], "loose equality on status check")
        self.assertEqual(rules[1]["dismissals"], 4)

    def test_parses_pure_json_array(self):
        rules = PRES._parse_rules_text(json.dumps([
            {"rule_id": "R1", "pattern": "pat", "agent": "a", "dismissals": 3},
        ]))
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["pattern"], "pat")

    def test_empty_file_no_rules(self):
        self.assertEqual(PRES._parse_rules_text("# only comments\n"), [])

    def test_missing_file_returns_no_rules(self):
        with tempfile.TemporaryDirectory() as d:
            rules, src = PRES.load_suppression_rules(os.path.join(d, "nope.yaml"))
            self.assertEqual(rules, [])
            self.assertIsNone(src)

    def test_explicit_path_loaded(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "rules.yaml")
            Path(p).write_text('- rule_id: R1\n  pattern: "x"\n  agent: a\n  dismissals: 3\n')
            rules, src = PRES.load_suppression_rules(p)
            self.assertEqual(len(rules), 1)
            self.assertEqual(src, p)


class TestSuppressionApplication(unittest.TestCase):
    def _f(self, msg, rule_id="B101", file="src/app.py"):
        return {"tool": "bandit", "rule_id": rule_id, "severity": "LOW",
                "file": file, "line": 1, "message": msg, "category": "security"}

    def test_matching_pattern_suppressed(self):
        rules = [{"pattern": "assert used in production", "file_scope": ""}]
        kept, sup = PRES.apply_suppression_rules(
            [self._f("B101: assert used in production code")], rules)
        self.assertEqual(len(sup), 1)
        self.assertEqual(kept, [])

    def test_non_matching_kept(self):
        rules = [{"pattern": "something else entirely", "file_scope": ""}]
        kept, sup = PRES.apply_suppression_rules(
            [self._f("assert used in production code")], rules)
        self.assertEqual(len(kept), 1)
        self.assertEqual(sup, [])

    def test_file_scope_restricts(self):
        rules = [{"pattern": "assert", "file_scope": "src/tests_helper.py"}]
        kept, sup = PRES.apply_suppression_rules(
            [self._f("assert used", file="src/app.py")], rules)
        self.assertEqual(len(kept), 1)  # different file — not suppressed
        rules2 = [{"pattern": "assert", "file_scope": "src/app.py"}]
        kept2, sup2 = PRES.apply_suppression_rules(
            [self._f("assert used", file="src/app.py")], rules2)
        self.assertEqual(len(sup2), 1)

    def test_no_rules_passthrough(self):
        findings = [self._f("anything")]
        kept, sup = PRES.apply_suppression_rules(findings, [])
        self.assertEqual(kept, findings)
        self.assertEqual(sup, [])


class TestEndToEndLoop(unittest.TestCase):
    """compile-rules DB → YAML → prescan applies it. The whole point."""

    def test_full_loop(self):
        CR = _load_module("hermaguard_compile_rules", "tools/hermaguard-compile-rules/hermaguard-compile-rules.py")

        with tempfile.TemporaryDirectory() as d:
            db = os.path.join(d, "feedback.db")
            # Build a feedback DB with one pattern dismissed 3x
            conn = sqlite3.connect(db)
            conn.executescript("""
                CREATE TABLE findings (
                    finding_id TEXT PRIMARY KEY,
                    run_id TEXT,
                    severity TEXT,
                    source_agent TEXT,
                    file_path TEXT,
                    trigger_condition TEXT,
                    status TEXT,
                    triage_note TEXT,
                    ts TEXT
                );
            """)
            for i in range(3):
                conn.execute(
                    "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?)",
                    (f"F{i}", "run1", "LOW", "edge-case-hunter", "src/app.py",
                     "assert used in production", "dismissed-false-positive", "", "2026-01-01"))
            conn.commit()
            conn.close()

            with unittest.mock.patch.dict(os.environ, {"HERMAGUARD_FEEDBACK_DB": db}):
                # compile-rules reads env at import time — reload with the env set
                spec2 = importlib.util.spec_from_file_location(
                    "cr2", ROOT / "tools/hermaguard-compile-rules/hermaguard-compile-rules.py")
                if spec2 is None or spec2.loader is None:
                    raise ImportError("could not load compile-rules")
                cr2 = importlib.util.module_from_spec(spec2)
                sys.modules["cr2"] = cr2
                spec2.loader.exec_module(cr2)
                rules = cr2.compile_rules(min_dismissals=3)

            self.assertEqual(len(rules), 1)
            self.assertEqual(rules[0]["pattern"], "assert used in production")

            # Write the YAML exactly as compile-rules main() writes it
            yaml_path = os.path.join(d, "hermaguard-rules.yaml")
            with open(yaml_path, "w") as f:
                f.write("# auto\n")
                for r in rules:
                    f.write(f"- rule_id: {r['rule_id']}\n")
                    f.write(f"  pattern: {json.dumps(r['pattern'])}\n")
                    f.write(f"  agent: {r['agent']}\n")
                    f.write(f"  dismissals: {r['dismissals']}\n\n")

            # Prescan side: load and apply
            loaded, src = PRES.load_suppression_rules(yaml_path)
            self.assertEqual(len(loaded), 1)
            self.assertEqual(src, yaml_path)

            findings = [
                {"tool": "bandit", "rule_id": "B101", "severity": "LOW",
                 "file": "src/app.py", "line": 10,
                 "message": "Assert used in production guard", "category": "security"},
                {"tool": "bandit", "rule_id": "B608", "severity": "HIGH",
                 "file": "src/db.py", "line": 20,
                 "message": "hardcoded_sql_expressions", "category": "security"},
            ]
            kept, suppressed = PRES.apply_suppression_rules(findings, loaded)
            self.assertEqual(len(kept), 1)
            self.assertEqual(len(suppressed), 1)
            self.assertEqual(kept[0]["rule_id"], "B608")  # the real finding survives
            self.assertEqual(suppressed[0]["rule_id"], "B101")  # the noise is gone


if __name__ == "__main__":
    unittest.main()
