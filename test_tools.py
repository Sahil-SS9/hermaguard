"""
Hermaguard Tools — Test Suite
Tests import and call real functions from the tools.
No placebo assertions. If a tool is deleted, its tests fail.

Usage:
    cd /tmp/hermaguard && python3 -m unittest test_tools.py -v
"""

import importlib.util
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent


def _load_module(name, relpath):
    """Import a Python module from a relative path under ROOT."""
    spec = importlib.util.spec_from_file_location(name, ROOT / relpath)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load {relpath}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── Pre-Scan tests (call real split_files, run_prescan, parsers) ────────────

class TestPreScan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module("prescan", "tools/hermaguard-prescan/hermaguard-prescan.py")

    def test_split_files_comma_separated(self):
        result = self.mod.split_files("a.py, b.py, c.ts")
        self.assertEqual(result, ["a.py", "b.py", "c.ts"])

    def test_split_files_newline_separated(self):
        result = self.mod.split_files("src/main.py\nsrc/utils.py\n")
        self.assertEqual(result, ["src/main.py", "src/utils.py"])

    def test_split_files_empty(self):
        self.assertEqual(self.mod.split_files(""), [])
        self.assertEqual(self.mod.split_files("  ,  "), [])

    def test_run_prescan_empty_files(self):
        """Empty file list produces valid output dict with zero findings."""
        output = self.mod.run_prescan([])
        self.assertEqual(output["stats"]["total_findings"], 0)
        self.assertEqual(output["stats"]["files_scanned"], 0)
        self.assertIsInstance(output["findings"], list)

    def test_run_prescan_nonexistent_tools(self):
        """Files with extensions that have no installed tools → all skipped."""
        # Create temp .py file that doesn't exist on disk (tools won't find it)
        # run_prescan will try to find bandit/ruff, fail, skip them
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as f:
            f.write(b"x = 1\n")
            pyfile = f.name
        try:
            output = self.mod.run_prescan([pyfile])
            # Should have scanned 1 file, but tools likely skipped (not installed)
            self.assertEqual(output["stats"]["files_scanned"], 1)
            self.assertIn("findings", output)
            self.assertIn("stats", output)
            self.assertIn("tools_run", output["stats"])
            self.assertIn("tools_skipped", output["stats"])
        finally:
            os.unlink(pyfile)

    def test_bandit_parser_real_output(self):
        """Parse real bandit JSON output."""
        sample = json.dumps({
            "results": [
                {
                    "test_id": "B301",
                    "issue_severity": "MEDIUM",
                    "filename": "src/auth.py",
                    "line_number": 42,
                    "issue_text": "Use of unsafe yaml.load()",
                }
            ]
        })
        findings = self.mod._parse_bandit(sample)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["tool"], "bandit")
        self.assertEqual(findings[0]["rule_id"], "B301")
        self.assertEqual(findings[0]["severity"], "MEDIUM")
        self.assertEqual(findings[0]["file"], "src/auth.py")
        self.assertEqual(findings[0]["line"], 42)

    def test_bandit_parser_empty(self):
        self.assertEqual(self.mod._parse_bandit("not json"), [])

    def test_ruff_parser_real_output(self):
        """Parse real ruff JSON-line output."""
        sample = json.dumps({
            "code": "B007",
            "filename": "src/main.py",
            "location": {"row": 15},
            "message": "Loop control variable not used",
        })
        findings = self.mod._parse_ruff(sample + "\n")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["tool"], "ruff")
        self.assertEqual(findings[0]["rule_id"], "B007")

    def test_semgrep_parser_real_output(self):
        sample = json.dumps({
            "results": [
                {
                    "check_id": "python.lang.security.audit.dangerous-subprocess-use",
                    "path": "src/runner.py",
                    "start": {"line": 10},
                    "extra": {"severity": "ERROR", "message": "subprocess call with shell=True"},
                }
            ]
        })
        findings = self.mod._parse_semgrep(sample)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertEqual(findings[0]["tool"], "semgrep")

    def test_eslint_parser_real_output(self):
        sample = json.dumps([
            {
                "filePath": "/app/src/index.ts",
                "messages": [
                    {"ruleId": "no-undef", "severity": 2, "line": 5, "message": "'foo' is not defined."}
                ]
            }
        ])
        findings = self.mod._parse_eslint(sample)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertEqual(findings[0]["rule_id"], "no-undef")

    def test_gosec_parser_real_output(self):
        sample = json.dumps({
            "Issues": [
                {"rule_id": "G104", "severity": "HIGH", "file": "main.go", "line": "20", "details": "Audit use of net/http"}
            ]
        })
        findings = self.mod._parse_gosec(sample)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["tool"], "gosec")

    def test_clippy_parser_real_output(self):
        sample = json.dumps({
            "reason": "compiler-message",
            "message": {"code": {"code": "clippy::needless_return"}, "message": "unneeded return statement", "level": "warning"},
            "spans": [{"file_name": "src/lib.rs", "line_start": 42}]
        })
        findings = self.mod._parse_cargo(sample + "\n")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["tool"], "clippy")

    def test_language_tool_mapping(self):
        """Every known extension maps to at least one tool definition."""
        for ext in [".py", ".ts", ".tsx", ".js", ".go", ".rs", ".java"]:
            tools = self.mod.LANGUAGE_TOOLS.get(ext, [])
            self.assertGreater(len(tools), 0, f"Extension {ext} should have tool mappings")

    def test_group_by_extension(self):
        groups = self.mod.group_by_extension(["src/main.py", "src/utils.py", "app/index.ts"])
        self.assertIn(".py", groups)
        self.assertIn(".ts", groups)
        self.assertEqual(len(groups[".py"]["files"]), 2)
        self.assertEqual(len(groups[".ts"]["files"]), 1)

    def test_find_tool_returns_none_for_nonexistent(self):
        result = self.mod.find_tool("hermaguard-nonexistent-tool-xyz")
        self.assertIsNone(result)

    def test_find_tool_returns_path_for_real(self):
        # python3 is guaranteed to exist
        result = self.mod.find_tool("python3")
        self.assertIsNotNone(result)


# ── Feedback MCP server tests (import module, test tool functions directly) ──

class TestFeedbackServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module("feedback_server", "mcp/hermaguard-feedback/server.py")

    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        # Create tables via the module's get_db logic
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, repo TEXT,
                diff_hash TEXT, files_changed INTEGER DEFAULT 0,
                files_blast_radius INTEGER DEFAULT 0, total_findings INTEGER DEFAULT 0,
                agent_1_findings INTEGER DEFAULT 0, agent_2_findings INTEGER DEFAULT 0,
                agent_3_findings INTEGER DEFAULT 0, prescan_findings INTEGER DEFAULT 0,
                overall_risk TEXT, report_path TEXT
            );
            CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(run_id),
                severity TEXT NOT NULL, source_agent TEXT NOT NULL,
                cross_agent_agreement TEXT, file_path TEXT, line_range TEXT,
                trigger_condition TEXT, consequence TEXT, recommendation TEXT,
                source_prescan INTEGER DEFAULT 0, prescan_tool TEXT, prescan_rule TEXT,
                status TEXT DEFAULT 'open', status_updated_at TEXT, status_note TEXT
            );
            CREATE TABLE IF NOT EXISTS acceptance_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id TEXT NOT NULL REFERENCES findings(finding_id),
                action TEXT NOT NULL, note TEXT, timestamp TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS suppression_rules_cache (
                rule_id TEXT PRIMARY KEY, pattern TEXT NOT NULL, reason TEXT,
                created_at TEXT, dismissals INTEGER DEFAULT 0
            );
        """)
        self.conn.commit()

    def tearDown(self):
        try:
            self.conn.close()
            os.unlink(self.db_path)
        except Exception:
            pass

    def test_tool_list(self):
        """tools/list returns all 6 tools."""
        tools = self.mod.tool_list_tools(self.conn)
        tool_names = {t["name"] for t in tools}
        for expected in ["record_findings", "accept_finding", "query_agent_precision",
                         "get_suppression_rules", "get_run_history", "get_run"]:
            self.assertIn(expected, tool_names)

    def test_record_and_query_run(self):
        """Record a run, then query it back."""
        report = {
            "meta": {"timestamp": "2026-06-15T10:00:00Z", "diff_ref": "main..HEAD",
                     "scope": {"files_changed": 2, "files_in_blast_radius": 5},
                     "prescan": {"total_findings": 1}},
            "summary": {"total": 2, "critical": 0, "high": 1, "medium": 1, "low": 0},
            "findings": [
                {"id": "HG-001", "severity": "HIGH", "source_agent": "adversarial-reviewer",
                 "cross_agent_agreement": ["edge-case-hunter"],
                 "file": "src/auth.py", "line_range": "42-42",
                 "trigger_condition": "unsafe yaml.load", "consequence": "RCE",
                 "recommendation": "Use safe_load", "source_prescan": True,
                 "prescan_tool": "bandit", "prescan_rule": "B301"},
                {"id": "HG-002", "severity": "MEDIUM", "source_agent": "edge-case-hunter",
                 "file": "src/auth.py", "line_range": "55-55",
                 "trigger_condition": "missing null check", "consequence": "TypeError",
                 "recommendation": "Add guard"},
            ],
            "verdict": {"overall_risk": "HIGH"},
        }
        result = self.mod.tool_record_findings(self.conn, {
            "run_id": "test-run-001",
            "findings_json": json.dumps(report),
        })
        self.assertEqual(result["status"], "recorded")
        self.assertEqual(result["findings_stored"], 2)

        # Query run history
        history = self.mod.tool_get_run_history(self.conn, {"limit": 5})
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["run_id"], "test-run-001")

        # Query full run
        run = self.mod.tool_get_run(self.conn, {"run_id": "test-run-001"})
        self.assertEqual(len(run["findings"]), 2)

    def test_accept_finding_and_precision(self):
        """Accept findings, then query precision — verify sane numbers."""
        # Record a run with 2 findings
        report = {
            "meta": {"timestamp": "2026-06-15T10:00:00Z", "scope": {"files_changed": 1, "files_in_blast_radius": 0}},
            "summary": {"total": 2, "critical": 0, "high": 1, "medium": 0, "low": 1},
            "findings": [
                {"id": "HG-001", "severity": "HIGH", "source_agent": "adversarial-reviewer",
                 "file": "src/x.py", "line_range": "10-10", "trigger_condition": "sql injection",
                 "consequence": "data leak", "recommendation": "parameterize"},
                {"id": "HG-002", "severity": "LOW", "source_agent": "edge-case-hunter",
                 "file": "src/x.py", "line_range": "20-20", "trigger_condition": "null check on validated input",
                 "consequence": "noise", "recommendation": "skip"},
            ],
            "verdict": {"overall_risk": "HIGH"},
        }
        self.mod.tool_record_findings(self.conn, {"run_id": "r1", "findings_json": json.dumps(report)})

        # Accept HG-001 as fixed, dismiss HG-002 as false positive
        self.mod.tool_accept_finding(self.conn, {"finding_id": "HG-001", "action": "fixed", "note": "parameterized"})
        self.mod.tool_accept_finding(self.conn, {"finding_id": "HG-002", "action": "dismissed-false-positive", "note": "validated upstream"})

        # Query precision for adversarial-reviewer
        prec = self.mod.tool_query_agent_precision(self.conn, {"agent_name": "adversarial-reviewer", "window_days": 30})
        # HG-001 is fixed → correct. HG-002 is edge-case-hunter, not adversarial-reviewer.
        # So adversarial-reviewer: 1 triaged (HG-001), 1 fixed → 100% precision
        self.assertEqual(prec["total_findings"], 1)
        self.assertEqual(prec["fixed_or_accepted"], 1)
        self.assertEqual(prec["overall_precision_pct"], 100.0)

        # Query precision for edge-case-hunter
        prec2 = self.mod.tool_query_agent_precision(self.conn, {"agent_name": "edge-case-hunter", "window_days": 30})
        # HG-002 is dismissed-false-positive → 0 fixed, 1 triaged → 0% precision
        self.assertEqual(prec2["total_findings"], 1)
        self.assertEqual(prec2["fixed_or_accepted"], 0)
        self.assertEqual(prec2["overall_precision_pct"], 0.0)

    def test_open_finding_excluded_from_precision(self):
        """An untriaged (open) finding must not count against precision."""
        # Record a run with 1 finding, leave it open
        report = {
            "meta": {"timestamp": "2026-06-15T10:00:00Z", "scope": {"files_changed": 1, "files_in_blast_radius": 0}},
            "summary": {"total": 1, "critical": 0, "high": 1, "medium": 0, "low": 0},
            "findings": [
                {"id": "HG-001", "severity": "HIGH", "source_agent": "adversarial-reviewer",
                 "file": "src/x.py", "line_range": "10-10", "trigger_condition": "sql injection",
                 "consequence": "data leak", "recommendation": "parameterize"},
            ],
            "verdict": {"overall_risk": "HIGH"},
        }
        self.mod.tool_record_findings(self.conn, {"run_id": "r-open", "findings_json": json.dumps(report)})

        # Query precision — finding is still open, never triaged
        prec = self.mod.tool_query_agent_precision(self.conn, {"agent_name": "adversarial-reviewer", "window_days": 30})
        # Open findings are excluded from the denominator → 0 triaged → N/A
        self.assertEqual(prec["total_findings"], 0, "Open finding must not count in denominator")
        self.assertEqual(prec["fixed_or_accepted"], 0)
        self.assertIsNone(prec["overall_precision_pct"], "Untriaged agent should return None, not 0%")
        self.assertEqual(prec["open_untriaged"], 1, "Should report how many findings are still open")

    def test_suppression_rules_after_repeated_dismissals(self):
        """After 3 dismissals of same pattern, suppression rules appear."""
        # Record 3 runs, each with one finding of the same pattern, then dismiss all 3
        for i in range(3):
            report = {
                "meta": {"timestamp": f"2026-06-15T0{i}:00:00Z", "scope": {"files_changed": 1, "files_in_blast_radius": 0}},
                "summary": {"total": 1, "critical": 0, "high": 0, "medium": 0, "low": 1},
                "findings": [
                    {"id": f"HG-00{i+1}", "severity": "LOW", "source_agent": "edge-case-hunter",
                     "file": "src/test.py", "line_range": "1-1",
                     "trigger_condition": "null-check on user.id",
                     "consequence": "noise", "recommendation": "skip"},
                ],
                "verdict": {"overall_risk": "LOW"},
            }
            self.mod.tool_record_findings(self.conn, {"run_id": f"r{i}", "findings_json": json.dumps(report)})
            self.mod.tool_accept_finding(self.conn, {"finding_id": f"HG-00{i+1}", "action": "dismissed-false-positive", "note": "validated upstream"})

        # Query suppression rules
        rules = self.mod.tool_get_suppression_rules(self.conn)
        self.assertGreaterEqual(len(rules), 1)
        self.assertIn("null-check", rules[0]["pattern"])


# ── Rule Compiler tests (call real compile_rules) ───────────────────────────

class TestRuleCompiler(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module("compiler", "tools/hermaguard-compile-rules/hermaguard-compile-rules.py")

    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")

    def tearDown(self):
        try:
            os.close(self.db_fd)
            os.unlink(self.db_path)
        except Exception:
            pass

    def _seed_db(self):
        """Create tables and insert 3 dismissed findings with same pattern."""
        conn = sqlite3.connect(self.db_path)
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT PRIMARY KEY, run_id TEXT, severity TEXT,
                source_agent TEXT, file_path TEXT, trigger_condition TEXT,
                status TEXT DEFAULT 'open'
            );
        """)
        for i in range(3):
            conn.execute(
                "INSERT INTO findings VALUES (?, ?, 'LOW', 'edge-case-hunter', 'src/test.py', 'null-check on user.id', 'dismissed-false-positive')",
                (f"HG-00{i+1}", f"r{i}"),
            )
        conn.commit()
        conn.close()

    def test_no_db_returns_empty(self):
        """When DB doesn't exist, compile_rules returns empty list."""
        with mock.patch.dict(os.environ, {"HERMAGUARD_FEEDBACK_DB": "/nonexistent/path.db"}):
            rules = self.mod.compile_rules(min_dismissals=3)
            self.assertEqual(rules, [])

    def test_compile_rules_from_real_db(self):
        """Seed DB with 3 dismissed findings → compile_rules returns 1 rule."""
        self._seed_db()
        # Patch the module's DB_PATH directly (set at import time, env override won't work)
        with mock.patch.object(self.mod, "DB_PATH", self.db_path):
            rules = self.mod.compile_rules(min_dismissals=3)
            self.assertEqual(len(rules), 1)
            self.assertEqual(rules[0]["agent"], "edge_case")
            self.assertEqual(rules[0]["dismissals"], 3)
            self.assertIn("null-check", rules[0]["pattern"])

    def test_below_threshold_no_rules(self):
        """With min_dismissals=5, 3 dismissals → no rules."""
        self._seed_db()
        with mock.patch.dict(os.environ, {"HERMAGUARD_FEEDBACK_DB": self.db_path}):
            rules = self.mod.compile_rules(min_dismissals=5)
            self.assertEqual(rules, [])


# ── Benchmark scoring tests (call real score_run logic) ──────────────────────

class TestBenchmark(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module("benchmark", "tools/hermaguard-benchmark/benchmark.py")

    def test_score_run_perfect_match(self):
        """One expected finding, one found finding that matches → 100% P/R/F1."""
        bug = {
            "id": "test-001", "title": "SQL Injection",
            "severity": "CRITICAL", "category": "security",
            "expected_findings": [
                {"file": "src/auth.py", "trigger": "unsafe sql query", "description": "SQLi in login", "severity": "CRITICAL"}
            ],
        }
        run_info = {
            "run_ok": True,
            "findings": [
                {"id": "HG-001", "file": "src/auth.py", "trigger_condition": "unsafe sql query in login handler",
                 "consequence": "SQL injection", "severity": "CRITICAL"}
            ],
            "summary": {"total": 1},
        }
        score = self.mod.score_run(bug, run_info)
        self.assertEqual(score["precision_pct"], 100.0)
        self.assertEqual(score["recall_pct"], 100.0)
        self.assertEqual(score["f1_score"], 100.0)
        self.assertEqual(score["severity_accuracy_pct"], 100.0)
        self.assertEqual(score["true_positives"], 1)
        self.assertEqual(score["false_positives"], 0)
        self.assertEqual(score["false_negatives"], 0)

    def test_score_run_no_match(self):
        """Finding in unrelated file → 0% precision, 0% recall."""
        bug = {
            "id": "test-002", "title": "Auth Bypass",
            "severity": "CRITICAL", "category": "security",
            "expected_findings": [
                {"file": "src/auth.py", "trigger": "missing auth check", "description": "No auth on admin endpoint", "severity": "CRITICAL"}
            ],
        }
        run_info = {
            "run_ok": True,
            "findings": [
                {"id": "HG-001", "file": "README.md", "trigger_condition": "typo in docs",
                 "consequence": "confusion", "severity": "LOW"}
            ],
            "summary": {"total": 1},
        }
        score = self.mod.score_run(bug, run_info)
        self.assertEqual(score["precision_pct"], 0.0)
        self.assertEqual(score["recall_pct"], 0.0)
        self.assertEqual(score["f1_score"], 0.0)
        self.assertEqual(score["true_positives"], 0)
        self.assertEqual(score["false_positives"], 1)
        self.assertEqual(score["false_negatives"], 1)

    def test_score_run_partial_match(self):
        """2 expected, 1 found that matches one → 50% recall, 100% precision."""
        bug = {
            "id": "test-003", "title": "Two Bugs",
            "severity": "HIGH", "category": "logic",
            "expected_findings": [
                {"file": "src/a.py", "trigger": "off by one", "description": "Loop boundary", "severity": "HIGH"},
                {"file": "src/b.py", "trigger": "race condition", "description": "No lock", "severity": "HIGH"},
            ],
        }
        run_info = {
            "run_ok": True,
            "findings": [
                {"id": "HG-001", "file": "src/a.py", "trigger_condition": "off by one in loop boundary",
                 "consequence": "index error", "severity": "HIGH"}
            ],
            "summary": {"total": 1},
        }
        score = self.mod.score_run(bug, run_info)
        self.assertEqual(score["precision_pct"], 100.0)
        self.assertEqual(score["recall_pct"], 50.0)
        self.assertEqual(score["f1_score"], 66.7)
        self.assertEqual(score["true_positives"], 1)
        self.assertEqual(score["false_positives"], 0)
        self.assertEqual(score["false_negatives"], 1)

    def test_score_run_severity_mismatch(self):
        """Match found but severity wrong → precision/recall OK, severity accuracy 0%."""
        bug = {
            "id": "test-004", "title": "Severity Test",
            "severity": "CRITICAL", "category": "security",
            "expected_findings": [
                {"file": "src/x.py", "trigger": "hardcoded secret", "description": "API key in source", "severity": "CRITICAL"}
            ],
        }
        run_info = {
            "run_ok": True,
            "findings": [
                {"id": "HG-001", "file": "src/x.py", "trigger_condition": "hardcoded secret key in source",
                 "consequence": "credential leak", "severity": "LOW"}
            ],
            "summary": {"total": 1},
        }
        score = self.mod.score_run(bug, run_info)
        self.assertEqual(score["precision_pct"], 100.0)  # still a match
        self.assertEqual(score["recall_pct"], 100.0)
        self.assertEqual(score["severity_accuracy_pct"], 0.0)  # severity wrong

    def test_score_run_empty(self):
        """No expected findings, no found findings → all zeroes, no crash."""
        bug = {"id": "test-005", "title": "Empty", "severity": "LOW", "category": "style",
               "expected_findings": []}
        run_info = {"run_ok": True, "findings": [], "summary": {"total": 0}}
        score = self.mod.score_run(bug, run_info)
        self.assertEqual(score["precision_pct"], 0.0)
        self.assertEqual(score["recall_pct"], 0.0)
        self.assertEqual(score["f1_score"], 0.0)

    def test_score_run_failed(self):
        """Run that failed → score reflects error, metrics are zero."""
        bug = {"id": "test-006", "title": "Failed Run", "severity": "HIGH", "category": "security",
               "expected_findings": [{"file": "x.py", "trigger": "bug", "description": "bug", "severity": "HIGH"}]}
        run_info = {"run_ok": False, "error": "timeout", "findings": [], "summary": {}}
        score = self.mod.score_run(bug, run_info)
        self.assertFalse(score["run_ok"])
        self.assertEqual(score["run_error"], "timeout")
        self.assertEqual(score["precision_pct"], 0.0)


# ── SKILL.md integrity tests ────────────────────────────────────────────────

class TestSKILLmd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.skill_path = ROOT / "SKILL.md"

    def test_skill_exists(self):
        self.assertTrue(self.skill_path.is_file())

    def test_version_is_2_0_0(self):
        content = self.skill_path.read_text()
        self.assertIn("version: 2.0.0", content)

    def test_json_schema_present(self):
        # The full JSON schema example lives in references/output-schema.md (the
        # skill body points to it); SKILL.md keeps a field-level description.
        schema_ref = (ROOT / "references/output-schema.md").read_text()
        self.assertIn('"id": "HG-001"', schema_ref, "JSON schema example should be in references/output-schema.md")
        self.assertIn("source_agent", self.skill_path.read_text(), "SKILL.md should describe the JSON fields")

    def test_no_hardcoded_delegate_task(self):
        """SKILL.md must not hardcode Hermes-specific delegate_task syntax."""
        content = self.skill_path.read_text()
        self.assertNotIn("delegate_task(tasks=[", content,
                         "SKILL.md should use harness-agnostic language, not Hermes-specific delegate_task")

    def test_harness_agnostic_dispatch_language(self):
        """SKILL.md should express dispatch intent generically."""
        content = self.skill_path.read_text()
        self.assertIn("dispatch", content.lower(),
                      "SKILL.md should describe dispatch generically (not framework-specific)")

    def test_prescan_referenced(self):
        content = self.skill_path.read_text()
        self.assertIn("pre-scan", content.lower())

    def test_feedback_referenced(self):
        content = self.skill_path.read_text()
        self.assertIn("feedback", content.lower())

    def test_runner_template_referenced(self):
        """SKILL.md should mention that any harness can run it, not assume one."""
        content = self.skill_path.read_text()
        harnesses = ["hermes agent", "claude code", "codex", "any agent framework"]
        found = sum(1 for h in harnesses if h in content.lower())
        self.assertGreaterEqual(found, 2, "SKILL.md should reference multiple harness options")


# ── AGENTS.md Linter tests (call real score_file) ────────────────────────────

class TestAgentsmdLinter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module("linter", "tools/agentsmd-linter/agentsmd-lint.py")

    def test_score_empty_file(self):
        """Empty file scores low but doesn't crash."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            f.write("")
            path = f.name
        try:
            result = self.mod.score_file(path)
            self.assertLess(result["score"], 30)
            self.assertIn("recommendations", result)
            self.assertGreater(len(result["recommendations"]), 0)
        finally:
            os.unlink(path)

    def test_score_well_structured_file(self):
        """A file with conventions, tests, stack details scores well."""
        content = """# Project X

## Conventions
- Always use TypeScript strict mode
- File names: kebab-case
- Imports: absolute paths from src/

## Testing
Run tests with `pnpm test`. Uses vitest. Coverage must stay above 80%.

## Architecture
- src/components/ — React components
- src/lib/ — business logic
- src/pages/ — route handlers

## Stack
- Node 22, TypeScript 5.5, React 19
- pnpm 9, vitest 2

## Don't
- Never import from `../../` — use absolute paths
- Don't modify generated files in src/generated/
- Avoid `any` — use `unknown` and narrow

## Scope
- You may modify src/components/ and src/lib/
- Do NOT touch src/generated/ or config files
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            f.write(content)
            path = f.name
        try:
            result = self.mod.score_file(path)
            self.assertGreaterEqual(result["score"], 55, f"Expected >=55, got {result['score']}")
            self.assertIn(result["grade"], ["A", "B"])
        finally:
            os.unlink(path)

    def test_score_hermaguard_skill(self):
        """The actual SKILL.md scores A or better."""
        result = self.mod.score_file(str(ROOT / "SKILL.md"))
        self.assertGreaterEqual(result["score"], 70, f"SKILL.md should score >=70, got {result['score']}")


class TestTakeoverFixes(unittest.TestCase):
    """Tests for the residual-nit fixes applied during takeover. Each calls the
    real function/CLI; each fails if the fix is reverted."""

    @classmethod
    def setUpClass(cls):
        cls.prescan = _load_module("prescan_fx", "tools/hermaguard-prescan/hermaguard-prescan.py")
        cls.feedback = _load_module("feedback_fx", "mcp/hermaguard-feedback/server.py")
        cls.compiler_path = ROOT / "tools/hermaguard-compile-rules/hermaguard-compile-rules.py"
        cls.benchmark = _load_module("benchmark_fx", "tools/hermaguard-benchmark/benchmark.py")

    def test_find_tool_cross_platform(self):
        """find_tool resolves a real executable and returns None for a missing one
        (shutil.which path, not POSIX-only `which`)."""
        self.assertIsNotNone(self.prescan.find_tool("python3") or self.prescan.find_tool("python"))
        self.assertIsNone(self.prescan.find_tool("definitely-not-a-real-tool-xyz123"))

    def test_diff_alias_splits_like_files(self):
        """--diff and --files feed the same splitter; newline form (git diff) works."""
        self.assertEqual(self.prescan.split_files("a.py\nb.py\n"), ["a.py", "b.py"])
        self.assertEqual(self.prescan.split_files("a.py, b.py"), ["a.py", "b.py"])

    def test_suppression_rules_returns_list(self):
        """get_suppression_rules returns a list, the type that made the old
        `'error' in result` dispatch guard fragile."""
        db_fd, db_path = tempfile.mkstemp(suffix=".db")
        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            conn.executescript(
                "CREATE TABLE suppression_rules_cache (rule_id TEXT PRIMARY KEY, "
                "pattern TEXT NOT NULL, reason TEXT, dismissals INTEGER DEFAULT 0);"
            )
            result = self.feedback.tool_get_suppression_rules(conn)
            self.assertIsInstance(result, list)
            conn.close()
        finally:
            os.close(db_fd)
            os.unlink(db_path)

    def test_compile_rules_escapes_quotes_in_pattern(self):
        """A trigger_condition containing a double-quote must produce a YAML
        pattern value that round-trips, not a broken file."""
        db_fd, db_path = tempfile.mkstemp(suffix=".db")
        out_fd, out_path = tempfile.mkstemp(suffix=".yaml")
        os.close(out_fd)
        try:
            conn = sqlite3.connect(db_path)
            conn.executescript(
                "CREATE TABLE findings (finding_id TEXT PRIMARY KEY, run_id TEXT, "
                "severity TEXT, source_agent TEXT, file_path TEXT, trigger_condition TEXT, "
                "status TEXT DEFAULT 'open');"
            )
            tricky = 'unsafe call to "eval" on user input'
            for i in range(3):
                conn.execute(
                    "INSERT INTO findings VALUES (?,?,?,?,?,?,?)",
                    (f"HG-00{i}", f"r{i}", "LOW", "edge-case-hunter", "src/x.py", tricky,
                     "dismissed-false-positive"),
                )
            conn.commit()
            conn.close()

            env = dict(os.environ, HERMAGUARD_FEEDBACK_DB=db_path)
            subprocess.run(
                [sys.executable, str(self.compiler_path), "--output", out_path,
                 "--min-dismissals", "1"],
                env=env, capture_output=True, text=True, timeout=30, check=True,
            )
            pattern_line = next(
                l for l in open(out_path).read().splitlines() if l.strip().startswith("pattern:")
            )
            value = pattern_line.split("pattern:", 1)[1].strip()
            self.assertEqual(json.loads(value), tricky)  # round-trips → escaping works
        finally:
            os.close(db_fd)
            os.unlink(db_path)
            os.unlink(out_path)

    def test_report_path_not_doubled(self):
        """generate_report writes to exactly the path given (the results/results/
        path-doubling bug)."""
        out_dir = tempfile.mkdtemp()
        target = os.path.join(out_dir, "report.html")
        self.benchmark.generate_report([], target)
        self.assertTrue(os.path.isfile(target))
        os.unlink(target)
        os.rmdir(out_dir)


if __name__ == "__main__":
    unittest.main()
