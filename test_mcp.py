"""
Hermaguard MCP Feedback Server — Test Suite

Two layers:
  1. Direct schema-validation unit tests (no subprocess).
  2. FULL e2e stdio test: spawns the real server, performs the MCP
     handshake (initialize → notifications/initialized → tools/list),
     calls record_findings / accept_finding / query_agent_precision /
     get_suppression_rules, and asserts on real responses over real pipes.
"""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SERVER = ROOT / "mcp/hermaguard-feedback/server.py"


def _load_module(name, relpath):
    spec = importlib.util.spec_from_file_location(name, ROOT / relpath)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load {relpath}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


MCP = _load_module("hermaguard_feedback_server", "mcp/hermaguard-feedback/server.py")


class TestSchemaValidation(unittest.TestCase):
    def test_missing_required_rejected(self):
        schema = {"type": "object", "properties": {"run_id": {"type": "string"}},
                  "required": ["run_id"]}
        errors = MCP.validate_args(schema, {})
        self.assertTrue(any("run_id" in e for e in errors))

    def test_wrong_type_rejected(self):
        schema = {"type": "object", "properties": {"limit": {"type": "integer"}}}
        errors = MCP.validate_args(schema, {"limit": "twenty"})
        self.assertTrue(any("expected integer" in e for e in errors))

    def test_enum_enforced(self):
        schema = {"type": "object",
                  "properties": {"action": {"type": "string", "enum": ["fixed", "dismissed-false-positive"]}},
                  "required": ["action"]}
        errors = MCP.validate_args(schema, {"action": "bogus"})
        self.assertTrue(any("enum" in e for e in errors))

    def test_unknown_arg_rejected(self):
        schema = {"type": "object", "properties": {}}
        errors = MCP.validate_args(schema, {"mystery": 1})
        self.assertTrue(any("unknown argument" in e for e in errors))

    def test_valid_args_pass(self):
        schema = {"type": "object",
                  "properties": {"run_id": {"type": "string"},
                                 "findings_json": {"type": "string"}},
                  "required": ["run_id", "findings_json"]}
        errors = MCP.validate_args(schema, {"run_id": "R1", "findings_json": "{}"})
        self.assertEqual(errors, [])

    def test_int_rejects_bool(self):
        schema = {"type": "object", "properties": {"limit": {"type": "integer"}}}
        errors = MCP.validate_args(schema, {"limit": True})
        self.assertTrue(any("expected integer" in e for e in errors))


class _MCPSession:
    """Spawns the real server and speaks JSON-RPC over stdio."""

    def __init__(self, db_path):
        self.proc = subprocess.Popen(
            [sys.executable, str(SERVER)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
            env={**os.environ, "HERMAGUARD_FEEDBACK_DB": db_path},
        )
        assert self.proc.stdin is not None and self.proc.stdout is not None

    def send(self, payload):
        assert self.proc.stdin is not None and self.proc.stdout is not None
        self.proc.stdin.write(json.dumps(payload) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            raise AssertionError(f"server died; stderr={self.proc.stderr.read()}")
        return json.loads(line)

    def close(self):
        try:
            self.send({"jsonrpc": "2.0", "id": 999, "method": "shutdown"})
        except Exception:
            pass
        if self.proc.stdin:
            self.proc.stdin.close()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


class TestE2EStdio(unittest.TestCase):
    def test_full_handshake_and_tool_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            db = os.path.join(d, "feedback.db")
            s = _MCPSession(db)
            try:
                # 1. initialize
                r = s.send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                            "params": {"protocolVersion": "2024-11-05"}})
                self.assertIn("result", r)
                self.assertEqual(r["result"]["serverInfo"]["name"], "hermaguard-feedback")

                # 2. notifications/initialized (no response expected — send, don't read)
                assert s.proc.stdin is not None
                s.proc.stdin.write(json.dumps(
                    {"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
                s.proc.stdin.flush()

                # 3. tools/list
                r = s.send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
                names = [t["name"] for t in r["result"]["tools"]]
                self.assertIn("record_findings", names)
                self.assertIn("accept_finding", names)
                self.assertIn("query_agent_precision", names)

                # 4. record_findings with a valid report
                report = {
                    "meta": {"timestamp": "2026-08-15T00:00:00Z", "repo": "demo",
                             "scope": {"files_changed": 2}},
                    "summary": {"total": 1},
                    "findings": [{
                        "id": "HG-001", "severity": "HIGH",
                        "source_agent": "adversarial-reviewer",
                        "file": "src/app.py",
                        "trigger_condition": "pickle.loads(data)",
                        "consequence": "RCE",
                        "recommendation": "use safe loader",
                        "cross_agent_agreement": ["edge-case-hunter"],
                    }],
                }
                r = s.send({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                            "params": {"name": "record_findings",
                                       "arguments": {"run_id": "HG-TEST-1",
                                                     "findings_json": json.dumps(report)}}})
                self.assertIn("result", r)
                self.assertEqual(r["result"]["content"][0]["text"],
                                 json.dumps({"status": "recorded", "run_id": "HG-TEST-1",
                                             "findings_stored": 1}))

                # 5. accept_finding — invalid action rejected by schema
                r = s.send({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                            "params": {"name": "accept_finding",
                                       "arguments": {"finding_id": "HG-001",
                                                     "action": "bogus-action"}}})
                self.assertIn("error", r)
                self.assertEqual(r["error"]["code"], -32602)
                self.assertIn("enum", r["error"]["message"])

                # 6. accept_finding — valid dismissals (3x → suppression rule)
                for i in range(3):
                    r = s.send({"jsonrpc": "2.0", "id": 10 + i, "method": "tools/call",
                                "params": {"name": "accept_finding",
                                           "arguments": {"finding_id": "HG-001",
                                                         "action": "dismissed-false-positive",
                                                         "note": f"fp #{i}"}}})
                    self.assertIn("result", r)

                # 7. get_suppression_rules — after 3 dismissals the rule exists
                r = s.send({"jsonrpc": "2.0", "id": 20, "method": "tools/call",
                            "params": {"name": "get_suppression_rules", "arguments": {}}})
                rules = json.loads(r["result"]["content"][0]["text"])
                self.assertGreaterEqual(len(rules), 1)
                self.assertIn("suppress-", rules[0]["rule_id"])

                # 8. query_agent_precision — 1 finding dismissed of 1 triaged = 0% precision.
                #    (3 dismissal EVENTS happened, but precision counts findings.)
                r = s.send({"jsonrpc": "2.0", "id": 21, "method": "tools/call",
                            "params": {"name": "query_agent_precision",
                                       "arguments": {"agent_name": "adversarial", "window_days": 30}}})
                stats = json.loads(r["result"]["content"][0]["text"])
                self.assertEqual(stats["dismissed_false_positive"], 1)
                self.assertEqual(stats["total_findings"], 1)
                self.assertEqual(stats["overall_precision_pct"], 0.0)

                # 9. get_run — full details
                r = s.send({"jsonrpc": "2.0", "id": 22, "method": "tools/call",
                            "params": {"name": "get_run",
                                       "arguments": {"run_id": "HG-TEST-1"}}})
                run = json.loads(r["result"]["content"][0]["text"])
                self.assertEqual(run["run"]["run_id"], "HG-TEST-1")
                self.assertEqual(len(run["findings"]), 1)
                self.assertEqual(len(run["acceptance_events"]), 3)

                # 10. unknown tool → -32601
                r = s.send({"jsonrpc": "2.0", "id": 30, "method": "tools/call",
                            "params": {"name": "nonexistent_tool", "arguments": {}}})
                self.assertEqual(r["error"]["code"], -32601)
            finally:
                s.close()

    def test_db_file_created_and_reused(self):
        with tempfile.TemporaryDirectory() as d:
            db = os.path.join(d, "feedback.db")
            s = _MCPSession(db)
            try:
                s.send({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
            finally:
                s.close()
            self.assertTrue(os.path.isfile(db))


if __name__ == "__main__":
    unittest.main()
