"""
Hermaguard Trajectory Audit — Test Suite

Tests the approval-gate, verification-bypass and deprecated-tool detection
against real trajectories. No mocks of the detection logic. Covers:

  1. A clean trajectory (every gated action approved, every required
     verification present and passing, no deprecated tool invoked)
     produces ZERO findings.
  2. Approval gate bypass (gated action with no approval) fires.
  3. Approval requested but never granted fires.
  4. Approval granted by a disallowed actor fires.
  5. Verification bypass (required step missing) fires.
  6. Verification present but failed fires.
  7. Deprecated tool invoked fires (via `tool` and via `action`).
  8. Missing or malformed metadata is handled safely.
  9. Configurable policy overrides the built-in default.
"""

import importlib.util
import json
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


TRAJ = _load_module("hermaguard_trajectory",
                    "tools/hermaguard-trajectory/hermaguard-trajectory.py")


def _clean_trajectory():
    """A trajectory that satisfies the built-in default policy."""
    return [
        {"step": 1, "action": "test", "actor": "agent", "status": "pass"},
        {"step": 2, "action": "review", "actor": "reviewer", "status": "pass"},
        {"step": 3, "action": "request_approval", "actor": "agent",
         "detail": "commit"},
        {"step": 4, "action": "approve", "actor": "human"},
        {"step": 5, "action": "commit", "actor": "agent"},
        {"step": 6, "action": "test", "actor": "agent", "status": "pass"},
        {"step": 7, "action": "review", "actor": "reviewer", "status": "pass"},
        {"step": 8, "action": "request_approval", "actor": "agent",
         "detail": "publish"},
        {"step": 9, "action": "approve", "actor": "human"},
        {"step": 10, "action": "publish", "actor": "agent"},
    ]


class TestCleanTrajectory(unittest.TestCase):
    def test_clean_trajectory_produces_no_findings(self):
        findings = TRAJ.audit_trajectory(_clean_trajectory())
        self.assertEqual(findings, [])

    def test_clean_trajectory_without_steps_still_clean(self):
        """Events without explicit step numbers are normalised and stay clean."""
        events = [
            {"action": "test", "actor": "agent", "status": "pass"},
            {"action": "review", "actor": "reviewer", "status": "pass"},
            {"action": "request_approval", "actor": "agent", "detail": "commit"},
            {"action": "approve", "actor": "human"},
            {"action": "commit", "actor": "agent"},
        ]
        findings = TRAJ.audit_trajectory(events)
        self.assertEqual(findings, [])


class TestApprovalGateBypass(unittest.TestCase):
    def test_commit_without_approval_fires(self):
        events = [
            {"step": 1, "action": "test", "actor": "agent", "status": "pass"},
            {"step": 2, "action": "review", "actor": "reviewer", "status": "pass"},
            {"step": 3, "action": "commit", "actor": "agent"},
        ]
        findings = TRAJ.audit_trajectory(events)
        self.assertTrue(any(f["rule_id"] == "TRAJ-APPROVAL-001" for f in findings))
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertIn("evidence", findings[0])
        self.assertIn("remediation", findings[0])

    def test_approval_requested_but_never_granted_fires(self):
        events = [
            {"step": 1, "action": "request_approval", "actor": "agent",
             "detail": "commit"},
            {"step": 2, "action": "commit", "actor": "agent"},
        ]
        findings = TRAJ.audit_trajectory(events)
        self.assertTrue(any(f["rule_id"] == "TRAJ-APPROVAL-002" for f in findings))

    def test_approval_by_disallowed_actor_fires(self):
        events = [
            {"step": 1, "action": "approve", "actor": "agent"},
            {"step": 2, "action": "commit", "actor": "agent"},
        ]
        findings = TRAJ.audit_trajectory(events)
        self.assertTrue(any(f["rule_id"] == "TRAJ-APPROVAL-003" for f in findings))

    def test_approval_after_action_does_not_count(self):
        """An approval that comes AFTER the gated action is still a bypass."""
        events = [
            {"step": 1, "action": "commit", "actor": "agent"},
            {"step": 2, "action": "approve", "actor": "human"},
        ]
        findings = TRAJ.audit_trajectory(events)
        self.assertTrue(any(f["rule_id"] == "TRAJ-APPROVAL-001" for f in findings))


class TestVerificationBypass(unittest.TestCase):
    def test_publish_without_test_fires(self):
        events = [
            {"step": 1, "action": "review", "actor": "reviewer", "status": "pass"},
            {"step": 2, "action": "publish", "actor": "agent"},
        ]
        findings = TRAJ.audit_trajectory(events)
        self.assertTrue(any(f["rule_id"] == "TRAJ-VERIFY-001" for f in findings))
        self.assertEqual(findings[0]["severity"], "HIGH")

    def test_publish_with_failed_test_fires(self):
        events = [
            {"step": 1, "action": "test", "actor": "agent", "status": "fail"},
            {"step": 2, "action": "review", "actor": "reviewer", "status": "pass"},
            {"step": 3, "action": "publish", "actor": "agent"},
        ]
        findings = TRAJ.audit_trajectory(events)
        self.assertTrue(any(f["rule_id"] == "TRAJ-VERIFY-002" for f in findings))

    def test_publish_with_all_verifications_passes(self):
        events = [
            {"step": 1, "action": "test", "actor": "agent", "status": "pass"},
            {"step": 2, "action": "review", "actor": "reviewer", "status": "pass"},
            {"step": 3, "action": "request_approval", "actor": "agent",
             "detail": "publish"},
            {"step": 4, "action": "approve", "actor": "human"},
            {"step": 5, "action": "publish", "actor": "agent"},
        ]
        findings = TRAJ.audit_trajectory(events)
        self.assertEqual(findings, [])


class TestDeprecatedTool(unittest.TestCase):
    def test_deprecated_tool_via_tool_field_fires(self):
        """A deprecated tool in the event's `tool` field fires."""
        policy = {
            "approval_gates": [],
            "verification_steps": [],
            "deprecated_tools": [
                {"tool": "legacy_commit", "replacement": "commit",
                 "reason": "superseded"},
            ],
        }
        events = [
            {"step": 1, "action": "run", "actor": "agent",
             "tool": "legacy_commit"},
        ]
        findings = TRAJ.audit_trajectory(events, policy)
        self.assertTrue(any(f["rule_id"] == "TRAJ-DEPRECATED-001"
                            for f in findings))
        f = next(f for f in findings
                 if f["rule_id"] == "TRAJ-DEPRECATED-001")
        self.assertEqual(f["severity"], "MEDIUM")
        self.assertIn("legacy_commit", f["evidence"])
        self.assertIn("commit", f["remediation"])
        self.assertIn("superseded", f["remediation"])

    def test_deprecated_tool_via_action_field_fires(self):
        """A deprecated tool whose name is the event's `action` fires."""
        policy = {
            "approval_gates": [],
            "verification_steps": [],
            "deprecated_tools": [
                {"tool": "legacy_commit", "replacement": "commit",
                 "reason": "superseded"},
            ],
        }
        events = [
            {"step": 1, "action": "legacy_commit", "actor": "agent"},
        ]
        findings = TRAJ.audit_trajectory(events, policy)
        self.assertTrue(any(f["rule_id"] == "TRAJ-DEPRECATED-001"
                            for f in findings))

    def test_clean_trajectory_no_deprecated_findings(self):
        """A trajectory with no deprecated tool produces no deprecated finding."""
        findings = TRAJ.audit_trajectory(_clean_trajectory())
        self.assertFalse(any(f["rule_id"] == "TRAJ-DEPRECATED-001"
                             for f in findings))

    def test_malformed_registry_handled_safely(self):
        """Non-list registry, non-dict entries and missing tool names are skipped."""
        policy = {
            "approval_gates": [],
            "verification_steps": [],
            "deprecated_tools": "not-a-list",
        }
        events = [{"step": 1, "action": "legacy_commit", "actor": "agent"}]
        self.assertEqual(TRAJ.audit_trajectory(events, policy), [])

        policy["deprecated_tools"] = ["not-a-dict", {"replacement": "x"},
                                      {"tool": "legacy_commit",
                                       "replacement": "commit"}]
        findings = TRAJ.audit_trajectory(events, policy)
        self.assertTrue(any(f["rule_id"] == "TRAJ-DEPRECATED-001"
                            for f in findings))

    def test_non_dict_event_handled_safely(self):
        """A non-dict event in the trajectory does not crash the audit."""
        policy = {
            "approval_gates": [],
            "verification_steps": [],
            "deprecated_tools": [
                {"tool": "legacy_commit", "replacement": "commit"},
            ],
        }
        events = ["not-a-dict", {"step": 1, "action": "legacy_commit",
                                 "actor": "agent"}]
        findings = TRAJ.audit_trajectory(events, policy)
        self.assertTrue(any(f["rule_id"] == "TRAJ-DEPRECATED-001"
                            for f in findings))


class TestConfigurablePolicy(unittest.TestCase):
    def test_custom_policy_overrides_default(self):
        """A custom policy with no gates produces no approval findings."""
        policy = {"approval_gates": [], "verification_steps": []}
        events = [
            {"step": 1, "action": "commit", "actor": "agent"},
            {"step": 2, "action": "publish", "actor": "agent"},
        ]
        findings = TRAJ.audit_trajectory(events, policy)
        self.assertEqual(findings, [])

    def test_custom_policy_adds_new_gate(self):
        """A custom gate on a new action is enforced."""
        policy = {
            "approval_gates": [
                {"action": "deploy", "requires": "approve",
                 "approvers": ["human"]},
            ],
            "verification_steps": [],
        }
        events = [
            {"step": 1, "action": "deploy", "actor": "agent"},
        ]
        findings = TRAJ.audit_trajectory(events, policy)
        self.assertTrue(any(f["rule_id"] == "TRAJ-APPROVAL-001" for f in findings))

    def test_custom_approvers_restrict_who_can_approve(self):
        policy = {
            "approval_gates": [
                {"action": "commit", "requires": "approve",
                 "approvers": ["human"]},
            ],
            "verification_steps": [],
        }
        events = [
            {"step": 1, "action": "approve", "actor": "reviewer"},
            {"step": 2, "action": "commit", "actor": "agent"},
        ]
        findings = TRAJ.audit_trajectory(events, policy)
        self.assertTrue(any(f["rule_id"] == "TRAJ-APPROVAL-003" for f in findings))


class TestCLI(unittest.TestCase):
    def test_cli_clean_trajectory(self):
        """CLI on a clean trajectory exits 0 with zero findings."""
        with tempfile.TemporaryDirectory() as d:
            traj = Path(d) / "traj.json"
            traj.write_text(json.dumps(_clean_trajectory()))
            out = Path(d) / "out.json"
            rc = TRAJ.main(["--trajectory", str(traj), "--json", str(out)])
            self.assertEqual(rc, 0)
            data = json.loads(out.read_text())
            self.assertEqual(data["stats"]["findings"], 0)

    def test_cli_flagged_trajectory(self):
        """CLI on a bypass trajectory reports the finding."""
        with tempfile.TemporaryDirectory() as d:
            traj = Path(d) / "traj.json"
            traj.write_text(json.dumps([
                {"step": 1, "action": "commit", "actor": "agent"},
            ]))
            out = Path(d) / "out.json"
            rc = TRAJ.main(["--trajectory", str(traj), "--json", str(out)])
            self.assertEqual(rc, 0)
            data = json.loads(out.read_text())
            self.assertGreaterEqual(data["stats"]["findings"], 1)
            self.assertTrue(any(
                f["rule_id"] == "TRAJ-APPROVAL-001" for f in data["findings"]))

    def test_cli_inline_trajectory(self):
        """Inline JSON array is accepted."""
        rc = TRAJ.main(["--trajectory",
                        '[{"step":1,"action":"commit","actor":"agent"}]'])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
