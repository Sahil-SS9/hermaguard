#!/usr/bin/env python3
"""
Hermaguard Trajectory Auditor — approval-gate, verification-bypass and
deprecated-tool checks.

Audits a skill-creation (or any agent) trajectory for misevolution: an
action that required an approval gate was executed without one, an output
was produced without a required verification step, or a deprecated tool
was invoked. This is the deterministic Phase-1/2 check for the
skill-safety-audit pipeline: before a skill is committed, scan the
trajectory for these bypass and hygiene classes.

Design (deterministic, stdlib-only, zero external deps):
  - Trajectory: an ordered list of events. Each event is a dict with at
    least {"step": int, "action": str, "actor": str}; optional "status"
    (e.g. "pass"/"fail"), "detail" and "tool".
  - Policy: configurable JSON describing the expected trajectory events.
      approval_gates:   [{"action": "commit", "requires": "approve",
                          "approvers": ["human", "reviewer"]}, ...]
      verification_steps: [{"action": "publish",
                            "requires": ["test", "review"]}, ...]
      deprecated_tools: [{"tool": "old_tool", "replacement": "new_tool",
                           "reason": "superseded in v2"}, ...]
    A built-in default policy is used when none is supplied.
  - Emits findings in the SAME schema the prescan normalizes to, so the
    rest of the pipeline (dedup, suppression, report) treats them as
    first-class findings: tool = "hermaguard-trajectory". Each finding
    carries rule_id, severity, evidence (the offending event(s)) and
    remediation (how to fix), per the audit contract.

Rules:
  TRAJ-APPROVAL-001    approval gate bypass — gated action with no approval
  TRAJ-APPROVAL-002    approval requested but never granted
  TRAJ-APPROVAL-003    approval granted by a disallowed actor
  TRAJ-VERIFY-001      verification bypass — required step missing
  TRAJ-VERIFY-002      verification present but failed
  TRAJ-DEPRECATED-001  deprecated tool invoked — replacement available

A clean trajectory (every gated action preceded by a granted approval,
every required verification present and passing, and no deprecated tool
invoked) produces zero findings.

Missing or malformed metadata is handled safely: a non-dict event, a
non-list deprecated_tools registry, or a registry entry without a "tool"
name is skipped rather than raising.

Usage:
    hermaguard-trajectory --trajectory traj.json [--policy policy.json] [--json out.json]
    hermaguard-trajectory --trajectory '[{"step":1,"action":"commit","actor":"agent"}]'
"""

import argparse
import json
import sys
from pathlib import Path

VERSION = "1.0.0"
TOOL_NAME = "hermaguard-trajectory"

# Built-in default policy for skill-creation trajectories. Overridable via
# --policy. "approvers" is the set of actors allowed to grant approval;
# "requires" is the ordered list of verification actions that must precede
# the gated action.
DEFAULT_POLICY = {
    "approval_gates": [
        {"action": "commit", "requires": "approve",
         "approvers": ["human", "reviewer"]},
        {"action": "publish", "requires": "approve",
         "approvers": ["human"]},
    ],
    "verification_steps": [
        {"action": "publish", "requires": ["test", "review"]},
    ],
    "deprecated_tools": [
        {"tool": "legacy_commit", "replacement": "commit",
         "reason": "superseded by the gated commit action"},
    ],
}

# rule_id -> (severity, category, message template, remediation)
RULE_META = {
    "TRAJ-APPROVAL-001": {
        "severity": "HIGH",
        "category": "security",
        "message": "approval gate bypass: action '{action}' executed without a granted approval",
        "remediation": "Obtain approval from an allowed approver ({approvers}) before '{action}'.",
    },
    "TRAJ-APPROVAL-002": {
        "severity": "MEDIUM",
        "category": "security",
        "message": "approval requested but never granted before '{action}'",
        "remediation": "Ensure the approval request for '{action}' is granted by an allowed approver before proceeding.",
    },
    "TRAJ-APPROVAL-003": {
        "severity": "HIGH",
        "category": "security",
        "message": "approval for '{action}' granted by disallowed actor '{actor}'",
        "remediation": "Approval must come from an allowed approver ({approvers}), not '{actor}'.",
    },
    "TRAJ-VERIFY-001": {
        "severity": "HIGH",
        "category": "correctness",
        "message": "verification bypass: '{action}' produced output without required step '{required}'",
        "remediation": "Run '{required}' and confirm it passes before '{action}'.",
    },
    "TRAJ-VERIFY-002": {
        "severity": "HIGH",
        "category": "correctness",
        "message": "verification for '{action}' present but failed ('{required}')",
        "remediation": "Re-run '{required}' until it passes before '{action}'.",
    },
    "TRAJ-DEPRECATED-001": {
        "severity": "MEDIUM",
        "category": "hygiene",
        "message": "deprecated tool '{tool}' invoked at step {step}",
        "remediation": "Replace '{tool}' with '{replacement}' ({reason}).",
    },
}


def _load_json(path_or_inline):
    """Load JSON from a file path or an inline JSON string."""
    s = path_or_inline.strip()
    if s.startswith("[") or s.startswith("{"):
        return json.loads(s)
    return json.loads(Path(path_or_inline).read_text())


def _events_before(events, step):
    """Return events strictly before the given step."""
    return [e for e in events
            if isinstance(e, dict) and e.get("step", 0) < step]


def _approval_for_gate(events, gate, step, gates):
    """Return the approval event for this gate before `step`, or None.

    Scoped to a single gated action so one approval cannot bleed across
    independent gates (a `commit` approval must not silently satisfy a
    `publish` gate). An approve event is matched for this gate when:
      1. It carries a ``detail`` that references this gate's action name
         (case-insensitive substring, the same convention `_has_request`
         uses); or
      2. It is a bare approve (no detail) that is the most recent one before
         `step` AND no later gated action intervenes between it and `step`
         (so a commit approval does not outlive the commit to authorize a
         later publish).
    Returns the matched event dict, or None.
    """
    gated = str(gate.get("action", "")).lower()
    candidate = None
    for e in _events_before(events, step):
        if e.get("action") != "approve":
            continue
        detail = str(e.get("detail", "")).lower().strip()
        if detail:
            if gated and gated in detail:
                return e
            continue  # approval for a different, explicitly-named action
        # Bare approve: it authorizes this gate only if this gate's action
        # is the next gated action after the approval.
        _blocked = False
        for f in events:
            if not isinstance(f, dict) or f.get("step", 0) <= e.get("step", 0):
                continue
            fstep = f.get("step", 0)
            if fstep >= step:
                break
            if f.get("action") in (g.get("action") for g in gates):
                if f.get("action") == gate.get("action"):
                    break
                _blocked = True
                break
        if not _blocked:
            candidate = e
    return candidate


def _has_request(events, gate, step):
    """Return True if an approval request scoped to this gate precedes step.

    A request only counts for the gate whose action it references by name
    (case-insensitive substring). A bare ``request_approval`` scopes to the
    next gated action that follows it, so it cannot spuriously downgrade an
    unrelated later gate.
    """
    gated = str(gate.get("action", "")).lower()
    for e in _events_before(events, step):
        if e.get("action") != "request_approval":
            continue
        detail = str(e.get("detail", "")).lower().strip()
        if detail:
            if gated and gated in detail:
                return True
        else:
            # Bare request scopes to the next gated action after it.
            for f in events:
                if not isinstance(f, dict) or f.get("step", 0) <= e.get("step", 0):
                    continue
                if f.get("action") == gate.get("action"):
                    return True
    return False


def _verification_event(events, action, step):
    """Return the most recent verification event for `action` before `step`."""
    found = None
    for e in _events_before(events, step):
        if e.get("action") == action:
            found = e
    return found


def _deprecated_tool_findings(events, registry):
    """Return TRAJ-DEPRECATED-001 findings for deprecated tool invocations.

    A deprecated tool is matched against an event's ``tool`` field (the
    tool actually invoked) and, as a fallback, its ``action`` field (an
    action that IS a tool invocation). Malformed registry entries (non-dict,
    or missing a "tool" name) and non-dict events are skipped safely.
    """
    findings = []
    if not isinstance(registry, list):
        return findings
    for entry in registry:
        if not isinstance(entry, dict):
            continue
        deprecated = entry.get("tool")
        if not isinstance(deprecated, str) or not deprecated:
            continue
        replacement = entry.get("replacement", "")
        reason = entry.get("reason", "deprecated")
        for e in events:
            if not isinstance(e, dict):
                continue
            invoked = e.get("tool") or e.get("action")
            if invoked != deprecated:
                continue
            step = e.get("step", 0)
            findings.append({
                "tool": TOOL_NAME,
                "rule_id": "TRAJ-DEPRECATED-001",
                "severity": RULE_META["TRAJ-DEPRECATED-001"]["severity"],
                "file": "trajectory",
                "line": step,
                "message": RULE_META["TRAJ-DEPRECATED-001"]["message"].format(
                    tool=deprecated, step=step),
                "category": RULE_META["TRAJ-DEPRECATED-001"]["category"],
                "class_id": "TRAJ-DEPRECATED-001",
                "evidence": f"deprecated tool '{deprecated}' invoked at step {step}",
                "remediation": RULE_META["TRAJ-DEPRECATED-001"]["remediation"].format(
                    tool=deprecated, replacement=replacement, reason=reason),
            })
    return findings


def audit_trajectory(events, policy=None):
    """Audit a trajectory against a policy. Returns a list of findings.

    Each finding: {tool, rule_id, severity, file, line, message, category,
    class_id, evidence, remediation}. `line` is the step of the offending
    event; `file` is the trajectory source label.
    """
    policy = policy or DEFAULT_POLICY
    findings = []
    gates = policy.get("approval_gates", [])
    verifications = policy.get("verification_steps", [])
    deprecated = policy.get("deprecated_tools", [])

    # Normalise events: ensure each dict event has a step. Non-dict events
    # are skipped safely (they cannot carry tool/action metadata).
    for i, e in enumerate(events):
        if isinstance(e, dict) and "step" not in e:
            e["step"] = i + 1

    # ---- approval gate checks ----
    for gate in gates:
        gated_action = gate.get("action")
        approvers = gate.get("approvers", [])
        for e in events:
            if not isinstance(e, dict) or e.get("action") != gated_action:
                continue
            step = e.get("step", 0)
            approver = _approval_for_gate(events, gate, step, gates)
            if approver is None:
                if _has_request(events, gate, step):
                    findings.append(_mk(
                        "TRAJ-APPROVAL-002", e, gate,
                        evidence=f"request_approval before step {step} for '{gated_action}' but no approval granted"))
                else:
                    findings.append(_mk(
                        "TRAJ-APPROVAL-001", e, gate,
                        evidence=f"action '{gated_action}' at step {step} with no approval event"))
            elif approver.get("actor") not in approvers:
                findings.append(_mk(
                    "TRAJ-APPROVAL-003", e, gate,
                    evidence=f"approval at step {approver.get('step')} by '{approver.get('actor')}' not in {approvers}", approver_actor=approver.get("actor")))

    # ---- verification step checks ----
    for vs in verifications:
        gated_action = vs.get("action")
        required = vs.get("requires", [])
        for e in events:
            if not isinstance(e, dict) or e.get("action") != gated_action:
                continue
            step = e.get("step", 0)
            for req in required:
                ve = _verification_event(events, req, step)
                if ve is None:
                    findings.append(_mk(
                        "TRAJ-VERIFY-001", e, vs,
                        evidence=f"'{gated_action}' at step {step} without required '{req}'",
                        required=req))
                elif str(ve.get("status", "")).lower() in ("fail", "failed", "error"):
                    findings.append(_mk(
                        "TRAJ-VERIFY-002", e, vs,
                        evidence=f"'{req}' at step {ve.get('step')} status='{ve.get('status')}' before '{gated_action}' at step {step}",
                        required=req))

    # ---- deprecated tool checks ----
    findings.extend(_deprecated_tool_findings(events, deprecated))

    return findings


def _mk(rule_id, event, gate, evidence, required=None, approver_actor=None):
    meta = RULE_META[rule_id]
    # For approval-actor findings (TRAJ-APPROVAL-003) the offending actor is
    # the approver, not the actor who executed the action.
    actor = event.get("actor", "?")
    if rule_id == "TRAJ-APPROVAL-003" and approver_actor:
        actor = approver_actor
    return {
        "tool": TOOL_NAME,
        "rule_id": rule_id,
        "severity": meta["severity"],
        "file": "trajectory",
        "line": event.get("step", 0),
        "message": meta["message"].format(
            action=gate.get("action", "?"),
            approvers=gate.get("approvers", []),
            actor=actor,
            required=required or gate.get("requires", "?")),
        "category": meta["category"],
        "class_id": rule_id,
        "evidence": evidence,
        "remediation": meta["remediation"].format(
            action=gate.get("action", "?"),
            approvers=gate.get("approvers", []),
            actor=actor,
            required=required or gate.get("requires", "?")),
    }


def main(argv=None):
    p = argparse.ArgumentParser(description="Hermaguard trajectory audit — approval/verification bypass checks")
    p.add_argument("--trajectory", required=True,
                   help="Path to trajectory JSON, or inline JSON array of events")
    p.add_argument("--policy", help="Path to policy JSON (defaults to built-in skill-creation policy)")
    p.add_argument("--json", dest="json_out", help="Write findings JSON to path")
    p.add_argument("--version", action="version", version=f"hermaguard-trajectory {VERSION}")
    args = p.parse_args(argv)

    try:
        events = _load_json(args.trajectory)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"hermaguard-trajectory: cannot read trajectory: {exc}", file=sys.stderr)
        return 1

    if not isinstance(events, list):
        print("hermaguard-trajectory: trajectory must be a JSON array of events", file=sys.stderr)
        return 1

    policy = None
    if args.policy:
        try:
            policy = _load_json(args.policy)
        except (json.JSONDecodeError, OSError) as exc:
            print(f"hermaguard-trajectory: cannot read policy: {exc}", file=sys.stderr)
            return 1

    findings = audit_trajectory(events, policy)

    out = {"tool": TOOL_NAME, "version": VERSION, "findings": findings,
           "stats": {"events": len(events), "findings": len(findings)}}
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(out, indent=2))
    print(f"trajectory: {len(findings)} findings from {len(events)} events")
    for f in findings:
        print(f"  [{f['rule_id']}] {f['severity']} step {f['line']} {f['message']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
