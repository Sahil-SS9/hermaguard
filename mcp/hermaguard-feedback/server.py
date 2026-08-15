#!/usr/bin/env python3
"""
hermaguard-feedback — MCP server for tracking HermaGuard findings and precision.
Stores runs and findings in SQLite. Provides tools for recording, accepting,
querying agent precision, and generating suppression rules.

MCP tools:
  - record_findings(run_id, findings_json): store a completed run's findings
  - accept_finding(finding_id, action, note): mark a finding as fixed/dismissed/accepted
  - query_agent_precision(agent_name, window_days): get precision stats
  - get_suppression_rules(): return patterns that have been repeatedly dismissed
  - get_run_history(limit): recent run summaries
  - get_run(run_id): full details for one run

Requirements: Python 3.10+, no pip deps (stdlib only).
Run: python3 hermaguard-feedback.py
"""

import json
import os
import sqlite3
import sys
import uuid
import time
from datetime import datetime, timezone, timedelta

VERSION = "1.0.0"
DB_PATH = os.environ.get("HERMAGUARD_FEEDBACK_DB", os.path.expanduser("~/.hermes/data/hermaguard-feedback.db"))


def get_db():
    """Get a connection to the feedback database, creating tables if needed."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS runs (
            run_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            repo TEXT,
            diff_hash TEXT,
            files_changed INTEGER DEFAULT 0,
            files_blast_radius INTEGER DEFAULT 0,
            total_findings INTEGER DEFAULT 0,
            agent_1_findings INTEGER DEFAULT 0,
            agent_2_findings INTEGER DEFAULT 0,
            agent_3_findings INTEGER DEFAULT 0,
            prescan_findings INTEGER DEFAULT 0,
            overall_risk TEXT,
            report_path TEXT
        );

        CREATE TABLE IF NOT EXISTS findings (
            finding_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL REFERENCES runs(run_id),
            severity TEXT NOT NULL,
            source_agent TEXT NOT NULL,
            cross_agent_agreement TEXT,  -- comma-separated agent names
            file_path TEXT,
            line_range TEXT,
            trigger_condition TEXT,
            consequence TEXT,
            recommendation TEXT,
            source_prescan INTEGER DEFAULT 0,
            prescan_tool TEXT,
            prescan_rule TEXT,
            status TEXT DEFAULT 'open',
            status_updated_at TEXT,
            status_note TEXT
        );

        CREATE TABLE IF NOT EXISTS acceptance_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id TEXT NOT NULL REFERENCES findings(finding_id),
            action TEXT NOT NULL,  -- fixed | dismissed-false-positive | dismissed-not-relevant | accepted-deferred
            note TEXT,
            timestamp TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS suppression_rules_cache (
            rule_id TEXT PRIMARY KEY,
            pattern TEXT NOT NULL,
            reason TEXT,
            created_at TEXT,
            dismissals INTEGER DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
        CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
        CREATE INDEX IF NOT EXISTS idx_findings_agent ON findings(source_agent);
        CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
        CREATE INDEX IF NOT EXISTS idx_runs_timestamp ON runs(timestamp);
        CREATE INDEX IF NOT EXISTS idx_acceptance_finding ON acceptance_events(finding_id);
    """)
    conn.commit()
    return conn


# ── MCP Protocol (stdio JSON-RPC) ───────────────────────────────────────────

def _read_message() -> dict:
    """Read a JSON-RPC message from stdin."""
    line = sys.stdin.readline()
    if not line:
        raise EOFError("stdin closed")
    return json.loads(line)


def _write_response(msg: dict):
    """Write a JSON-RPC response to stdout."""
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def _error(request_id, code, message):
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _result(request_id, result):
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


# ── Argument schema validation (draft-04 subset, stdlib only) ──────────────

def _validate_value(value, schema, path: str) -> list:
    """Validate one value against one schema node. Returns error strings."""
    errors = []
    t = schema.get("type", "any")
    if t == "string":
        if not isinstance(value, str):
            errors.append(f"{path}: expected string, got {type(value).__name__}")
        elif "enum" in schema and value not in schema["enum"]:
            errors.append(f"{path}: value {value!r} not in enum {schema['enum']}")
    elif t == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            errors.append(f"{path}: expected integer, got {type(value).__name__}")
    elif t == "number":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            errors.append(f"{path}: expected number, got {type(value).__name__}")
    elif t == "boolean":
        if not isinstance(value, bool):
            errors.append(f"{path}: expected boolean, got {type(value).__name__}")
    elif t == "array":
        if not isinstance(value, list):
            errors.append(f"{path}: expected array, got {type(value).__name__}")
    elif t == "object":
        if not isinstance(value, dict):
            errors.append(f"{path}: expected object, got {type(value).__name__}")
        else:
            props = schema.get("properties", {})
            for k, ps in props.items():
                if k in value:
                    errors.extend(_validate_value(value[k], ps, f"{path}.{k}"))
    return errors


def validate_args(schema: dict, args: dict) -> list:
    """Validate tool call arguments against an inputSchema.
    Returns a list of error strings (empty = valid)."""
    errors = []
    for req in schema.get("required", []):
        if req not in args:
            errors.append(f"missing required argument: {req}")
    props = schema.get("properties", {})
    for k, v in args.items():
        if k not in props:
            errors.append(f"unknown argument: {k}")
        else:
            errors.extend(_validate_value(v, props[k], k))
    return errors


# ── Tool implementations ────────────────────────────────────────────────────

def tool_list_tools(conn):
    return [
        {
            "name": "record_findings",
            "description": "Record completed HermaGuard run findings. Accepts the JSON report output and stores all findings with metadata.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "run_id": {"type": "string", "description": "Unique run ID (e.g., HG-20260615-001)"},
                    "findings_json": {"type": "string", "description": "Full JSON report from HermaGuard (the .json output)"},
                },
                "required": ["run_id", "findings_json"],
            },
        },
        {
            "name": "accept_finding",
            "description": "Accept, dismiss, or defer a specific finding. Records the feedback for precision tracking.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "finding_id": {"type": "string", "description": "Finding ID (e.g., HG-001)"},
                    "action": {"type": "string", "enum": ["fixed", "dismissed-false-positive", "dismissed-not-relevant", "accepted-deferred"]},
                    "note": {"type": "string", "description": "Optional note explaining the action"},
                },
                "required": ["finding_id", "action"],
            },
        },
        {
            "name": "query_agent_precision",
            "description": "Get precision stats for a specific agent over a time window.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_name": {"type": "string", "description": "Source agent (edge-case-hunter | adversarial-reviewer | blast-radius-integration | prescan)"},
                    "window_days": {"type": "integer", "default": 30, "description": "Days to look back"},
                },
                "required": ["agent_name"],
            },
        },
        {
            "name": "get_suppression_rules",
            "description": "Get patterns that have been repeatedly dismissed as false positives. Agents should skip these.",
            "inputSchema": {
                "type": "object",
                "properties": {},
            },
        },
        {
            "name": "get_run_history",
            "description": "Get recent run summaries with aggregate stats.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "default": 20, "description": "Max runs to return"},
                },
            },
        },
        {
            "name": "get_run",
            "description": "Get full details for a single run including all findings.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "run_id": {"type": "string", "description": "Run ID to retrieve"},
                },
                "required": ["run_id"],
            },
        },
    ]


def tool_record_findings(conn, args):
    run_id = args["run_id"]
    findings_json_str = args["findings_json"]

    try:
        data = json.loads(findings_json_str)
    except json.JSONDecodeError as e:
        return {"error": f"Invalid JSON: {e}"}

    meta = data.get("meta", {})
    summary = data.get("summary", {})
    findings_list = data.get("findings", [])
    blast = data.get("blast_radius", {})
    verdict = data.get("verdict", {})

    # Count per agent
    a1 = a2 = a3 = 0
    for f in findings_list:
        agent = f.get("source_agent", "")
        if "adversarial-reviewer" in agent:
            a2 += 1
        elif "blast-radius" in agent:
            a3 += 1
        else:
            a1 += 1

    now = datetime.now(timezone.utc).isoformat()

    conn.execute(
        """INSERT OR REPLACE INTO runs
           (run_id, timestamp, repo, diff_hash, files_changed, files_blast_radius,
            total_findings, agent_1_findings, agent_2_findings, agent_3_findings,
            prescan_findings, overall_risk, report_path)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            run_id, meta.get("timestamp", now), meta.get("repo", ""),
            meta.get("diff_ref", ""),
            meta.get("scope", {}).get("files_changed", 0),
            meta.get("scope", {}).get("files_in_blast_radius", 0),
            summary.get("total", len(findings_list)),
            a1, a2, a3,
            meta.get("prescan", {}).get("total_findings", 0),
            verdict.get("overall_risk", "UNKNOWN"),
            meta.get("report_path", ""),
        ),
    )

    for f in findings_list:
        fid = f.get("id", str(uuid.uuid4())[:8])
        cross = ",".join(f.get("cross_agent_agreement", [])) if f.get("cross_agent_agreement") else ""
        conn.execute(
            """INSERT OR REPLACE INTO findings
               (finding_id, run_id, severity, source_agent, cross_agent_agreement,
                file_path, line_range, trigger_condition, consequence, recommendation,
                source_prescan, prescan_tool, prescan_rule, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')""",
            (
                fid, run_id,
                f.get("severity", "UNKNOWN"),
                f.get("source_agent", "unknown"),
                cross,
                f.get("file", ""),
                f.get("line_range", ""),
                f.get("trigger_condition", ""),
                f.get("consequence", ""),
                f.get("recommendation", ""),
                1 if f.get("source_prescan") else 0,
                f.get("prescan_tool", ""),
                f.get("prescan_rule", ""),
            ),
        )

    conn.commit()
    return {"status": "recorded", "run_id": run_id, "findings_stored": len(findings_list)}


def tool_accept_finding(conn, args):
    fid = args["finding_id"]
    action = args["action"]
    note = args.get("note", "")

    now = datetime.now(timezone.utc).isoformat()

    # Update finding status
    cursor = conn.execute("UPDATE findings SET status = ?, status_updated_at = ?, status_note = ? WHERE finding_id = ?",
                          (action, now, note, fid))
    if cursor.rowcount == 0:
        return {"error": f"Finding {fid} not found"}

    # Record acceptance event
    conn.execute(
        "INSERT INTO acceptance_events (finding_id, action, note, timestamp) VALUES (?, ?, ?, ?)",
        (fid, action, note, now),
    )

    # If dismissed as false positive, check if pattern should become a suppression rule
    if action == "dismissed-false-positive":
        row = conn.execute("SELECT file_path, trigger_condition, source_agent FROM findings WHERE finding_id = ?", (fid,)).fetchone()
        if row:
            # Count how many times this pattern was dismissed — from the
            # acceptance EVENTS table, not the findings table: a single
            # finding row is updated in place, so counting rows would
            # never reach the threshold for repeated dismissals.
            pattern = f"{row['source_agent']}:{row['trigger_condition'][:80]}"
            count = conn.execute(
                "SELECT COUNT(*) FROM acceptance_events "
                "WHERE finding_id IN ("
                "  SELECT finding_id FROM findings WHERE source_agent = ? AND trigger_condition = ?"
                ") AND action = 'dismissed-false-positive'",
                (row["source_agent"], row["trigger_condition"]),
            ).fetchone()[0]

            if count >= 3:
                rule_id = f"suppress-{fid}"
                conn.execute(
                    """INSERT OR REPLACE INTO suppression_rules_cache
                       (rule_id, pattern, reason, created_at, dismissals)
                       VALUES (?, ?, ?, ?, ?)""",
                    (rule_id, pattern, f"Dismissed {count}x as false positive", now, count),
                )

    conn.commit()
    return {"status": "recorded", "finding_id": fid, "action": action}


def tool_query_agent_precision(conn, args):
    agent = args["agent_name"]
    window = args.get("window_days", 30)

    cutoff = (datetime.now(timezone.utc) - timedelta(days=window)).isoformat()

    # Match agent names flexibly
    agent_where = "source_agent LIKE ?"
    agent_param = f"%{agent}%"

    # Denominator: triaged findings only (fixed + accepted + dismissed-false-positive).
    # Open findings are excluded — they haven't been evaluated yet.
    triaged_statuses = "('fixed', 'accepted-deferred', 'dismissed-false-positive')"

    total = conn.execute(
        f"SELECT COUNT(*) FROM findings WHERE {agent_where} AND status IN {triaged_statuses}",
        (agent_param,),
    ).fetchone()[0] or 0

    open_untriaged = conn.execute(
        f"SELECT COUNT(*) FROM findings WHERE {agent_where} AND status = 'open'",
        (agent_param,),
    ).fetchone()[0] or 0

    fixed_or_accepted = conn.execute(
        f"SELECT COUNT(*) FROM findings WHERE {agent_where} AND status IN ('fixed', 'accepted-deferred')",
        (agent_param,),
    ).fetchone()[0] or 0

    dismissed_fp = conn.execute(
        f"SELECT COUNT(*) FROM findings WHERE {agent_where} AND status = 'dismissed-false-positive'",
        (agent_param,),
    ).fetchone()[0] or 0

    by_severity = {}
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        sev_total = conn.execute(
            f"SELECT COUNT(*) FROM findings WHERE {agent_where} AND severity = ? AND status IN {triaged_statuses}",
            (agent_param, sev),
        ).fetchone()[0] or 0
        sev_correct = conn.execute(
            f"SELECT COUNT(*) FROM findings WHERE {agent_where} AND severity = ? AND status IN ('fixed', 'accepted-deferred')",
            (agent_param, sev),
        ).fetchone()[0] or 0
        by_severity[sev] = {
            "total": sev_total,
            "correct": sev_correct,
            "precision": round(sev_correct / sev_total * 100, 1) if sev_total > 0 else None,
        }

    precision = round(((fixed_or_accepted) / total * 100), 1) if total > 0 else None

    return {
        "agent": agent,
        "window_days": window,
        "total_findings": total,
        "open_untriaged": open_untriaged,
        "fixed_or_accepted": fixed_or_accepted,
        "dismissed_false_positive": dismissed_fp,
        "overall_precision_pct": precision,
        "by_severity": by_severity,
    }


def tool_get_suppression_rules(conn, args=None):
    rows = conn.execute(
        "SELECT rule_id, pattern, reason, dismissals FROM suppression_rules_cache ORDER BY dismissals DESC"
    ).fetchall()
    return [
        {"rule_id": r["rule_id"], "pattern": r["pattern"], "reason": r["reason"], "dismissals": r["dismissals"]}
        for r in rows
    ]


def tool_get_run_history(conn, args):
    limit = args.get("limit", 20)
    rows = conn.execute(
        "SELECT run_id, timestamp, repo, files_changed, total_findings, overall_risk, report_path FROM runs ORDER BY timestamp DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def tool_get_run(conn, args):
    run_id = args["run_id"]
    run = conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    if not run:
        return {"error": f"Run {run_id} not found"}
    findings = conn.execute("SELECT * FROM findings WHERE run_id = ?", (run_id,)).fetchall()
    events = conn.execute(
        "SELECT * FROM acceptance_events WHERE finding_id IN (SELECT finding_id FROM findings WHERE run_id = ?)",
        (run_id,),
    ).fetchall()
    return {
        "run": dict(run),
        "findings": [dict(f) for f in findings],
        "acceptance_events": [dict(e) for e in events],
    }


TOOL_DISPATCH = {
    "record_findings": tool_record_findings,
    "accept_finding": tool_accept_finding,
    "query_agent_precision": tool_query_agent_precision,
    "get_suppression_rules": tool_get_suppression_rules,
    "get_run_history": tool_get_run_history,
    "get_run": tool_get_run,
}


# ── Server loop ─────────────────────────────────────────────────────────────

def main():
    conn = get_db()

    # MCP handshake: handle initialize request
    while True:
        line = sys.stdin.readline()
        if not line:
            break  # EOF — stdin closed
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue

        req_id = msg.get("id")
        method = msg.get("method", "")

        if method == "initialize":
            _write_response(_result(req_id, {
                "protocolVersion": "2024-11-05",
                "serverInfo": {"name": "hermaguard-feedback", "version": VERSION},
                "capabilities": {"tools": {}},
            }))

        elif method == "notifications/initialized":
            pass  # ack, no response needed

        elif method == "tools/list":
            _write_response(_result(req_id, {"tools": tool_list_tools(conn)}))

        elif method == "tools/call":
            tool_name = msg.get("params", {}).get("name", "")
            tool_args = msg.get("params", {}).get("arguments", {})

            if tool_name not in TOOL_DISPATCH:
                _write_response(_error(req_id, -32601, f"Unknown tool: {tool_name}"))
                continue

            # Schema validation before dispatch — invalid params are
            # rejected with -32602 instead of surfacing as handler crashes.
            schema = next((t["inputSchema"] for t in tool_list_tools(conn)
                           if t["name"] == tool_name), {})
            validation_errors = validate_args(schema, tool_args)
            if validation_errors:
                _write_response(_error(req_id, -32602,
                                       "Invalid params: " + "; ".join(validation_errors)))
                continue

            try:
                handler = TOOL_DISPATCH[tool_name]
                result = handler(conn, tool_args)
                # Only dict results carry an "error" key; list results (e.g.
                # get_suppression_rules) must not be probed with `in`.
                if isinstance(result, dict) and "error" in result:
                    _write_response(_error(req_id, -32000, result["error"]))
                else:
                    _write_response(_result(req_id, {
                        "content": [{"type": "text", "text": json.dumps(result)}]
                    }))
            except Exception as e:
                _write_response(_error(req_id, -32000, str(e)))

        elif method == "shutdown":
            conn.close()
            _write_response(_result(req_id, {}))
            sys.stdout.flush()
            sys.exit(0)

        else:
            _write_response(_error(req_id, -32601, f"Method not found: {method}"))


if __name__ == "__main__":
    main()
