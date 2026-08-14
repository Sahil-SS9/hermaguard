# Hermaguard — Schemas and Config Reference

Full schemas and project config for the `hermaguard` skill. The skill body
keeps the behavioural instructions; the verbose data shapes live here so the
loaded skill stays lean.

## Pre-scan output schema

`hermaguard-prescan` writes this JSON (consumed as Agent 1/2 context):

```json
{
  "findings": [
    {
      "tool": "bandit",
      "rule_id": "B301",
      "severity": "HIGH",
      "file": "src/auth.py",
      "line": 42,
      "message": "Use of unsafe yaml.load() — allows arbitrary code execution",
      "category": "security"
    }
  ],
  "stats": {
    "tools_run": ["bandit", "ruff"],
    "tools_skipped": ["gosec"],
    "total_findings": 12,
    "by_severity": {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 5, "LOW": 5}
  }
}
```

## JSON report schema (`--json`)

The consolidator writes this alongside the markdown report:

```json
{
  "meta": {
    "timestamp": "ISO8601",
    "scope": {"files_changed": 4, "files_in_blast_radius": 12},
    "diff_ref": "git diff main..HEAD",
    "version": "2.0.0",
    "prescan": {"tools_run": ["bandit"], "tools_skipped": ["eslint"], "total_findings": 3}
  },
  "summary": {"total": 7, "critical": 0, "high": 2, "medium": 3, "low": 2},
  "findings": [
    {
      "id": "HG-001",
      "severity": "HIGH",
      "source_agent": "adversarial-reviewer",
      "cross_agent_agreement": ["edge-case-hunter"],
      "file": "src/handler.ts",
      "line_range": "42-58",
      "trigger_condition": "Concurrent calls to processPayment without mutex",
      "consequence": "Double-charge on payment",
      "recommendation": "Add distributed lock on orderId before processing",
      "exploit_poc": "Send two identical requests within 100ms window",
      "classes": ["CWE-362", "HG-PARTIAL-WRITE"],
      "source_prescan": false
    },
    {
      "id": "HG-004",
      "severity": "HIGH",
      "source_agent": "edge-case-hunter",
      "cross_agent_agreement": [],
      "file": "src/auth.py",
      "line_range": "42-42",
      "trigger_condition": "Unsafe yaml.load() allows arbitrary code execution",
      "consequence": "Remote code execution via crafted YAML input",
      "recommendation": "Replace yaml.load() with yaml.safe_load()",
      "exploit_poc": "",
      "source_prescan": true,
      "prescan_tool": "bandit",
      "prescan_rule": "B301"
    }
  ],
  "blast_radius": {
    "callers": [
      {"file": "src/handler.ts", "line": 42, "symbol": "processPayment()", "risk": "HIGH", "notes": "Assumes sync return"}
    ],
    "downstream": [
      {"callee": "payments/gateway.ts", "change_impact": "Now called without retry wrapper", "risk": "MEDIUM"}
    ],
    "config_affected": ["PAYMENT_TIMEOUT_MS"],
    "revert_safety": {"safe": true, "procedure": "Roll back commit, no migration needed"}
  },
  "coverage": [
    {"class_id": "CWE-362", "status": "finding", "backed_by": ["HG-001"]},
    {"class_id": "CWE-89", "status": "clean"},
    {"class_id": "CWE-787", "status": "not_applicable", "reason": "memory-unsafe class N/A for this language"}
  ],
  "verdict": {
    "overall_risk": "HIGH",
    "recommended_actions": {
      "before_merge": ["Fix HG-001"],
      "before_deploy": ["Fix HG-002", "Fix HG-003"],
      "next_sprint": ["Address HG-004"],
      "backlog": ["HG-005", "HG-006", "HG-007"]
    }
  }
}
```

## Project config (optional `.kensei/hermaguard.yaml`)

```yaml
hermaguard:
  enabled: true
  auto_trigger: false           # opt-in — no auto-trigger on commit
  scope: modified               # modified | staged | all
  skip_patterns: ["*.test.*", "*.spec.*", "*.md", "*.json", "*.yaml"]
  max_files: 50                 # skip if more than this many files changed
  blast_radius:
    max_depth: 2                # max caller/callee hop depth
    skip_patterns: ["node_modules/", "vendor/", "dist/"]
  severity_threshold: LOW       # minimum severity to report
  agents:
    parallel: 3                 # always 3 — non-configurable
    batch: true                 # parallel dispatch via harness subagents
  prescan:
    enabled: true               # run deterministic pre-scan before agents
    tools: auto                 # auto-detect from file extensions | explicit list
  json_output: false            # write JSON report alongside markdown
  feedback:
    mcp_url: ""                 # hermaguard-feedback MCP server URL (if available)
```
