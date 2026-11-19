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
  "files": [
    {"path": "src/auth.py", "status": "examined", "examined_by": ["bandit", "ruff"], "reason": null},
    {"path": "tools/run.rb", "status": "unsupported", "examined_by": [], "reason": "no tool configured for .rb"}
  ],
  "stats": {
    "state": "partial",
    "tools_run": ["bandit", "ruff"],
    "tools_skipped": ["gosec"],
    "scan_complete": false,
    "total_findings": 12,
    "by_severity": {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 5, "LOW": 5},
    "files_scanned": 3, "files_in_scope": 2, "files_examined": 2,
    "files_unsupported": 1, "files_missing": 0
  }
}
```

`stats.state` is the field consumers must read before interpreting `findings`:

| state | meaning | an empty `findings` list means |
|---|---|---|
| `complete` | every in-scope file was examined and no tool was skipped | no issues from the tools that ran |
| `partial` | something was examined, but a file or tool was not (a requested file is missing, a tool is not installed or failed) | **nothing** - not a clean result |
| `unavailable` | files were in scope but nothing could be examined | **nothing** |
| `out_of_scope` | nothing requested is a type the scanner has a tool for | **nothing** - the change was not reviewed |

Per-file `status` is one of `examined`, `not_examined`, `unsupported`
(no tool for this type, or excluded by `--tools`) and `missing` (the path does
not exist). Unsupported files do not stop a scan being `complete`, but they are
listed and counted (`files_unsupported`) so a change is never silently narrowed.

`scan_complete` is kept for old readers and is `true` only when
`state == "complete"`. Consumers must never treat an empty `findings` array as a
clean scan unless the state is `complete`. Exit code: `0` when at least one tool
ran, `1` otherwise - read `state`, not the exit code, to judge the result.

Pass long or awkward file lists with `--files-from PATH` (NUL- or
newline-delimited). `--files` accepts comma- or newline-separated names only; a
space-separated string is read as one file name.

Severity note: the bundled parsers emit `HIGH`, `MEDIUM` and `LOW` (and raw
`ERROR`/`WARNING` from gosec and clippy). None currently emits `CRITICAL`, so a
CI gate of `block_on: CRITICAL` cannot trip on a scanner finding. Use `HIGH`
to gate on high-severity scanner output.

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
  "report_version": 2,
  "revision": "9f3c2d1e8a7b6c5d4e3f20191817161514131211",
  "observations": [
    {
      "id": "OBS-1",
      "kind": "manual",
      "revision": "9f3c2d1e8a7b6c5d4e3f20191817161514131211",
      "scope": ["src/handler.ts::processPayment"],
      "check": "traced every query built in processPayment for string concatenation",
      "covers": ["CWE-89"]
    }
  ],
  "coverage": [
    {"class_id": "CWE-362", "status": "finding", "backed_by": ["HG-001"]},
    {"class_id": "CWE-89", "status": "clean", "observation": "OBS-1"},
    {"class_id": "HG-ASYNC", "status": "not_checked", "reason": "event handlers not traced"},
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

### Report versions and evidence

`report_version: 2` reports are checked for evidence. Reports without the field
are **legacy**: they still load and render, are labelled "evidence not checked",
and are never upgraded silently (`--require-evidence` makes the gates fail them).

**Coverage statuses.** `finding`, `clean`, `not_applicable`, `not_checked`,
`inconclusive`. `not_applicable`, `not_checked` and `inconclusive` need a
`reason`. A report with `not_checked` / `inconclusive` rows is *issuable* (its
findings stay readable) but does not clear the gate; a missing row is a gap and
is not issuable.

**A `clean` row must cite evidence.** `observation` (or `observations`) names
entries in the report's `observations[]`. Each observation needs: `id`, the
`revision` reviewed (must equal the report's), a bounded `scope` (`path` or
`path::symbol`, at least one path inside the changed files), the `check` that
was performed, and `covers` listing the class ids it supports. One observation
may support many rows. `kind` is `manual` (default) or `tool`; a tool
observation needs an `artifact` path (relative to the report, may not escape it)
and its `artifact_sha256`, and a declared artifact must exist and match.

**Findings link to coverage** through `classes` (the authority). `backed_by` is
an optional cross-reference whose ids must be findings that cite the class.

**Hard-class findings** (CWE-362, HG-ASYNC, HG-PARTIAL-WRITE, CWE-416) count as
VERIFIED only through a verifier record:

```json
"verification": {"verdict": "VERIFIED", "record": "verify-hg001.json", "record_sha256": "<64 hex>"}
```

`hermaguard-verify --json` writes the record: `binding` (finding id and classes,
reviewed `revision`, target path/`sha256`/symbol, PoC path/`sha256`, expected
result), the redacted run evidence, and a `record_sha256` over the whole record.
The gate admits the claim only if the record exists inside the evidence
directory, hashes correctly, and matches the finding, revision, target and
result. Otherwise the finding stays in the report as `UNVERIFIED` (or `REFUTED`)
and the gate fails. Failure classes: `absent`, `invalid`, `altered`,
`mismatched`, `stale`, `refuted`, `contradictory`, `unverified`. Records are
hashed, not signed: they stop copied, stale and edited records, not a forger who
can rewrite a record and its hash.

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
