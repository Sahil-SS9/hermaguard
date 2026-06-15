---
name: hermaguard
description: "Adversarial bug-hunting code review with deterministic pre-scan + 3 parallel specialist subagents and a consolidator. Finds what's broken, not what looks nice. Read-only — no fixes applied. Reports only."
version: 2.0.0
category: software-development
---

# Hermaguard

## What This Is

A read-only adversarial review skill that hunts bugs, edge cases, and integration risks in code changes. A deterministic pre-scan runs static analysis tools first (semgrep, bandit, eslint, etc.), then 3 parallel subagents attack the code from different angles using the pre-scan findings as context. A consolidator merges and triages everything into a structured report.

**This skill does NOT apply fixes.** It finds problems. Octacon or the feature pipeline picks up findings as separate tasks.

Synthesised from 8 implementations (Trail of Bits `differential-review`, BMAD `edge-case-hunter`/`adversarial-general`/`bmad-code-review`, dementev-dev `adversarial-review`, Anthropic `claude-code-security-review` + Code Review Plugin, and the community adversarial-prompt pattern). Schemas and project config: `references/output-schema.md`.

## When to Invoke

**Auto-invoke after:**
- Any implementation task completes and passes `code-simplifier`
- Pre-commit when `--hermaguard` flag is passed
- New feature or refactor that touches >3 files (blast radius concern)

**Manual invoke when Sahil says:**
- "hermaguard this" / "guard this" / "adversarial review"
- "bug hunt this" / "break this" / "what could go wrong"
- "check for edge cases" / "security review this change"

**Do NOT invoke if:**
- Tests are failing (fix tests first — you can't hunt bugs in broken code)
- No code was modified (config/docs-only changes)
- The change is a one-liner with no control flow (trivial assignment, typo fix)
- Already guarded this diff in the last 10 minutes (dedup)

## Slash Command

**`/hermaguard`** — triggers this skill on the current diff. On Hermes Agent, the skill loader matches keywords ("hermaguard this", "guard this", "adversarial review") — the slash syntax here is for Claude Code compatibility. On Hermes, any of the trigger phrases in "When to Invoke" will load this skill.

Optional flags:

| Flag | Effect |
|------|--------|
| `/hermaguard` | Auto-detect scope (unstaged → staged → branch diff) |
| `/hermaguard --full` | Run all 3 agents even if <3 files changed |
| `/hermaguard --quick` | Single-pass review with all 3 perspectives in one agent (fastest) |
| `/hermaguard --file path/to/file.ts` | Scope to a specific file |
| `/hermaguard --since HEAD~3` | Scope to commits since a ref |
| `/hermaguard --json` | Write structured JSON report alongside markdown |
| `/hermaguard --no-prescan` | Skip deterministic pre-scan (faster, less thorough) |

The `/hermaguard` command is **opt-in only** — no auto-trigger on commits. Sahil runs it explicitly when he wants adversarial review.

## Relationship to Code Simplifier

| Aspect | Code Simplifier | Hermaguard |
|--------|----------------|------------|
| Goal | Cleaner code, same behaviour | Find behaviour problems |
| Stance | Constructive refinement | Adversarial, destructive |
| Scope | Recently modified code | Modified + blast radius |
| Applies changes | Yes (auto-apply or diffs) | No (read-only report) |
| Output | Modified files + summary | Risk-triaged findings report + JSON |

**Chained workflow:**
```
Implement → Verify (tests pass) → Simplify → Hermaguard → Fix (Octacon) → Simplify → Commit
```

## Architecture: Pre-Scan + 3 Agents + Consolidator

```
                    ┌──────────────────────────────┐
                    │   Phase 0: Deterministic      │
                    │   Pre-Scan (semgrep, bandit,  │
                    │   eslint, gosec, ruff)        │
                    └──────────┬───────────────────┘
                               │ prescan context
                    ┌──────────▼───────────────────┐
                    │   Hermaguard                  │
                    │   (Orchestrator — this skill) │
                    └──────────┬───────────────────┘
                               │
          ┌────────────────────┼────────────────────┐
          ▼                    ▼                    ▼
   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
   │ 1. Edge Case │    │ 2. Adver-    │    │ 3. Blast     │
   │    Hunter    │    │    sarial    │    │    Radius +   │
   │ (diff only)  │    │  Reviewer    │    │  Integration  │
   │              │    │ (full files) │    │ (full files + │
   │              │    │              │    │  call graph)  │
   └──────┬───────┘    └──────┬───────┘    └──────┬───────┘
          │                   │                   │
          └───────────────────┼───────────────────┘
                              ▼
                      ┌──────────────┐
                      │ Consolidator │
                      │ Merge +      │
                      │ Triage +     │
                      │ Report (MD + │
                      │ JSON)        │
                      └──────────────┘
```

### Rationale for 3 agents (not 7 like the simplifier swarm)

The simplifier needs many narrow agents because it's mutating code — each change type has its own risk profile and failure mode. Bug hunting is different: it's a pure analysis task. More agents = more duplicate findings, not more coverage. Three distinct perspectives (exhaustive paths, adversarial attack, blast radius) give ~95% coverage without redundant cross-talk.

### Pre-Scan rationale

Pure LLM agents guess at what might be wrong. Static analysis tools (semgrep, bandit, eslint) find real, deterministic issues — SQL injection patterns, unsafe deserialisation, hardcoded secrets. The pre-scan gives agents a floor of real findings to investigate rather than starting from zero. Agents then verify exploitability, assess blast radius, and find logic bugs the scanners miss. The combination catches more than either alone.

---

## Execution Flow

### Phase 0: Scope Detection

```bash
# Detect changes — try unstaged first, then staged, then branch diff
git diff --name-only -- '*.ts' '*.tsx' '*.js' '*.py' '*.go' '*.rs' '*.java' 2>/dev/null
# If empty, try staged:
git diff --cached --name-only -- '*.ts' '*.tsx' '*.js' '*.py' '*.go' '*.rs' '*.java'
# If still empty, try branch diff:
git diff --name-only $(git symbolic-ref refs/remotes/origin/HEAD 2>/dev/null | sed 's|refs/remotes/origin/||' || echo main)...HEAD -- '*.ts' '*.tsx' '*.js' '*.py' '*.go' '*.rs' '*.java'
```

Skip: test files (`*.test.*`, `*.spec.*`, `tests/`, `__tests__/`), config files (`*.json`, `*.yaml`, `*.toml`, `*.md`), generated code, vendored deps.

If no files found: "No code changes to guard." Stop.

### Phase 0b: Deterministic Pre-Scan

Run `hermaguard-prescan` against the changed files. This is a standalone CLI tool that wraps static analysis.

```bash
# Run pre-scan — captures deterministic findings before LLM agents run
hermaguard-prescan --files <changed-files-list> --output /tmp/hermaguard/prescan-{hash}.json 2>/dev/null
```

If the tool is not installed, skip pre-scan and note it in the report: "Pre-scan unavailable — install hermaguard-prescan for deterministic analysis layer." Do NOT fail.

If the tool returns findings, load the JSON and inject as context into agents 1 and 2. Each finding has `tool`, `rule_id`, `severity`, `file`, `line`, `message`, `category`; full schema in `references/output-schema.md`.

Skip pre-scan with `--no-prescan` flag.

### Phase 1: Parallel Dispatch (Batch Mode)

**Progress visibility (required):** `delegate_task` blocks until all agents return — typically 2–5 minutes with no intermediate output. Never leave the user staring at silence. Immediately before dispatching, print a status block so the wait is expected:

```
Dispatching 3 adversarial agents over {N} changed files:
  1. Edge Case Hunter — path/boundary tracing (diff only)
  2. Adversarial Reviewer — attack surfaces (full files)
  3. Blast Radius — callers, contracts, revert safety

Read-only phase: nothing is modified. Expect ~2–5 min of background work.
```

**Batch dispatch:** All 3 agents are dispatched simultaneously via your harness's parallel subagent mechanism. This reduces LLM round-trips from 4 to 2 (parallel dispatch + consolidator). Agents are independent — their outputs are consumed only by the consolidator.

```python
# Hermes Agent: single batch call via delegate_task tasks array
# Claude Code: parallel subagent spawn
# Codex CLI: concurrent subprocess delegation
# Any harness: dispatch 3 reviewers in parallel, collect outputs
```

For `--quick` mode (small diffs, <3 files): use a single `delegate_task` with all 3 perspectives as sequential sections in one prompt:
```
You are three reviewers operating in sequence. First, think as Edge Case Hunter... 
Now, think as Adversarial Reviewer... Now, think as Blast Radius analyst. 
Then output one consolidated report.
```

#### Agent 1: Edge Case Hunter

```
Scope: Diff only (git diff output) + Pre-scan findings as context
Context: Only the actual diff hunks — not full files. If pre-scan ran, use those findings as starting points — investigate exploitability, don't re-discover what semgrep already found.
```

**Stance:** You are a pure path tracer. Method-driven, not attitude-driven. Never comment on whether code is good or bad; only list missing handling.

**Method:** Walk every branching path and boundary condition reachable from the changed lines. Exhaustively enumerate — do not hunt by intuition. When pre-scan findings are present, start from those locations and trace outward.

**Edge classes to check:**
- **Control flow**: missing else/default, unguarded switch fall-through, early returns that skip cleanup
- **Null/empty**: null, undefined, empty string, empty array, zero, NaN
- **Boundary values**: off-by-one in loops/indices, overflow/underflow, min/max thresholds, empty collections
- **Type coercion**: implicit conversions, truthy/falsy gotchas, `==` vs `===`, `parseInt` without radix
- **State transitions**: loading→error, active→expired, before→after auth, first-use vs subsequent
- **Async**: promise rejection unhandled, race between async operations, partial success states
- **Concurrency**: shared mutable state, non-atomic read-modify-write
- **Degenerate handlers**: empty catch/then blocks, no-op error paths, fallthrough switch cases with identical bodies, placeholder return values that mask failures

**Output contract:** Return ONLY a JSON array. Each object has exactly these 4 fields:
```json
[{
  "location": "file:line-range",
  "trigger_condition": "one-line description (max 15 words)",
  "guard_snippet": "minimal code sketch that closes the gap",
  "potential_consequence": "what could actually go wrong (max 15 words)"
}]
```
An empty array `[]` is valid when no unhandled paths are found.

**Halt conditions:**
- Diff is empty or undecodable → return `[{"location":"N/A","trigger_condition":"Input empty","guard_snippet":"Provide valid diff","potential_consequence":"Review skipped"}]`
- Zero findings → return `[]` — this IS valid; do not fabricate findings

---

#### Agent 2: Adversarial Reviewer

```
Scope: Full file contents of changed files (read_file on each changed file) + Pre-scan findings as context
Context: Entire file — you need to understand what the change sits within. Pre-scan findings provide deterministic starting points — verify these and hunt for additional vulnerabilities.
```

**Stance:** "Your job is to break confidence in the change, not to validate it." Default to skepticism. Assume the change can fail in subtle, high-cost, or user-visible ways until the evidence says otherwise. Do not give credit for good intent, partial fixes, or likely follow-up work. If something only works on the happy path, treat that as a real weakness.

**Persona:** You are a precise, professional reviewer looking for real vulnerabilities. No profanity, no personal attacks, no speculation without a concrete trigger scenario. But be relentless — if something can fail, say how.

**Attack surfaces (check each — skip if not applicable):**
- **Auth & Permissions:** bypasses, privilege escalation, missing checks on new endpoints
- **Data Integrity:** loss, corruption, partial writes, constraint violations, missing transactions
- **Race Conditions:** TOCTOU, concurrent access without locks, deadlocks, non-atomic operations
- **Rollback Safety:** can this change be safely reverted? Does it need a migration rollback plan?
- **Schema Drift:** migrations present and correct, backward compatibility maintained, data format changes handled
- **Error Handling:** swallowed errors (empty catch), missing retries, cascading failure chains, `except: pass`
- **Observability:** will operators know when this breaks? Are error logs meaningful? Are internal error details (stack traces, DB queries, file paths) exposed to untrusted clients through error responses?
- **Input Validation:** injection vectors (SQL, command, path traversal), unsanitised user input reaching dangerous sinks
- **Return Value Integrity:** does the function return a semantically correct value in all paths? Are there placeholder/fallback returns that mask failures (e.g., returning a fake success after an empty catch)?

**Finding bar (every finding MUST answer 4 questions):**
1. What can go wrong? (concrete scenario, not hypothetical)
2. Why is this code vulnerable? (cite specific file and lines)
3. Impact — what breaks and how badly? (data loss > outage > degraded UX)
4. Recommendation — specific fix with code reference

**Scope exclusions — DO NOT comment on:**
- Code style, formatting, naming conventions
- "Nice to have" improvements unrelated to correctness or safety
- Speculative issues without concrete trigger scenario
- Performance micro-optimisations

**Calibration:** Prefer one strong finding over several weak ones. If the change is genuinely solid, say so clearly — false positives erode trust.

**Output format:**
```markdown
## Adversarial Review Findings

### [SEVERITY] Finding Title

**File:** path:line-range

**What can go wrong:** ...
**Why vulnerable:** ...
**Impact:** ...
**Recommendation:** ...

(Repeat per finding. Zero findings → "No adversarial findings — change appears robust against attack.")
```

---

#### Agent 3: Blast Radius + Integration

```
Scope: Full file contents + call graph analysis
Context: Changed files PLUS grep/rg for all callers and callees
```

**Stance:** Strategic — zoom out. A change that's locally correct can still break the system. Your job: map the wider impact.

**Method:**
1. For each changed function/class/export, find ALL callers:
   ```bash
   rg -n "functionName|ClassName|exportName" --type-add 'code:*.{ts,tsx,js,py,go,rs,java}' --type code
   ```
2. For each caller, assess: does the change break the caller's assumptions?
3. Check configuration that depends on this behaviour (env vars, feature flags, API contracts, route paths)
4. Assess migration/revert safety

**Specific checks:**
- **Caller impact:** List every caller. For each: is the call signature compatible? Are return value assumptions still valid?
- **Downstream effects:** What does THIS code call? Have those callees' contracts changed?
- **Configuration coupling:** Does a config key, env var, or feature flag control this behaviour? Has the default changed?
- **Database/Migration:** Schema changes? New queries that need indexes? Backward-compatible writes?
- **API contracts:** Do route paths, request/response shapes, or error codes change?
- **Observability:** Are there metrics/alerts on this code path? Will this change trigger false alarms or silence real ones?
- **Performance anti-patterns:** N+1 queries (DB calls inside loops), unbounded loops without pagination/LIMIT, missing batch operations where available, caching opportunities missed on hot paths

**Output format:**
```markdown
## Blast Radius Analysis

### Callers of changed code

| Caller (file:line) | Changed symbol | Risk | Notes |
|---|---|---|---|
| src/handler.ts:42 | `processPayment()` | HIGH | Assumes sync return, change makes it async |

### Downstream dependencies

| Callee | Change impact | Risk |
|---|---|---|
| payments/gateway.ts | Now called without retry wrapper | MEDIUM |

### Configuration & Contracts

- **Config keys affected:** `PAYMENT_TIMEOUT_MS` — default changed from 30s to 10s
- **API contract changes:** Response shape adds `correlationId` field (backward-compatible)
- **Migration notes:** No schema change required

### Revert Safety

- **Safe to revert?** Yes — old behaviour is additive
- **Revert procedure:** Roll back this commit, no data migration needed
```

---

### Phase 2: Consolidation

After all 3 subagents return, merge their findings:

1. **De-duplicate:** Same bug found by multiple agents → keep the most detailed version, note cross-agent agreement
2. **Triage by risk tier:**
   - **CRITICAL:** Data loss, auth bypass, security exploit, unrecoverable state corruption
   - **HIGH:** Production outage risk, silent failure, race condition with user-visible impact
   - **MEDIUM:** Edge case with degraded UX, missing error handling in non-critical path, observability gap
   - **LOW:** Minor edge case unlikely to trigger, missing guard on validated input, cosmetic in logs

3. **Cross-reference:** If Agent 3 found a caller that Agent 2 flagged as vulnerable, escalate the finding severity. Also escalate when Agent 2 flags an auth/security vulnerability and Agent 3 confirms the affected surface is externally accessible (endpoint without auth gate, public API, config exposed to untrusted callers) — the blast radius finding provides independent confirmation of exploitability.

4. **Incorporate pre-scan findings:** Pre-scan findings that weren't duplicated by any agent still go in the report, marked `source: prescan` with the tool name. They're lower confidence until an agent investigates, but they're real static analysis hits.

5. **Generate the report**

---

### Phase 3: Report

Output a structured markdown report AND (if `--json` flag was passed) a JSON file. Both are written to disk; markdown is also summarised in chat.

**Report location:** `/tmp/hermaguard/hermaguard-{timestamp}-{short-hash}.md`
**JSON location:** `/tmp/hermaguard/hermaguard-{timestamp}-{short-hash}.json`

**Report structure:**
```markdown
# Hermaguard Report

**Date:** {DD/MM/YY HH:MM}
**Scope:** {N} files changed, {M} files in blast radius
**Diff reference:** `git diff {from}..{to}`
**Pre-scan:** {N} findings from {tools} | {if skipped, note reason}

---

## Summary

**Total findings:** {N}
**CRITICAL:** {N} | **HIGH:** {N} | **MEDIUM:** {N} | **LOW:** {N}

{One-paragraph narrative: the change, the key risks, what needs attention first}

---

## CRITICAL Findings

{Only CRITICAL findings here — each a full section with exploit PoC, impact, recommendation}

## HIGH Findings

{HIGH findings}

## MEDIUM Findings

{MEDIUM findings}

## LOW Findings

{LOW findings — can be a compact table}

---

## Pre-Scan Findings

{Findings from static analysis that weren't duplicated by agents. Each: tool, rule_id, file:line, message. Compact table format.}

---

## Blast Radius Map

{Files affected, callers, downstream — links to the Integration section}

---

## Verdict

**Overall risk:** {LOW / MEDIUM / HIGH / CRITICAL}

**Recommended action:**
- [ ] Fix CRITICAL findings before merge
- [ ] Fix HIGH findings before deploy
- [ ] Address MEDIUM findings next sprint
- [ ] LOW findings — backlog or dismiss

**No fixes were applied by this review.** Findings to be picked up by Octacon as separate tasks.
```

**JSON output schema:** four top-level keys — `meta` (timestamp, scope, diff_ref, version, prescan stats), `summary` (total + per-severity counts), `findings[]` (id, severity, source_agent, cross_agent_agreement, file, line_range, trigger_condition, consequence, recommendation, exploit_poc, source_prescan + prescan_tool/prescan_rule when applicable), `blast_radius` (callers, downstream, config_affected, revert_safety), and `verdict` (overall_risk + recommended_actions buckets). Full worked example in `references/output-schema.md`. Feedback MCP `record_findings` consumes this shape verbatim.

---

## Integration Points

### With Octacon (Coding Lead)
Octacon reads the Hermaguard report after any implementation task. Flow:
```
Octacon implements → Simplify → Hermaguard → Octacon fixes → Simplify → Commit
```

### With the Feature Pipeline
The feature pipeline's review step (`sdlc-review`) checks that Hermaguard was run. If a task reaches review without Hermaguard evidence for tier=full tasks, flag it. The pipeline integration is configured in `governance/multi-gate-qa.md` under a new **Gate 0 (Adversarial Review)** that gates entry to the review column.

**Gate 0 wiring** (amended in `multi-gate-qa.md`):
- Gate 0: Hermaguard — adversarial review before SDLC review
- Applies to: `backend`, `frontend`, `security`, `new-feature` tiers
- Skips for: `config`, `content`, `infra` tiers
- Evidence required: Hermaguard report path in task metadata

### With KENSEI Governance
CRITICAL findings should be logged to `#governance` — they're system-level risks.

### With Feedback MCP Server
If the `hermaguard-feedback` MCP server is available, record findings and query suppression rules:
- After report generation: call `record_findings` to store all findings for precision tracking
- Before Agent 1 dispatch: call `get_suppression_rules` to load patterns that have been repeatedly dismissed

### With Knowledge Graph MCP Server
If the `kensei-kg` MCP server is available, query before review:
- Call `search_patterns(query)` for each major file/function being changed
- Call `get_related_concepts(finding_text)` on any finding to link to wiki entries

---

## Configuration

Optional project config at `.kensei/hermaguard.yaml` (scope, skip_patterns, max_files, blast_radius depth, severity_threshold, prescan toggle, json_output, feedback MCP url). Full annotated template in `references/output-schema.md`. All keys have sensible defaults; the skill runs with no config file.

---

## Output Format Summary

**In chat** (after report is written):
```
Hermaguard complete.

Scope: 4 files changed, 12 files in blast radius
Pre-scan: 3 findings from bandit, ruff
Findings: 7 total
  CRITICAL: 0
  HIGH: 2
  MEDIUM: 3
  LOW: 2

Report: /tmp/hermaguard/hermaguard-20260608-1430-a1b2c3d.md
JSON: /tmp/hermaguard/hermaguard-20260608-1430-a1b2c3d.json

Top finding: [HIGH] Race condition in payment processing (Agent 2 + Agent 1 agree)
  → src/payments/handler.ts:42 — concurrent calls can double-charge

No fixes applied. Handing findings to Octacon.
```

---

## Pitfalls

- **Don't guard code you don't understand.** If you can't trace the full call graph, mark findings as lower confidence.
- **Don't fabricate findings.** An empty agent report IS valid. False positives erode trust faster than missed bugs.
- **Don't fight the blast radius agent.** If it says "safe to revert," believe it unless you have concrete contrary evidence.
- **Don't let the adversarial agent go soft.** If it returns "no findings," ask it to re-examine — adversarial reviewers should ALWAYS find something worth noting, even if LOW severity.
- **Don't mix guarding with simplification.** They're separate skills with separate triggering conditions. Guard after simplify, never during.
- **Report files are mandatory.** Don't just summarise in chat — write the full report AND (with --json) JSON to disk for governance and traceability.
- **Pre-scan may be unavailable.** If `hermaguard-prescan` isn't installed, skip it gracefully and note it. Don't fail the review because a companion tool is missing.
- **Don't re-discover pre-scan findings.** If semgrep already found an SQL injection, Agent 2 should verify exploitability and assess impact, not "discover" it again. The finding should appear once in the report, credited to both prescan and the agent that investigated it.
- **JSON output is additive, not replacement.** Markdown report is always written. JSON is additional when `--json` is passed. Both are equally authoritative.

---

## Platforms

This skill is designed to run on any platform that supports Hermes Agent or Claude Code:
- **Hermes Agent** (native) — via `delegate_task` subagent dispatch
- **Claude Code** — via subagent system or as a standalone skill
- **Codex CLI** — via subprocess delegation
- **Any agent framework** with subagent capabilities
