# HermaGuard v2.0.0

Adversarial bug-hunting code review for AI agents. Deterministic pre-scan + 3 parallel subagents attack your code changes from different angles, then a consolidator merges and triages the findings. Read-only — finds problems, doesn't touch your code.

```
                   ┌──────────────────────────────┐
                   │   Phase 0: Deterministic      │
                   │   Pre-Scan (semgrep, bandit,  │
                   │   eslint, gosec, ruff)        │
                   └──────────┬───────────────────┘
                              │ prescan context
                   ┌──────────▼───────────────────┐
                   │   HermaGuard                  │
                   │   (Orchestrator)              │
                   └──────────┬───────────────────┘
                              │
         ┌────────────────────┼────────────────────┐
         ▼                    ▼                    ▼
  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
  │ Edge Case    │    │ Adversarial  │    │ Blast Radius │
  │ Hunter       │    │ Reviewer     │    │ + Integration│
  │ (diff only)  │    │ (full files) │    │ (call graph) │
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

## What's new in v2.1.0

v2.1 adds the **accountability layer** — the review can no longer claim things without proving them:

- **Coverage checklist:** every report accounts for all 32 bug classes (MITRE 2024 CWE Top 25 + races, async gaps, partial writes). Each class gets exactly one status — finding, clean, or N/A-with-reason. Gaps fail the check.
- **Verified findings:** agents write a proof-of-concept; `hermaguard-verify` runs it in a hardened sandbox (empty env, rlimits, kill-on-timeout) and verdicts VERIFIED / REFUTED / UNVERIFIED from execution output — never model self-report. Hard classes (races, async, partial writes) cannot ship without VERIFIED evidence.
- **Regression gate:** benchmark corpus grown 5 → 25 bugs covering every claimed class. Scoring is deterministic class-matching — no keyword fuzz, no gamed scores.
- **L0–L6 harm grader:** deterministic action-graded severity per finding (taxonomy from arXiv:2607.07474).
- **Closed learning loop:** dismiss a false positive 3× → compiled suppression rule → prescan applies it on every future run. Suppression is always visible in stats.
- **Research pre-passes:** locate (SHERLOC-style fault localization, arXiv:2606.24820), role-patterns (agent-specific SAST rules, CLAWAUDIT lesson), sanitize (CodeSentinel-style prompt-injection defense, arXiv:2606.19235).
- **CI on itself, pip packaging** with 9 console scripts, and 130 tests across 7 suites.

See [docs/architecture.html](docs/architecture.html) for the full pipeline diagram, and [CHANGELOG.md](CHANGELOG.md) for details.

## What's new in v2.0.0

- **Deterministic pre-scan layer:** Runs semgrep, bandit, eslint, gosec, and ruff on your diff BEFORE the LLM agents. Catches SQL injection, unsafe deserialisation, hardcoded secrets, and other patterns that language scanners find. Agents then investigate exploitability instead of guessing from scratch.
- **JSON output mode:** `--json` flag writes structured machine-readable findings alongside the markdown report. Enables CI integration, dashboards, and precision tracking.
- **Batch agent dispatch:** the 3 agents run in parallel via your harness's subagent mechanism (Hermes: one batched `delegate_task`; Claude Code: parallel subagent spawn; Codex/others: concurrent delegation). Fewer round-trips, less hallucination surface. Harness-agnostic by design.
- **Feedback MCP server:** Track which findings get fixed vs dismissed. Query agent precision (computed over triaged findings only) over time. Auto-generate suppression rules for repeatedly false-positive patterns.
- **Benchmark suite (score-only):** Seeded corpus of bugs with ground truth; scores any harness's `--json` output for precision/recall/F1/severity accuracy and writes an HTML report. It does NOT run HermaGuard itself (it's a skill, not a binary) — your harness produces the report, the benchmark scores it.
- **GitHub Action:** Runs the deterministic pre-scan and posts findings as PR comments; optionally blocks merge on CRITICAL. The LLM review is interactive and is not run inside CI (the action is honest about this).
- **Suppression rules:** Dismiss a pattern 3 times → it becomes a rule that future runs skip. Reduces false positive noise.
- **AGENTS.md linter:** A regex keyword/structure heuristic inspired by (not derived from) the Instructions-as-Code criteria. A high score is necessary, not sufficient.

## What it does

- **Agent 1 (Edge Case Hunter):** Exhaustive path tracer. Walks every branching path and boundary condition in the diff — null/empty, off-by-one, type coercion, async gaps, race conditions. Reports only unhandled paths.
- **Agent 2 (Adversarial Reviewer):** Investigates exploitability of pre-scan findings and hunts additional vulnerabilities. 9 attack surfaces: auth, data integrity, race conditions, rollback safety, schema drift, error handling, observability, input validation, return value integrity.
- **Agent 3 (Blast Radius + Integration):** Traces every caller and callee. Maps config coupling, migration safety, API contract changes. Answers: "what else breaks if this ships?"
- **Consolidator:** Merges, de-duplicates, triages by risk tier (CRITICAL/HIGH/MEDIUM/LOW), writes structured markdown + JSON report.

## Project structure

```
hermaguard/
├── SKILL.md                          # The skill (Hermes/Claude/Codex/any harness)
├── README.md                         # This file
├── CHANGELOG.md                      # Release history
├── LICENSE                           # MIT
├── pyproject.toml                    # pip install . → 9 console scripts
├── docs/
│   └── architecture.html             # Pipeline architecture diagram
├── test_tools.py                     # 130 tests across 7 suites, all calling real code
├── tools/
│   ├── hermaguard-prescan/           # Deterministic pre-scan CLI (+ suppression rules)
│   ├── hermaguard-coverage/          # Coverage checklist (32 bug classes)
│   ├── hermaguard-verify/            # PoC sandbox runner (VERIFIED/REFUTED/UNVERIFIED)
│   ├── hermaguard-locate/            # SHERLOC-style fault localization
│   ├── hermaguard-role-patterns/     # Agent-specific SAST rules
│   ├── hermaguard-sanitize/          # Prompt-injection sanitizer
│   ├── hermaguard-grader/            # L0–L6 harm grader
│   ├── hermaguard-benchmark/         # Score-only benchmark (25-bug corpus)
│   ├── hermaguard-compile-rules/     # TRACE-style rule compiler
│   └── agentsmd-linter/              # Instruction file scorer
├── integrations/
│   └── github-action/                # GitHub Action (pre-scan in CI)
├── mcp/
│   └── hermaguard-feedback/          # Feedback MCP server
└── data/                             # Runtime data (gitignored)
```

## Quick start

**Install (recommended):**

```bash
pip install .
# → hermaguard-coverage, hermaguard-locate, hermaguard-role-patterns,
#   hermaguard-sanitize, hermaguard-verify, hermaguard-grader,
#   hermaguard-prescan, hermaguard-compile-rules, hermaguard-benchmark
```

**Or run from source:** drop `SKILL.md` into your agent's skills directory. On Hermes Agent:

```bash
cp SKILL.md ~/.hermes/skills/software-development/hermaguard/SKILL.md
```

Install the pre-scan tool for deterministic analysis:

```bash
chmod +x tools/hermaguard-prescan/hermaguard-prescan.py
sudo ln -sf $(pwd)/tools/hermaguard-prescan/hermaguard-prescan.py /usr/local/bin/hermaguard-prescan
```

Then trigger it:

```
/hermaguard
/hermaguard --json          # with structured JSON output
/hermaguard --quick         # single-pass (fastest)
/hermaguard --no-prescan    # skip deterministic layer
```

Supported flags: `--focus edge` (Edge Case Hunter only), `--file path/to/file.ts` (scope to one file), `--since HEAD~3` (scope to recent commits), `--json` (write JSON report), `--no-prescan` (skip static analysis).

Also works with Claude Code, Codex CLI, or any agent framework with subagent capabilities.

## Run tests

```bash
python3 -m unittest test_tools.py test_coverage.py test_loop.py \
  test_verify.py test_research.py test_mcp.py test_packaging.py -v
# 126 tests across 7 suites. Every test imports the module and calls real
# functions — delete a tool and its tests error rather than pass.
```

## Benchmark

Score-only: your harness emits a `--json` report per bug, this scores it against a seeded corpus's ground truth. It does not run the skill itself.

```bash
python3 tools/hermaguard-benchmark/benchmark.py \
  --bugs tools/hermaguard-benchmark/bugs --results tools/hermaguard-benchmark/results
```

Run it yourself to get precision/recall/F1 for your harness.

## Integration with CI

Copy `.github/workflows/hermaguard.yml` using the provided action:

```yaml
- uses: Sahil-SS9/hermaguard@v2
  with:
    block_on: CRITICAL  # or HIGH or never
    comment_mode: inline
```

Pre-scan runs automatically. Full LLM review runs interactively (`/hermaguard`).

## Why it exists

Existing code review tools fall into two camps: security scanners (narrow to auth/crypto, miss logic bugs) and general review tools (mix bug hunting with style checks, diluting focus). HermaGuard is the first skill where ALL agents are purely adversarial — every subagent is trying to break the code, not validate it. With v2.0.0, it adds a deterministic floor (static analysis) underneath the LLM ceiling, closing the gap on both false positives and missed bugs.

Built by synthesising 8 implementations: Trail of Bits `differential-review`, BMAD `edge-case-hunter` and `adversarial-general`, BMAD `bmad-code-review`, dementev-dev `adversarial-review`, Anthropic `claude-code-security-review`, Anthropic Claude Code Review Plugin, and the adversarial prompt pattern from r/ClaudeAI.

v2.0.0 extensions based on findings from TRACE (runtime enforcement), HyperTool (composite calls), OrchRM (orchestration reward modeling), Agents-K1 (knowledge graphs), Agentic PR Rejection (failure mode analysis), Instructions-as-Code (instruction file effectiveness), and RAH (harness recursion measurement).

## Related

- **Benchmark and GitHub Action:** in-repo under `tools/hermaguard-benchmark/` and `integrations/github-action/` (not separate repos).
- **Author:** Sahil Saghir ([@Sahil-SS9](https://github.com/Sahil-SS9))
- **License:** MIT

## Contributing

Open an issue or PR. Bug reports with reproduction steps appreciated. Feature ideas for additional agents (e.g., performance regression hunter, accessibility auditor) welcome. Run `python3 -m pytest test_tools.py -q` before submitting PRs.
