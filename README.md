# Hermaguard

Adversarial bug-hunting code review for AI agents. Three parallel subagents attack your code changes from different angles, then a consolidator merges and triages the findings. Read-only — finds problems, doesn't touch your code.

```
                    ┌──────────────────────────────┐
                    │   Hermaguard                  │
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
                      │ Report       │
                      └──────────────┘
```

## What it does

- **Agent 1 (Edge Case Hunter):** Exhaustive path tracer. Walks every branching path and boundary condition in the diff — null/empty, off-by-one, type coercion, async gaps, race conditions. Reports only unhandled paths.
- **Agent 2 (Adversarial Reviewer):** Cynical persona — "break confidence in the change, not validate it." 8 attack surfaces: auth, data integrity, race conditions, rollback safety, schema drift, error handling, observability, input validation.
- **Agent 3 (Blast Radius + Integration):** Traces every caller and callee. Maps config coupling, migration safety, API contract changes. Answers: "what else breaks if this ships?"
- **Consolidator:** Merges, de-duplicates, triages by risk tier (CRITICAL/HIGH/MEDIUM/LOW), writes structured markdown report.

## Quick start

Drop `SKILL.md` into your agent's skills directory. On Hermes Agent:

```bash
cp SKILL.md ~/.hermes/skills/software-development/hermaguard/SKILL.md
```

Then trigger it:

```
/hermaguard
```

Supported flags: `--focus edge` (fastest, Edge Case Hunter only), `--file path/to/file.ts` (scope to one file), `--since HEAD~3` (scope to recent commits).

Also works with Claude Code, Codex CLI, or any agent framework with subagent capabilities. The skill is a single markdown file — no dependencies, no install script.

## Why it exists

Existing code review tools fall into two camps: security scanners (narrow to auth/crypto, miss logic bugs) and general review tools (mix bug hunting with style checks, diluting focus). Hermaguard is the first skill where ALL agents are purely adversarial — every subagent is trying to break the code, not validate it.

Built by synthesising 8 implementations: Trail of Bits `differential-review`, BMAD `edge-case-hunter` and `adversarial-general`, BMAD `bmad-code-review`, dementev-dev `adversarial-review`, Anthropic `claude-code-security-review`, Anthropic Claude Code Review Plugin, and the adversarial prompt pattern from r/ClaudeAI.

## Related

- **Hermes Agent PR:** [#42171](https://github.com/NousResearch/hermes-agent/pull/42171) — upstream contribution to bundle this skill
- **Author:** Sahil Saghir ([@Sahil-SS9](https://github.com/Sahil-SS9))
- **License:** MIT

## Contributing

Open an issue or PR. Bug reports with reproduction steps appreciated. Feature ideas for additional agents (e.g., performance regression hunter, accessibility auditor) welcome. The adversarial agent's attitude complaints are also valid — it's designed to be a bit of a bastard.
