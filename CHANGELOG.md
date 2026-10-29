# Changelog

All notable changes to Hermaguard are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed — reviewer method: unreachable gates and end-state impact

- **Edge Case Hunter** gains an *Unreachable gates* edge class: a
  skip/wait/admission condition must be able to become true in the state the
  system is actually in when the gate runs. Field miss: a review weighed a
  requeue gate's probe cost but not that it only passed on a "ready" state the
  target never held at boot, so parked work was skipped forever.
- **Adversarial Reviewer** finding bar: impact must be graded after tracing the
  affected entity to its end state ("lost" vs "delayed and self-healing").
  Field miss: a finding claimed a retry was burned without an attempt when the
  work item was durably back in the queue for the next cycle.

### Added — skill-creation trajectory audit (Phase 1 of skill-safety-audit)

- **Trajectory audit** (`hermaguard-trajectory`): deterministic scan of a
  skill-creation trajectory for misevolution. Detects approval-gate bypasses
  (gated action executed without a granted approval, approval requested but
  never granted, approval granted by a disallowed actor), outputs produced
  without a required verification step (required step missing, or present but
  failed), and deprecated tool invocations (configurable `deprecated_tools`
  registry with replacement guidance). Emits findings in the prescan-normalized
  schema with rule ID, severity, evidence and remediation. Policy is
  configurable via JSON (`approval_gates` + `verification_steps` +
  `deprecated_tools`); a built-in skill-creation default is used when none is
  supplied. Missing or malformed tool metadata is handled safely. A clean
  trajectory produces zero findings.
- **Packaging**: new `hermaguard-trajectory` console script (10 total) and
  data-file entry; `test_trajectory.py` suite (23 tests) covering clean and
  flagged trajectories plus configurable-policy, deprecated-tool and CLI paths.

### Fixed — trajectory approval-gate scoping (security)

- **Approval-gate scoping**: approval events are now scoped to the exact gated
  action they authorize (`detail` reference, else the next gated action). An
  approval granted for one gate (e.g. `commit`) can no longer bleed across an
  independent gate (e.g. `publish`), eliminating a **false negative** where a
  `publish` with no approval passed the gate when any earlier bare/human
  approval existed, and a **false positive** (`TRAJ-APPROVAL-003`) on clean
  multi-gate trajectories.
- **`TRAJ-APPROVAL-003` attribution**: the finding now cites the disallowed
  *approver*, not the actor who executed the action.

## [2.1.0] — 2026-08-15

### Added — accountability layer (the "can't lie" upgrades)

- **Coverage checklist** (`hermaguard-coverage`): every report must account
  for every applicable bug class from the MITRE 2024 CWE Top 25 plus
  hermaguard-native classes (race, async, partial-write, degenerate
  handler). Finding / clean / not-applicable-with-reason are the only
  allowed statuses; gaps fail the check. Registry validated by
  `--self-check` (32 classes).
- **Verified findings** (`hermaguard-verify`): findings get proven, not
  asserted. The review agent writes a PoC; the runner executes it in a
  hardened sandbox (empty env, rlimits, isolated Python, kill-on-timeout)
  and emits VERIFIED / REFUTED / UNVERIFIED from subprocess evidence —
  never model self-report (Vera principle). Hard classes (CWE-362, HG-ASYNC,
  HG-PARTIAL-WRITE, CWE-416) must carry VERIFIED evidence or the report
  fails `--check-report`.
- **Regression gate**: benchmark corpus grown from 5 to 25 bugs covering
  the classes the agents claim to check (auth bypass, CSRF, SSRF, XSS,
  eval, races, async gaps, empty catches, partial writes). Scoring is now
  deterministic class-based matching, not fuzzy keyword overlap.
- **L0–L6 harm grader** (`hermaguard-grader`): deterministic action-graded
  severity (arXiv 2607.07474 taxonomy), 100% oracle alignment on the
  self-test corpus, wires into the report phase.
- **Closed suppression loop**: dismiss a finding as false positive 3× →
  `hermaguard-compile-rules` compiles a suppression rule → prescan applies
  it automatically on every future run. Suppression is visible in stats,
  never silent.

### Added — research pre-pass layer

- **Locate** (`hermaguard-locate`): SHERLOC-style fault localization
  (arXiv 2606.24820). Churn + signal-concentration scoring produces an
  attack list for the review agents instead of a blind sweep.
- **Role patterns** (`hermaguard-role-patterns`): agent-specific SAST rule
  bundles (CLAWAUDIT lesson — generic SAST catches only ~14–22% of
  agent-specific bugs). Per-role rules keyed to coverage classes, emitted
  as first-class prescan findings.
- **Sanitize** (`hermaguard-sanitize`): CodeSentinel layer-1 defense
  (arXiv 2606.19235). Neutralizes instruction-shaped comments/strings and
  decoy payloads before code enters review prompts. Line count preserved;
  manifest always emitted.

### Added — hardening

- **CI on the repo itself** (`.github/workflows/ci.yml`): tests on Python
  3.10–3.12, byte-compile gate on every tool, benchmark smoke, actionlint.
- **MCP feedback server**: argument schema validation (invalid params →
  -32602), suppression-rules table created with the rest of the schema,
  full e2e stdio test.
- **Packaging**: `pyproject.toml` with nine console scripts; all tools
  installable via `pip install .`.

### Fixed

- `get_suppression_rules` MCP tool crashed on every call (dispatcher passed
  two args, handler took one) — it had never worked.
- Suppression-rule threshold never triggered: dismissal count queried the
  findings table (a single row, updated in place) instead of the
  acceptance-events log, so 3 dismissals never accumulated.
- Prescan now actually consumes compiled suppression rules (the loop was
  previously dead — compile-rules emitted YAML that nothing read).

### Tests

- **126 tests across 6 suites**: tools, coverage, loop, verify, research, MCP.
  (Final pre-push audit added regression tests for the benchmark run_ok
  handling and non-POSIX sandbox fallback — 130 tests across 7 suites.)
- E2E coverage: real subprocess sandbox PoCs (including a live race
  condition), full MCP handshake over stdio, compile-rules → prescan loop,
  corpus integrity (all 25 bugs validate against the coverage registry).

## [2.0.0] — 2026-07-01

Original public release: three-agent adversarial review (security,
edge-case, blast-radius), deterministic pre-scan (bandit, ruff, eslint,
semgrep), feedback MCP server for precision tracking, benchmark with 5
Python bugs, GitHub Action integration.
