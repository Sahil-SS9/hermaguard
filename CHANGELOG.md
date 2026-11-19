# Changelog

All notable changes to Hermaguard are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed - GitHub Action and pre-scan told the truth about unfinished scans

- **Security:** the Action no longer interpolates PR-controlled values (changed
  file names, `skip_patterns`, `max_files`, `block_on`) into shell. Values go
  through `env:`; changed files are collected with `git diff -z` and handed to
  the scanner as a file (`--files-from`). A file named `x$(touch PWNED).py`
  used to run in the consumer's CI.
- **Install path:** the README told users to write `Sahil-SS9/hermaguard@v2`
  (no root `action.yml`, no `v2` tag) and to copy a workflow file that did not
  exist. It now documents `Sahil-SS9/hermaguard/integrations/github-action@<sha>`,
  a complete example workflow, least-privilege `permissions`, and a warning
  against `pull_request_target`.
- **False "clean":** the Action passed files space-separated, which the scanner
  read as one non-existent file (0 findings, exit 0), then posted "No
  deterministic issues found". It also looked for the scanner without its `.py`
  suffix inside the consumer's checkout, hid scanner failure with `|| true`, and
  printed "No blocking findings" when no report existed.
- The scanner now has four result states in `stats.state` - `complete`,
  `partial`, `unavailable`, `out_of_scope` - and a per-file record (`files[]`).
  `scan_complete` is kept and is true only for `complete`. Missing input files
  are reported instead of ignored.
- The Action validates the report before reading it, and writes the PR comment
  and the exit status from the same decision. With `block_on` CRITICAL or HIGH,
  a `partial` or `unavailable` scan fails; `out_of_scope` passes and says it was
  not reviewed; exceeding `max_files` is `partial`, never clean. On push events
  the summary goes to the job summary instead of a PR comment.
- Default `skip_patterns` now match (the `\n` separators were literal text),
  and `max_files` is compared as a number.
- The scanner ran each tool once per tool *name*, so eslint ran for `.ts` files
  but never for `.js`/`.tsx` files in the same change. It now runs per
  extension group.
- `--tools` is now honoured by the generic semgrep pass.

### Added - evidence for "clean" and "verified" (report_version 2)

- **Clean needs evidence.** In a `report_version: 2` report a `clean` coverage row
  must cite an observation naming the reviewed revision, a bounded scope inside
  the change, the check performed and the class covered. A bare `clean`, an
  unknown observation, a missing or altered artifact, a wrong revision and an
  unrelated scope all fail. New statuses `not_checked` and `inconclusive` let a
  review say what it did not establish; a report containing them is issuable as
  a partial report but does not clear the gate. `hermaguard-coverage` gains
  `--expect-revision`, `--require-evidence` and `--render-markdown`.
- **Verified needs the verifier's record.** `hermaguard-verify` now writes a
  record bound by content hash to the finding, revision, target, PoC and
  expected result, with output redacted. The report gate admits a hard-class
  finding as VERIFIED only if its referenced record exists, is unaltered and
  matches. Unadmitted findings stay in the report as UNVERIFIED (previously the
  whole report was rejected) and the gate fails. Failures are classified as
  absent, invalid, altered, mismatched, stale, refuted, contradictory or
  unverified. `--repo-root` detects a changed target; `--rerun` (opt-in) re-runs
  the PoC. Records are hashed, not signed.
- **Compatibility.** Reports without `report_version` are legacy: still read, now
  labelled "evidence not checked", never certified. The schema docs previously
  linked coverage to findings with `backed_by` while the checker read
  `classes`; `classes` is now documented as the authority and `backed_by` is
  validated as an optional cross-reference.

### Changed - public skill policy aligned (scope, triage, fix re-review)

- Scope is now chosen by effect, not file extension or line count: a one-line
  permission, registration, default or test-contract change is in scope; prose-only
  changes are `out of scope`, never `clean`. The Phase 0 commands no longer
  filter by extension before review.
- Consolidation de-duplicates by root cause but keeps every distinct trigger and
  impact, and adds a triage step before anything is called a defect (violated
  requirement, location, affected party, consequence, evidence; known issues and
  documented exceptions first; scanner warnings start an investigation).
- New pitfalls: re-review the fix on the new revision and record `fixed`,
  `partial`, `not_addressed` or `regressed`; keep incomplete reviews visible.
- Added `references/policy-examples.md` (12 worked cases) and `test_policy.py`,
  which pins the skill text to them.

### Changed - the benchmark scores the right thing (scorer version 3)

- **Location is required.** A finding now matches only with a class in common AND the
  exact normalised repo-relative path AND the expected symbol, line region or outcome.
  Previously a basename match was enough and a blank file on either side passed, so the
  right class in the wrong `app.py` earned credit. Line numbers may move
  (`line_tolerance`); a different file never matches.
- **Controls.** New `extended/` corpus: 4 clean lookalikes, 4 repaired twins of corpus
  bugs, a same-filename-in-two-directories defect and a two-defect case. The original 25
  cases (one finding each) are unchanged apart from added `symbol` / `region` fields.
- **Incomplete is not clean.** No output, an error, `run_ok: false`, an interrupted
  status, or zero findings with no completed checks is incomplete (ungraded), never a
  true negative.
- **Separate counts.** Defects found / missed / in incomplete runs (always summing to the
  expected total), extra and duplicate findings, clean cases wrongly accused, incomplete
  runs, and recall over both all and graded cases. Usage (time, turns, cost) is reported on
  its own and never scored. Two reports of one root cause are one finding plus a duplicate.
- **Versions.** Every score records its scorer version. Version 1 (original keyword) and 2
  (class + basename) are frozen and selectable with `--scorer-version`; the committed
  reference results are pinned to version 1 by `results/MANIFEST.json`, so their published
  numbers are reproduced unchanged. The new default is version 3, so results without a
  `scorer_version` field are now scored strictly - pass `--scorer-version 2` to reproduce
  old numbers.
- Fixed: the HTML report raised `KeyError: 'score'` for any class-mode match, so a report
  could not be generated for a run that found anything.
- `--lint-corpus` lists ground truth that scorer 3 cannot grade.
- Note for the README's reference run: 100% recall was measured over the 5 of 25 cases
  that were run. It is now reported as 5 found / 0 missed / 20 not run.

### Removed

- Unimplemented Action inputs `comment_mode`, `min_severity`, `hermaguard_args`,
  and the placeholder "Run HermaGuard" step that only printed setup advice.
  Passing the inputs is now ignored (GitHub warns on unknown inputs).

### Changed - public skill text

- Removed "adversarial reviewers should ALWAYS find something" and the
  unmeasured "~95% coverage" claim. Zero findings from completed checks is a
  valid result; an unfinished check is not.

### Changed - Action default gate is now HIGH

- No bundled parser emits `CRITICAL`, so the old default `block_on: CRITICAL`
  could never block on a scanner finding. The default is now `HIGH`, and an
  unrecognised `block_on` value fails closed to `HIGH`. Users who set
  `block_on` explicitly are unaffected; set `CRITICAL` or `never` to keep the old
  behaviour.

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
