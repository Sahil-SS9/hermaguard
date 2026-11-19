# HermaGuard review policy: worked examples

Each case is an input and the outcome a reviewer must reach. The same cases are used to check every copy of the policy (this skill, an installed runner, and any portable persona that embeds a HermaGuard-style reviewer). Prompts and tools may differ between copies. Decisions on the same evidence may not.

All inputs are invented and harmless.

## P1. A clean diff with every check completed has zero findings

**Input.** A 12-line change to a pure function. Static checks ran and finished. Every applicable class has a cited observation. Nothing is wrong.
**Expected.** Zero findings. The report is valid and may say clean. The reviewer does not invent a LOW finding, and does not ask for "one more look" unless it can name an unchecked part of the diff or evidence that contradicts the conclusion.

## P2. A skipped or unfinished check makes the review partial

**Input.** Same diff, but the dependency scanner was not installed and the async paths were not traced.
**Expected.** The result is `partial`. The missing scanner and the untraced paths are listed as `not_checked`. The review is never reported as clean, and a partial report may still be issued with whatever findings it has.

## P3. A one-line change that alters behaviour is in scope

**Input.** A diff that flips `allow_anonymous: false` to `true` in a service config, or adds one entry to a permission manifest, or changes a default timeout to `0`.
**Expected.** In scope, reviewed for its effect. Size and file extension do not exclude it.

## P4. A wording-only change is out of scope

**Input.** A diff that only fixes spelling and rephrases a paragraph in a README.
**Expected.** `out of scope`. Not reviewed, and not reported as clean.

## P5. Two reviewers, one root cause

**Input.** Two reviewers each report an unchecked return value at the same call site. One found it through a retry loop, the other through a shutdown path.
**Expected.** One finding. Both triggers and both impacts are kept under it. Agreement between the two reviewers is noted but is not treated as independent proof.

## P6. A documented, intentional exception is not a defect

**Input.** A route marked retired in the API notes is still registered, and the notes say it is kept for a named partner until a stated date.
**Expected.** Not a defect. At most a note that the exception exists and has an expiry. A retired route that is still registered with no such exception is a defect.

## P7. A fix is not closed on a promise

**Input.** A finding was reported against revision A. The author pushes revision B and says it is fixed. At B, the original trigger no longer fires but a related one does.
**Expected.** Review revision B and record `partial` (or `regressed` if the fix introduced a new defect), with fresh evidence from B. A fix verified at A does not certify B. The reviewer does not apply the fix or merge.

## P8. A scanner warning starts an investigation

**Input.** A static scanner reports "possible SQL injection" on a line that builds a query from a constant.
**Expected.** The warning is a hypothesis. The reviewer checks whether untrusted input can reach it. If not, it is not a finding. If it cannot be established either way, it is an unverified risk, not a confirmed defect.

## P9. Triage before calling something a defect

**Input.** A reviewer is about to report "missing validation on `limit`".
**Expected.** The report states the violated requirement, the location, who is affected, the concrete consequence and the evidence. If the contract only says "must accept values up to 100", that is a positive requirement and does not forbid other values; a stronger rule is raised as a question, not a defect. Questions, advice, duplicates, accepted risks and confirmed defects stay in separate categories.

## P10. A "clean" claim needs support

**Input.** A coverage row says `clean` for an injection class with no observation behind it.
**Expected.** Not accepted. Either cite what was checked (revision, scope, check, class covered), or mark the row `not_checked` or `inconclusive`. Never mark a class clean to pass a check.

## P11. "Verified" needs the verifier's record

**Input.** A race-condition finding carries `verdict: VERIFIED` but no verifier record, or a record for a different finding or revision.
**Expected.** The finding stays in the report as UNVERIFIED and the gate fails. A refuted record is never shown as confirmed.

## P12. An empty or unfinished scan is not a clean scan

**Input.** The deterministic pre-scan reports zero findings with state `partial`, `unavailable` or `out_of_scope`.
**Expected.** Reported as exactly that state. "No issues found" is allowed only for `complete`.
