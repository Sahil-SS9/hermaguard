"""Policy-text guard for the public skill (C3).

Written policy is not mechanical enforcement, but a skill that contradicts its
own tools drifts back silently. These tests pin the rules in policy-examples.md
to the wording of SKILL.md so a regression is caught in CI.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SKILL = (ROOT / "SKILL.md").read_text(encoding="utf-8")
EXAMPLES = (ROOT / "references" / "policy-examples.md").read_text(encoding="utf-8")


class NoContradictions(unittest.TestCase):
    def test_no_quota_for_findings(self):
        self.assertNotRegex(SKILL, r"(?i)ALWAYS find something")
        self.assertNotRegex(SKILL, r"(?i)should always find")

    def test_no_unmeasured_coverage_percentage(self):
        self.assertNotRegex(SKILL, r"~?\d{2}% coverage")

    def test_scope_is_not_decided_by_suffix_or_size(self):
        self.assertNotIn("Skip: test files", SKILL)
        self.assertNotRegex(SKILL, r"one-liner with no control flow")
        self.assertNotRegex(SKILL, r"No code was modified \(config/docs-only")
        phase0 = SKILL[SKILL.index("### Phase 0: Scope Detection"):SKILL.index("### Phase 0b")]
        self.assertNotRegex(phase0, r"-- '\*\.ts'")  # no extension pathspec filtering before review
        self.assertIn("by effect", phase0)

    def test_nothing_in_scope_is_out_of_scope_not_clean(self):
        phase0 = SKILL[SKILL.index("### Phase 0: Scope Detection"):SKILL.index("### Phase 0b")]
        self.assertRegex(phase0, r"`out of scope`, never `clean`")


class RequiredRules(unittest.TestCase):
    def test_zero_findings_is_valid_and_evidence_bound(self):
        self.assertIn("Accept an evidenced zero", SKILL)
        self.assertIn("not a clean result", SKILL)

    def test_fix_rereview_states_and_new_revision(self):
        for state in ("fixed", "partial", "not_addressed", "regressed"):
            self.assertIn(f"`{state}`", SKILL)
        self.assertIn("a verified fix for one revision does not certify another", SKILL)

    def test_triage_before_defect(self):
        for phrase in ("Triage before calling something a defect", "documented exceptions",
                       "A scanner warning starts an investigation", "positive requirement"):
            self.assertIn(phrase, SKILL)

    def test_dedupe_keeps_distinct_triggers(self):
        self.assertIn("De-duplicate by root cause", SKILL)
        self.assertIn("Keep every distinct trigger", SKILL)

    def test_incomplete_reviews_stay_visible(self):
        self.assertIn("Keep incomplete reviews visible", SKILL)

    def test_prescan_state_rule(self):
        self.assertIn("an empty pre-scan is not a clean pre-scan", SKILL)


class ExamplesFile(unittest.TestCase):
    def test_every_case_has_input_and_expected(self):
        cases = re.split(r"(?m)^## (P\d+)\. ", EXAMPLES)[1:]
        ids = cases[0::2]
        bodies = cases[1::2]
        self.assertEqual(ids, [f"P{i}" for i in range(1, 13)])
        for cid, body in zip(ids, bodies):
            self.assertIn("**Input.**", body, cid)
            self.assertIn("**Expected.**", body, cid)

    def test_examples_contain_no_private_references(self):
        for needle in ("/home/", "Sahil", "kensei", "Foundry", "agent-personas"):
            self.assertNotIn(needle, EXAMPLES)


if __name__ == "__main__":
    unittest.main()
