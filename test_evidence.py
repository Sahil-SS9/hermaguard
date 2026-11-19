"""C2 tests: evidence for `clean` coverage rows and for VERIFIED findings.

Fixtures are original, harmless and owned by this suite. No real systems and
no credentials are used; the one PoC that runs executes a toy in-memory class
inside the verifier's own sandbox.
"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


COV = _load("cov_evidence", "tools/hermaguard-coverage/hermaguard-coverage.py")
VER = _load("ver_evidence", "tools/hermaguard-verify/hermaguard-verify.py")
MCP = _load("mcp_evidence", "mcp/hermaguard-feedback/server.py")

REV = "9f3c2d1e8a7b6c5d4e3f20191817161514131211"


def v2_report(ledger, observation_overrides=None, files=("src/app.py",)):
    """A complete, genuine v2 report: one tool-free observation backs every class."""
    ids = [c["id"] for c in ledger["classes"] if c["applicable"]]
    obs = {"id": "OBS-1", "kind": "manual", "revision": REV, "scope": [f"{files[0]}::handle"],
           "check": "read every branch of handle() for these classes", "covers": ids}
    obs.update(observation_overrides or {})
    return {
        "report_version": 2, "revision": REV, "findings": [], "observations": [obs],
        "coverage": [{"class_id": i, "status": "clean", "observation": "OBS-1"} for i in ids],
    }


class CleanNeedsEvidence(unittest.TestCase):
    def setUp(self):
        self.ledger = COV.build_ledger(["src/app.py"])
        self.ids = [c["id"] for c in self.ledger["classes"] if c["applicable"]]
        self.tmp = Path(tempfile.mkdtemp(prefix="hg-cov-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def check(self, report, **kw):
        return COV.check_report(report, self.ledger, report_dir=self.tmp, **kw)

    def test_genuine_scope_matched_observation_passes(self):
        r = self.check(v2_report(self.ledger))
        self.assertTrue(r["ok"], r["errors"])
        self.assertTrue(r["issuable"])
        self.assertTrue(r["evidence_checked"])
        self.assertFalse(r["legacy"])

    def test_one_observation_may_back_many_rows(self):
        report = v2_report(self.ledger)
        self.assertGreater(len(report["coverage"]), 5)
        self.assertEqual(len(report["observations"]), 1)
        self.assertTrue(self.check(report)["ok"])

    def test_bare_clean_fails_in_v2(self):
        report = v2_report(self.ledger)
        report["coverage"][0] = {"class_id": self.ids[0], "status": "clean"}
        r = self.check(report)
        self.assertFalse(r["ok"])
        self.assertFalse(r["issuable"])
        self.assertTrue(any("without evidence" in e for e in r["errors"]), r["errors"])

    def test_unknown_observation_fails(self):
        report = v2_report(self.ledger)
        report["coverage"][0]["observation"] = "OBS-404"
        self.assertTrue(any("unknown observation" in e for e in self.check(report)["errors"]))

    def test_missing_artifact_fails(self):
        report = v2_report(self.ledger, {"kind": "tool", "artifact": "evidence/scan.json",
                                         "artifact_sha256": "0" * 64})
        r = self.check(report)
        self.assertFalse(r["ok"])
        self.assertTrue(any("missing or outside" in e for e in r["errors"]), r["errors"])

    def test_tool_observation_without_artifact_fails(self):
        r = self.check(v2_report(self.ledger, {"kind": "tool"}))
        self.assertTrue(any("has no artifact" in e for e in r["errors"]))

    def test_altered_artifact_fails_and_intact_artifact_passes(self):
        art = self.tmp / "evidence"
        art.mkdir()
        (art / "scan.json").write_text('{"ok": true}')
        good = COV._sha256_file(art / "scan.json")
        report = v2_report(self.ledger, {"kind": "tool", "artifact": "evidence/scan.json", "artifact_sha256": good})
        self.assertTrue(self.check(report)["ok"])
        (art / "scan.json").write_text('{"ok": false}')
        self.assertTrue(any("altered" in e for e in self.check(report)["errors"]))

    def test_artifact_path_cannot_escape_the_report_directory(self):
        outside = self.tmp.parent / "outside-evidence.txt"
        outside.write_text("x")
        self.addCleanup(outside.unlink)
        report = v2_report(self.ledger, {"artifact": "../outside-evidence.txt",
                                         "artifact_sha256": COV._sha256_file(outside)})
        self.assertTrue(any("missing or outside" in e for e in self.check(report)["errors"]))

    def test_wrong_revision_fails(self):
        r = self.check(v2_report(self.ledger, {"revision": "deadbeef"}))
        self.assertTrue(any("stale" in e for e in r["errors"]), r["errors"])
        self.assertFalse(r["ok"])

    def test_report_for_a_different_head_fails_when_head_is_known(self):
        r = self.check(v2_report(self.ledger), expect_revision="0" * 40)
        self.assertTrue(any("stale report" in e for e in r["errors"]))

    def test_unrelated_scope_fails(self):
        r = self.check(v2_report(self.ledger, {"scope": ["docs/other.py::main"]}))
        self.assertTrue(any("unrelated" in e for e in r["errors"]), r["errors"])

    def test_observation_that_does_not_cover_the_class_fails(self):
        r = self.check(v2_report(self.ledger, {"covers": [self.ids[0]]}))
        self.assertTrue(any("does not cover" in e for e in r["errors"]))

    def test_observation_must_say_which_check_was_done(self):
        r = self.check(v2_report(self.ledger, {"check": "  "}))
        self.assertTrue(any("which check" in e for e in r["errors"]))

    def test_partial_report_is_issuable_keeps_findings_but_fails_the_gate(self):
        report = v2_report(self.ledger)
        first = self.ids[0]
        report["coverage"][0] = {"class_id": first, "status": "not_checked",
                                 "reason": "async paths not traced - time ran out"}
        report["findings"] = [{"id": "HG-001", "classes": [self.ids[1]], "file": "src/app.py"}]
        report["coverage"][1] = {"class_id": self.ids[1], "status": "finding", "backed_by": ["HG-001"]}
        r = self.check(report)
        self.assertTrue(r["issuable"], r["errors"])
        self.assertFalse(r["ok"])
        self.assertEqual(r["unresolved"], [first])
        md = COV.render_markdown(r, self.ledger, report)
        self.assertIn("FAIL - partial report (issuable)", md)
        self.assertIn("async paths not traced", md)
        self.assertIn("HG-001", md)

    def test_inconclusive_needs_a_reason(self):
        report = v2_report(self.ledger)
        report["coverage"][0] = {"class_id": self.ids[0], "status": "inconclusive"}
        r = self.check(report)
        self.assertFalse(r["issuable"])
        self.assertTrue(any("without saying what is unresolved" in e for e in r["errors"]))

    def test_missing_row_is_still_a_gap_and_not_issuable(self):
        report = v2_report(self.ledger)
        dropped = report["coverage"].pop()["class_id"]
        r = self.check(report)
        self.assertEqual(r["gaps"], [dropped])
        self.assertFalse(r["issuable"])

    def test_backed_by_must_reference_a_finding_that_cites_the_class(self):
        report = v2_report(self.ledger)
        report["findings"] = [{"id": "HG-001", "classes": [self.ids[2]]}]
        report["coverage"][1] = {"class_id": self.ids[1], "status": "finding", "backed_by": ["HG-001"]}
        report["findings"].append({"id": "HG-002", "classes": [self.ids[1]]})
        r = self.check(report)
        self.assertTrue(any("backed_by 'HG-001'" in e for e in r["errors"]), r["errors"])

    def test_unsupported_report_version_is_rejected(self):
        report = v2_report(self.ledger)
        report["report_version"] = 3
        self.assertTrue(any("unsupported report_version" in e for e in self.check(report)["errors"]))

    def test_v2_needs_a_revision(self):
        report = v2_report(self.ledger)
        del report["revision"]
        self.assertTrue(any("no `revision`" in e for e in self.check(report)["errors"]))

    def test_report_version_constants_agree_across_tools(self):
        self.assertEqual(COV.REPORT_VERSION, VER.REPORT_VERSION)


class LegacyReports(unittest.TestCase):
    def setUp(self):
        self.ledger = COV.build_ledger(["src/app.py"])
        ids = [c["id"] for c in self.ledger["classes"] if c["applicable"]]
        self.legacy = {"coverage": [{"class_id": i, "status": "clean"} for i in ids], "findings": []}

    def test_legacy_report_still_loads_but_is_labelled_unchecked(self):
        r = COV.check_report(self.legacy, self.ledger)
        self.assertTrue(r["ok"])
        self.assertTrue(r["legacy"])
        self.assertFalse(r["evidence_checked"])
        self.assertTrue(any("NOT checked" in w for w in r["warnings"]))

    def test_legacy_report_is_never_silently_upgraded(self):
        r = COV.check_report(self.legacy, self.ledger)
        self.assertNotIn("report_version", self.legacy)
        self.assertFalse(r["evidence_checked"])

    def test_require_evidence_fails_a_legacy_report(self):
        r = COV.check_report(self.legacy, self.ledger, require_evidence=True)
        self.assertFalse(r["ok"])

    def test_markdown_renderer_labels_legacy(self):
        r = COV.check_report(self.legacy, self.ledger)
        md = COV.render_markdown(r, self.ledger, self.legacy)
        self.assertIn("LEGACY report", md)
        self.assertIn("legacy - not checked", md)


# --------------------------------------------------------------------------- verify

TARGET = '''class Account:
    def __init__(self):
        self.balance = 100

    def withdraw(self, amount):
        if self.balance >= amount:
            self.balance -= amount
            return True
        return False
'''
# Demonstrates a double spend deterministically (an interleaving is simulated).
POC_BUG = '''from app import Account
a = Account()
ok1 = a.balance >= 80      # both "threads" pass the check ...
ok2 = a.balance >= 80
if ok1 and ok2:            # ... before either debits
    a.balance -= 80
    a.balance -= 80
assert a.balance >= 0, "balance went negative: %d" % a.balance
'''
POC_CLEAN = "from app import Account\nassert Account().withdraw(10) is True\n"


class VerifiedNeedsTheVerifiersRecord(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="hg-ver-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.repo = self.tmp / "repo"
        (self.repo / "src").mkdir(parents=True)
        (self.repo / "src" / "app.py").write_text(TARGET)
        self.ev = self.tmp / "evidence"
        self.ev.mkdir()
        (self.ev / "poc.py").write_text(POC_BUG)
        self.finding = {"id": "HG-001", "classes": ["CWE-362"], "file": "src/app.py"}

    def make_record(self, name="HG-001.json", poc=POC_BUG, finding=None, revision=REV, expect_fail=True,
                    target=None):
        (self.ev / "poc.py").write_text(poc)
        target = target or str(self.repo / "src" / "app.py")
        evidence = VER.run_poc(str(self.ev / "poc.py"), target, expect_fail=expect_fail)
        record = VER.build_record(finding or self.finding, evidence, poc_path=str(self.ev / "poc.py"),
                                  target_path=target, revision=revision, expect_fail=expect_fail)
        # record the repo-relative target, as the CLI does when run from the repo root
        record["binding"]["target"]["path"] = "src/app.py"
        record["record_sha256"] = VER.record_digest(record)
        (self.ev / name).write_text(json.dumps(record))
        return record

    def report(self, record_name="HG-001.json", label="VERIFIED", extra=None):
        path = self.ev / record_name
        ref = {"verdict": label}
        if path.exists():
            ref.update({"record": record_name, "record_sha256": json.loads(path.read_text())["record_sha256"]})
        finding = dict(self.finding, verification=ref)
        finding.update(extra or {})
        return {"report_version": 2, "revision": REV, "findings": [finding]}

    def policy(self, report, **kw):
        kw.setdefault("evidence_dir", self.ev)
        return VER.check_report_policy(report, **kw)

    def only(self, result):
        self.assertEqual(len(result["findings"]), 1)
        return result["findings"][0]

    def test_intact_matching_record_is_admitted(self):
        rec = self.make_record()
        self.assertEqual(rec["verification"]["verdict"], VER.VERIFIED)
        r = self.policy(self.report())
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.only(r)["status"], "admitted")
        self.assertTrue(r["evidence_checked"])

    def test_bare_label_is_rejected_and_finding_stays_as_unverified(self):
        r = self.policy({"report_version": 2, "revision": REV,
                         "findings": [dict(self.finding, verification={"verdict": "VERIFIED"})]})
        f = self.only(r)
        self.assertFalse(r["ok"])
        self.assertEqual((f["status"], f["effective_verdict"]), ("absent", "UNVERIFIED"))
        self.assertEqual(r["hard_class_findings"], 1)  # still in the report, not dropped

    def test_missing_record_file_is_absent(self):
        rep = self.report()
        rep["findings"][0]["verification"].update({"record": "nope.json", "record_sha256": "a" * 64})
        self.assertEqual(self.only(self.policy(rep))["status"], "absent")

    def test_record_path_cannot_escape_the_evidence_directory(self):
        (self.tmp / "elsewhere.json").write_text("{}")
        rep = self.report()
        rep["findings"][0]["verification"].update({"record": "../elsewhere.json", "record_sha256": "a" * 64})
        self.assertEqual(self.only(self.policy(rep))["status"], "absent")

    def test_record_for_another_finding_is_mismatched(self):
        self.make_record(finding={"id": "HG-999", "classes": ["CWE-362"], "file": "src/app.py"})
        self.assertEqual(self.only(self.policy(self.report()))["status"], "mismatched")

    def test_record_for_a_different_target_is_mismatched(self):
        self.make_record()
        rep = self.report(extra={"file": "src/other.py"})
        self.assertEqual(self.only(self.policy(rep))["status"], "mismatched")

    def test_record_for_unrelated_class_is_mismatched(self):
        self.make_record(finding={"id": "HG-001", "classes": ["CWE-89"], "file": "src/app.py"})
        self.assertEqual(self.only(self.policy(self.report()))["status"], "mismatched")

    def test_stale_revision_is_rejected(self):
        self.make_record(revision="0ldrev")
        self.assertEqual(self.only(self.policy(self.report()))["status"], "stale")

    def test_record_without_revision_is_stale(self):
        self.make_record(revision=None)
        self.assertEqual(self.only(self.policy(self.report()))["status"], "stale")

    def test_target_changed_since_the_record_is_stale_when_repo_root_given(self):
        self.make_record()
        (self.repo / "src" / "app.py").write_text(TARGET + "# changed\n")
        r = self.policy(self.report(), repo_root=self.repo)
        self.assertEqual(self.only(r)["status"], "stale")

    def test_edited_record_is_altered(self):
        self.make_record()
        rep = self.report()  # captures the genuine hash
        path = self.ev / "HG-001.json"
        rec = json.loads(path.read_text())
        rec["verification"]["signal"] = "edited after the fact"
        path.write_text(json.dumps(rec))
        self.assertEqual(self.only(self.policy(rep))["status"], "altered")

    def test_swapping_in_a_different_genuine_record_is_altered(self):
        self.make_record()
        rep = self.report()
        rep["findings"][0]["verification"]["record_sha256"] = "f" * 64
        self.assertEqual(self.only(self.policy(rep))["status"], "altered")

    def test_refuted_record_can_never_be_presented_as_confirmed(self):
        rec = self.make_record(poc=POC_CLEAN)
        self.assertEqual(rec["verification"]["verdict"], VER.REFUTED)
        r = self.policy(self.report(label="VERIFIED"))  # the finding lies
        f = self.only(r)
        self.assertFalse(r["ok"])
        self.assertEqual((f["status"], f["effective_verdict"]), ("refuted", "REFUTED"))

    def test_unverified_record_stays_unverified(self):
        rec = self.make_record(poc=POC_CLEAN, expect_fail=False)
        self.assertEqual(rec["verification"]["verdict"], VER.UNVERIFIED)
        self.assertEqual(self.only(self.policy(self.report()))["status"], "unverified")

    def test_rerun_confirms_a_genuine_record(self):
        self.make_record()
        r = self.policy(self.report(), repo_root=self.repo, rerun=True)
        self.assertTrue(r["ok"], r)

    def test_rerun_detects_a_tampered_poc(self):
        self.make_record()
        (self.ev / "poc.py").write_text(POC_CLEAN)
        r = self.policy(self.report(), repo_root=self.repo, rerun=True)
        self.assertEqual(self.only(r)["status"], "absent")

    def test_rerun_needs_the_target(self):
        self.make_record()
        r = self.policy(self.report(), rerun=True)
        self.assertEqual(self.only(r)["status"], "absent")

    def test_non_hard_class_findings_are_unaffected(self):
        rep = {"report_version": 2, "revision": REV,
               "findings": [{"id": "HG-002", "classes": ["CWE-89"], "file": "src/app.py"}]}
        r = self.policy(rep)
        self.assertTrue(r["ok"])
        self.assertEqual(r["hard_class_findings"], 0)

    def test_legacy_label_is_read_but_never_certified(self):
        r = VER.check_report_policy({"findings": [dict(self.finding, verification={"verdict": "VERIFIED"})]})
        self.assertTrue(r["ok"])  # old behaviour preserved for old reports
        self.assertTrue(r["legacy"])
        self.assertFalse(r["evidence_checked"])
        self.assertEqual(r["findings"][0]["status"], "legacy")

    def test_require_evidence_fails_legacy(self):
        r = VER.check_report_policy({"findings": []}, require_evidence=True)
        self.assertFalse(r["ok"])

    def test_documented_limit_a_forger_who_rewrites_record_and_hash_is_not_stopped(self):
        # Honest scope: no signing keys. This stops copied, stale and edited
        # records; it cannot stop someone who can write the record AND its hash.
        self.make_record()
        path = self.ev / "HG-001.json"
        rec = json.loads(path.read_text())
        rec["verification"]["signal"] = "forged but self-consistent"
        rec["record_sha256"] = VER.record_digest(rec)
        path.write_text(json.dumps(rec))
        self.assertTrue(self.policy(self.report())["ok"])
        self.assertIn("not a forger", VER.__doc__)

    def test_stored_output_is_redacted_before_hashing(self):
        out = VER.redact("api_key = EXAMPLE-KEY-DO-NOT-USE-123\npassword: hunter2\nBearer abcdefgh12345678")
        self.assertNotIn("EXAMPLE-KEY-DO-NOT-USE-123", out)
        self.assertNotIn("hunter2", out)
        self.assertNotIn("abcdefgh12345678", out)
        self.assertEqual(out.count("[REDACTED]"), 3)

    def test_cli_round_trip_produces_a_bindable_record_and_gate_passes(self):
        verify = str(ROOT / "tools" / "hermaguard-verify" / "hermaguard-verify.py")
        (self.ev / "poc.py").write_text(POC_BUG)
        rec_path = self.ev / "HG-001.json"
        run = subprocess.run(
            [sys.executable, verify, "--poc", str(self.ev / "poc.py"), "--target", "src/app.py",
             "--finding", json.dumps({"id": "HG-001", "classes": ["CWE-362"], "file": "src/app.py"}),
             "--revision", REV, "--expect-fail", "--json", str(rec_path)],
            cwd=self.repo, capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        rec = json.loads(rec_path.read_text())
        self.assertEqual(rec["binding"]["target"]["path"], "src/app.py")
        self.assertEqual(rec["binding"]["revision"], REV)
        report_path = self.ev / "report.json"
        report_path.write_text(json.dumps(self.report()))
        gate = subprocess.run([sys.executable, verify, "--check-report", str(report_path),
                               "--repo-root", str(self.repo)], capture_output=True, text=True)
        self.assertEqual(gate.returncode, 0, gate.stdout + gate.stderr)
        # a bare label in the same position fails the gate
        report_path.write_text(json.dumps({"report_version": 2, "revision": REV, "findings": [
            dict(self.finding, verification={"verdict": "VERIFIED"})]}))
        gate = subprocess.run([sys.executable, verify, "--check-report", str(report_path)],
                              capture_output=True, text=True)
        self.assertEqual(gate.returncode, 1)
        self.assertIn("UNVERIFIED [absent]", gate.stdout)


class DownstreamReaders(unittest.TestCase):
    """The feedback MCP consumer must keep reading both report formats."""

    def record(self, report):
        with tempfile.TemporaryDirectory() as d:
            MCP.DB_PATH = os.path.join(d, "fb.db")
            conn = MCP.get_db()
            try:
                return MCP.tool_record_findings(conn, {"run_id": "HG-T-1", "findings_json": json.dumps(report)})
            finally:
                conn.close()

    base = {"meta": {"timestamp": "2026-11-19T00:00:00Z", "scope": {"files_changed": 1}},
            "summary": {"total": 1}, "verdict": {"overall_risk": "HIGH"}}

    def finding(self):
        return {"id": "HG-001", "severity": "HIGH", "source_agent": "adversarial-reviewer",
                "file": "src/app.py", "classes": ["CWE-362"],
                "verification": {"verdict": "UNVERIFIED"}}

    def test_legacy_report_is_recorded(self):
        out = self.record(dict(self.base, findings=[self.finding()],
                               coverage=[{"class_id": "CWE-89", "status": "clean"}]))
        self.assertEqual(out["status"], "recorded")
        self.assertEqual(out["findings_stored"], 1)

    def test_v2_report_with_new_fields_is_recorded_and_unverified_finding_kept(self):
        out = self.record(dict(self.base, report_version=2, revision=REV, findings=[self.finding()],
                               observations=[{"id": "OBS-1"}],
                               coverage=[{"class_id": "CWE-89", "status": "not_checked", "reason": "x"}]))
        self.assertEqual(out["status"], "recorded")
        self.assertEqual(out["findings_stored"], 1)


if __name__ == "__main__":
    unittest.main()
