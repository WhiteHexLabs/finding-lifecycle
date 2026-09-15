"""Engine tests: config validation, batch order, recovery, staleness.

Preserved behaviors of the pre-split audit engine (plan.md section 5)."""

import json
import os
import unittest

import yaml

try:
    from ._common import (REPO, AuditBase, legacy_result, run, wfile,
                        write_analysis, wyaml, run_yaml)
except ImportError:
    from _common import (REPO, AuditBase, legacy_result, run, wfile,
                        write_analysis, wyaml, run_yaml)


# ---------------------------------------------------------------------------
# config validation

class TestAuditConfig(AuditBase):
    def test_relative_target_root_resolves_against_work_root(self):
        self.write_config(target_root=os.path.join("..", "target"))
        r = self.prepare()
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout)
        self.assertEqual(len(out["steps"]), 2)
        self.assertTrue(os.path.isdir(os.path.join(self.root, "audits", out["run_id"])))

    def test_empty_skills_is_config_error(self):
        self.write_config(skills=[])
        r = self.prepare()
        self.assertEqual(r.returncode, 2)
        self.assertIn("skills", r.stderr)

    def test_unknown_config_keys_rejected(self):
        wyaml(os.path.join(self.root, "audit-skills.yaml"), {
            "target_root": self.target, "scope": ["src"],
            "skills": [self.skill_a], "shell": "rm -rf /",
        })
        r = self.prepare()
        self.assertEqual(r.returncode, 2)
        self.assertIn("unknown key", r.stderr)

    def test_duplicate_skills_rejected(self):
        self.write_config(skills=[self.skill_a, self.skill_a])
        r = self.prepare()
        self.assertEqual(r.returncode, 2)
        self.assertIn("duplicate", r.stderr)

    def test_scope_escape_rejected(self):
        wfile(os.path.join(self.tmp, "outside", "X.sol"), "x\n")
        self.write_config(scope=[os.path.join("..", "outside")])
        r = self.prepare()
        self.assertEqual(r.returncode, 2)
        self.assertIn("escapes target_root", r.stderr)

    def test_self_call_rejected(self):
        self.write_config(skills=[os.path.join(REPO, "skills", "audit-orchestrator", "SKILL.md")])
        r = self.prepare()
        self.assertEqual(r.returncode, 2)
        self.assertIn("itself", r.stderr)

    def test_lifecycle_skill_rejected(self):
        self.write_config(skills=[os.path.join(REPO, "skills", "finding-lifecycle", "SKILL.md")])
        r = self.prepare()
        self.assertEqual(r.returncode, 2)
        self.assertIn("itself", r.stderr)

    def test_missing_skill_blocks_step_but_batch_continues(self):
        missing = os.path.join(self.tmp, "skills", "gone", "SKILL.md")
        self.write_config(skills=[missing, self.skill_a])
        r = self.prepare()
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout)
        self.assertEqual([s["status"] for s in out["steps"]], ["BLOCKED", "PENDING"])
        # the blocked step still counts as recorded: later steps stay reachable
        report = wfile(os.path.join(self.tmp, "r1.md"), "# r1\nzero findings, covered\n")
        log = wfile(os.path.join(self.tmp, "l1.txt"), "ran\n")
        r = self.record(2, "COMPLETED", report=report, log=log)
        self.assertEqual(r.returncode, 0, r.stderr)
        # but the batch can never pass while a step is BLOCKED
        r = self.check()
        self.assertEqual(r.returncode, 1)

    def test_cannot_complete_step_whose_skill_never_loaded(self):
        missing = os.path.join(self.tmp, "skills", "gone", "SKILL.md")
        self.write_config(skills=[missing])
        self.prepare()
        report = wfile(os.path.join(self.tmp, "r1.md"), "# r1\n")
        r = self.record(1, "COMPLETED", report=report,
                        note="pretending the missing skill ran fine")
        self.assertEqual(r.returncode, 2)
        self.assertIn("skill entry", r.stderr)

    def test_deprecated_case_root_alias(self):
        self.write_config()
        r = run(["prepare", "--case-root", self.root, "--json"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("deprecated", r.stderr)
        out = json.loads(r.stdout)
        self.assertEqual(len(out["steps"]), 2)


# ---------------------------------------------------------------------------
# ordering, retries, completion

class TestAuditOrdering(AuditBase):
    def test_cannot_skip_unexecuted_step(self):
        self.write_config()
        self.prepare()
        report = wfile(os.path.join(self.tmp, "r2.md"), "# r2\n")
        r = self.record(2, "COMPLETED", report=report)
        self.assertEqual(r.returncode, 2)
        self.assertIn("record them first", r.stderr)

    def test_failure_continues_but_blocks_check(self):
        self.write_config()
        self.prepare()
        r = self.record(1, "FAILED", note="skill crashed reading a contract; no report")
        self.assertEqual(r.returncode, 0, r.stderr)
        report = wfile(os.path.join(self.tmp, "r2.md"), "# r2\ncovered everything\n")
        log = wfile(os.path.join(self.tmp, "l2.txt"), "ran\n")
        r = self.record(2, "COMPLETED", report=report, log=log)
        self.assertEqual(r.returncode, 0, r.stderr)
        # audit completion stays blocked while a failure is unresolved
        r = self.check()
        self.assertEqual(r.returncode, 1)

    def test_rerun_failed_step_then_check_passes(self):
        self.write_config()
        self.prepare()
        self.record(1, "FAILED", note="skill crashed reading a contract; no report")
        self.record(2, "COMPLETED",
                    report=wfile(os.path.join(self.tmp, "r2.md"), "# r2\ncovered\n"),
                    log=wfile(os.path.join(self.tmp, "l2.txt"), "ran\n"))
        # retry step 1 (nothing before it unresolved) -> completes
        report1 = wfile(os.path.join(self.tmp, "r1.md"), "# r1\nretry ok; zero findings\n")
        log1 = wfile(os.path.join(self.tmp, "l1.txt"), "ran\n")
        r = self.record(1, "COMPLETED", report=report1, log=log1)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = self.check()
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_retry_out_of_original_order_rejected(self):
        self.write_config()
        self.prepare()
        self.record(1, "FAILED", note="first pass failed for step one")
        self.record(2, "FAILED", note="first pass failed for step two")
        r = self.record(2, "FAILED", note="retrying step two while step one failed")
        self.assertEqual(r.returncode, 2)
        self.assertIn("original order", r.stderr)

    def test_zero_findings_report_completes(self):
        self.write_config()
        self.complete_all()
        r = run(["check", "--work-root", self.root, "--json"])
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout)
        self.assertEqual(out["status"], "PASS")

    def test_completed_requires_report_and_substantive_note(self):
        self.write_config()
        self.prepare()
        r = self.record(1, "COMPLETED", note="ran fine, covered everything, nothing found")
        self.assertEqual(r.returncode, 2)
        self.assertIn("report", r.stderr)
        report = wfile(os.path.join(self.tmp, "r1.md"), "# r1\n")
        r = self.record(1, "COMPLETED", note="too short", report=report)
        self.assertEqual(r.returncode, 2)
        self.assertIn("note", r.stderr)

    def test_completed_step_cannot_be_re_recorded(self):
        self.write_config()
        self.prepare()
        self.record(1, "COMPLETED",
                    report=wfile(os.path.join(self.tmp, "r1.md"), "# r1\n"),
                    log=wfile(os.path.join(self.tmp, "l1.txt"), "x\n"))
        r = self.record(1, "FAILED", note="changed my mind about the step one result")
        self.assertEqual(r.returncode, 2)
        self.assertIn("not re-executed", r.stderr)

    def test_revision_conflict_rejected(self):
        self.write_config()
        self.prepare()
        report = wfile(os.path.join(self.tmp, "r1.md"), "# r1\n")
        r = self.record(1, "COMPLETED", report=report, rev=99)
        self.assertEqual(r.returncode, 2)
        self.assertIn("revision conflict", r.stderr)

    def test_finalized_run_rejects_further_records(self):
        self.write_config(skills=[self.skill_a])
        self.complete_all()
        rid = self.rid()
        write_analysis(self.root, rid)
        r = run(["finalize", "--work-root", self.root,
                 "--expected-revision", str(self.rev())])
        self.assertEqual(r.returncode, 0, r.stderr)
        report = wfile(os.path.join(self.tmp, "again.md"), "# again\n")
        r = self.record(1, "FAILED", note="trying to mutate a finalized batch")
        self.assertEqual(r.returncode, 2)
        self.assertIn("finalized", r.stderr)


# ---------------------------------------------------------------------------
# recovery and history preservation

class TestAuditRecovery(AuditBase):
    def test_prepare_recovery_does_not_rerun_completed(self):
        self.write_config()
        self.complete_all()
        rid = self.rid()
        r = self.prepare()
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout)
        self.assertEqual(out["run_id"], rid)
        self.assertTrue(out["recovered"])
        self.assertEqual(os.listdir(os.path.join(self.root, "audits")), [rid])

    def test_prepare_new_keeps_history(self):
        self.write_config()
        self.complete_all()
        old = self.rid()
        r = self.prepare("--new")
        self.assertEqual(r.returncode, 0, r.stderr)
        new = self.rid()
        self.assertNotEqual(old, new)
        self.assertTrue(os.path.isfile(os.path.join(self.root, "audits", old, "run.yaml")))
        self.assertEqual(run_yaml(self.root, new)["steps"][0]["status"], "PENDING")

    def test_retry_preserves_old_attempts(self):
        self.write_config()
        self.prepare()
        self.record(1, "FAILED", note="first attempt failed for the record")
        self.record(1, "COMPLETED",
                    report=wfile(os.path.join(self.tmp, "r1.md"), "# r1\n"),
                    log=wfile(os.path.join(self.tmp, "l1.txt"), "x\n"),
                    note="second attempt completed with full coverage")
        atts = run_yaml(self.root, self.rid())["steps"][0]["attempts"]
        self.assertEqual(len(atts), 2)
        self.assertEqual(atts[0]["status"], "FAILED")
        self.assertEqual(atts[0]["note"], "first attempt failed for the record")
        self.assertEqual(atts[-1]["status"], "COMPLETED")


# ---------------------------------------------------------------------------
# staleness: config / target / skill / artifact drift

class TestAuditStaleness(AuditBase):
    def test_config_change_requires_new_batch(self):
        self.write_config()
        self.complete_all()
        self.write_config(skills=[self.skill_b, self.skill_a])  # reorder = new hash
        r = self.check()
        self.assertEqual(r.returncode, 1)
        self.assertIn("config changed", r.stdout + r.stderr)
        r = self.record(2, "FAILED", note="attempting to record into a stale batch")
        self.assertEqual(r.returncode, 1)
        r = self.prepare()
        self.assertEqual(r.returncode, 1)
        self.assertIn("--new", r.stdout + r.stderr)

    def test_target_change_requires_new_batch(self):
        self.write_config()
        self.complete_all()
        wfile(os.path.join(self.target, "src", "Vault.sol"), "contract Vault2 {}\n")
        r = self.check()
        self.assertEqual(r.returncode, 1)
        self.assertIn("scope drifted", r.stdout + r.stderr)

    def test_target_file_added_requires_new_batch(self):
        self.write_config()
        self.complete_all()
        wfile(os.path.join(self.target, "src", "New.sol"), "contract New {}\n")
        r = self.check()
        self.assertEqual(r.returncode, 1)
        self.assertIn("New.sol", r.stdout + r.stderr)

    def test_target_file_deleted_requires_new_batch(self):
        self.write_config()
        self.complete_all()
        os.remove(os.path.join(self.target, "src", "Pool.sol"))
        r = self.check()
        self.assertEqual(r.returncode, 1)
        self.assertIn("scope drifted", r.stdout + r.stderr)

    def test_skill_change_requires_new_batch(self):
        self.write_config()
        self.complete_all()
        wfile(self.skill_b, "# beta\n\ninstructions changed\n")
        r = self.check()
        self.assertEqual(r.returncode, 1)
        self.assertIn("skill entry changed", r.stdout + r.stderr)

    def test_tampered_canonical_artifact_fails_check(self):
        self.write_config()
        self.complete_all()
        rid = self.rid()
        data = run_yaml(self.root, rid)
        report_rel = data["steps"][0]["attempts"][-1]["report"]["path"]
        wfile(os.path.join(self.root, report_rel), "# tampered after the fact\n")
        r = self.check()
        self.assertEqual(r.returncode, 1)
        self.assertIn("hash mismatch", r.stdout + r.stderr)

    def test_tampered_manifest_fails_check(self):
        self.write_config()
        self.complete_all()
        rid = self.rid()
        mp = os.path.join(self.root, "audits", rid, "steps", "1", "artifact-manifest.yaml")
        with open(mp, encoding="utf-8") as f:
            m = yaml.safe_load(f)
        m["artifacts"][0]["sha256"] = "0" * 64
        with open(mp, "w", encoding="utf-8") as f:
            yaml.safe_dump(m, f)
        r = self.check()
        self.assertEqual(r.returncode, 1)
        self.assertIn("hash mismatch", r.stdout + r.stderr)


# ---------------------------------------------------------------------------
# legacy batch compatibility (pre-split layout)

class TestLegacyBatches(AuditBase):
    def legacy_complete(self):
        """Record with the legacy flat result shape (no schema/primary)."""
        out = json.loads(self.prepare().stdout)
        for st in out["steps"]:
            report = wfile(os.path.join(self.tmp, f"lrep-{st['step']}.md"),
                           f"# legacy report {st['step']}\n\ncovered everything\n")
            log = wfile(os.path.join(self.tmp, f"llog-{st['step']}.txt"), "ran\n")
            p = legacy_result(os.path.join(self.tmp, f"lres-{st['step']}.yaml"),
                              report=report, log=log,
                              note=f"legacy skill {st['step']} covered src fully")
            r = run(["record", "--work-root", self.root, "--step", st["step"],
                     "--input", p, "--expected-revision",
                     run_yaml(self.root, self.rid())["revision"]])
            self.assertEqual(r.returncode, 0, r.stderr)

    def test_legacy_result_shape_accepted(self):
        self.write_config()
        self.legacy_complete()
        r = self.check()
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_legacy_completed_step_exposed_as_manifest_at_finalize(self):
        import hashlib

        def sha(p):
            return hashlib.sha256(open(p, "rb").read()).hexdigest()

        self.write_config(skills=[self.skill_a])
        rid = json.loads(self.prepare().stdout)["run_id"]
        # rewrite step 1 into the pre-split layout: frozen copies directly
        # under steps/<N>/, attempt dicts without canonical artifacts
        report_rel = f"audits/{rid}/steps/1/attempt-1-report.md"
        wfile(os.path.join(self.root, report_rel), "# legacy report\n\ncovered\n")
        log_rel = f"audits/{rid}/steps/1/attempt-1-log.txt"
        wfile(os.path.join(self.root, log_rel), "ran\n")
        data = run_yaml(self.root, rid)
        st = data["steps"][0]
        st["status"] = "COMPLETED"
        st["attempts"] = [{
            "at": "2026-01-01T00:00:00+00:00", "status": "COMPLETED",
            "note": "legacy completed attempt recorded by the old tool",
            "report": {"path": report_rel, "sha256": sha(os.path.join(self.root, report_rel))},
            "log": {"path": log_rel, "sha256": sha(os.path.join(self.root, log_rel))},
        }]
        wyaml(os.path.join(self.root, "audits", rid, "run.yaml"), data)
        # no artifact-manifest.yaml exists yet (legacy layout)
        self.assertFalse(os.path.isfile(
            os.path.join(self.root, "audits", rid, "steps", "1", "artifact-manifest.yaml")))
        write_analysis(self.root, rid)
        r = run(["finalize", "--work-root", self.root, "--expected-revision", "1"])
        self.assertEqual(r.returncode, 0, r.stderr)
        # the adapter synthesized a manifest from the frozen copies
        mp = os.path.join(self.root, "audits", rid, "steps", "1", "artifact-manifest.yaml")
        self.assertTrue(os.path.isfile(mp))
        with open(mp, encoding="utf-8") as f:
            m = f.read()
        self.assertIn("primary-report", m)
        self.assertIn("legacy-frozen-copy", m)


if __name__ == "__main__":
    unittest.main()
