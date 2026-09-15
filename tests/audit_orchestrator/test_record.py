"""result.yaml schema, artifact normalization, fixed-output skills and the
target-modification guard (plan.md sections 50-53)."""

import json
import os
import shutil
import unittest

import yaml

try:
    from ._common import (AuditBase, RESULT_SCHEMA, legacy_result, run, run_yaml,
                     v1_result, wfile, wyaml)
except ImportError:
    from _common import (AuditBase, RESULT_SCHEMA, legacy_result, run, run_yaml,
                     v1_result, wfile, wyaml)


def manifest(root, run_id, step):
    p = os.path.join(root, "audits", run_id, "steps", str(step), "artifact-manifest.yaml")
    with open(p, encoding="utf-8") as f:
        return yaml.safe_load(f)


# ---------------------------------------------------------------------------
# result schema (section 50)

class TestResultSchema(AuditBase):
    def test_record_accepts_v1_result_schema(self):
        self.write_config()
        self.prepare()
        report = wfile(os.path.join(self.tmp, "r1.md"), "# r1\ncovered\n")
        log = wfile(os.path.join(self.tmp, "l1.txt"), "x\n")
        p = v1_result(os.path.join(self.tmp, "res-v1.yaml"), report=report, log=log)
        r = run(["record", "--work-root", self.root, "--step", "1", "--input", p,
                 "--expected-revision", self.rev(), "--json"])
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout)
        self.assertEqual(out["status"], "COMPLETED")
        ids = [a["id"] for a in out["artifacts"]]
        self.assertIn("primary-report", ids)
        self.assertIn("execution-log", ids)

    def test_record_accepts_legacy_result_schema(self):
        self.write_config()
        self.prepare()
        report = wfile(os.path.join(self.tmp, "r1.md"), "# r1\ncovered\n")
        log = wfile(os.path.join(self.tmp, "l1.txt"), "x\n")
        p = legacy_result(os.path.join(self.tmp, "legacy.yaml"),
                          report=report, log=log)
        r = run(["record", "--work-root", self.root, "--step", "1", "--input", p,
                 "--expected-revision", self.rev()])
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_record_rejects_unknown_result_schema(self):
        self.write_config()
        self.prepare()
        report = wfile(os.path.join(self.tmp, "r1.md"), "# r1\ncovered\n")
        p = wyaml(os.path.join(self.tmp, "bad-schema.yaml"),
                  {"schema": "whitehexlabs.audit-result/v2", "status": "COMPLETED",
                   "note": "covered both contracts in scope fully",
                   "primary": {"report": report, "log": None}, "artifacts": []})
        r = run(["record", "--work-root", self.root, "--step", "1", "--input", p,
                 "--expected-revision", self.rev()])
        self.assertEqual(r.returncode, 2)
        self.assertIn("schema", r.stderr)

    def test_record_requires_primary_report_for_completed(self):
        self.write_config()
        self.prepare()
        p = v1_result(os.path.join(self.tmp, "noreport.yaml"),
                      note="finished without a report somehow")
        r = run(["record", "--work-root", self.root, "--step", "1", "--input", p,
                 "--expected-revision", self.rev()])
        self.assertEqual(r.returncode, 2)
        self.assertIn("primary.report", r.stderr)

    def test_record_rejects_missing_declared_artifact(self):
        self.write_config()
        self.prepare()
        report = wfile(os.path.join(self.tmp, "r1.md"), "# r1\ncovered\n")
        p = v1_result(os.path.join(self.tmp, "gone.yaml"), report=report,
                      artifacts=[{"path": os.path.join(self.tmp, "missing.json"),
                                  "type": "findings", "note": "not there"}])
        r = run(["record", "--work-root", self.root, "--step", "1", "--input", p,
                 "--expected-revision", self.rev()])
        self.assertEqual(r.returncode, 2)
        self.assertIn("not found", r.stderr)

    def test_record_rejects_unknown_artifact_type(self):
        self.write_config()
        self.prepare()
        report = wfile(os.path.join(self.tmp, "r1.md"), "# r1\ncovered\n")
        extra = wfile(os.path.join(self.tmp, "x.bin"), "bin")
        p = v1_result(os.path.join(self.tmp, "badtype.yaml"), report=report,
                      artifacts=[{"path": extra, "type": "screenshots", "note": "x"}])
        r = run(["record", "--work-root", self.root, "--step", "1", "--input", p,
                 "--expected-revision", self.rev()])
        self.assertEqual(r.returncode, 2)
        self.assertIn("screenshots", r.stderr)

    def test_record_accepts_other_artifact_type(self):
        self.write_config()
        self.prepare()
        report = wfile(os.path.join(self.tmp, "r1.md"), "# r1\ncovered\n")
        extra = wfile(os.path.join(self.tmp, "x.bin"), "bin")
        p = v1_result(os.path.join(self.tmp, "oktype.yaml"), report=report,
                      artifacts=[{"path": extra, "type": "other", "note": "x"}])
        r = run(["record", "--work-root", self.root, "--step", "1", "--input", p,
                 "--expected-revision", self.rev()])
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_record_rejects_path_escape_in_artifact(self):
        # the file exists inside the target BEFORE prepare (no drift);
        # declaring it as the primary report is still rejected outright
        fake = wfile(os.path.join(self.target, "src", "fake-report.md"),
                     "# i am inside the target\n")
        self.write_config()
        self.prepare()
        r = self.record(1, "COMPLETED", report=fake)
        self.assertEqual(r.returncode, 2)
        self.assertIn("target", r.stderr)

    def test_record_rejects_target_tree_as_artifact(self):
        self.write_config()
        self.prepare()
        report = wfile(os.path.join(self.tmp, "r1.md"), "# r1\ncovered\n")
        p = v1_result(os.path.join(self.tmp, "tricky.yaml"), report=report,
                      artifacts=[{"path": os.path.join(self.target, "src"),
                                  "type": "other", "note": "the source tree itself"}])
        r = run(["record", "--work-root", self.root, "--step", "1", "--input", p,
                 "--expected-revision", self.rev()])
        self.assertEqual(r.returncode, 2)
        self.assertIn("target", r.stderr)

    def test_record_rejects_secret_material(self):
        self.write_config()
        self.prepare()
        report = wfile(os.path.join(self.tmp, "key.md"),
                       "# report\n\nprivate key: 0xdeadbeef\n")
        r = self.record(1, "COMPLETED", report=report)
        self.assertEqual(r.returncode, 2)
        self.assertIn("secret", r.stderr.lower())


# ---------------------------------------------------------------------------
# artifact normalization (section 51)

class TestNormalization(AuditBase):
    def setUp(self):
        super().setUp()
        self.write_config(skills=[self.skill_a])
        self.prepare()
        self.run_id = self.rid()
        self.report = wfile(os.path.join(self.tmp, "r1.md"),
                            "# r1\n\ncovered both contracts, zero findings\n")
        self.log = wfile(os.path.join(self.tmp, "run.log"), "executed\n")

    def att_dir(self, step=1, attempt=1):
        return os.path.join(self.root, "audits", self.run_id, "steps", str(step),
                            "attempts", str(attempt), "artifacts")

    def test_record_copies_report_to_canonical_artifacts(self):
        r = self.record(1, "COMPLETED", report=self.report, log=self.log)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.isfile(os.path.join(self.att_dir(), "report.md")))

    def test_record_copies_log(self):
        self.record(1, "COMPLETED", report=self.report, log=self.log)
        self.assertTrue(os.path.isfile(os.path.join(self.att_dir(), "log.log")))

    def test_record_copies_findings_json(self):
        findings = wfile(os.path.join(self.tmp, "findings.json"), "[]\n")
        p = v1_result(os.path.join(self.tmp, "res.json.yaml"), report=self.report,
                      log=self.log,
                      artifacts=[{"path": findings, "type": "findings", "note": "structured"}])
        r = run(["record", "--work-root", self.root, "--step", "1", "--input", p,
                 "--expected-revision", self.rev()])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.isfile(os.path.join(self.att_dir(), "findings.json")))

    def test_record_copies_poc_directory(self):
        poc = os.path.join(self.tmp, "poc")
        wfile(os.path.join(poc, "Exploit.t.sol"), "contract Exploit {}\n")
        wfile(os.path.join(poc, "run.sh"), "forge test\n")
        p = v1_result(os.path.join(self.tmp, "res.poc.yaml"), report=self.report,
                      log=self.log,
                      artifacts=[{"path": poc, "type": "poc", "note": "poc dir"}])
        r = run(["record", "--work-root", self.root, "--step", "1", "--input", p,
                 "--expected-revision", self.rev()])
        self.assertEqual(r.returncode, 0, r.stderr)
        dest = os.path.join(self.att_dir(), "poc")
        self.assertTrue(os.path.isfile(os.path.join(dest, "Exploit.t.sol")))
        self.assertTrue(os.path.isfile(os.path.join(dest, "run.sh")))

    def test_record_generates_artifact_manifest(self):
        self.record(1, "COMPLETED", report=self.report, log=self.log)
        m = manifest(self.root, self.run_id, 1)
        self.assertEqual(m["schema"], "whitehexlabs.audit-artifacts/v1")
        self.assertEqual(m["run_id"], self.run_id)
        self.assertEqual(m["step"], 1)
        self.assertEqual(m["status"], "COMPLETED")
        self.assertEqual(m["skill"]["name"], "alpha-auditor")
        self.assertEqual(m["skill"]["sha256"],
                         run_yaml(self.root, self.run_id)["steps"][0]["skill_sha256"])

    def test_artifact_manifest_contains_hashes(self):
        findings = wfile(os.path.join(self.tmp, "findings.json"), '[{"id": 1}]\n')
        p = v1_result(os.path.join(self.tmp, "res2.yaml"), report=self.report,
                      log=self.log,
                      artifacts=[{"path": findings, "type": "findings", "note": "f"}])
        run(["record", "--work-root", self.root, "--step", "1", "--input", p,
             "--expected-revision", self.rev()])
        m = manifest(self.root, self.run_id, 1)
        by_id = {e["id"]: e for e in m["artifacts"]}
        self.assertTrue(by_id["primary-report"]["sha256"])
        self.assertEqual(by_id["primary-report"]["path"],
                         "attempts/1/artifacts/report.md")
        self.assertTrue(by_id["findings-findings-json"]["sha256"])

    def test_directory_artifact_tree_hash_is_deterministic(self):
        # same content, different mtimes/order -> same tree hash
        def build(tag):
            d = os.path.join(self.tmp, f"poc-{tag}")
            wfile(os.path.join(d, "a.txt"), "alpha\n")
            wfile(os.path.join(d, "sub", "b.txt"), "beta\n")
            os.utime(os.path.join(d, "a.txt"), (1000000, 1000000))
            return d

        results = []
        for tag in ("x", "y"):
            work = os.path.join(self.tmp, f"w-{tag}")
            os.makedirs(work)
            shutil.copy(os.path.join(self.root, "audit-skills.yaml"), work)
            r = run(["prepare", "--work-root", work, "--json"])
            rid = json.loads(r.stdout)["run_id"]
            p = v1_result(os.path.join(self.tmp, f"res-{tag}.yaml"),
                          report=self.report,
                          artifacts=[{"path": build(tag), "type": "poc", "note": "p"}])
            r = run(["record", "--work-root", work, "--step", "1", "--input", p,
                     "--expected-revision", 1])
            self.assertEqual(r.returncode, 0, r.stderr)
            m = manifest(work, rid, 1)
            results.append(next(e for e in m["artifacts"] if e["type"] == "poc"))
        self.assertEqual(results[0]["tree_sha256"], results[1]["tree_sha256"])
        self.assertEqual(results[0]["file_count"], 2)

    def test_original_output_can_be_deleted_after_record(self):
        r = self.record(1, "COMPLETED", report=self.report, log=self.log)
        self.assertEqual(r.returncode, 0, r.stderr)
        os.remove(self.report)
        os.remove(self.log)
        r = self.check()
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_canonical_artifact_remains_valid_after_original_deleted(self):
        self.record(1, "COMPLETED", report=self.report, log=self.log)
        os.remove(self.report)
        m = manifest(self.root, self.run_id, 1)
        by_id = {e["id"]: e for e in m["artifacts"]}
        canonical = os.path.join(self.root, "audits", self.run_id, "steps", "1",
                                 by_id["primary-report"]["path"])
        self.assertTrue(os.path.isfile(canonical))
        with open(canonical, encoding="utf-8") as f:
            self.assertIn("zero findings", f.read())

    def test_filename_collision_is_handled(self):
        # two declared artifacts with the same basename in different dirs
        a1 = wfile(os.path.join(self.tmp, "one", "out.txt"), "first\n")
        a2 = wfile(os.path.join(self.tmp, "two", "out.txt"), "second\n")
        p = v1_result(os.path.join(self.tmp, "res-col.yaml"), report=self.report,
                      log=self.log,
                      artifacts=[{"path": a1, "type": "trace", "note": "t1"},
                                 {"path": a2, "type": "trace", "note": "t2"}])
        r = run(["record", "--work-root", self.root, "--step", "1", "--input", p,
                 "--expected-revision", self.rev()])
        self.assertEqual(r.returncode, 0, r.stderr)
        names = sorted(os.listdir(self.att_dir()))
        self.assertEqual(names.count("out.txt"), 1)
        self.assertEqual(names.count("out-2.txt"), 1)
        m = manifest(self.root, self.run_id, 1)
        ids = [e["id"] for e in m["artifacts"]]
        self.assertEqual(len(ids), len(set(ids)))

    def test_retry_does_not_overwrite_prior_artifacts(self):
        # FAILED attempts may still declare artifacts; each attempt keeps
        # its own canonical directory and nothing is ever overwritten
        r1 = wfile(os.path.join(self.tmp, "fail-1.md"), "# failed report one\n")
        r2 = wfile(os.path.join(self.tmp, "fail-2.md"), "# failed report two\n")
        r3 = wfile(os.path.join(self.tmp, "good.md"), "# good report\n")
        self.record(1, "FAILED", note="first attempt failed for the record here",
                    report=r1)
        self.record(1, "FAILED", note="second attempt failed differently",
                    report=r2)
        self.record(1, "COMPLETED", report=r3,
                    note="third attempt completed with full coverage")
        with open(os.path.join(self.att_dir(1, 1), "report.md"), encoding="utf-8") as f:
            self.assertIn("one", f.read())
        with open(os.path.join(self.att_dir(1, 2), "report.md"), encoding="utf-8") as f:
            self.assertIn("two", f.read())
        m = manifest(self.root, self.run_id, 1)
        self.assertEqual(m["attempt"], 3)
        self.assertIn("attempts/3/artifacts/report.md",
                      [e["path"] for e in m["artifacts"]])
        data = run_yaml(self.root, self.run_id)
        self.assertEqual([a["status"] for a in data["steps"][0]["attempts"]],
                         ["FAILED", "FAILED", "COMPLETED"])
        # and the completed step is terminal within the batch
        r = self.record(1, "FAILED", note="cannot touch a completed step")
        self.assertEqual(r.returncode, 2)


# ---------------------------------------------------------------------------
# fixed-output skill behavior (section 52)

class TestFixedOutputSkills(AuditBase):
    def setUp(self):
        super().setUp()
        # skill A honors the preferred work dir (the session writes there);
        # skill B always writes to its own fixed directory
        self.fixed_dir = os.path.join(self.tmp, "fixed-output")
        self.write_config()
        out = json.loads(self.prepare().stdout)
        self.run_id = out["run_id"]

    def test_configurable_output_skill_uses_step_work_dir(self):
        work = os.path.join(self.root, "audits", self.run_id, "steps", "1", "work")
        report = wfile(os.path.join(work, "report-a.md"), "# A\n\ncovered all\n")
        log = wfile(os.path.join(work, "run.log"), "ran a\n")
        r = self.record(1, "COMPLETED", report=report, log=log,
                        note="skill a wrote directly into its work dir")
        self.assertEqual(r.returncode, 0, r.stderr)
        m = manifest(self.root, self.run_id, 1)
        self.assertEqual(m["artifacts"][0]["path"], "attempts/1/artifacts/report.md")

    def complete_step1(self):
        work = os.path.join(self.root, "audits", self.run_id, "steps", "1", "work")
        r = self.record(1, "COMPLETED",
                        report=wfile(os.path.join(work, "report-a.md"), "# A\n\ncovered\n"),
                        log=wfile(os.path.join(work, "run.log"), "a\n"),
                        note="skill a wrote into its work dir")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_fixed_output_skill_can_register_external_output(self):
        self.complete_step1()
        report = wfile(os.path.join(self.fixed_dir, "report-b.md"),
                       "# B\n\ncovered everything\n")
        log = wfile(os.path.join(self.fixed_dir, "run-b.log"), "ran b\n")
        r = self.record(2, "COMPLETED", report=report, log=log,
                        note="skill b only writes to its own fixed directory")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_external_output_is_copied_into_canonical_dir(self):
        self.complete_step1()
        report = wfile(os.path.join(self.fixed_dir, "report-b.md"),
                       "# B\n\ncovered everything\n")
        self.record(2, "COMPLETED", report=report,
                    note="skill b only writes to its own fixed directory")
        canonical = os.path.join(self.root, "audits", self.run_id, "steps", "2",
                                 "attempts", "1", "artifacts", "report.md")
        self.assertTrue(os.path.isfile(canonical))

    def test_aggregation_never_requires_external_output(self):
        # complete step 1 from the work dir and step 2 from the fixed dir,
        # then delete the fixed dir entirely; check must still pass
        work = os.path.join(self.root, "audits", self.run_id, "steps", "1", "work")
        self.record(1, "COMPLETED",
                    report=wfile(os.path.join(work, "report-a.md"), "# A\n\ncovered\n"),
                    log=wfile(os.path.join(work, "run.log"), "a\n"),
                    note="skill a wrote into its work dir")
        self.record(2, "COMPLETED",
                    report=wfile(os.path.join(self.fixed_dir, "report-b.md"), "# B\n\ncovered\n"),
                    log=wfile(os.path.join(self.fixed_dir, "run-b.log"), "b\n"),
                    note="skill b wrote to its fixed dir")
        shutil.rmtree(self.fixed_dir)
        r = self.check()
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_ambiguous_discovery_blocks_instead_of_guessing(self):
        self.complete_step1()
        # two plausible reports exist; the agent cannot disambiguate ->
        # the step is recorded BLOCKED (the CLI never guesses), and the
        # batch cannot pass
        wfile(os.path.join(self.fixed_dir, "report-b.md"), "# B1\n")
        wfile(os.path.join(self.fixed_dir, "report-b-alt.md"), "# B2\n")
        r = self.record(2, "BLOCKED",
                        note="two candidate primary reports; cannot disambiguate")
        self.assertEqual(r.returncode, 0, r.stderr)
        r = self.check()
        self.assertEqual(r.returncode, 1)
        data = run_yaml(self.root, self.run_id)
        self.assertEqual(data["steps"][1]["status"], "BLOCKED")


# ---------------------------------------------------------------------------
# target modification guard (section 53)

class TestTargetGuard(AuditBase):
    def complete_step1(self):
        report = wfile(os.path.join(self.tmp, "r1.md"), "# r1\ncovered\n")
        log = wfile(os.path.join(self.tmp, "l1.txt"), "x\n")
        return self.record(1, "COMPLETED", report=report, log=log,
                           note="step one covered everything in scope")

    def test_skill_modifying_target_invalidates_record(self):
        self.write_config()
        self.prepare()
        report = wfile(os.path.join(self.tmp, "r1.md"), "# r1\ncovered\n")
        log = wfile(os.path.join(self.tmp, "l1.txt"), "x\n")
        # simulate a skill that edited target source while "auditing"
        wfile(os.path.join(self.target, "src", "Vault.sol"),
              "contract Vault { // patched by the auditor\n}\n")
        r = self.record(1, "COMPLETED", report=report, log=log,
                        note="step one covered everything in scope")
        self.assertEqual(r.returncode, 1)
        self.assertIn("drifted", r.stdout + r.stderr)

    def test_skill_adding_target_file_invalidates_record(self):
        self.write_config()
        self.prepare()
        report = wfile(os.path.join(self.tmp, "r1.md"), "# r1\ncovered\n")
        wfile(os.path.join(self.target, "src", "New.sol"), "contract New {}\n")
        r = self.record(1, "COMPLETED", report=report,
                        note="step one covered everything in scope")
        self.assertEqual(r.returncode, 1)
        self.assertIn("New.sol", r.stdout + r.stderr)

    def test_skill_deleting_target_file_invalidates_record(self):
        self.write_config()
        self.prepare()
        report = wfile(os.path.join(self.tmp, "r1.md"), "# r1\ncovered\n")
        os.remove(os.path.join(self.target, "src", "Pool.sol"))
        r = self.record(1, "COMPLETED", report=report,
                        note="step one covered everything in scope")
        self.assertEqual(r.returncode, 1)
        self.assertIn("drifted", r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
