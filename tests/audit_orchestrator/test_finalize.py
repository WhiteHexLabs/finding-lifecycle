"""Aggregation contract and finalize tests (plan.md sections 54-55)."""

import copy
import json
import os
import shutil
import unittest

import yaml

try:
    from ._common import (CANDIDATE_SCHEMA, AuditBase, run, run_yaml, v1_result,
                     wfile, write_analysis, wyaml)
except ImportError:
    from _common import (CANDIDATE_SCHEMA, AuditBase, run, run_yaml, v1_result,
                     wfile, write_analysis, wyaml)


def load_candidate(root, run_id):
    with open(os.path.join(root, "audits", run_id, "handoff", "candidates",
                           "A-001.yaml"), encoding="utf-8") as f:
        return yaml.safe_load(f)


class FinalizeBase(AuditBase):
    """Two completed steps (one from work dir, one from a fixed dir) plus a
    consolidated candidate sourced from both."""

    def setUp(self):
        super().setUp()
        self.write_config()
        out = json.loads(self.prepare().stdout)
        self.run_id = out["run_id"]
        self.work = os.path.join(self.root, "audits", self.run_id, "steps", "1", "work")
        self.fixed = os.path.join(self.tmp, "fixed-output")
        self.record(1, "COMPLETED",
                    report=wfile(os.path.join(self.work, "report-a.md"),
                                 "# A\n\nshare-price manipulation finding\n"),
                    log=wfile(os.path.join(self.work, "run.log"), "a\n"),
                    note="skill a wrote into its work dir")
        self.record(2, "COMPLETED",
                    report=wfile(os.path.join(self.fixed, "report-b.md"),
                                 "# B\n\ninflation attack finding\n"),
                    log=wfile(os.path.join(self.fixed, "run-b.log"), "b\n"),
                    note="skill b wrote to its fixed dir")
        self.analysis = write_analysis(
            self.root, self.run_id,
            "one consolidated root cause: unprotected initial share-price formation")

    def candidate(self, **overrides):
        doc = {
            "schema": CANDIDATE_SCHEMA,
            "id": "A-001",
            "title": "Donation-based share-price inflation",
            "claim": "First depositor can manipulate the share price before deposits",
            "root_cause": {"summary": "unprotected initial share-price formation",
                            "mechanism": "donate before first deposit to inflate rate"},
            "sources": [
                {"step": 1, "skill_name": "alpha-auditor",
                 "original_finding_id": "a-1",
                 "artifact_manifest": "../steps/1/artifact-manifest.yaml",
                 "report": {"artifact_id": "primary-report"},
                 "locations": ["src/Vault.sol:42"], "note": ""},
                {"step": 2, "skill_name": "beta-auditor",
                 "original_finding_id": "b-7",
                 "artifact_manifest": "../steps/2/artifact-manifest.yaml",
                 "report": {"artifact_id": "primary-report"},
                 "locations": ["src/Vault.sol:40"], "note": ""},
            ],
            "preconditions": ["vault holds zero or few shares"],
            "affected_code": ["src/Vault.sol"],
            "disagreements": ["alpha rates it medium, beta high"],
            "coverage_gaps": ["fee-on-convert variant not executed"],
            "severity_hint": "HIGH",
            "confidence_hint": "medium",
        }
        doc.update(overrides)
        return doc

    def author_candidate(self, doc=None, name="A-001"):
        doc = doc or self.candidate()
        doc["id"] = name
        return wyaml(os.path.join(self.root, "audits", self.run_id, "candidates",
                                  f"{name}.yaml"), doc)

    def finalize(self, rev=None):
        return run(["finalize", "--work-root", self.root, "--json",
                    "--expected-revision",
                    rev if rev is not None else self.rev()])


# ---------------------------------------------------------------------------
# aggregation contract (section 54) — the CLI validates scaffolding, the
# agent performs semantic consolidation

class TestAggregation(FinalizeBase):
    def test_aggregation_reads_only_artifact_manifests(self):
        # deleting the skills' original outputs changes nothing: aggregation
        # inputs are the canonical manifests + artifacts only
        shutil.rmtree(self.fixed)
        self.author_candidate()
        r = self.finalize()
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_aggregation_ignores_original_external_paths(self):
        doc = self.candidate()
        doc["sources"] = [{
            "step": 1, "skill_name": "alpha-auditor",
            "original_finding_id": None,
            # pointing at the skill's original output location is rejected
            "artifact_manifest": self.work + "/report-a.md",
            "report": {"artifact_id": "primary-report"},
            "locations": [], "note": "",
        }]
        self.author_candidate(doc)
        r = self.finalize()
        self.assertEqual(r.returncode, 1)
        self.assertIn("canonical", r.stdout + r.stderr)

    def test_aggregation_prefers_structured_findings(self):
        # a findings artifact participates as its own manifest entry
        findings = wfile(os.path.join(self.tmp, "findings.json"),
                         '[{"title": "inflation", "severity": "HIGH"}]\n')
        p = v1_result(os.path.join(self.tmp, "res.json.yaml"),
                      report=wfile(os.path.join(self.work, "report-a2.md"), "# A2\n"),
                      log=wfile(os.path.join(self.work, "run2.log"), "a\n"),
                      artifacts=[{"path": findings, "type": "findings", "note": "structured"}])
        # record into a fresh batch (step statuses are terminal here)
        work2 = os.path.join(self.tmp, "w2")
        os.makedirs(work2)
        shutil.copy(os.path.join(self.root, "audit-skills.yaml"), work2)
        rid2 = json.loads(run(["prepare", "--work-root", work2, "--json"]).stdout)["run_id"]
        w1 = os.path.join(work2, "audits", rid2, "steps", "1", "work")
        fixed2 = os.path.join(self.tmp, "fixed2")
        r = run(["record", "--work-root", work2, "--step", "1", "--input", p,
                 "--expected-revision", 1])
        self.assertEqual(r.returncode, 0, r.stderr)
        r = run(["record", "--work-root", work2, "--step", "2", "--input",
                 v1_result(os.path.join(self.tmp, "res2b.yaml"),
                           report=wfile(os.path.join(fixed2, "r2.md"), "# B\n"),
                           note="covered everything in scope"),
                 "--expected-revision", 2])
        self.assertEqual(r.returncode, 0, r.stderr)
        write_analysis(work2, rid2)
        wyaml(os.path.join(work2, "audits", rid2, "candidates", "A-001.yaml"),
              {"schema": CANDIDATE_SCHEMA, "id": "A-001", "title": "t", "claim": "c",
               "root_cause": {"summary": "s", "mechanism": "m"},
               "sources": [{"step": 1, "skill_name": "alpha-auditor",
                             "original_finding_id": None,
                             "artifact_manifest": "../steps/1/artifact-manifest.yaml",
                             "report": {"artifact_id": "findings-findings-json"},
                             "locations": [], "note": ""}],
               "preconditions": [], "affected_code": [], "disagreements": [],
               "coverage_gaps": [], "severity_hint": None, "confidence_hint": None})
        r = run(["finalize", "--work-root", work2, "--expected-revision", 3])
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_aggregation_falls_back_to_primary_report(self):
        self.author_candidate()   # sources reference primary-report artifacts
        r = self.finalize()
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_root_cause_duplicates_merge(self):
        # one candidate, two sources = the merged representation of two
        # same-root-cause leads; finalize binds both source manifests
        self.author_candidate()
        r = self.finalize()
        self.assertEqual(r.returncode, 0, r.stderr)
        doc = load_candidate(self.root, self.run_id)
        self.assertEqual(len(doc["sources"]), 2)

    def test_different_root_causes_remain_separate(self):
        self.author_candidate(name="A-001")
        second = self.candidate(
            id="A-002", title="Oracle staleness", claim="stale price feed",
            root_cause={"summary": "no freshness check", "mechanism": "old round used"},
            sources=[{"step": 1, "skill_name": "alpha-auditor",
                       "original_finding_id": None,
                       "artifact_manifest": "../steps/1/artifact-manifest.yaml",
                       "report": {"artifact_id": "primary-report"},
                       "locations": [], "note": ""}])
        second["id"] = "A-002"
        self.author_candidate(second, name="A-002")
        r = self.finalize()
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout)
        self.assertEqual(sorted(out["candidates"]), ["A-001", "A-002"])

    def test_source_attribution_preserved(self):
        self.author_candidate()
        self.finalize()
        doc = load_candidate(self.root, self.run_id)
        self.assertEqual([s["skill_name"] for s in doc["sources"]],
                         ["alpha-auditor", "beta-auditor"])
        self.assertEqual([s["original_finding_id"] for s in doc["sources"]],
                         ["a-1", "b-7"])

    def test_disagreements_preserved(self):
        self.author_candidate()
        self.finalize()
        doc = load_candidate(self.root, self.run_id)
        self.assertEqual(len(doc["disagreements"]), 1)

    def test_zero_findings_allowed(self):
        write_analysis(self.root, self.run_id)
        r = self.finalize()
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout)
        self.assertEqual(out["candidates"], [])


# ---------------------------------------------------------------------------
# finalization (section 55)

class TestFinalize(FinalizeBase):
    def test_finalize_requires_completed_audit(self):
        work = os.path.join(self.tmp, "w-inc")
        os.makedirs(work)
        shutil.copy(os.path.join(self.root, "audit-skills.yaml"), work)
        rid = json.loads(run(["prepare", "--work-root", work, "--json"]).stdout)["run_id"]
        run(["record", "--work-root", work, "--step", "1", "--input",
             v1_result(os.path.join(self.tmp, "f1.yaml"), status="FAILED",
                       note="skill crashed; nothing recorded"),
             "--expected-revision", 1])
        r = run(["finalize", "--work-root", work, "--expected-revision", 2])
        self.assertEqual(r.returncode, 1)
        self.assertIn("FAILED", r.stdout + r.stderr)

    def test_finalize_requires_analysis(self):
        os.remove(self.analysis)
        self.author_candidate()
        r = self.finalize()
        self.assertEqual(r.returncode, 1)
        self.assertIn("analysis", r.stdout + r.stderr)

    def test_finalize_rejects_empty_analysis(self):
        wfile(self.analysis, "")
        self.author_candidate()
        r = self.finalize()
        self.assertEqual(r.returncode, 1)
        self.assertIn("too short", r.stdout + r.stderr)

    def test_finalize_rejects_analysis_missing_sections(self):
        wfile(self.analysis, "# Audit Analysis\n\n## Audit Run\n\nsome content "
              "that is long enough but misses most required section headings")
        self.author_candidate()
        r = self.finalize()
        self.assertEqual(r.returncode, 1)
        self.assertIn("required section", r.stdout + r.stderr)

    def test_finalize_accepts_zero_candidates(self):
        r = self.finalize()
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout)
        self.assertEqual(out["candidates"], [])

    def test_finalize_accepts_candidates(self):
        self.author_candidate()
        r = self.finalize()
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout)
        self.assertEqual(out["candidates"], ["A-001"])
        self.assertTrue(os.path.isfile(
            os.path.join(self.root, "audits", self.run_id, "handoff", "manifest.yaml")))

    def test_finalize_rejects_duplicate_candidate_ids(self):
        self.author_candidate()
        self.author_candidate(name="A-001")  # same id, second file impossible;
        # emulate by copying the file under a name that also parses to A-001
        shutil.copyfile(os.path.join(self.root, "audits", self.run_id, "candidates",
                                     "A-001.yaml"),
                        os.path.join(self.root, "audits", self.run_id, "candidates",
                                     "A-001-copy.yaml"))
        r = self.finalize()
        self.assertEqual(r.returncode, 1)
        self.assertIn("filename must be A-001.yaml", r.stdout + r.stderr)

    def test_finalize_rejects_missing_artifact_manifest(self):
        self.author_candidate()
        # deleting only the manifest is recoverable (deterministic re-synthesis
        # from frozen copies); deleting the frozen artifacts too must fail
        sdir = os.path.join(self.root, "audits", self.run_id, "steps", "2")
        os.remove(os.path.join(sdir, "artifact-manifest.yaml"))
        shutil.rmtree(os.path.join(sdir, "attempts"))
        r = self.finalize()
        self.assertEqual(r.returncode, 1)

    def test_finalize_rejects_candidate_referencing_external_path(self):
        doc = self.candidate()
        doc["sources"][0]["artifact_manifest"] = "/etc/passwd"
        self.author_candidate(doc)
        r = self.finalize()
        self.assertEqual(r.returncode, 1)
        self.assertIn("absolute", r.stdout + r.stderr)

    def test_finalize_rejects_bad_hash(self):
        # tamper a canonical artifact after record -> manifests no longer
        # verify -> finalize refuses
        self.author_candidate()
        sdir = os.path.join(self.root, "audits", self.run_id, "steps", "1")
        with open(os.path.join(sdir, "attempts", "1", "artifacts", "report.md"),
                  "w", encoding="utf-8") as f:
            f.write("# tampered\n")
        r = self.finalize()
        self.assertEqual(r.returncode, 1)
        self.assertIn("hash mismatch", r.stdout + r.stderr)

    def test_finalize_writes_handoff_manifest(self):
        self.author_candidate()
        r = self.finalize()
        self.assertEqual(r.returncode, 0, r.stderr)
        mp = os.path.join(self.root, "audits", self.run_id, "handoff", "manifest.yaml")
        with open(mp, encoding="utf-8") as f:
            m = yaml.safe_load(f)
        self.assertEqual(m["schema"], "whitehexlabs.audit-handoff/v1")
        self.assertEqual(m["status"], "FINALIZED")
        self.assertEqual(m["run_id"], self.run_id)
        self.assertEqual(m["candidate_count"], 1)
        self.assertEqual(len(m["steps"]), 2)
        self.assertTrue(all("artifact_manifest" in s for s in m["steps"]))
        run_doc = run_yaml(self.root, self.run_id)
        self.assertIn("finalization", run_doc)
        self.assertEqual(run_doc["finalization"]["candidate_count"], 1)

    def test_finalize_is_idempotent(self):
        self.author_candidate()
        r1 = self.finalize()
        self.assertEqual(r1.returncode, 0, r1.stderr)
        rev_after = self.rev()
        # re-finalize with a stale revision: read-only idempotent success
        r2 = self.finalize(rev=1)
        self.assertEqual(r2.returncode, 0, r2.stderr)
        out = json.loads(r2.stdout)
        self.assertTrue(out.get("idempotent"))
        self.assertEqual(self.rev(), rev_after)   # no mutation

    def _finalize_and_tamper(self, mutate):
        self.author_candidate()
        self.assertEqual(self.finalize().returncode, 0)
        mutate()
        r = self.check()
        self.assertEqual(r.returncode, 1)
        r = self.finalize()
        self.assertEqual(r.returncode, 1)

    def test_finalized_artifact_mutation_invalidates_handoff(self):
        def mutate():
            sdir = os.path.join(self.root, "audits", self.run_id, "steps", "1")
            with open(os.path.join(sdir, "attempts", "1", "artifacts", "report.md"),
                      "a", encoding="utf-8") as f:
                f.write("tampered\n")
        self._finalize_and_tamper(mutate)

    def test_finalized_analysis_mutation_invalidates_handoff(self):
        def mutate():
            with open(self.analysis, "a", encoding="utf-8") as f:
                f.write("tampered\n")
        self._finalize_and_tamper(mutate)

    def test_finalized_candidate_mutation_invalidates_handoff(self):
        def mutate():
            p = os.path.join(self.root, "audits", self.run_id, "handoff",
                             "candidates", "A-001.yaml")
            with open(p, "a", encoding="utf-8") as f:
                f.write("# tampered\n")
        self._finalize_and_tamper(mutate)


if __name__ == "__main__":
    unittest.main()
