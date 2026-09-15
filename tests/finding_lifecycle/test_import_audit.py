"""Tests for `import-audit` (plan.md section 57): verification, immutable
copy, idempotency, scaffolding, and workspace independence.

Handoffs are produced by the real audit-orchestrator CLI."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml

try:
    from .test_lifecycle import Base, FINDING_SRC, PROGRAM, run, wfile, wyaml
except ImportError:
    from test_lifecycle import Base, FINDING_SRC, PROGRAM, run, wfile, wyaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
AUDIT = os.path.join(REPO, "skills", "audit-orchestrator", "scripts", "audit.py")

CANDIDATE_SCHEMA = "whitehexlabs.audit-candidate/v1"
ANALYSIS_SECTIONS = [
    "# Audit Analysis", "## Audit Run", "## Target and Scope",
    "## Audit Skills Executed", "## Coverage Summary",
    "## Consolidated Findings", "## Duplicate / Overlapping Leads",
    "## Disagreements Between Auditors", "## Coverage Gaps and Limitations",
    "## Zero-Finding Statement",
]


def arun(args):
    return subprocess.run([sys.executable, AUDIT] + [str(a) for a in args],
                          capture_output=True, text=True)


def analysis_text(run_id, body):
    parts = [ANALYSIS_SECTIONS[0], f"Run {run_id} over the toy target."]
    for h in ANALYSIS_SECTIONS[1:]:
        parts.append(h)
        parts.append("No candidate findings were identified within the executed "
                     "audit scope and methods." if "Zero-Finding" in h
                     else f"content: {body}")
    return "\n\n".join(parts) + "\n"


def build_prefinalized(tmp, tag, skills=2):
    """Drive audit.py up to (but excluding) finalize; returns (work, rid)."""
    work = os.path.join(tmp, f"aw-{tag}")
    target = os.path.join(tmp, f"at-{tag}")
    os.makedirs(work)
    sk = []
    for i in range(skills):
        sk.append(wfile(os.path.join(tmp, f"sk-{tag}-{i}", "SKILL.md"),
                        f"---\nname: skill-{i}\n---\n# skill {i}\n"))
    wfile(os.path.join(target, "src", "Vault.sol"), "contract Vault {}\n")
    wyaml(os.path.join(work, "audit-skills.yaml"),
          {"target_root": target, "scope": ["src"], "skills": sk})
    rid = json.loads(arun(["prepare", "--work-root", work, "--json"]).stdout)["run_id"]
    for n in range(1, skills + 1):
        out = (os.path.join(work, "audits", rid, "steps", str(n), "work")
               if n == 1 else os.path.join(tmp, f"fixed-{tag}-{n}"))
        report = wfile(os.path.join(out, f"report-{n}.md"),
                       f"# report {n}\n\nfinding: share price inflation\n")
        log = wfile(os.path.join(out, f"run-{n}.log"), f"ran {n}\n")
        res = wyaml(os.path.join(tmp, f"res-{tag}-{n}.yaml"),
                    {"schema": "whitehexlabs.audit-result/v1",
                     "status": "COMPLETED",
                     "note": f"skill {n} covered the scope; one candidate found",
                     "primary": {"report": report, "log": log},
                     "artifacts": []})
        rev = n  # prepare=1, each record +1
        r = arun(["record", "--work-root", work, "--step", n, "--input", res,
                  "--expected-revision", rev])
        assert r.returncode == 0, r.stderr
    return work, rid


def candidate_doc():
    return {
        "schema": CANDIDATE_SCHEMA, "id": "A-001",
        "title": "Share price inflation",
        "claim": "First depositor inflates the share price before deposits",
        "root_cause": {"summary": "unprotected initial share-price formation",
                        "mechanism": "donate before first deposit"},
        "sources": [
            {"step": 1, "skill_name": "skill-0", "original_finding_id": "s0-1",
             "artifact_manifest": "../steps/1/artifact-manifest.yaml",
             "report": {"artifact_id": "primary-report"},
             "locations": ["src/Vault.sol:1"], "note": ""},
            {"step": 2, "skill_name": "skill-1", "original_finding_id": "s1-1",
             "artifact_manifest": "../steps/2/artifact-manifest.yaml",
             "report": {"artifact_id": "primary-report"},
             "locations": ["src/Vault.sol:1"], "note": ""},
        ],
        "preconditions": [], "affected_code": [], "disagreements": [],
        "coverage_gaps": [], "severity_hint": "HIGH", "confidence_hint": None,
    }


def finalize_with(work, rid, body="one root cause", with_candidate=True):
    wfile(os.path.join(work, "audits", rid, "analysis.md"), analysis_text(rid, body))
    if with_candidate:
        wyaml(os.path.join(work, "audits", rid, "candidates", "A-001.yaml"),
              candidate_doc())
    cur = yaml.safe_load(open(os.path.join(work, "audits", rid, "run.yaml"),
                              encoding="utf-8"))["revision"]
    r = arun(["finalize", "--work-root", work, "--expected-revision", cur])
    assert r.returncode == 0, r.stderr
    return os.path.join(work, "audits", rid, "handoff", "manifest.yaml")


def make_handoff(tmp, tag, with_candidate=True):
    work, rid = build_prefinalized(tmp, tag)
    h = finalize_with(work, rid, with_candidate=with_candidate)
    return work, rid, h


class TestImportAudit(Base):
    def setUp(self):
        super().setUp()
        self.work, self.rid, self.handoff = make_handoff(self.tmp, "main")

    def import_cmd(self, handoff=None, *extra):
        return run(["import-audit", "--case-root", self.root,
                    "--handoff", handoff or self.handoff, "--json", *extra])

    def imports_dir(self):
        return os.path.join(self.root, "imports", "audit", self.rid)

    def test_import_valid_handoff(self):
        r = self.import_cmd()
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout)
        self.assertEqual(out["status"], "imported")
        self.assertEqual(out["candidates"], ["A-001"])
        for rel in ("manifest.yaml", "analysis.md", "candidates/A-001.yaml",
                    "artifact-manifests/step-1.yaml", "artifact-manifests/step-2.yaml"):
            self.assertTrue(os.path.isfile(os.path.join(self.imports_dir(), rel)),
                            rel)
        # canonical artifacts came along (sources/step-1/attempts/1/...)
        src1 = os.path.join(self.imports_dir(), "sources", "step-1")
        found = [os.path.join(dp, f) for dp, _, fs in os.walk(src1) for f in fs]
        self.assertTrue(any("report" in f for f in found), found)

    def test_import_rejects_unfinalized_handoff(self):
        with open(self.handoff, encoding="utf-8") as f:
            m = yaml.safe_load(f)
        m["status"] = "DRAFT"
        wyaml(self.handoff, m)
        r = self.import_cmd()
        self.assertEqual(r.returncode, 2)
        self.assertIn("FINALIZED", r.stderr)

    def test_import_rejects_unknown_schema(self):
        with open(self.handoff, encoding="utf-8") as f:
            m = yaml.safe_load(f)
        m["schema"] = "whitehexlabs.audit-handoff/v2"
        wyaml(self.handoff, m)
        r = self.import_cmd()
        self.assertEqual(r.returncode, 2)
        self.assertIn("schema", r.stderr)

    def test_import_rejects_analysis_hash_mismatch(self):
        p = os.path.join(self.work, "audits", self.rid, "analysis.md")
        with open(p, "a", encoding="utf-8") as f:
            f.write("tampered\n")
        r = self.import_cmd()
        self.assertEqual(r.returncode, 2)
        self.assertIn("analysis", r.stderr)

    def test_import_rejects_candidate_hash_mismatch(self):
        p = os.path.join(self.work, "audits", self.rid, "handoff",
                         "candidates", "A-001.yaml")
        with open(p, "a", encoding="utf-8") as f:
            f.write("# tampered\n")
        r = self.import_cmd()
        self.assertEqual(r.returncode, 2)
        self.assertIn("candidate", r.stderr)

    def test_import_rejects_artifact_manifest_hash_mismatch(self):
        p = os.path.join(self.work, "audits", self.rid, "steps", "2",
                         "artifact-manifest.yaml")
        with open(p, "a", encoding="utf-8") as f:
            f.write("# tampered\n")
        r = self.import_cmd()
        self.assertEqual(r.returncode, 2)
        self.assertIn("manifest", r.stderr)

    def test_import_rejects_source_artifact_hash_mismatch(self):
        p = os.path.join(self.work, "audits", self.rid, "steps", "1",
                         "attempts", "1", "artifacts", "report.md")
        with open(p, "a", encoding="utf-8") as f:
            f.write("tampered\n")
        r = self.import_cmd()
        self.assertEqual(r.returncode, 2)
        self.assertIn("hash mismatch", r.stderr)

    def test_import_rejects_path_escape(self):
        with open(self.handoff, encoding="utf-8") as f:
            m = yaml.safe_load(f)
        m["audit"]["analysis"]["path"] = "../../../../etc/hosts"
        wyaml(self.handoff, m)
        r = self.import_cmd()
        self.assertEqual(r.returncode, 2)
        self.assertIn("escape", r.stderr)

    def test_import_is_idempotent(self):
        r1 = self.import_cmd()
        self.assertEqual(r1.returncode, 0, r1.stderr)
        draft = os.path.join(self.root, "ingest", self.rid,
                             "finding-source.A-001.yaml")
        before = open(draft, encoding="utf-8").read()
        r2 = self.import_cmd()
        self.assertEqual(r2.returncode, 0, r2.stderr)
        out = json.loads(r2.stdout)
        self.assertEqual(out["status"], "already-imported")
        self.assertEqual(open(draft, encoding="utf-8").read(), before)
        drafts = os.listdir(os.path.join(self.root, "ingest", self.rid))
        self.assertEqual(drafts, ["finding-source.A-001.yaml"])

    def test_same_run_id_different_manifest_rejected(self):
        self.assertEqual(self.import_cmd().returncode, 0)
        # same run id, different content: clone the run pre-finalization state
        work2 = os.path.join(self.tmp, "aw-clone")
        os.makedirs(work2)
        shutil.copy(os.path.join(self.work, "audit-skills.yaml"), work2)
        shutil.copytree(os.path.join(self.work, "audits", self.rid),
                        os.path.join(work2, "audits", self.rid))
        # strip the finalization from the clone and re-finalize differently
        rp = os.path.join(work2, "audits", self.rid, "run.yaml")
        data = yaml.safe_load(open(rp, encoding="utf-8"))
        data.pop("finalization", None)
        while len(data["history"]) != data["revision"]:
            data["history"].pop()
        wyaml(rp, data)
        shutil.rmtree(os.path.join(work2, "audits", self.rid, "handoff"))
        h2 = finalize_with(work2, self.rid, body="a different analysis body")
        r = self.import_cmd(handoff=h2)
        self.assertEqual(r.returncode, 2)
        self.assertIn("different hash", r.stderr)

    def test_zero_candidate_import(self):
        work, rid, h = make_handoff(self.tmp, "zero", with_candidate=False)
        r = run(["import-audit", "--case-root", self.root, "--handoff", h, "--json"])
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout)
        self.assertEqual(out["candidates"], [])
        self.assertTrue(os.path.isfile(
            os.path.join(self.root, "imports", "audit", rid, "analysis.md")))
        self.assertFalse(os.path.isdir(os.path.join(self.root, "ingest", rid)))

    def test_import_scaffolds_one_draft_per_candidate(self):
        self.import_cmd()
        draft = os.path.join(self.root, "ingest", self.rid,
                             "finding-source.A-001.yaml")
        self.assertTrue(os.path.isfile(draft))
        text = "\n".join(l for l in open(draft, encoding="utf-8").read().splitlines()
                         if not l.startswith("#"))
        doc = yaml.safe_load(text)
        self.assertEqual(doc["sources"]["auditor"], "audit-orchestrator")
        self.assertEqual(doc["sources"]["original_finding_id"], "A-001")
        self.assertEqual(doc["sources"]["audit_round"], self.rid)
        files = [f["path"] for f in doc["sources"]["files"]]
        self.assertIn(f"imports/audit/{self.rid}/analysis.md", files)
        self.assertTrue(any(f.startswith(f"imports/audit/{self.rid}/sources/")
                            for f in files), files)
        aspects = {p["aspect"]: p["status"] for p in doc["prescreen"]}
        self.assertEqual(set(aspects), {"scope", "authority", "exclusion",
                                         "duplication"})
        self.assertTrue(all(v == "UNKNOWN" for v in aspects.values()))

    def test_import_does_not_auto_register(self):
        self.import_cmd()
        self.assertEqual(os.listdir(os.path.join(self.root, "findings")), [])

    def test_import_does_not_guess_prescreen(self):
        self.import_cmd()
        draft = os.path.join(self.root, "ingest", self.rid,
                             "finding-source.A-001.yaml")
        r = run(["register", "--case-root", self.root, "--from", draft])
        self.assertEqual(r.returncode, 2)
        self.assertIn("TODO", r.stderr)

    def test_import_survives_original_audit_workspace_deletion(self):
        self.import_cmd()
        shutil.rmtree(self.work)
        draft = os.path.join(self.root, "ingest", self.rid,
                             "finding-source.A-001.yaml")
        self.assertTrue(os.path.isfile(draft))
        # complete the draft and register: every file reference resolves
        # INSIDE the case root (imports/), never the deleted workspace
        text = "\n".join(l for l in open(draft, encoding="utf-8").read().splitlines()
                         if not l.startswith("#"))
        doc = yaml.safe_load(text)
        doc["title"] = "Share price inflation"
        doc["claim"] = "First depositor inflates the share price before deposits"
        for item in doc["prescreen"]:
            item["evidence"] = "checked by hand"
            item["explanation"] = {"scope": "in scope", "authority": "no role",
                                    "exclusion": "none applies",
                                    "duplication": "no prior finding"}[item["aspect"]]
            if item["aspect"] == "duplication":
                item["status"] = "PASS"
        wyaml(draft, doc)
        r = run(["register", "--case-root", self.root, "--from", draft, "--json"])
        self.assertEqual(r.returncode, 0, r.stderr)
        fid = json.loads(r.stdout)["id"]
        ev = os.listdir(os.path.join(self.root, "evidence", fid, "sources"))
        self.assertIn("analysis.md", ev)


if __name__ == "__main__":
    unittest.main()
