"""End-to-end integration: audit-orchestrator -> finalized handoff ->
finding-lifecycle import -> registered DISCOVERED finding (plan.md section 58).

Covers a configurable-output skill (writes into steps/<N>/work/) and a
fixed-output skill (writes only to its own directory), canonical artifact
ownership after original deletion, and lifecycle independence from the
audit workspace."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
AUDIT = os.path.join(REPO, "skills", "audit-orchestrator", "scripts", "audit.py")
LC = os.path.join(REPO, "skills", "finding-lifecycle", "scripts", "lifecycle.py")
TEMPLATES = os.path.join(REPO, "skills", "finding-lifecycle", "templates")

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


def lrun(args):
    return subprocess.run([sys.executable, LC] + [str(a) for a in args],
                          capture_output=True, text=True)


def wfile(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


def wyaml(path, obj):
    return wfile(path, yaml.safe_dump(obj, sort_keys=False, allow_unicode=True))


PROGRAM = {
    "program": {
        "id": "itest-prog", "name": "Integration Program",
        "rules_url": "https://example.test/rules", "fetched_at": "2026-01-01",
        "valid_until": None,
        "snapshot": {"path": "rules-snapshot.md", "sha256": None},
    },
    "scope": {"chains": [1],
               "targets": [{"address": "0x" + "11" * 20, "role": "primary",
                             "note": ""}],
               "assets": ["USDC"], "impacts_allowed": ["loss-of-funds"]},
    "severity_matrix": [
        {"id": "S1", "level": "CRITICAL", "text": "big loss", "basis": "rules"},
        {"id": "S2", "level": "HIGH", "text": "small loss", "basis": "rules"},
    ],
    "exclusions": [{"id": "E1", "category": "privileged",
                     "text": "privileged roles excluded"}],
    "novelty_sources": [{"source": "prior-audits", "location": None,
                          "status": "missing"}],
    "bounty": {"currency": "USD", "ranges": "high: 10k", "min_accepted_payout": None},
    "submission_limits": {"accounts": [], "counting": "per 14 days",
                           "window": None, "max_per_window": None, "timezone": "UTC"},
    "delivery": {"language": "en", "fields": ["summary"], "attachments": "zip",
                  "private_channels": ["private repo"]},
    "kyc": {"required": "UNKNOWN"},
    "response": {"sla": None, "appeal": {"method": None, "deadline_days": None}},
}


class TestAuditToLifecycle(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="fl-itest-")

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_full_pipeline(self):
        # 1. toy protocol target
        target = os.path.join(self.tmp, "protocol")
        wfile(os.path.join(target, "src", "Vault.sol"),
              "contract Vault { mapping(address=>uint) bal; }\n")
        wfile(os.path.join(target, "src", "Pool.sol"), "contract Pool {}\n")
        # 2. two dummy audit skills
        skill_a = wfile(os.path.join(self.tmp, "skills", "configurable", "SKILL.md"),
                        "---\nname: configurable-auditor\n---\n"
                        "# configurable\n\nwrites wherever the orchestrator asks\n")
        skill_b = wfile(os.path.join(self.tmp, "skills", "fixed", "SKILL.md"),
                        "---\nname: fixed-auditor\n---\n"
                        "# fixed\n\nalways writes to <cwd>/fixed-output/\n")

        work = os.path.join(self.tmp, "audit-work")
        os.makedirs(work)
        wyaml(os.path.join(work, "audit-skills.yaml"),
              {"target_root": target, "scope": ["src"],
                "skills": [skill_a, skill_b]})

        # 5. audit prepare
        r = arun(["prepare", "--work-root", work, "--json"])
        self.assertEqual(r.returncode, 0, r.stderr)
        rid = json.loads(r.stdout)["run_id"]
        # 6. both execution prompts exist
        for n in (1, 2):
            self.assertTrue(os.path.isfile(
                os.path.join(work, "audits", rid, "steps", str(n),
                             "execution-prompt.md")))
            self.assertTrue(os.path.isdir(
                os.path.join(work, "audits", rid, "steps", str(n), "work")))

        # 7. run/record skill A (configurable output -> step work dir)
        work_a = os.path.join(work, "audits", rid, "steps", "1", "work")
        report_a = wfile(os.path.join(work_a, "report.md"),
                         "# configurable report\n\nfinding: share price can be "
                         "inflated via donation before first deposit\n")
        log_a = wfile(os.path.join(work_a, "run.log"), "ran configurable auditor\n")
        findings_a = wfile(os.path.join(work_a, "findings.json"),
                           '[{"id": "ca-1", "title": "inflation"}]\n')
        res_a = wyaml(os.path.join(work_a, "result.yaml"),
                      {"schema": "whitehexlabs.audit-result/v1",
                        "status": "COMPLETED",
                        "note": "configurable skill covered both contracts",
                        "primary": {"report": report_a, "log": log_a},
                        "artifacts": [{"path": findings_a, "type": "findings",
                                        "note": "structured findings"}]})
        r = arun(["record", "--work-root", work, "--step", "1", "--input", res_a,
                  "--expected-revision", 1])
        self.assertEqual(r.returncode, 0, r.stderr)
        # 8. canonical artifacts exist
        att_a = os.path.join(work, "audits", rid, "steps", "1",
                             "attempts", "1", "artifacts")
        for name in ("report.md", "log.log", "findings.json"):
            self.assertTrue(os.path.isfile(os.path.join(att_a, name)), name)

        # 9. run/record skill B from its own fixed output location
        fixed = os.path.join(self.tmp, "fixed-output")
        report_b = wfile(os.path.join(fixed, "report-b.md"),
                         "# fixed report\n\nfinding: first-depositor inflation "
                         "attack on the vault share price\n")
        log_b = wfile(os.path.join(fixed, "run-b.log"), "ran fixed auditor\n")
        res_b = wyaml(os.path.join(self.tmp, "result-b.yaml"),
                      {"schema": "whitehexlabs.audit-result/v1",
                        "status": "COMPLETED",
                        "note": "fixed-output skill covered both contracts",
                        "primary": {"report": report_b, "log": log_b},
                        "artifacts": []})
        r = arun(["record", "--work-root", work, "--step", "2", "--input", res_b,
                  "--expected-revision", 2])
        self.assertEqual(r.returncode, 0, r.stderr)
        # 10. canonical artifacts exist
        att_b = os.path.join(work, "audits", rid, "steps", "2",
                             "attempts", "1", "artifacts")
        self.assertTrue(os.path.isfile(os.path.join(att_b, "report.md")))

        # 11. delete skill B's original output directory
        shutil.rmtree(fixed)
        # 12. audit check still succeeds
        r = arun(["check", "--work-root", work, "--json"])
        self.assertEqual(r.returncode, 0, r.stderr)

        # 13. aggregated analysis.md (semantic consolidation, agent work)
        parts = [ANALYSIS_SECTIONS[0],
                 f"Run {rid} over the toy protocol with two skills."]
        for h in ANALYSIS_SECTIONS[1:]:
            parts.append(h)
            if "Consolidated Findings" in h:
                parts.append("A-001: unprotected initial share-price formation "
                             "permits donation-based inflation; both auditors "
                             "found the same root cause with different wording.")
            elif "Zero-Finding" in h:
                parts.append("One candidate finding was identified.")
            else:
                parts.append(f"{h[3:].strip()}: recorded for {rid}.")
        wfile(os.path.join(work, "audits", rid, "analysis.md"),
              "\n\n".join(parts) + "\n")

        # 14. one consolidated candidate sourced from both skills
        wyaml(os.path.join(work, "audits", rid, "candidates", "A-001.yaml"), {
            "schema": CANDIDATE_SCHEMA,
            "id": "A-001",
            "title": "Donation-based share-price inflation",
            "claim": "A first depositor can inflate the vault share price "
                      "before deposits, stealing later depositors' funds",
            "root_cause": {
                "summary": "unprotected initial share-price formation",
                "mechanism": "donate assets before the first deposit to "
                              "manipulate the exchange rate"},
            "sources": [
                {"step": 1, "skill_name": "configurable-auditor",
                  "original_finding_id": "ca-1",
                  "artifact_manifest": "../steps/1/artifact-manifest.yaml",
                  "report": {"artifact_id": "primary-report"},
                  "locations": ["src/Vault.sol:1"], "note": "share price manipulation"},
                {"step": 2, "skill_name": "fixed-auditor",
                  "original_finding_id": None,
                  "artifact_manifest": "../steps/2/artifact-manifest.yaml",
                  "report": {"artifact_id": "primary-report"},
                  "locations": ["src/Vault.sol:1"], "note": "inflation attack"},
            ],
            "preconditions": ["vault holds zero or few shares"],
            "affected_code": ["src/Vault.sol"],
            "disagreements": ["fixed-auditor rates it medium, configurable high"],
            "coverage_gaps": ["fee-on-deposit variant not exercised"],
            "severity_hint": "HIGH",
            "confidence_hint": "high",
        })

        # 15. audit finalize
        r = arun(["finalize", "--work-root", work, "--expected-revision", 3,
                  "--json"])
        self.assertEqual(r.returncode, 0, r.stderr)
        handoff = json.loads(r.stdout)["handoff"]
        self.assertTrue(os.path.isfile(handoff))
        self.assertIn("Audit complete", "\n".join(json.loads(r.stdout)["lines"]))

        # 16-17. separate lifecycle case with program/rules initialized
        case = os.path.join(self.tmp, "case")
        rules = wfile(os.path.join(self.tmp, "rules-snapshot.md"),
                      "# Rules v1\n\nimpacts: loss of funds\n")
        prog = wyaml(os.path.join(self.tmp, "program.yaml"), PROGRAM)
        r = lrun(["init", "--case-root", case, "--program-yaml", prog,
                  "--rules-snapshot", rules])
        self.assertEqual(r.returncode, 0, r.stderr)

        # 18. import-audit
        r = lrun(["import-audit", "--case-root", case, "--handoff", handoff,
                  "--json"])
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout)
        self.assertEqual(out["status"], "imported")
        self.assertEqual(out["candidates"], ["A-001"])

        # 19. delete the original audit workspace entirely
        shutil.rmtree(work)

        # 20. lifecycle imported evidence remains complete
        imports = os.path.join(case, "imports", "audit", rid)
        for rel in ("manifest.yaml", "analysis.md", "candidates/A-001.yaml",
                    "artifact-manifests/step-1.yaml", "artifact-manifests/step-2.yaml"):
            self.assertTrue(os.path.isfile(os.path.join(imports, rel)), rel)
        srcs = [os.path.join(dp, f)
                for dp, _, fs in os.walk(os.path.join(imports, "sources"))
                for f in fs]
        self.assertTrue(any("report" in s for s in srcs), srcs)

        # 21. complete the prescreen in the scaffolded draft
        draft = os.path.join(case, "ingest", rid, "finding-source.A-001.yaml")
        self.assertTrue(os.path.isfile(draft))
        text = "\n".join(l for l in open(draft, encoding="utf-8").read().splitlines()
                         if not l.startswith("#"))
        doc = yaml.safe_load(text)
        doc["title"] = "Donation-based share-price inflation"
        doc["claim"] = "A first depositor can inflate the vault share price"
        for item in doc["prescreen"]:
            item["evidence"] = "verified by hand"
            item["explanation"] = {
                "scope": "vault is an in-scope target",
                "authority": "attack needs no privileged role",
                "exclusion": "no exclusion clause applies",
                "duplication": "index empty; no prior finding",
            }[item["aspect"]]
            if item["aspect"] == "duplication":
                item["status"] = "PASS"
        wyaml(draft, doc)

        # 22. register
        r = lrun(["register", "--case-root", case, "--from", draft, "--json"])
        self.assertEqual(r.returncode, 0, r.stderr)

        # 23. the finding reaches DISCOVERED
        fid = json.loads(r.stdout)["id"]
        ledger = os.path.join(case, "findings", f"{fid}.md")
        self.assertTrue(os.path.isfile(ledger))
        lines = open(ledger, encoding="utf-8").read().splitlines()
        end = lines.index("---", 1)
        fm = yaml.safe_load("\n".join(lines[1:end]))
        self.assertEqual(fm["stage"], "DISCOVERED")
        self.assertEqual(fm["disposition"], "OPEN")
        self.assertEqual(fm["sources"]["auditor"], "audit-orchestrator")
        self.assertEqual(fm["sources"]["original_finding_id"], "A-001")
        self.assertEqual(fm["sources"]["audit_round"], rid)


if __name__ == "__main__":
    unittest.main()
