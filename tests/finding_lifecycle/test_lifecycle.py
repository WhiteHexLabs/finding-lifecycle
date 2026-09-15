"""Behavioral acceptance tests for the finding-lifecycle CLI.

Covers the ten scenarios from plan.md section 5 using stdlib unittest,
exercising the real CLI via subprocess in temporary directories.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCRIPT = os.path.join(REPO, "skills", "finding-lifecycle", "scripts", "lifecycle.py")
TEMPLATE_RUNNER = os.path.join(REPO, "skills", "finding-lifecycle", "templates",
                                "poc", "setup_and_run.sh")

TARGET_ADDR = "0x" + "11" * 20
CODE_SHA = "0x" + "cd" * 32
BLOCK_HASH = "0x" + "ab" * 32


def run(args):
    return subprocess.run([sys.executable, SCRIPT] + [str(a) for a in args],
                          capture_output=True, text=True)


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


def wfile(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


def wyaml(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(obj, f, sort_keys=False, allow_unicode=True)
    return path


def read_ledger(root, fid):
    path = os.path.join(root, "findings", fid + ".md")
    with open(path, encoding="utf-8") as f:
        text = f.read()
    lines = text.splitlines()
    end = lines.index("---", 1)
    return yaml.safe_load("\n".join(lines[1:end]))


def write_ledger_fm(root, fid, fm):
    """Simulate a manual frontmatter edit (body preserved)."""
    path = os.path.join(root, "findings", fid + ".md")
    with open(path, encoding="utf-8") as f:
        text = f.read()
    lines = text.splitlines()
    end = lines.index("---", 1)
    body = "\n".join(lines[end + 1:])
    new = "---\n" + yaml.safe_dump(fm, sort_keys=False, allow_unicode=True) + "---\n\n" + body
    with open(path, "w", encoding="utf-8") as f:
        f.write(new)


PROGRAM = {
    "program": {
        "id": "test-prog", "name": "Test Program",
        "rules_url": "https://example.test/rules", "fetched_at": "2026-01-01",
        "valid_until": None,
        "snapshot": {"path": "rules-snapshot.md", "sha256": None},
    },
    "scope": {
        "chains": [1],
        "targets": [{"address": TARGET_ADDR, "role": "primary", "note": ""}],
        "assets": ["USDC"], "impacts_allowed": ["loss-of-funds"],
    },
    "severity_matrix": [
        {"id": "S1", "level": "CRITICAL", "text": "big loss", "basis": "rules"},
        {"id": "S2", "level": "HIGH", "text": "small loss", "basis": "rules"},
    ],
    "exclusions": [{"id": "E1", "category": "privileged", "text": "privileged roles excluded"}],
    "novelty_sources": [{"source": "prior-audits", "location": None, "status": "missing"}],
    "bounty": {"currency": "USD", "ranges": "high: 10k", "min_accepted_payout": None},
    "submission_limits": {"accounts": [], "counting": "per 14 days", "window": None,
                          "max_per_window": None, "timezone": "UTC"},
    "delivery": {"language": "en", "fields": ["summary"], "attachments": "zip",
                 "private_channels": ["private repo"]},
    "kyc": {"required": "UNKNOWN"},
    "response": {"sla": None, "appeal": {"method": None, "deadline_days": None}},
}

FINDING_SRC = {
    "title": "State updated after transfer in withdraw()",
    "claim": "withdraw() sends ETH before clearing the balance mapping",
    "sources": {"auditor": "self-audit", "original_finding_id": "A-7",
                "audit_round": "round-1", "files": []},
    "prescreen": [
        {"aspect": "scope", "status": "PASS", "evidence": "program.yaml scope",
         "explanation": "target address is in scope"},
        {"aspect": "authority", "status": "PASS", "evidence": "none needed",
         "explanation": "attack requires no privileged role"},
        {"aspect": "exclusion", "status": "PASS", "evidence": "rules E1..E2",
         "explanation": "not MEV, not privileged"},
        {"aspect": "duplication", "status": "PASS", "evidence": "index.md empty",
         "explanation": "no prior finding matches"},
    ],
}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="fl-case-")
        self.root = os.path.join(self.tmp, "case")
        self.snap = wfile(os.path.join(self.tmp, "rules-snapshot.md"),
                          "# Rules snapshot v1\n\n impacts: loss of funds\n")
        self.prog_src = wyaml(os.path.join(self.tmp, "program-src.yaml"), PROGRAM)
        r = run(["init", "--case-root", self.root, "--program-yaml", self.prog_src,
                 "--rules-snapshot", self.snap])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.snap_hash = sha(self.snap)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    # -- flow helpers -------------------------------------------------------

    def register(self, src=None):
        src = src or FINDING_SRC
        p = wyaml(os.path.join(self.tmp, "finding-src.yaml"), src)
        r = run(["register", "--case-root", self.root, "--from", p, "--json"])
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)["id"]

    def evidence(self, fid, name):
        return os.path.join(self.root, "evidence", fid, name)

    def build_prior_art(self, fid, result="NO_MATCH", still_eligible=None,
                        no_reports=False, missing_file=False, wrong_hash=False,
                        conclusion="NEW", checks=None):
        report_rel = f"evidence/{fid}/prior-art/audit-2025.md"
        if not no_reports and not missing_file:
            wfile(os.path.join(self.root, report_rel),
                  "# 2025 audit\n\nfindings: oracle staleness, governance delay\n")
        reports = []
        if not no_reports:
            reports.append({
                "title": "2025 audit", "url": "https://example.test/audit-2025.pdf",
                "auditor": "Firm X", "date": "2025-06-01", "path": report_rel,
                "sha256": "0" * 64 if (wrong_hash or missing_file)
                          else sha(os.path.join(self.root, report_rel)),
            })
        if checks is None:
            if no_reports:
                checks = []
            else:
                check = {
                    "report": "2025 audit",
                    "searched_for": ["withdraw", "reentrancy", "state update"],
                    "result": result,
                    "detail": "no finding shares this root cause" if result == "NO_MATCH"
                              else "see overlap note",
                    "location": "p.12 §3.4" if result in ("MATCH", "PARTIAL") else None,
                }
                if still_eligible:
                    check["still_eligible"] = still_eligible
                checks = [check]
        wyaml(self.evidence(fid, "prior-art.yaml"), {
            "discovery": [
                {"kind": "docs_site", "url": "https://docs.example.test/security",
                 "fetched_at": "2026-09-14", "note": "audits section"},
                {"kind": "program_page", "url": "https://platform.test/example",
                 "fetched_at": "2026-09-14", "note": "audit links"},
            ],
            "reports": reports,
            "checks": checks,
            "no_reports_found": bool(no_reports),
            "no_reports_note": "docs site and program page list no audits"
                               if no_reports else None,
            "conclusion": conclusion,
        })

    def build_cross_check(self, fid, skip_assessment=False):
        if not skip_assessment:
            wfile(self.evidence(fid, "assessment.md"),
                  "# Assessment\n\nclaim holds on the live deployment\n")
        wyaml(self.evidence(fid, "cross-check.yaml"), {
            "targets": [{
                "chain_id": 1, "address": TARGET_ADDR,
                "proxy_address": None, "implementation_address": None,
                "block": 19000000, "code_sha256": CODE_SHA,
            }],
            "root_cause": {"claim": "state cleared after external call",
                           "variants": []},
            "refutation_attempts": [
                {"attempt": "try the owner-guarded path",
                 "outcome": "reverts via onlyOwner"}],
            "damage_vs_profit": {
                "victim_damage": "depositors lose 123 USDC",
                "attacker_profit": "attacker extracts 123 USDC"},
            "assessment": f"evidence/{fid}/assessment.md",
            "uncovered_variants": [],
        })

    def build_fork_proof(self, fid, result="PASS", break_log=None):
        log_text = "ExploitTest: PASS ProfitWithdrawn (runs: 1)\n"
        if break_log:
            log_text = break_log
        wfile(self.evidence(fid, "Exploit.t.sol"), "// exploit test\n")
        wfile(self.evidence(fid, "run.log"), log_text)
        wyaml(self.evidence(fid, "fork-proof.yaml"), {
            "fork": {"chain_id": 1, "block_number": 19000000,
                     "block_hash": BLOCK_HASH,
                     "rpc_url_ref": "env MAINNET_RPC_URL",
                     "tool_versions": {"forge": "0.2.2"}},
            "targets_checked": [TARGET_ADDR],
            "capabilities": [{"name": "deal",
                              "used_for": "seed attacker balance",
                              "justification": "attacker already holds equivalent funds"}],
            "controls": [{"control": "pause", "applicable": False,
                          "verified": "target exposes no pause"}],
            "poc": {"test_file": f"evidence/{fid}/Exploit.t.sol",
                    "run_log": f"evidence/{fid}/run.log",
                    "expected_assertions": ["ProfitWithdrawn"],
                    "result": result},
            "pnl": {"currency": "USDC",
                    "attacker": [{"item": "gross_proceeds", "amount": "123", "known": True}],
                    "victim": [{"item": "direct_loss", "amount": "123", "known": True}]},
        })

    def build_triage(self, fid):
        wyaml(self.evidence(fid, "triage.yaml"), {
            "severity": {"final": "HIGH", "matrix_entry": "S2",
                         "justification": f"amounts in evidence/{fid}/run.log match matrix S2"},
            "eligibility": [
                {"aspect": "scope", "rule_ref": "rules-snapshot.md#scope", "status": "PASS",
                 "evidence": f"evidence/{fid}/run.log", "explanation": "target in scope list"},
                {"aspect": "E1 privileged", "rule_ref": "rules-snapshot.md#E1", "status": "PASS",
                 "evidence": f"evidence/{fid}/assessment.md",
                 "explanation": "no privileged role involved"},
            ],
            "novelty": {"sources_searched": [
                {"source": "prior-audits", "result": "no matching issue", "location": None}],
                "known_issues_found": "none",
                "missing_materials": ["era map not published"]},
            "program_snapshot": {"sha256": self.snap_hash},
        })

    def build_package(self, fid, clean_marker="RESULT: PASS", omit_dep=False,
                      wrong_hash=False, drop_from_zip=False):
        pkg = os.path.join(self.root, "packages", fid)
        report = wfile(os.path.join(pkg, "report.en.md"),
                       "# Unsafe withdraw\n\nroot cause and impact, english report\n")
        test = wfile(os.path.join(pkg, "test", "Exploit.t.sol"), "// poc test\n")
        # omit_dep: the manifest still declares the dependency, but the file
        # itself is missing from the package (the failure the gate must catch)
        dep = None if omit_dep else wfile(os.path.join(pkg, "lib", "util.sh"),
                                          "assert_equal() { [ \"$1\" = \"$2\" ]; }\n")
        wfile(self.evidence(fid, "clean-run.log"),
              f"clean dir run\n{clean_marker}\n")
        files = [
            {"path": f"packages/{fid}/report.en.md",
             "sha256": sha(report), "purpose": "final-report"},
            {"path": f"packages/{fid}/test/Exploit.t.sol",
             "sha256": sha(test), "purpose": "poc-test"},
            {"path": f"packages/{fid}/lib/util.sh",
             "sha256": "0" * 64 if omit_dep else sha(dep), "purpose": "dependency"},
        ]
        if wrong_hash:
            files[0]["sha256"] = "0" * 64
        zpath = os.path.join(pkg, "package.zip")
        with zipfile.ZipFile(zpath, "w") as zf:
            if not drop_from_zip:
                zf.write(report, "report.en.md")
            zf.write(test, "test/Exploit.t.sol")
            if dep:
                zf.write(dep, "lib/util.sh")
        wyaml(os.path.join(pkg, "manifest.yaml"), {
            "package": {
                "report": {"path": f"packages/{fid}/report.en.md",
                           "language": "en", "root_cause_id": "RC-1"},
                "files": files,
                "zip": {"path": f"packages/{fid}/package.zip", "sha256": sha(zpath)},
                "clean_run": {"performed_in": "/tmp/clean-run",
                              "log_path": f"evidence/{fid}/clean-run.log",
                              "result": "PASS"},
                "secrets_scan": {"status": "CLEAN", "exceptions": []},
                "dependencies": {
                    "pinned": [{"name": "foundry", "version": "0.2.2"}],
                    "external_prereqs": ["foundry 0.2.2", "archive RPC"]},
                "self_contained": True,
            },
        })
        return sha(zpath)

    def build_self_review(self, fid, zip_hash, pkg_hash=None):
        wfile(self.evidence(fid, "self-rerun.log"), "independent rerun ok\nRESULT: PASS\n")
        wyaml(self.evidence(fid, "self-review.yaml"), {
            "reviewer": {"identity": "agent-2/session-xyz",
                         "kind": "independent_agent"},
            "package_sha256": "0x" + (pkg_hash or zip_hash),
            "checks": {
                "rerun": {"performed": True, "result": "PASS",
                          "log_path": f"evidence/{fid}/self-rerun.log"},
                "amounts": {"status": "VERIFIED", "notes": "matched run.log"},
                "preconditions": {"status": "VERIFIED", "notes": "checked table"},
                "wording": {"changes": []},
            },
            "adverse_facts": ["none beyond report limitations"],
            "unresolved_objections": [],
        })

    def build_submission(self, fid, zip_hash):
        receipt = wfile(self.evidence(fid, "receipt.txt"), "platform ack ref IMM-1001\n")
        wyaml(self.evidence(fid, "submission.yaml"), {
            "platform_id": "IMM-1001",
            "submitted_at": "2026-09-14T10:00:00+00:00",
            "channel": {"kind": "private_repo", "detail": "private reports repo",
                        "privacy_check": {"performed": True, "result": "PRIVATE"}},
            "package_sha256": "0x" + zip_hash,
            "receipt": {"path": f"evidence/{fid}/receipt.txt", "sha256": sha(receipt)},
            "account_limits": {"checked": True,
                               "result": "1 of 3 in window per manual ledger"},
            "kyc": {"status": "PENDING"},
        })

    def advance(self, fid, stage, reason, code=0):
        r = run(["advance", "--case-root", self.root, "--id", fid,
                 "--reviewer", "tester", "--reason", reason,
                 "--expected-revision", self.revision(fid)])
        self.assertEqual(r.returncode, code,
                         f"advance->{stage}: rc={r.returncode}\nstdout={r.stdout}\nstderr={r.stderr}")
        return r

    def revision(self, fid):
        return read_ledger(self.root, fid)["revision"]

    def flow_to(self, fid, target):
        """Advance through all stages up to and including target."""
        order = ["PRIOR_ART_CHECKED", "CROSS_CHECKED", "FORK_PROVEN", "TRIAGED",
                 "PACKAGED", "SELF_REVIEWED", "SUBMITTED"]
        zip_hash = None
        for stage in order[:order.index(target) + 1]:
            if stage == "PRIOR_ART_CHECKED":
                self.build_prior_art(fid)
                self.advance(fid, stage,
                             f"no audit overlap per evidence/{fid}/prior-art/audit-2025.md")
            elif stage == "CROSS_CHECKED":
                self.build_cross_check(fid)
                self.advance(fid, stage,
                             f"cross-checked deployments; see evidence/{fid}/assessment.md")
            elif stage == "FORK_PROVEN":
                self.build_fork_proof(fid)
                self.advance(fid, stage,
                             f"fork run reproduced at pinned block per evidence/{fid}/run.log")
            elif stage == "TRIAGED":
                self.build_triage(fid)
                self.advance(fid, stage,
                             f"eligibility PASS; severity per evidence/{fid}/run.log")
            elif stage == "PACKAGED":
                zip_hash = self.build_package(fid)
                self.advance(fid, stage,
                             f"clean-dir run passed; log at evidence/{fid}/clean-run.log")
            elif stage == "SELF_REVIEWED":
                self.build_self_review(fid, zip_hash)
                self.advance(fid, stage,
                             f"independent rerun bound to package; log evidence/{fid}/self-rerun.log")
            elif stage == "SUBMITTED":
                self.build_submission(fid, zip_hash)
                r = run(["record", "submission", "--case-root", self.root, "--id", fid,
                         "--expected-revision", self.revision(fid)])
                self.assertEqual(r.returncode, 0, r.stderr)
                self.advance(fid, stage,
                             f"receipt verified, channel PRIVATE; see evidence/{fid}/receipt.txt")
        return zip_hash


# ---------------------------------------------------------------------------
# scenario 1: normal finding advances stage by stage; missing evidence blocks

class TestScenario1(Base):
    def test_full_lifecycle(self):
        fid = self.register()
        self.flow_to(fid, "SUBMITTED")
        fm = read_ledger(self.root, fid)
        self.assertEqual(fm["stage"], "SUBMITTED")
        self.assertEqual(fm["disposition"], "OPEN")
        self.assertEqual(fm["severity"]["final"], "HIGH")
        self.assertEqual([g["status"] for g in fm["gates"]],
                         ["PASSED"] * 7)
        self.assertEqual(fm["revision"], len(fm["history"]))

    def test_missing_assessment_blocks(self):
        fid = self.register()
        self.flow_to(fid, "PRIOR_ART_CHECKED")
        self.build_cross_check(fid, skip_assessment=True)
        self.advance(fid, "CROSS_CHECKED", f"see evidence/{fid}/assessment.md", code=1)
        fm = read_ledger(self.root, fid)
        self.assertEqual(fm["stage"], "PRIOR_ART_CHECKED")
        self.assertEqual(fm["revision"], 2)

    def test_missing_run_log_blocks(self):
        fid = self.register()
        self.flow_to(fid, "CROSS_CHECKED")
        self.build_fork_proof(fid)
        os.remove(self.evidence(fid, "run.log"))
        r = self.advance(fid, "FORK_PROVEN",
                         f"fork reproduced per evidence/{fid}/run.log", code=1)
        self.assertIn("run.log", r.stdout + r.stderr)

    def test_unknown_input_keys_rejected(self):
        fid = self.register()
        self.flow_to(fid, "PRIOR_ART_CHECKED")
        self.build_cross_check(fid)
        path = self.evidence(fid, "cross-check.yaml")
        doc = yaml.safe_load(open(path))
        doc["force"] = True
        wyaml(path, doc)
        r = run(["advance", "--case-root", self.root, "--id", fid,
                 "--reviewer", "t", "--reason", "x" * 40,
                 "--expected-revision", 2])
        self.assertEqual(r.returncode, 2)
        self.assertIn("unknown key", r.stderr)


# ---------------------------------------------------------------------------
# scenario 11: prior-art dedup against the project's own audit reports

class TestScenarioPriorArt(Base):
    def test_match_blocks_advance(self):
        fid = self.register()
        self.build_prior_art(fid, result="MATCH")
        r = self.advance(fid, "PRIOR_ART_CHECKED",
                         f"overlap in evidence/{fid}/prior-art/audit-2025.md", code=1)
        out = r.stdout + r.stderr
        self.assertIn("INELIGIBLE", out)
        fm = read_ledger(self.root, fid)
        self.assertEqual(fm["stage"], "DISCOVERED")

    def test_match_with_still_eligible_passes(self):
        fid = self.register()
        self.build_prior_art(fid, result="MATCH",
                             still_eligible={"rule_ref": "rules-snapshot.md#known-issues",
                                             "explanation": "program pays for known-but-unfixed"})
        self.advance(fid, "PRIOR_ART_CHECKED",
                     f"overlap allowed by rules; report evidence/{fid}/prior-art/audit-2025.md")
        fm = read_ledger(self.root, fid)
        self.assertEqual(fm["stage"], "PRIOR_ART_CHECKED")
        self.assertEqual(fm["prior_art"]["conclusion"], "NEW")
        self.assertEqual(len(fm["prior_art"]["reports"]), 1)
        purposes = [e["purpose"] for e in fm["evidence"]]
        self.assertTrue(any(p.startswith("prior-art-report:") for p in purposes))

    def test_match_then_close_ineligible(self):
        fid = self.register()
        self.build_prior_art(fid, result="MATCH")
        self.advance(fid, "PRIOR_ART_CHECKED",
                     f"overlap in evidence/{fid}/prior-art/audit-2025.md", code=1)
        overlap = wfile(self.evidence(fid, "overlap.md"),
                        "root cause already reported as finding #3 of the 2025 audit\n")
        r = run(["close", "--case-root", self.root, "--id", fid,
                 "--disposition", "INELIGIBLE",
                 "--reason", "already reported in the project's 2025 audit",
                 "--evidence", f"evidence/{fid}/overlap.md",
                 "--expected-revision", 1])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(read_ledger(self.root, fid)["disposition"], "INELIGIBLE")

    def test_not_searchable_blocks(self):
        fid = self.register()
        self.build_prior_art(fid, result="NOT_SEARCHABLE")
        r = self.advance(fid, "PRIOR_ART_CHECKED",
                         f"report at evidence/{fid}/prior-art/audit-2025.md", code=1)
        self.assertIn("NOT_SEARCHABLE", r.stdout + r.stderr)

    def test_known_conclusion_blocks(self):
        fid = self.register()
        self.build_prior_art(fid, conclusion="KNOWN")
        self.advance(fid, "PRIOR_ART_CHECKED",
                     f"known per evidence/{fid}/prior-art/audit-2025.md", code=1)

    def test_missing_report_file_blocks(self):
        fid = self.register()
        self.build_prior_art(fid, missing_file=True)
        r = self.advance(fid, "PRIOR_ART_CHECKED",
                         f"report at evidence/{fid}/prior-art/audit-2025.md", code=1)
        self.assertIn("audit-2025.md", r.stdout + r.stderr)

    def test_wrong_report_hash_blocks(self):
        fid = self.register()
        self.build_prior_art(fid, wrong_hash=True)
        r = self.advance(fid, "PRIOR_ART_CHECKED",
                         f"report at evidence/{fid}/prior-art/audit-2025.md", code=1)
        self.assertIn("hash mismatch", r.stdout + r.stderr)

    def test_no_reports_declared_passes(self):
        fid = self.register()
        self.build_prior_art(fid, no_reports=True)
        r = run(["advance", "--case-root", self.root, "--id", fid,
                 "--reviewer", "t",
                 "--reason", "checked docs site and program page, no audits published anywhere",
                 "--expected-revision", 1])
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_no_reports_undeclared_fails(self):
        fid = self.register()
        self.build_prior_art(fid, no_reports=True)
        path = self.evidence(fid, "prior-art.yaml")
        doc = yaml.safe_load(open(path))
        doc["no_reports_found"] = False
        doc["no_reports_note"] = None
        wyaml(path, doc)
        r = run(["advance", "--case-root", self.root, "--id", fid,
                 "--reviewer", "t",
                 "--reason", "checked docs site and program page, no audits published anywhere",
                 "--expected-revision", 1])
        self.assertEqual(r.returncode, 1)

    def test_check_for_unknown_report_rejected(self):
        fid = self.register()
        self.build_prior_art(fid, checks=[{
            "report": "nonexistent report", "searched_for": ["withdraw"],
            "result": "NO_MATCH", "detail": "n/a", "location": None,
        }])
        r = self.advance(fid, "PRIOR_ART_CHECKED",
                         f"report at evidence/{fid}/prior-art/audit-2025.md", code=1)
        self.assertIn("unknown report", r.stdout + r.stderr)

    def test_discovery_required(self):
        fid = self.register()
        self.build_prior_art(fid)
        path = self.evidence(fid, "prior-art.yaml")
        doc = yaml.safe_load(open(path))
        doc["discovery"] = []
        wyaml(path, doc)
        r = self.advance(fid, "PRIOR_ART_CHECKED",
                         f"report at evidence/{fid}/prior-art/audit-2025.md", code=1)
        self.assertIn("discovery", r.stdout + r.stderr)

    def test_modified_report_invalidates_gate(self):
        fid = self.register()
        self.flow_to(fid, "PRIOR_ART_CHECKED")
        wfile(self.evidence(fid, "prior-art/audit-2025.md"), "tampered report\n")
        r = self.advance(fid, "CROSS_CHECKED",
                         f"see evidence/{fid}/assessment.md", code=1)
        self.assertIn("INVALID", r.stdout + r.stderr)


# ---------------------------------------------------------------------------
# scenario 2: REFUTED needs fork counter-evidence; RPC failure stays a blocker

class TestScenario2(Base):
    def test_refuted_requires_fork_counter_evidence(self):
        fid = self.register()
        # no refutation artifacts -> rejected; static doubt stays a blocker
        r = run(["close", "--case-root", self.root, "--id", fid,
                 "--disposition", "REFUTED", "--boundary", "b" * 40,
                 "--expected-revision", 1])
        self.assertEqual(r.returncode, 2)
        # log without the explicit refutation marker -> rejected
        wfile(self.evidence(fid, "Refuted.t.sol"), "// blocked\n")
        wfile(self.evidence(fid, "weak.log"),
              "attack script reverted\nRESULT: PASS\n")
        r = run(["close", "--case-root", self.root, "--id", fid,
                 "--disposition", "REFUTED",
                 "--refutation-poc", f"evidence/{fid}/Refuted.t.sol",
                 "--refutation-log", f"evidence/{fid}/weak.log",
                 "--boundary", "b" * 40,
                 "--expected-revision", 1])
        self.assertEqual(r.returncode, 2)
        self.assertIn("RESULT: REFUTED", r.stderr)
        self.assertEqual(read_ledger(self.root, fid)["disposition"], "OPEN")

    def test_refuted_needs_artifacts_and_boundary(self):
        fid = self.register()
        r = run(["close", "--case-root", self.root, "--id", fid,
                 "--disposition", "REFUTED", "--boundary", "b" * 40,
                 "--expected-revision", self.revision(fid)])
        self.assertEqual(r.returncode, 2)
        poc = wfile(self.evidence(fid, "Refuted.t.sol"), "// blocked\n")
        log = wfile(self.evidence(fid, "refuted.log"),
                    "attempted exploit reverts at onlyOwner\nRESULT: REFUTED\n")
        r = run(["close", "--case-root", self.root, "--id", fid,
                 "--disposition", "REFUTED",
                 "--refutation-poc", f"evidence/{fid}/Refuted.t.sol",
                 "--refutation-log", f"evidence/{fid}/refuted.log",
                 "--boundary",
                 "refuted on deployment 0x11..1 at block 19000000 only; "
                 "other variants untouched",
                 "--expected-revision", self.revision(fid)])
        self.assertEqual(r.returncode, 0, r.stderr)
        fm = read_ledger(self.root, fid)
        self.assertEqual(fm["disposition"], "REFUTED")
        self.assertIn("boundary", fm["refutation"])

    def test_rpc_failure_stays_blocked(self):
        fid = self.register()
        self.flow_to(fid, "CROSS_CHECKED")
        self.build_fork_proof(fid, result="FAIL",
                              break_log="error: RPC endpoint unreachable\n")
        self.advance(fid, "FORK_PROVEN",
                     f"fork failed; see evidence/{fid}/run.log", code=1)
        r = run(["record", "blocker", "--case-root", self.root, "--id", fid,
                 "--item", "RPC unavailable", "--next-step", "switch archive provider",
                 "--expected-revision", self.revision(fid)])
        self.assertEqual(r.returncode, 0, r.stderr)
        r = run(["close", "--case-root", self.root, "--id", fid,
                 "--disposition", "REFUTED", "--boundary", "b" * 40,
                 "--refutation-poc", "x", "--refutation-log", "y",
                 "--expected-revision", self.revision(fid)])
        self.assertEqual(r.returncode, 2)
        fm = read_ledger(self.root, fid)
        self.assertEqual(fm["disposition"], "OPEN")
        self.assertEqual(len(fm["blockers"]), 1)


# ---------------------------------------------------------------------------
# scenario 3: ineligible vs refuted are distinct; merges keep sources, no cycles

class TestScenario3(Base):
    def test_ineligible_close(self):
        fid = self.register()
        ev = wfile(self.evidence(fid, "ineligible.md"), "target out of scope per rules\n")
        r = run(["close", "--case-root", self.root, "--id", fid,
                 "--disposition", "INELIGIBLE", "--reason", "out of scope",
                 "--evidence", f"evidence/{fid}/ineligible.md",
                 "--expected-revision", 1])
        self.assertEqual(r.returncode, 0, r.stderr)
        fm = read_ledger(self.root, fid)
        self.assertEqual(fm["disposition"], "INELIGIBLE")
        purposes = [e["purpose"] for e in fm["evidence"]]
        self.assertIn("ineligibility-evidence", purposes)

    def test_merge_preserves_sources(self):
        a = self.register()
        b_src = dict(FINDING_SRC)
        b_src["title"] = "Duplicate of the withdraw issue"
        b = self.register(b_src)
        r = run(["close", "--case-root", self.root, "--id", b,
                 "--disposition", "MERGED", "--into", a,
                 "--expected-revision", 1])
        self.assertEqual(r.returncode, 0, r.stderr)
        fmb = read_ledger(self.root, b)
        self.assertEqual(fmb["disposition"], "MERGED")
        self.assertEqual(fmb["duplicate_of"], a)
        self.assertEqual(fmb["sources"]["original_finding_id"], "A-7")
        self.assertEqual([h["event"] for h in fmb["history"]][-1], "closed")

    def test_merge_cycles_rejected(self):
        a = self.register()
        b = self.register(dict(FINDING_SRC, title="dup"))
        r = run(["close", "--case-root", self.root, "--id", b,
                 "--disposition", "MERGED", "--into", a, "--expected-revision", 1])
        self.assertEqual(r.returncode, 0, r.stderr)
        r = run(["close", "--case-root", self.root, "--id", a,
                 "--disposition", "MERGED", "--into", b,
                 "--expected-revision", self.revision(a)])
        self.assertEqual(r.returncode, 2)
        self.assertIn("cycle", r.stderr)
        r = run(["close", "--case-root", self.root, "--id", a,
                 "--disposition", "MERGED", "--into", a,
                 "--expected-revision", self.revision(a)])
        self.assertEqual(r.returncode, 2)


# ---------------------------------------------------------------------------
# scenario 4: modified PoC / report / deployment / rules invalidate gates

class TestScenario4(Base):
    def test_modified_poc_invalidates_gate(self):
        fid = self.register()
        self.flow_to(fid, "FORK_PROVEN")
        wfile(self.evidence(fid, "run.log"), "tampered log\n")
        r = self.advance(fid, "TRIAGED",
                         f"eligibility ok per evidence/{fid}/run.log", code=1)
        out = r.stdout + r.stderr
        self.assertIn("INVALID", out)
        r = run(["resume", "--case-root", self.root, "--id", fid])
        self.assertEqual(r.returncode, 1)

    def test_modified_rules_invalidates_gate(self):
        fid = self.register()
        self.flow_to(fid, "TRIAGED")
        wfile(os.path.join(self.root, "rules-snapshot.md"), "changed rules\n")
        self.advance(fid, "PACKAGED",
                     f"package ok per evidence/{fid}/clean-run.log", code=1)

    def test_modified_targets_invalidates_gate(self):
        fid = self.register()
        self.flow_to(fid, "PACKAGED")
        fm = read_ledger(self.root, fid)
        fm["targets"].append({"chain_id": 1, "address": "0x" + "22" * 20,
                              "proxy_address": None, "implementation_address": None,
                              "block": None, "code_sha256": "0x" + "ee" * 32})
        write_ledger_fm(self.root, fid, fm)
        self.advance(fid, "SELF_REVIEWED",
                     f"review bound to package; log evidence/{fid}/self-rerun.log",
                     code=1)


# ---------------------------------------------------------------------------
# scenario 5: concurrent writers — one wins, the other gets a conflict

class TestScenario5(Base):
    def test_revision_conflict(self):
        fid = self.register()
        self.build_prior_art(fid)
        r1 = run(["advance", "--case-root", self.root, "--id", fid,
                  "--reviewer", "s1", "--reason",
                  f"session1 checked evidence/{fid}/prior-art/audit-2025.md",
                  "--expected-revision", 1])
        r2 = run(["advance", "--case-root", self.root, "--id", fid,
                  "--reviewer", "s2", "--reason",
                  f"session2 checked evidence/{fid}/prior-art/audit-2025.md",
                  "--expected-revision", 1])
        self.assertEqual(r1.returncode, 0, r1.stderr)
        self.assertEqual(r2.returncode, 2)
        self.assertIn("revision conflict", r2.stderr)
        fm = read_ledger(self.root, fid)
        self.assertEqual(fm["revision"], 2)
        self.assertEqual(len(fm["history"]), 2)


# ---------------------------------------------------------------------------
# scenario 6: ledger saved but index update fails — recovery rebuilds, no re-migration

class TestScenario6(Base):
    def test_index_failure_then_recovery(self):
        fid = self.register()
        self.build_prior_art(fid)
        idx = os.path.join(self.root, "index.md")
        os.remove(idx)
        os.mkdir(idx)  # make the index path unwritable-as-file
        r = run(["advance", "--case-root", self.root, "--id", fid,
                 "--reviewer", "t", "--reason",
                 f"checked evidence/{fid}/prior-art/audit-2025.md",
                 "--expected-revision", 1])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("index needs repair", r.stderr)
        fm = read_ledger(self.root, fid)
        self.assertEqual(fm["stage"], "PRIOR_ART_CHECKED")
        self.assertEqual(fm["revision"], 2)
        self.assertEqual(sum(1 for h in fm["history"] if h["event"] == "advanced"), 1)
        # recovery: rebuild index, no duplicate migration
        shutil.rmtree(idx)
        r = run(["index", "--case-root", self.root])
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(os.path.join(self.root, "index.md"), encoding="utf-8") as f:
            content = f.read()
        self.assertIn(fid, content)
        self.assertIn("PRIOR_ART_CHECKED", content)
        fm2 = read_ledger(self.root, fid)
        self.assertEqual(fm2["revision"], 2)


# ---------------------------------------------------------------------------
# scenario 7: illegal fields, path traversal, wrong hashes, merge cycles

class TestScenario7(Base):
    def test_path_traversal_rejected(self):
        fid = self.register()
        self.flow_to(fid, "PRIOR_ART_CHECKED")
        wfile(os.path.join(self.tmp, "outside.md"), "outside\n")
        self.build_cross_check(fid)
        path = self.evidence(fid, "cross-check.yaml")
        doc = yaml.safe_load(open(path))
        doc["assessment"] = "../outside.md"
        wyaml(path, doc)
        r = run(["advance", "--case-root", self.root, "--id", fid,
                 "--reviewer", "t", "--reason", "../outside.md reviewed",
                 "--expected-revision", 2])
        self.assertEqual(r.returncode, 2)
        self.assertIn("escapes", r.stderr)

    def test_wrong_evidence_hash_blocks(self):
        fid = self.register()
        self.flow_to(fid, "TRIAGED")
        self.build_package(fid, wrong_hash=True)
        r = self.advance(fid, "PACKAGED",
                         f"package ok per evidence/{fid}/clean-run.log", code=1)
        self.assertIn("hash mismatch", r.stdout + r.stderr)

    def test_register_rejects_missing_prescreen(self):
        src = dict(FINDING_SRC)
        src["prescreen"] = src["prescreen"][:2]
        p = wyaml(os.path.join(self.tmp, "bad-src.yaml"), src)
        r = run(["register", "--case-root", self.root, "--from", p])
        self.assertEqual(r.returncode, 2)
        self.assertIn("prescreen", r.stderr)

    def test_register_rejects_duplication_not_pass(self):
        src = yaml.safe_load(yaml.safe_dump(FINDING_SRC))
        src["prescreen"][3]["status"] = "UNKNOWN"
        p = wyaml(os.path.join(self.tmp, "bad-dup.yaml"), src)
        r = run(["register", "--case-root", self.root, "--from", p])
        self.assertEqual(r.returncode, 2)
        self.assertIn("duplication", r.stderr)

    def test_bad_enum_rejected(self):
        fid = self.register()
        self.flow_to(fid, "CROSS_CHECKED")
        self.build_fork_proof(fid)
        path = self.evidence(fid, "fork-proof.yaml")
        doc = yaml.safe_load(open(path))
        doc["poc"]["result"] = "MAYBE"
        wyaml(path, doc)
        r = run(["advance", "--case-root", self.root, "--id", fid,
                 "--reviewer", "t", "--reason",
                 f"fork ok per evidence/{fid}/run.log",
                 "--expected-revision", self.revision(fid)])
        self.assertEqual(r.returncode, 2)


# ---------------------------------------------------------------------------
# scenario 8: wrong-bound self-review, receipt-less submission, baseless decision

class TestScenario8(Base):
    def test_self_review_wrong_package_hash(self):
        fid = self.register()
        zip_hash = self.flow_to(fid, "PACKAGED")
        self.build_self_review(fid, zip_hash, pkg_hash="ff" * 32)
        r = self.advance(fid, "SELF_REVIEWED",
                         f"review bound; log evidence/{fid}/self-rerun.log", code=1)
        self.assertIn("package", (r.stdout + r.stderr).lower())

    def test_submitted_requires_recorded_receipt(self):
        fid = self.register()
        zip_hash = self.flow_to(fid, "SELF_REVIEWED")
        r = self.advance(fid, "SUBMITTED",
                         f"receipt at evidence/{fid}/receipt.txt", code=1)
        self.assertIn("submission", (r.stdout + r.stderr).lower())
        self.build_submission(fid, zip_hash)
        r = run(["record", "submission", "--case-root", self.root, "--id", fid,
                 "--expected-revision", self.revision(fid)])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.advance(fid, "SUBMITTED",
                     f"receipt verified; see evidence/{fid}/receipt.txt")

    def test_platform_result_requires_submission(self):
        fid = self.register()
        ev = wfile(self.evidence(fid, "award.md"), "award notice\n")
        r = run(["close", "--case-root", self.root, "--id", fid,
                 "--disposition", "ACCEPTED", "--evidence", f"evidence/{fid}/award.md",
                 "--expected-revision", 1])
        self.assertEqual(r.returncode, 2)
        self.assertIn("submission", r.stderr)


# ---------------------------------------------------------------------------
# scenario 9: REJECTED -> appeal -> new decision; history preserved

class TestScenario9(Base):
    def test_appeal_flow(self):
        fid = self.register()
        self.flow_to(fid, "SUBMITTED")
        rev = self.revision(fid)
        rej = wfile(self.evidence(fid, "rejection.md"), "duplicate per triager\n")
        r = run(["record", "response", "--case-root", self.root, "--id", fid,
                 "--decision", "REJECTED", "--evidence", f"evidence/{fid}/rejection.md",
                 "--reason", "triager says duplicate",
                 "--expected-revision", rev])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(read_ledger(self.root, fid)["disposition"], "REJECTED")

        mat = wfile(self.evidence(fid, "appeal.md"), "point-by-point rebuttal\n")
        r = run(["record", "appeal", "--case-root", self.root, "--id", fid,
                 "--status", "DRAFTED", "--materials", f"evidence/{fid}/appeal.md",
                 "--deadline", "2026-09-30", "--expected-revision", self.revision(fid)])
        self.assertEqual(r.returncode, 0, r.stderr)
        rcpt = wfile(self.evidence(fid, "appeal-receipt.txt"), "sent via portal\n")
        r = run(["record", "appeal", "--case-root", self.root, "--id", fid,
                 "--status", "SENT", "--receipt", f"evidence/{fid}/appeal-receipt.txt",
                 "--expected-revision", self.revision(fid)])
        self.assertEqual(r.returncode, 0, r.stderr)

        award = wfile(self.evidence(fid, "award.md"), "re-reviewed: accepted\n")
        r = run(["record", "response", "--case-root", self.root, "--id", fid,
                 "--decision", "ACCEPTED", "--evidence", f"evidence/{fid}/award.md",
                 "--expected-revision", self.revision(fid)])
        self.assertEqual(r.returncode, 0, r.stderr)

        fm = read_ledger(self.root, fid)
        self.assertEqual(fm["disposition"], "ACCEPTED")
        self.assertEqual(fm["appeal"]["status"], "RESOLVED")
        events = [h["event"] for h in fm["history"]]
        self.assertEqual(events.count("response_recorded"), 2)
        self.assertEqual(events.count("appeal_updated"), 2)
        # the rejection event and both appeal updates are still in history
        decisions = [h["detail"].get("decision") for h in fm["history"]
                     if h["event"] == "response_recorded"]
        self.assertEqual(decisions, ["REJECTED", "ACCEPTED"])

    def test_appeal_requires_sequential_transition(self):
        fid = self.register()
        self.flow_to(fid, "SUBMITTED")
        wfile(self.evidence(fid, "rejection.md"), "rej\n")
        run(["record", "response", "--case-root", self.root, "--id", fid,
             "--decision", "REJECTED", "--evidence", f"evidence/{fid}/rejection.md",
             "--expected-revision", self.revision(fid)])
        rcpt = wfile(self.evidence(fid, "appeal-receipt.txt"), "sent\n")
        r = run(["record", "appeal", "--case-root", self.root, "--id", fid,
                 "--status", "SENT", "--receipt", f"evidence/{fid}/appeal-receipt.txt",
                 "--expected-revision", self.revision(fid)])
        self.assertEqual(r.returncode, 2)
        self.assertIn("sequential", r.stderr)


# ---------------------------------------------------------------------------
# scenario 10: clean-dir package behavior

class TestScenario10(Base):
    def test_missing_dependency_fails_gate(self):
        fid = self.register()
        self.flow_to(fid, "TRIAGED")
        self.build_package(fid, omit_dep=True)
        self.advance(fid, "PACKAGED",
                     f"package per evidence/{fid}/clean-run.log", code=1)

    def test_clean_run_marker_required(self):
        fid = self.register()
        self.flow_to(fid, "TRIAGED")
        self.build_package(fid, clean_marker="finished without marker")
        r = self.advance(fid, "PACKAGED",
                         f"package per evidence/{fid}/clean-run.log", code=1)
        self.assertIn("RESULT: PASS", r.stdout + r.stderr)

    def test_zip_must_contain_listed_files(self):
        fid = self.register()
        self.flow_to(fid, "TRIAGED")
        self.build_package(fid, drop_from_zip=True)
        self.advance(fid, "PACKAGED",
                     f"package per evidence/{fid}/clean-run.log", code=1)

    def test_runner_script_executes_assertions(self):
        work = tempfile.mkdtemp(prefix="fl-pkg-")
        self.addCleanup(shutil.rmtree, work)
        script = wfile(os.path.join(work, "setup_and_run.sh"), (
            "#!/usr/bin/env bash\nset -euo pipefail\n"
            "if [ ! -f lib/util.sh ]; then echo 'missing pinned dependency lib/util.sh' >&2; exit 2; fi\n"
            ". ./lib/util.sh\n"
            "assert_equal 2 2\n"
            "echo 'RESULT: PASS'\n"))
        os.chmod(script, 0o755)
        r = subprocess.run(["bash", script], capture_output=True, text=True, cwd=work)
        self.assertEqual(r.returncode, 2)
        self.assertIn("missing pinned dependency", r.stderr)
        wfile(os.path.join(work, "lib", "util.sh"),
              'assert_equal() { [ "$1" = "$2" ]; }\n')
        r = subprocess.run(["bash", script], capture_output=True, text=True, cwd=work)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("RESULT: PASS", r.stdout)

    def test_template_runner_requires_env(self):
        work = tempfile.mkdtemp(prefix="fl-tpl-")
        self.addCleanup(shutil.rmtree, work)
        r = subprocess.run(["bash", TEMPLATE_RUNNER], capture_output=True,
                           text=True, cwd=work)
        self.assertEqual(r.returncode, 2)
        self.assertTrue(r.stderr.strip())


# ---------------------------------------------------------------------------
# reopen semantics (plan 2.2)

class TestReopen(Base):
    def test_reopen_invalidates_gates_and_keeps_history(self):
        fid = self.register()
        self.flow_to(fid, "FORK_PROVEN")
        ev = wfile(self.evidence(fid, "ineligible.md"), "wrong chain\n")
        run(["close", "--case-root", self.root, "--id", fid,
             "--disposition", "INELIGIBLE", "--reason", "wrong chain",
             "--evidence", f"evidence/{fid}/ineligible.md",
             "--expected-revision", self.revision(fid)])
        newev = wfile(self.evidence(fid, "new-rules.md"), "rules updated\n")
        r = run(["reopen", "--case-root", self.root, "--id", fid,
                 "--reason", "program scope was updated",
                 "--affect-stage", "CROSS_CHECKED",
                 "--evidence", f"evidence/{fid}/new-rules.md",
                 "--expected-revision", self.revision(fid)])
        self.assertEqual(r.returncode, 0, r.stderr)
        fm = read_ledger(self.root, fid)
        self.assertEqual(fm["disposition"], "OPEN")
        self.assertEqual(fm["stage"], "PRIOR_ART_CHECKED")
        events = [h["event"] for h in fm["history"]]
        self.assertIn("closed", events)
        self.assertEqual(events[-1], "reopened")
        statuses = {g["id"]: g["status"] for g in fm["gates"]}
        self.assertEqual(statuses["advance:PRIOR_ART_CHECKED"], "PASSED")
        self.assertEqual(set(statuses.values()) - {"PASSED"}, {"INVALID"})
        r = run(["resume", "--case-root", self.root, "--id", fid])
        self.assertEqual(r.returncode, 0)

    def test_reopen_open_finding_rejected(self):
        fid = self.register()
        r = run(["reopen", "--case-root", self.root, "--id", fid,
                 "--reason", "x" * 40, "--affect-stage", "CROSS_CHECKED",
                 "--expected-revision", 1])
        self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    unittest.main()
