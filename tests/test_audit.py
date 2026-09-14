"""Tests for the sequential audit entry: config validation, batch order,
recovery, staleness and the ingest/register entry gate."""

import json
import os
import unittest

import yaml

from test_lifecycle import Base, FINDING_SRC, REPO, run, wfile, wyaml


def run_yaml(root, run_id):
    with open(os.path.join(root, "audits", run_id, "run.yaml"), encoding="utf-8") as f:
        return yaml.safe_load(f)


def current_run_id(root):
    runs = sorted(d for d in os.listdir(os.path.join(root, "audits"))
                  if d.startswith("run-"))
    return runs[-1]


class AuditBase(Base):
    def setUp(self):
        super().setUp()
        self.target = os.path.join(self.tmp, "target")
        self.skill_a = wfile(os.path.join(self.tmp, "skills", "alpha", "SKILL.md"),
                             "---\nname: alpha-auditor\n---\n\n"
                             "# alpha\n\nread every scope file and report findings.\n")
        self.skill_b = wfile(os.path.join(self.tmp, "skills", "beta", "SKILL.md"),
                             "---\nname: beta-auditor\n---\n\n"
                             "# beta\n\ncheck invariants and report findings.\n")
        wfile(os.path.join(self.target, "src", "Vault.sol"), "contract Vault {}\n")
        wfile(os.path.join(self.target, "src", "Pool.sol"), "contract Pool {}\n")

    def write_config(self, skills=None, scope=("src",), target_root=None):
        wyaml(os.path.join(self.root, "audit-skills.yaml"), {
            "target_root": target_root or self.target,
            "scope": list(scope),
            "skills": list(skills if skills is not None else [self.skill_a, self.skill_b]),
        })

    def prepare(self, *extra):
        return run(["audit", "prepare", "--case-root", self.root, "--json", *extra])

    def rid(self):
        return current_run_id(self.root)

    def rev(self):
        return run_yaml(self.root, self.rid())["revision"]

    def record(self, step, status, note="covered both contracts in scope; see report",
               report=None, log=None, rev=None):
        p = wyaml(os.path.join(self.tmp, f"result-{step}-{status}-{id(note) % 997}.yaml"),
                  {"status": status, "note": note, "report": report, "log": log})
        return run(["audit", "record", "--case-root", self.root, "--step", step,
                    "--input", p,
                    "--expected-revision", rev if rev is not None else self.rev()])

    def complete_all(self):
        """First pass: complete every step in order (zero-findings reports)."""
        out = json.loads(self.prepare().stdout)
        for st in out["steps"]:
            report = wfile(os.path.join(self.tmp, f"report-{st['step']}.md"),
                           f"# report {st['step']}\n\nno findings; both contracts covered\n")
            log = wfile(os.path.join(self.tmp, f"log-{st['step']}.txt"),
                        f"executed skill {st['step']}\n")
            r = self.record(st["step"], "COMPLETED",
                            note=f"skill {st['step']} covered src fully; zero findings",
                            report=report, log=log)
            self.assertEqual(r.returncode, 0, r.stderr)


# ---------------------------------------------------------------------------
# config validation

class TestAuditConfig(AuditBase):
    def test_relative_target_root_resolves_against_case_root(self):
        self.write_config(target_root=os.path.join("..", "target"))
        r = self.prepare()
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout)
        self.assertEqual(len(out["steps"]), 2)
        self.assertTrue(os.path.isdir(os.path.join(self.root, "audits", out["run_id"])))

    def test_empty_skills_is_config_error_without_fallback(self):
        self.write_config(skills=[])
        r = self.prepare()
        self.assertEqual(r.returncode, 2)
        self.assertIn("skills", r.stderr)
        # the report-import entry must NOT open as a fallback
        r = run(["ingest", "--case-root", self.root, "--scan-dir", self.tmp])
        self.assertEqual(r.returncode, 1)
        src = wyaml(os.path.join(self.tmp, "src.yaml"), FINDING_SRC)
        r = run(["register", "--case-root", self.root, "--from", src])
        self.assertEqual(r.returncode, 1)

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
        self.write_config(skills=[os.path.join(REPO, "SKILL.md")])
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
        r = run(["audit", "check", "--case-root", self.root])
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

    def test_failure_continues_but_blocks_check_and_entry(self):
        self.write_config()
        self.prepare()
        r = self.record(1, "FAILED", note="skill crashed reading a contract; no report")
        self.assertEqual(r.returncode, 0, r.stderr)
        report = wfile(os.path.join(self.tmp, "r2.md"), "# r2\ncovered everything\n")
        log = wfile(os.path.join(self.tmp, "l2.txt"), "ran\n")
        r = self.record(2, "COMPLETED", report=report, log=log)
        self.assertEqual(r.returncode, 0, r.stderr)
        # analysis/registration entry stays closed
        r = run(["audit", "check", "--case-root", self.root])
        self.assertEqual(r.returncode, 1)
        src = wyaml(os.path.join(self.tmp, "src.yaml"), FINDING_SRC)
        r = run(["register", "--case-root", self.root, "--from", src])
        self.assertEqual(r.returncode, 1)
        r = run(["ingest", "--case-root", self.root, "--scan-dir", self.tmp])
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
        r = run(["audit", "check", "--case-root", self.root])
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
        r = run(["audit", "check", "--case-root", self.root, "--json"])
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

    def test_resume_reports_audit_without_findings(self):
        self.write_config()
        self.prepare()
        self.record(1, "FAILED", note="blocked: skill needs a tool missing in this env")
        r = run(["resume", "--case-root", self.root])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("audit batch", r.stdout)
        self.assertIn("step 1 FAILED", r.stdout)
        self.assertIn("no findings registered", r.stdout)


# ---------------------------------------------------------------------------
# staleness: config / target / skill / report drift

class TestAuditStaleness(AuditBase):
    def test_config_change_requires_new_batch(self):
        self.write_config()
        self.complete_all()
        self.write_config(skills=[self.skill_b, self.skill_a])  # reorder = new hash
        r = run(["audit", "check", "--case-root", self.root])
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
        r = run(["audit", "check", "--case-root", self.root])
        self.assertEqual(r.returncode, 1)
        self.assertIn("scope drifted", r.stdout + r.stderr)

    def test_target_file_added_requires_new_batch(self):
        self.write_config()
        self.complete_all()
        wfile(os.path.join(self.target, "src", "New.sol"), "contract New {}\n")
        r = run(["audit", "check", "--case-root", self.root])
        self.assertEqual(r.returncode, 1)
        self.assertIn("New.sol", r.stdout + r.stderr)

    def test_skill_change_requires_new_batch(self):
        self.write_config()
        self.complete_all()
        wfile(self.skill_b, "# beta\n\ninstructions changed\n")
        r = run(["audit", "check", "--case-root", self.root])
        self.assertEqual(r.returncode, 1)
        self.assertIn("skill entry changed", r.stdout + r.stderr)

    def test_tampered_report_fails_check(self):
        self.write_config()
        self.complete_all()
        data = run_yaml(self.root, self.rid())
        report_rel = data["steps"][0]["attempts"][-1]["report"]["path"]
        wfile(os.path.join(self.root, report_rel), "# tampered after the fact\n")
        r = run(["audit", "check", "--case-root", self.root])
        self.assertEqual(r.returncode, 1)
        self.assertIn("hash mismatch", r.stdout + r.stderr)

    def test_register_blocked_when_stale(self):
        self.write_config()
        self.complete_all()
        wfile(self.skill_a, "# alpha changed\n")
        src = wyaml(os.path.join(self.tmp, "src.yaml"), FINDING_SRC)
        r = run(["register", "--case-root", self.root, "--from", src])
        self.assertEqual(r.returncode, 1)


# ---------------------------------------------------------------------------
# ingest/register entry gating

class TestAuditGating(AuditBase):
    def test_ingest_blocked_before_prepare(self):
        self.write_config()
        r = run(["ingest", "--case-root", self.root, "--scan-dir", self.tmp])
        self.assertEqual(r.returncode, 1)
        self.assertIn("audit", (r.stdout + r.stderr).lower())

    def test_deleting_config_cannot_bypass_unfinished_batch(self):
        self.write_config()
        self.prepare()
        self.record(1, "FAILED", note="blocked pending tool availability in this env")
        os.remove(os.path.join(self.root, "audit-skills.yaml"))
        r = run(["ingest", "--case-root", self.root, "--scan-dir", self.tmp])
        self.assertEqual(r.returncode, 1)
        src = wyaml(os.path.join(self.tmp, "src.yaml"), FINDING_SRC)
        r = run(["register", "--case-root", self.root, "--from", src])
        self.assertEqual(r.returncode, 1)

    def test_register_requires_batch_references_when_complete(self):
        self.write_config()
        self.complete_all()
        rid = self.rid()
        # plain source without batch linkage -> rejected
        src = wyaml(os.path.join(self.tmp, "src.yaml"), FINDING_SRC)
        r = run(["register", "--case-root", self.root, "--from", src])
        self.assertEqual(r.returncode, 2)
        self.assertIn("audit_round", r.stderr)
        # proper source: analysis + both raw step reports
        data = run_yaml(self.root, rid)
        reports = [att["report"]["path"]
                   for st in data["steps"] for att in st["attempts"]]
        wfile(os.path.join(self.root, "audits", rid, "analysis.md"),
              "# Analysis\n\none distinct root cause across both skills\n")
        doc = yaml.safe_load(yaml.safe_dump(FINDING_SRC))
        doc["sources"]["audit_round"] = rid
        doc["sources"]["files"] = (
            [{"path": f"audits/{rid}/analysis.md", "note": "batch analysis"}]
            + [{"path": p, "note": "raw step report"} for p in reports])
        src = wyaml(os.path.join(self.tmp, "src2.yaml"), doc)
        r = run(["register", "--case-root", self.root, "--from", src, "--json"])
        self.assertEqual(r.returncode, 0, r.stderr)
        fid = json.loads(r.stdout)["id"]
        copied = os.listdir(os.path.join(self.root, "evidence", fid, "sources"))
        self.assertIn("analysis.md", copied)
        self.assertEqual(len([c for c in copied if "attempt-1-report" in c]), 2)

    def test_no_config_no_batch_keeps_old_entry(self):
        r = run(["ingest", "--case-root", self.root, "--scan-dir", self.tmp])
        self.assertEqual(r.returncode, 0, r.stderr)
        src = wyaml(os.path.join(self.tmp, "src.yaml"), FINDING_SRC)
        r = run(["register", "--case-root", self.root, "--from", src])
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main()
