"""Execution-prompt contract tests (plan.md section 49)."""

import json
import os
import unittest

try:
    from ._common import AuditBase, run, wfile
except ImportError:
    from _common import AuditBase, run, wfile


def prompt(root, run_id, step):
    p = os.path.join(root, "audits", run_id, "steps", str(step), "execution-prompt.md")
    with open(p, encoding="utf-8") as f:
        return f.read()


class TestExecutionPrompt(AuditBase):
    def test_prepare_generates_execution_prompt(self):
        self.write_config()
        out = json.loads(self.prepare().stdout)
        rid = out["run_id"]
        for step in (1, 2):
            self.assertTrue(os.path.isfile(
                os.path.join(self.root, "audits", rid, "steps", str(step),
                             "execution-prompt.md")))
        # every step also gets its preferred work directory
        for step in (1, 2):
            self.assertTrue(os.path.isdir(
                os.path.join(self.root, "audits", rid, "steps", str(step), "work")))
        self.assertTrue(os.path.isfile(
            os.path.join(self.root, "audits", rid, "steps", "1", "step.yaml")))

    def test_execution_prompt_contains_target(self):
        self.write_config()
        rid = json.loads(self.prepare().stdout)["run_id"]
        self.assertIn(self.target, prompt(self.root, rid, 1))

    def test_execution_prompt_contains_scope(self):
        self.write_config(scope=["src"])
        rid = json.loads(self.prepare().stdout)["run_id"]
        self.assertIn("src", prompt(self.root, rid, 1))

    def test_execution_prompt_contains_work_dir(self):
        self.write_config()
        rid = json.loads(self.prepare().stdout)["run_id"]
        text = prompt(self.root, rid, 1)
        self.assertIn(f"audits{os.sep}{rid}{os.sep}steps{os.sep}1{os.sep}work", text)

    def test_execution_prompt_requires_result_contract(self):
        self.write_config()
        rid = json.loads(self.prepare().stdout)["run_id"]
        text = prompt(self.root, rid, 1)
        self.assertIn("whitehexlabs.audit-result/v1", text)
        self.assertIn("status: COMPLETED | FAILED | BLOCKED", text)
        self.assertIn("primary:", text)
        self.assertIn("artifacts:", text)

    def test_execution_prompt_forbids_target_modification(self):
        self.write_config()
        rid = json.loads(self.prepare().stdout)["run_id"]
        text = prompt(self.root, rid, 1)
        self.assertIn("Do not modify the audited target source", text)

    def test_execution_prompt_documents_fixed_output_fallback(self):
        self.write_config()
        rid = json.loads(self.prepare().stdout)["run_id"]
        text = prompt(self.root, rid, 1)
        self.assertIn("fixed output directory", text)
        self.assertIn("result.yaml", text)

    def test_recovery_regenerates_missing_prompt_for_next_step(self):
        self.write_config()
        self.prepare()
        report = wfile(os.path.join(self.tmp, "r1.md"), "# r1\ncovered\n")
        log = wfile(os.path.join(self.tmp, "l1.txt"), "x\n")
        self.record(1, "COMPLETED", report=report, log=log)
        # record already ensured step 2's prompt; delete it and recover
        os.remove(os.path.join(self.root, "audits", self.rid(), "steps", "2",
                               "execution-prompt.md"))
        r = self.prepare()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.isfile(
            os.path.join(self.root, "audits", self.rid(), "steps", "2",
                         "execution-prompt.md")))


if __name__ == "__main__":
    unittest.main()
