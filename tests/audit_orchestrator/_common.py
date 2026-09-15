"""Shared helpers for audit-orchestrator tests."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCRIPT = os.path.join(REPO, "skills", "audit-orchestrator", "scripts", "audit.py")

RESULT_SCHEMA = "whitehexlabs.audit-result/v1"
CANDIDATE_SCHEMA = "whitehexlabs.audit-candidate/v1"


def run(args):
    return subprocess.run([sys.executable, SCRIPT] + [str(a) for a in args],
                          capture_output=True, text=True)


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


def run_yaml(root, run_id):
    with open(os.path.join(root, "audits", run_id, "run.yaml"), encoding="utf-8") as f:
        return yaml.safe_load(f)


def current_run_id(root):
    runs = sorted(d for d in os.listdir(os.path.join(root, "audits"))
                  if d.startswith("run-"))
    return runs[-1]


def v1_result(path, status="COMPLETED", note="covered both contracts; zero findings",
              report=None, log=None, artifacts=()):
    doc = {"schema": RESULT_SCHEMA, "status": status, "note": note,
           "primary": {"report": report, "log": log}, "artifacts": list(artifacts)}
    return wyaml(path, doc)


def legacy_result(path, status="COMPLETED", note="covered both contracts; zero findings",
                  report=None, log=None):
    return wyaml(path, {"status": status, "note": note, "report": report, "log": log})


ANALYSIS_SECTIONS = [
    "# Audit Analysis",
    "## Audit Run",
    "## Target and Scope",
    "## Audit Skills Executed",
    "## Coverage Summary",
    "## Consolidated Findings",
    "## Duplicate / Overlapping Leads",
    "## Disagreements Between Auditors",
    "## Coverage Gaps and Limitations",
    "## Zero-Finding Statement",
]


def write_analysis(root, run_id, body="one distinct root cause across both skills"):
    parts = [ANALYSIS_SECTIONS[0], f"Run {run_id} over the toy target."]
    for h in ANALYSIS_SECTIONS[1:]:
        parts.append(h)
        parts.append(f"{h[3:]}: {body}." if "Zero-Finding" not in h else
                     "No candidate findings were identified within the executed "
                     "audit scope and methods.")
    return wfile(os.path.join(root, "audits", run_id, "analysis.md"),
                 "\n\n".join(parts) + "\n")


class AuditBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="fl-audit-")
        self.root = os.path.join(self.tmp, "work")
        os.makedirs(self.root, exist_ok=True)
        self.target = os.path.join(self.tmp, "target")
        self.skill_a = wfile(os.path.join(self.tmp, "skills", "alpha", "SKILL.md"),
                             "---\nname: alpha-auditor\n---\n\n"
                             "# alpha\n\nread every scope file and report findings.\n")
        self.skill_b = wfile(os.path.join(self.tmp, "skills", "beta", "SKILL.md"),
                             "---\nname: beta-auditor\n---\n\n"
                             "# beta\n\ncheck invariants and report findings.\n")
        wfile(os.path.join(self.target, "src", "Vault.sol"), "contract Vault {}\n")
        wfile(os.path.join(self.target, "src", "Pool.sol"), "contract Pool {}\n")

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def write_config(self, skills=None, scope=("src",), target_root=None):
        wyaml(os.path.join(self.root, "audit-skills.yaml"), {
            "target_root": target_root or self.target,
            "scope": list(scope),
            "skills": list(skills if skills is not None else [self.skill_a, self.skill_b]),
        })

    def prepare(self, *extra):
        return run(["prepare", "--work-root", self.root, "--json", *extra])

    def rid(self):
        return current_run_id(self.root)

    def rev(self):
        return run_yaml(self.root, self.rid())["revision"]

    def result_path(self, step, status="COMPLETED", note="covered both contracts; zero findings",
                    report=None, log=None, artifacts=()):
        return v1_result(os.path.join(self.tmp, f"result-{step}-{status}-{id(note) % 997}.yaml"),
                         status, note, report, log, artifacts)

    def record(self, step, status="COMPLETED", note="covered both contracts; zero findings",
               report=None, log=None, rev=None, artifacts=()):
        p = self.result_path(step, status, note, report, log, artifacts)
        return run(["record", "--work-root", self.root, "--step", step,
                    "--input", p,
                    "--expected-revision", rev if rev is not None else self.rev()])

    def check(self):
        return run(["check", "--work-root", self.root])

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
