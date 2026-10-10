"""Lifecycle decoupling from audit execution (plan.md section 56)."""

import os
import shutil
import tempfile
import unittest

try:
    from .test_lifecycle import Base, FINDING_SRC, PROGRAM, run, sha, wfile, wyaml
except ImportError:
    from test_lifecycle import Base, FINDING_SRC, PROGRAM, run, sha, wfile, wyaml


def seed_unfinished_batch(root, target):
    """Simulate a legacy audit config + unfinished batch in a case root."""
    wyaml(os.path.join(root, "audit-skills.yaml"),
          {"target_root": target, "scope": ["src"], "skills": []})
    rid = "run-20260101-000000-000000-aaaa"
    wyaml(os.path.join(root, "audits", rid, "run.yaml"), {
        "run_id": rid, "created_at": "2026-01-01T00:00:00+00:00", "revision": 2,
        "config": {"path": os.path.join(root, "audit-skills.yaml"),
                    "sha256": "0" * 64, "target_root": target,
                    "scope": [os.path.join(target, "src")], "skills": []},
        "target": {"root": target, "scope": [os.path.join(target, "src")], "files": []},
        "steps": [{"step": 1, "skill": os.path.join(target, "SKILL.md"),
                    "skill_sha256": None, "status": "FAILED",
                   "attempts": [{"at": "2026-01-01T00:00:01+00:00",
                                  "status": "FAILED", "note": "blocked pending tool",
                                  "report": None, "log": None}]}],
        "history": [{"at": "2026-01-01T00:00:00+00:00", "event": "created",
                      "detail": {}},
                     {"at": "2026-01-01T00:00:01+00:00", "event": "recorded",
                      "detail": {"step": 1, "status": "FAILED"}}],
    })


class TestLifecycleDecoupling(Base):
    def setUp(self):
        super().setUp()
        self.scan = os.path.join(self.tmp, "scan")
        os.makedirs(self.scan, exist_ok=True)
        wfile(os.path.join(self.scan, "audit-report.md"), "# Audit\n\nfinding 1\n")

    def test_lifecycle_has_no_audit_prepare(self):
        r = run(["audit", "prepare", "--case-root", self.root])
        self.assertEqual(r.returncode, 2)
        self.assertIn("invalid choice", r.stderr)
        self.assertNotIn("prepare", [c for c in ("check",)])
        # and the audit subtree is gone entirely:
        r = run(["audit", "check", "--case-root", self.root])
        self.assertEqual(r.returncode, 2)

    def test_lifecycle_has_no_audit_record(self):
        r = run(["audit", "record", "--case-root", self.root, "--step", "1",
                 "--input", "result.yaml", "--expected-revision", "1"])
        self.assertEqual(r.returncode, 2)
        self.assertIn("invalid choice", r.stderr)

    def test_lifecycle_has_no_audit_check(self):
        # top-level `check` is the finding gate check and requires --id;
        # the audit batch check no longer exists
        seed_unfinished_batch(self.root, self.scan)
        r = run(["check", "--case-root", self.root])
        self.assertEqual(r.returncode, 2)
        self.assertIn("--id", r.stderr)

    def test_legacy_audit_config_only_warns(self):
        wyaml(os.path.join(self.root, "audit-skills.yaml"),
              {"target_root": self.scan, "scope": ["."], "skills": []})
        r = run(["ingest", "--case-root", self.root, "--scan-dir", self.scan])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("no longer executed", r.stderr)
        src = wyaml(os.path.join(self.tmp, "src.yaml"), FINDING_SRC)
        r = run(["register", "--case-root", self.root, "--from", src])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("no longer executed", r.stderr)
        r = run(["resume", "--case-root", self.root])
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_register_is_not_gated_by_audit_batch(self):
        seed_unfinished_batch(self.root, self.scan)
        src = wyaml(os.path.join(self.tmp, "src.yaml"), FINDING_SRC)
        r = run(["register", "--case-root", self.root, "--from", src, "--json"])
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_ingest_is_not_gated_by_audit_batch(self):
        seed_unfinished_batch(self.root, self.scan)
        r = run(["ingest", "--case-root", self.root, "--scan-dir", self.scan,
                 "--json"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertGreaterEqual(len(r.stdout.strip().splitlines()), 1)


if __name__ == "__main__":
    unittest.main()
