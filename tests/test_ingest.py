"""Tests for `ingest`: name-based audit-artifact discovery and draft scaffolding."""

import json
import os
import unittest

import yaml

from test_lifecycle import Base, FINDING_SRC, run, wfile, wyaml


def drafts(root):
    d = os.path.join(root, "ingest")
    if not os.path.isdir(d):
        return []
    return sorted(f for f in os.listdir(d) if f.endswith(".yaml"))


class TestIngest(Base):
    def setUp(self):
        super().setUp()
        self.scan = os.path.join(self.tmp, "scan")
        os.makedirs(self.scan, exist_ok=True)

    def ingest(self, *extra):
        return run(["ingest", "--case-root", self.root,
                    "--scan-dir", self.scan, "--json", *extra])

    def test_discovers_standalone_audit_file(self):
        wfile(os.path.join(self.scan, "notes.md"), "no match here\n")
        target = wfile(os.path.join(self.scan, "audit-report.md"),
                       "# Audit\n\nfinding 1: unsafe withdraw\n")
        r = self.ingest()
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout)
        self.assertEqual(len(out["bundles"]), 1)
        self.assertIn("audit-report.md", out["bundles"][0]["origin"])
        draft_rel = out["drafts"][0]["draft"]
        self.assertTrue(draft_rel.startswith("ingest/finding-source.audit-report-md-"))
        text = open(os.path.join(self.root, draft_rel), encoding="utf-8").read()
        self.assertIn(target, text)          # absolute source path embedded
        self.assertIn("TODO", text)
        parsed = yaml.safe_load(text)        # the draft must be valid YAML
        self.assertEqual(parsed["prescreen"][3]["aspect"], "duplication")

    def test_bundles_audit_directory(self):
        wfile(os.path.join(self.scan, "reports", "my-audit", "findings.md"), "f1\n")
        wfile(os.path.join(self.scan, "reports", "my-audit", "summary.txt"), "s\n")
        wfile(os.path.join(self.scan, "reports", "my-audit", "logo.png"), "bin")
        r = self.ingest()
        out = json.loads(r.stdout)
        self.assertEqual(len(out["bundles"]), 1)
        files = out["bundles"][0]["files"]
        self.assertEqual(len(files), 2)      # .png skipped
        self.assertTrue(any(f.endswith("findings.md") for f in files))
        self.assertTrue(any(f.endswith("summary.txt") for f in files))

    def test_skips_case_root_and_hidden_dirs(self):
        # an audit-named file inside the case root: already managed, must be skipped
        wfile(os.path.join(self.root, "evidence", "audit-notes.md"), "managed\n")
        wfile(os.path.join(self.scan, ".git", "audit-inside-git.md"), "hidden\n")
        wfile(os.path.join(self.scan, "outside-audit.md"), "real candidate\n")
        r = self.ingest()
        out = json.loads(r.stdout)
        origins = [b["origin"] for b in out["bundles"]]
        self.assertEqual(origins, [os.path.realpath(os.path.join(self.scan, "outside-audit.md"))])

    def test_pattern_override(self):
        wfile(os.path.join(self.scan, "results", "findings.json"), "[]\n")
        r = self.ingest("--pattern", "findings")
        out = json.loads(r.stdout)
        self.assertEqual(len(out["bundles"]), 1)
        self.assertIn("findings.json", out["bundles"][0]["origin"])

    def test_draft_rejected_until_completed(self):
        target = wfile(os.path.join(self.scan, "audit-report.md"), "finding 1\n")
        out = json.loads(self.ingest().stdout)
        draft_abs = os.path.join(self.root, out["drafts"][0]["draft"])

        r = run(["register", "--case-root", self.root, "--from", draft_abs])
        self.assertEqual(r.returncode, 2)
        self.assertIn("TODO", r.stderr)

        # complete the draft: real claim, duplication PASS, UNKNOWN allowed elsewhere
        doc = yaml.safe_load(open(draft_abs, encoding="utf-8"))
        doc["title"] = "Unsafe withdraw"
        doc["claim"] = "withdraw sends before clearing state"
        doc["sources"]["auditor"] = "test-auditor"
        for item in doc["prescreen"]:
            item["evidence"] = "checked manually"
            item["explanation"] = {
                "scope": "target in scope list",
                "authority": "no role needed",
                "exclusion": "no clause applies",
                "duplication": "no prior finding matches",
            }[item["aspect"]]
            if item["aspect"] == "duplication":
                item["status"] = "PASS"
        wyaml(draft_abs, doc)
        r = run(["register", "--case-root", self.root, "--from", draft_abs, "--json"])
        self.assertEqual(r.returncode, 0, r.stderr)
        fid = json.loads(r.stdout)["id"]
        ev = os.path.join(self.root, "evidence", fid, "sources")
        self.assertTrue(any(f.startswith("audit-report") for f in os.listdir(ev)))

    def test_idempotent_rerun(self):
        wfile(os.path.join(self.scan, "audit-report.md"), "finding 1\n")
        self.ingest()
        first = drafts(self.root)
        self.assertEqual(len(first), 1)
        r = self.ingest()
        out = json.loads(r.stdout)
        self.assertEqual(out["drafts"][0]["status"], "exists")
        self.assertEqual(drafts(self.root), first)


if __name__ == "__main__":
    unittest.main()
