"""Contest-platform material specs: Code4rena / CodeHawks / Sherlock / Cantina
gate PACKAGED, export assembles their one-body layouts, and the two
platform-specific mechanical rules (Sherlock commit-pinned permalinks,
individual-submission severity vocabularies) hold end to end."""

import os
import unittest

import yaml

try:
    from .test_lifecycle import Base, read_ledger, run, sha, wfile, wyaml
except ImportError:
    from test_lifecycle import Base, read_ledger, run, sha, wfile, wyaml


PERMALINK = ("https://github.com/org/repo/blob/"
             "aabbccddeeff00112233445566778899aabbccdd/src/Vault.sol#L10-L12")
BRANCH_LINK = "https://github.com/org/repo/blob/main/src/Vault.sol#L10-L12"

# platform -> (body field name, canonical filename, header-complete body)
PLATFORM_BODIES = {
    "code4rena": ("details", "2-finding.md",
                  "## Impact\n\nimpact\n\n## Proof of Concept\n\npoc\n\n"
                  "## Recommended Mitigation Steps\n\nfix\n"),
    "codehawks": ("details", "2-finding.md",
                  "## Summary\n\nsummary\n\n## Vulnerability Details\n\ndetails\n\n"
                  "## Impact\n\nimpact\n\n## Tools Used\n\nFoundry\n\n"
                  "## Recommended Mitigation\n\nfix\n"),
    "sherlock": ("issue_body", "2-issue-body.md",
                 "## Issue\n\nissue with code at " + PERMALINK + "\n\n"
                 "## Impact\n\nimpact\n\n## Attack path\n\n1. steps\n\n"
                 "## PoC\n\npoc\n"),
    "cantina": ("description", "2-description.md",
                "## Root cause\n\nrc\n\n## PoC\n\npoc\n\n## Impact\n\nimpact\n"),
}

CONTEST_PLATFORMS = sorted(PLATFORM_BODIES)


class ContestBase(Base):
    def set_platform(self, platform):
        path = os.path.join(self.root, "program.yaml")
        with open(path, encoding="utf-8") as f:
            prog = yaml.safe_load(f)
        prog.setdefault("delivery", {})["platform"] = platform
        wyaml(path, prog)

    def add_materials(self, fid, platform, slug="contest-finding", body=None,
                      drop_field=False, wrong_path=False):
        body_field, body_name, body_text = PLATFORM_BODIES[platform]
        if body is not None:
            body_text = body
        pkg = os.path.join(self.root, "packages", fid, platform)
        title = wfile(os.path.join(pkg, "1-title.txt"),
                      "Contest finding in withdraw()\n")
        body_p = wfile(os.path.join(pkg, body_name), body_text)
        fields = [
            {"field": "title", "path": f"packages/{fid}/{platform}/1-title.txt",
             "sha256": sha(title)},
            {"field": body_field, "path": f"packages/{fid}/{platform}/{body_name}",
             "sha256": sha(body_p)},
        ]
        if drop_field:
            fields = fields[:1]
        if wrong_path:
            fields[1]["path"] = f"packages/{fid}/{platform}/fields/{body_name}"
        mpath = os.path.join(self.root, "packages", fid, "manifest.yaml")
        with open(mpath, encoding="utf-8") as f:
            manifest = yaml.safe_load(f)
        manifest["materials"] = {"platform": platform, "slug": slug,
                                 "fields": fields}
        wyaml(mpath, manifest)

    def packaged(self, platform, slug="contest-finding", **kw):
        self.set_platform(platform)
        fid = self.register()
        self.flow_to(fid, "TRIAGED")
        self.build_package(fid)
        self.add_materials(fid, platform, slug=slug, **kw)
        self.advance(fid, "PACKAGED",
                     f"clean-dir run passed; log at evidence/{fid}/clean-run.log")
        return fid


class TestContestMaterialsGate(ContestBase):
    def test_contest_platform_requires_materials(self):
        for platform in CONTEST_PLATFORMS:
            with self.subTest(platform=platform):
                self.set_platform(platform)
                fid = self.register()
                self.flow_to(fid, "TRIAGED")
                self.build_package(fid)
                r = self.advance(fid, "PACKAGED",
                                 f"clean-dir run passed; log at evidence/{fid}/clean-run.log",
                                 code=1)
                self.assertIn("materials missing", r.stdout + r.stderr)

    def test_contest_materials_pass(self):
        for platform in CONTEST_PLATFORMS:
            with self.subTest(platform=platform):
                fid = self.packaged(platform)
                fm = read_ledger(self.root, fid)
                self.assertEqual(fm["stage"], "PACKAGED")
                purposes = [e["purpose"] for e in fm["evidence"]]
                body_field = PLATFORM_BODIES[platform][0]
                self.assertIn(f"material:{body_field}", purposes)

    def test_missing_header_blocks(self):
        dropped = {
            "code4rena": "## Recommended Mitigation Steps",
            "codehawks": "## Tools Used",
            "sherlock": "## Attack path",
            "cantina": "## Root cause",
        }
        for platform in CONTEST_PLATFORMS:
            with self.subTest(platform=platform):
                _, body_name, body_text = PLATFORM_BODIES[platform]
                header = dropped[platform]
                self.set_platform(platform)
                fid = self.register()
                self.flow_to(fid, "TRIAGED")
                self.build_package(fid)
                self.add_materials(fid, platform,
                                   body=body_text.replace(header + "\n", ""))
                r = self.advance(fid, "PACKAGED",
                                 f"clean-dir run passed; log at evidence/{fid}/clean-run.log",
                                 code=1)
                self.assertIn(header, r.stdout + r.stderr)

    def test_noncanonical_path_blocked(self):
        self.set_platform("codehawks")
        fid = self.register()
        self.flow_to(fid, "TRIAGED")
        self.build_package(fid)
        self.add_materials(fid, "codehawks", wrong_path=True)
        r = self.advance(fid, "PACKAGED",
                         f"clean-dir run passed; log at evidence/{fid}/clean-run.log",
                         code=1)
        self.assertIn(f"must be the packages/{fid}/codehawks/2-finding.md",
                      r.stdout + r.stderr)

    def test_undeclared_field_blocks(self):
        self.set_platform("cantina")
        fid = self.register()
        self.flow_to(fid, "TRIAGED")
        self.build_package(fid)
        self.add_materials(fid, "cantina", drop_field=True)
        r = self.advance(fid, "PACKAGED",
                         f"clean-dir run passed; log at evidence/{fid}/clean-run.log",
                         code=1)
        self.assertIn("missing: description", r.stdout + r.stderr)


class TestSherlockPermalinks(ContestBase):
    def gate_run(self, body_text, code=0):
        self.set_platform("sherlock")
        fid = self.register()
        self.flow_to(fid, "TRIAGED")
        self.build_package(fid)
        self.add_materials(fid, "sherlock", body=body_text)
        return self.advance(fid, "PACKAGED",
                            f"clean-dir run passed; log at evidence/{fid}/clean-run.log",
                            code=code)

    def test_branch_link_blocks_the_gate(self):
        _, _, clean = PLATFORM_BODIES["sherlock"]
        r = self.gate_run(clean.replace(PERMALINK, BRANCH_LINK), code=1)
        self.assertIn("permalink", r.stdout + r.stderr)

    def test_bare_repo_link_blocks_the_gate(self):
        _, _, clean = PLATFORM_BODIES["sherlock"]
        r = self.gate_run(clean.replace(PERMALINK, "https://github.com/org/repo"),
                          code=1)
        self.assertIn("permalink", r.stdout + r.stderr)

    def test_markdown_paren_permalink_passes(self):
        _, _, clean = PLATFORM_BODIES["sherlock"]
        wrapped = clean.replace(
            PERMALINK, f"[the check]({PERMALINK})")
        r = self.gate_run(wrapped)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_edited_branch_link_caught_by_lint(self):
        fid = self.packaged("sherlock")
        r = run(["lint", "--case-root", self.root, "--id", fid])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        _, body_name, clean = PLATFORM_BODIES["sherlock"]
        wfile(os.path.join(self.root, "packages", fid, "sherlock", body_name),
              clean.replace(PERMALINK, BRANCH_LINK))
        r = run(["lint", "--case-root", self.root, "--id", fid])
        self.assertEqual(r.returncode, 1)
        self.assertIn("permalink", r.stdout)
        self.assertIn("sections", r.stdout)

    def test_permalink_allowlist_with_reason(self):
        fid = self.packaged("sherlock")
        _, body_name, clean = PLATFORM_BODIES["sherlock"]
        wfile(os.path.join(self.root, "packages", fid, "sherlock", body_name),
              clean.replace(PERMALINK, BRANCH_LINK))
        wyaml(os.path.join(self.root, "lint-allowlist.yaml"), {"allow": [
            {"check": "sections", "pattern": BRANCH_LINK,
             "reason": "upstream audit repo reference, not contest code"},
        ]})
        r = run(["lint", "--case-root", self.root, "--id", fid])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


class TestSeverityVocabularyGuard(ContestBase):
    def make_low_finding(self, platform):
        """TRIAGED as LOW against a matrix entry added post-init."""
        self.set_platform(platform)
        path = os.path.join(self.root, "program.yaml")
        with open(path, encoding="utf-8") as f:
            prog = yaml.safe_load(f)
        prog["severity_matrix"].append(
            {"id": "S3", "level": "LOW", "text": "dust", "basis": "rules"})
        wyaml(path, prog)
        fid = self.register()
        self.flow_to(fid, "FORK_PROVEN")
        wyaml(self.evidence(fid, "triage.yaml"), {
            "severity": {"final": "LOW", "matrix_entry": "S3",
                         "justification": f"dust only per evidence/{fid}/run.log"},
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
        self.advance(fid, "TRIAGED",
                     f"eligibility PASS; severity per evidence/{fid}/run.log")
        self.build_package(fid)
        self.add_materials(fid, platform)
        self.advance(fid, "PACKAGED",
                     f"clean-dir run passed; log at evidence/{fid}/clean-run.log")
        return fid

    def test_codehawks_refuses_low_severity_export(self):
        fid = self.make_low_finding("codehawks")
        out = os.path.join(self.tmp, "submission")
        r = run(["export", "--case-root", self.root, "--id", fid, "--out", out])
        self.assertEqual(r.returncode, 2)
        self.assertIn("individual-submission", r.stderr)
        self.assertIn("platform-standards.md", r.stderr)
        self.assertFalse(os.path.exists(os.path.join(out, "01-contest-finding-low")))

    def test_code4rena_refuses_low_severity_export(self):
        fid = self.make_low_finding("code4rena")
        r = run(["export", "--case-root", self.root, "--id", fid,
                 "--out", os.path.join(self.tmp, "submission")])
        self.assertEqual(r.returncode, 2)
        self.assertIn("individual-submission", r.stderr)

    def test_cantina_accepts_low_severity_export(self):
        fid = self.make_low_finding("cantina")
        out = os.path.join(self.tmp, "submission")
        r = run(["export", "--case-root", self.root, "--id", fid, "--out", out])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.isdir(os.path.join(out, "01-contest-finding-low")))


class TestContestExport(ContestBase):
    def test_export_copies_layout_and_bundle(self):
        for platform in CONTEST_PLATFORMS:
            with self.subTest(platform=platform):
                slug = f"{platform}-drain"
                fid = self.packaged(platform, slug=slug)
                out = os.path.join(self.tmp, f"sub-{platform}")
                r = run(["export", "--case-root", self.root, "--id", fid,
                         "--out", out, "--json"])
                self.assertEqual(r.returncode, 0, r.stderr)
                _, body_name, _ = PLATFORM_BODIES[platform]
                d = os.path.join(out, f"01-{slug}-high")
                for rel in ("1-title.txt", body_name, f"{slug}-poc.zip"):
                    self.assertTrue(os.path.isfile(os.path.join(d, rel)), rel)
                # the exported bundle is byte-identical to the frozen zip
                self.assertEqual(
                    sha(os.path.join(self.root, "packages", fid, "package.zip")),
                    sha(os.path.join(d, f"{slug}-poc.zip")))
                readme = open(os.path.join(out, "README.md"), encoding="utf-8").read()
                self.assertIn(platform, readme)
                self.assertIn(f"{slug}-poc.zip sha256", readme)

    def test_export_drifted_material_aborts(self):
        fid = self.packaged("code4rena")
        wfile(os.path.join(self.root, "packages", fid, "code4rena", "1-title.txt"),
              "edited after packaging\n")
        r = run(["export", "--case-root", self.root, "--id", fid,
                 "--out", os.path.join(self.tmp, "submission")])
        self.assertEqual(r.returncode, 2)
        self.assertIn("hash changed", r.stderr)


if __name__ == "__main__":
    unittest.main()
