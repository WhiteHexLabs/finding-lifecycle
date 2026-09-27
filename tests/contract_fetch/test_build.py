"""Tests for `build`: the forge gate (self-skips without forge)."""

import os
import shutil
import unittest

import yaml

try:
    from ._common import ADDR_A, Base, TINY_SOL, row, std_json
except ImportError:
    from _common import ADDR_A, Base, TINY_SOL, row, std_json

HAVE_FORGE = shutil.which("forge") is not None


@unittest.skipUnless(HAVE_FORGE, "forge not installed")
class TestBuild(Base):
    def setUp(self):
        super().setUp()
        self.init()
        self.server.codes[ADDR_A] = "0xdeadbeef"
        self.server.fixtures[ADDR_A] = std_json({"src/Tiny.sol": TINY_SOL})
        self.wtargets([row("a", ADDR_A)])
        self.assertEqual(self.cf("fetch").returncode, 0)
        self.assertEqual(self.cf("assemble").returncode, 0)

    def build_report(self):
        st = self.state()
        path = os.path.join(self.root, "projects", st["batch"], "build-report.yaml")
        with open(path, encoding="utf-8") as f:
            return yaml.safe_load(f)

    def test_build_pass(self):
        r = self.cf("build")
        self.assertEqual(r.returncode, 0, r.stderr)
        st = self.state()["targets"]["a"]
        self.assertEqual(st["state"], "BUILT")
        self.assertEqual(st["build"]["verdict"], "BUILD_PASS")
        report = self.build_report()
        self.assertEqual(report["schema"], "whitehexlabs.build-report/v1")
        self.assertEqual(report["entries"][0]["verdict"], "BUILD_PASS")
        self.assertIn("forge", report["forge_version"].lower())

    def test_build_fail_records_excerpt(self):
        # simulate a verified-but-uncompilable payload (e.g. exotic pragma): refresh
        # the cache with a broken source and rebuild the tree from it
        self.server.fixtures[ADDR_A] = std_json(
            {"src/Broken.sol": "contract Broken { this is not solidity }\n"},
            contract_name="Broken")
        self.assertEqual(self.cf("fetch", "--refresh", ADDR_A).returncode, 0)
        self.assertEqual(self.cf("assemble", "--rebuild", "a").returncode, 0)
        r = self.cf("build")
        self.assertEqual(r.returncode, 1)
        self.assertIn("[BUILD]", r.stderr)
        st = self.state()["targets"]["a"]
        self.assertEqual(st["state"], "FAILED:BUILD")
        report = self.build_report()
        self.assertEqual(report["entries"][0]["verdict"], "BUILD_FAIL")
        self.assertTrue(report["entries"][0].get("excerpt"))

    def test_rebuild_of_verified_tree_overrides_local_edits(self):
        tdir = os.path.join(self.root, "projects", self.state()["batch"], "targets", "a")
        src = os.path.join(tdir, "src", "src", "Tiny.sol")
        with open(src, "w", encoding="utf-8") as f:
            f.write("contract Tampered { function f() external {} }\n")
        self.cf("assemble", "--rebuild", "a")
        with open(src, encoding="utf-8") as f:
            self.assertEqual(f.read(), TINY_SOL)
        self.assertEqual(self.cf("build").returncode, 0)


if __name__ == "__main__":
    unittest.main()
