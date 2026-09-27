"""Tests for `manifest` + `check`: batch gate and audit handoff."""

import json
import os
import unittest

import yaml

try:
    from ._common import ADDR_A, ADDR_B, Base, TINY_SOL, row, std_json
    from .test_verify import VerifyBase
except ImportError:
    from _common import ADDR_A, ADDR_B, Base, TINY_SOL, row, std_json
    from test_verify import VerifyBase


class TestManifestCheck(VerifyBase):
    def ready_target(self, tid, addr, code="0xdeadbeef"):
        self.server.codes[addr] = code
        self.server.fixtures[addr] = std_json({"src/Tiny.sol": TINY_SOL},
                                              compiler="v0.8.99+commit.00000000")
        self.wtargets([row(tid, addr)]) if tid == "a" else None
        self.assertEqual(self.cf("fetch").returncode, 0)
        self.assertEqual(self.cf("assemble").returncode, 0)
        st = self.state()
        tdir = os.path.join(self.root, "projects", st["batch"], "targets", tid)
        self.place_artifact(tdir, "Tiny", code)
        self.set_state(tid, "BUILT")
        self.set_onchain(code)
        self.assertEqual(self.cf("verify").returncode, 0, f"verify {tid}")

    def test_full_pipeline_to_ready(self):
        self.ready_target("a", ADDR_A)
        r = self.cf("manifest")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("[READY] a", r.stdout)
        man = self.read_yaml("sources-manifest.yaml")
        self.assertEqual(man["schema"], "whitehexlabs.sources-manifest/v1")
        entry = man["targets"][0]
        self.assertTrue(entry["audit_recommended"])
        self.assertEqual(entry["verification"], "MATCH_EXACT")
        self.assertTrue(os.path.isdir(os.path.join(self.root, entry["src"])))
        self.assertEqual(self.cf("check").returncode, 0)
        self.assertEqual(self.state()["targets"]["a"]["state"], "READY")

    def test_manifest_lists_failed_targets_honestly(self):
        # one healthy row and one unverified row in the SAME batch from the start
        self.server.codes[ADDR_A] = "0xdeadbeef"
        self.server.fixtures[ADDR_A] = std_json({"src/Tiny.sol": TINY_SOL},
                                                compiler="v0.8.99+commit.00000000")
        self.server.fixtures[ADDR_B] = {"status": "1", "message": "OK", "result": [{
            "SourceCode": "", "ABI": "Contract source code not verified",
            "ContractName": "", "CompilerVersion": "", "OptimizationUsed": "0",
            "Runs": "200", "EVMVersion": "", "Proxy": "0", "Implementation": "",
            "SwarmSource": ""}]}
        self.wtargets([row("a", ADDR_A), row("b", ADDR_B)])
        self.assertEqual(self.cf("fetch").returncode, 1)
        self.assertEqual(self.cf("assemble").returncode, 0)
        st = self.state()
        tdir = os.path.join(self.root, "projects", st["batch"], "targets", "a")
        self.place_artifact(tdir, "Tiny", "0xdeadbeef")
        self.set_state("a", "BUILT")
        self.set_onchain("0xdeadbeef")
        self.assertEqual(self.cf("verify").returncode, 0)
        r = self.cf("manifest")
        self.assertEqual(r.returncode, 0, r.stderr)
        man = self.read_yaml("sources-manifest.yaml")
        by_id = {t["id"]: t for t in man["targets"]}
        self.assertTrue(by_id["a"]["audit_recommended"])
        self.assertFalse(by_id["b"]["audit_recommended"])
        self.assertEqual(by_id["b"]["state"], "FAILED:FETCH")
        c = self.cf("check")
        self.assertEqual(c.returncode, 1)
        self.assertIn("b", c.stderr)
        self.assertIn("excluded", " ".join(c.stderr.split()))  # next step mentions exclusion

    def test_check_empty_root_is_ok(self):
        self.init()
        self.assertEqual(self.cf("check").returncode, 0)

    def test_stage_ordering_enforced(self):
        # no batch before fetch: assemble/verify must refuse
        self.assertEqual(self.cf("assemble").returncode, 2)
        self.assertEqual(self.cf("verify").returncode, 2)
        # targets still SELECTED: verify is a no-op, check demands fetch
        self.server.codes[ADDR_A] = "0xdeadbeef"
        self.server.fixtures[ADDR_A] = std_json({"src/Tiny.sol": TINY_SOL})
        self.wtargets([row("a", ADDR_A)])
        self.assertEqual(self.cf("fetch").returncode, 0)
        r = self.cf("verify")
        self.assertEqual(r.returncode, 0)
        self.assertIn("nothing to verify", r.stdout)
        self.assertEqual(self.cf("check").returncode, 1)

    def test_corrupt_state_file_is_input_error(self):
        self.init()
        with open(os.path.join(self.root, "state.yaml"), "w") as f:
            f.write("schema: bogus\n")
        self.assertEqual(self.cf("check").returncode, 2)

    def test_handoff_snippet_paths_exist(self):
        self.ready_target("a", ADDR_A)
        self.cf("manifest")
        man = self.read_yaml("sources-manifest.yaml")
        for entry in man["targets"]:
            if entry.get("audit_recommended"):
                self.assertTrue(os.path.isdir(os.path.join(self.root, entry["src"])))
                self.assertTrue(os.path.isfile(
                    os.path.join(self.root, entry["verification_report"])))


if __name__ == "__main__":
    unittest.main()
