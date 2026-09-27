"""Tests for `assemble`: tree reconstruction, remappings, fail-closed paths.

Path convention under test: a verified source key K lands at
<fetch-root>/projects/<batch>/targets/<id>/src/<K> — original paths, no
rewriting (so key "src/Vault.sol" sits at src/src/Vault.sol)."""

import hashlib
import json
import os
import unittest

import yaml

try:
    from ._common import ADDR_A, ADDR_B, Base, TINY_SOL, multi_file, row, std_json
except ImportError:
    from _common import ADDR_A, ADDR_B, Base, TINY_SOL, multi_file, row, std_json


class TestAssemble(Base):
    def setUp(self):
        super().setUp()
        self.init()
        self.server.codes[ADDR_A] = "0xdeadbeef"
        self.server.codes[ADDR_B] = "0x" + "00" * 4

    def fetch_fixture(self, tid, addr, fixture, expect_rc=0):
        self.server.fixtures[addr] = fixture
        self.wtargets([row(tid, addr)])
        r = self.cf("fetch")
        self.assertEqual(r.returncode, expect_rc, r.stderr)
        st = self.state()
        return os.path.join(self.root, "projects", st["batch"], "targets", tid)

    def tfile(self, tdir, key):
        return os.path.join(tdir, "src", *key.split("/"))

    def target_yaml(self, tdir):
        with open(os.path.join(tdir, "target.yaml"), encoding="utf-8") as f:
            return yaml.safe_load(f)

    def test_standard_json_tree_is_byte_identical(self):
        files = {"src/Vault.sol": "// header line\ncontract Vault {}\n",
                 "src/lib/Math.sol": "library Math {}\n"}
        tdir = self.fetch_fixture("a", ADDR_A, std_json(files))
        self.assertEqual(self.cf("assemble").returncode, 0)
        for rel, content in files.items():
            with open(self.tfile(tdir, rel), "rb") as f:
                self.assertEqual(f.read(), content.encode("utf-8"), rel)
        ty = self.target_yaml(tdir)
        self.assertEqual(ty["schema"], "whitehexlabs.target/v1")
        self.assertEqual(ty["format"], "standard-json")
        self.assertTrue(ty["input_exact"])
        self.assertEqual(len(ty["files"]), 2)
        by_path = {f["path"]: f for f in ty["files"]}
        disk = open(self.tfile(tdir, "src/Vault.sol"), "rb").read()
        self.assertEqual(by_path["src/src/Vault.sol"]["sha256"],
                         hashlib.sha256(disk).hexdigest())
        self.assertEqual(by_path["src/src/Vault.sol"]["lines"], 2)

    def test_input_json_verbatim_for_standard_json(self):
        tdir = self.fetch_fixture("a", ADDR_A, std_json({"src/Tiny.sol": TINY_SOL}))
        self.assertEqual(self.cf("assemble").returncode, 0)
        with open(os.path.join(tdir, "artifacts", "input.json"), encoding="utf-8") as f:
            input_doc = json.load(f)
        self.assertEqual(input_doc["language"], "Solidity")
        self.assertEqual(set(input_doc["sources"]), {"src/Tiny.sol"})
        self.assertTrue(input_doc["settings"]["optimizer"]["enabled"])
        with open(os.path.join(tdir, "artifacts", "explorer.json"), encoding="utf-8") as f:
            self.assertEqual(json.load(f)["ContractName"], "Tiny")

    def test_multi_file_synthesizes_input(self):
        tdir = self.fetch_fixture("b", ADDR_B, multi_file({"src/A.sol": "contract A {}\n"}))
        self.assertEqual(self.cf("assemble").returncode, 0)
        self.assertFalse(self.target_yaml(tdir)["input_exact"])
        with open(os.path.join(tdir, "artifacts", "input.json"), encoding="utf-8") as f:
            self.assertIn("outputSelection", json.load(f)["settings"])

    def test_remappings_for_bare_imports(self):
        files = {
            "@acme/lib/Lib.sol": "library Lib {}\n",
            "src/Main.sol": 'pragma solidity ^0.8.26;\nimport "@acme/lib/Lib.sol";\ncontract Main {}\n',
        }
        tdir = self.fetch_fixture("a", ADDR_A, std_json(files))
        self.assertEqual(self.cf("assemble").returncode, 0)
        toml = open(os.path.join(os.path.dirname(os.path.dirname(tdir)),
                                 "foundry.toml"), encoding="utf-8").read()
        self.assertIn("@acme/=targets/a/src/@acme/", toml)
        self.assertIn("[profile.a]", toml)
        self.assertIn('solc = "0.8.26"', toml)
        self.assertTrue(os.path.isdir(os.path.join(tdir, "src", "@acme", "lib")))

    def test_relative_imports_resolve_without_remappings(self):
        files = {"src/Main.sol": 'import "./Dep.sol";\ncontract Main {}\n',
                 "src/Dep.sol": "contract Dep {}\n"}
        tdir = self.fetch_fixture("a", ADDR_A, std_json(files))
        r = self.cf("assemble")
        self.assertEqual(r.returncode, 0, r.stderr)
        toml = open(os.path.join(os.path.dirname(os.path.dirname(tdir)),
                                 "foundry.toml"), encoding="utf-8").read()
        self.assertNotIn("remappings", toml)
        self.assertEqual(self.state()["targets"]["a"]["state"], "ASSEMBLED")

    def test_dangling_import_fails_assemble(self):
        files = {"src/Main.sol": 'import "nowhere/Dep.sol";\ncontract Main {}\n'}
        self.fetch_fixture("a", ADDR_A, std_json(files))
        r = self.cf("assemble")
        self.assertEqual(r.returncode, 1)
        self.assertIn("[DANGLING_IMPORT]", r.stderr)
        self.assertIn("nowhere/Dep.sol", r.stderr)
        self.assertEqual(self.state()["targets"]["a"]["state"], "FAILED:ASSEMBLE")

    def test_commented_import_is_ignored(self):
        files = {"src/Main.sol": '// import "nowhere/Dep.sol";\ncontract Main {}\n'}
        self.fetch_fixture("a", ADDR_A, std_json(files))
        self.assertEqual(self.cf("assemble").returncode, 0)

    def test_path_traversal_rejected_at_fetch(self):
        self.fetch_fixture("a", ADDR_A, std_json({"../evil.sol": "contract E {}\n"}),
                           expect_rc=1)
        st = self.state()["targets"]["a"]
        self.assertEqual(st["state"], "FAILED:FETCH")
        self.assertIn("escapes", st["issues"][0])

    def test_normalized_path_collision_rejected_at_fetch(self):
        self.fetch_fixture("a", ADDR_A, std_json({"src/A.sol": "contract A1 {}\n",
                                                  "/src/A.sol": "contract A2 {}\n"}),
                           expect_rc=1)
        st = self.state()["targets"]["a"]
        self.assertEqual(st["state"], "FAILED:FETCH")
        self.assertIn("collide", st["issues"][0])

    def test_leading_slash_keys_are_rooted(self):
        tdir = self.fetch_fixture("a", ADDR_A, std_json({"/src/A.sol": "contract A {}\n"}))
        self.assertEqual(self.cf("assemble").returncode, 0)
        self.assertTrue(os.path.isfile(self.tfile(tdir, "src/A.sol")))

    def test_flattened_single_file(self):
        fixture = {"status": "1", "message": "OK", "result": [{
            "SourceCode": "pragma solidity ^0.8.19;\ncontract Flat {}\n", "ABI": "[]",
            "ContractName": "Flat", "CompilerVersion": "v0.8.19+commit.b60b008e",
            "OptimizationUsed": "0", "Runs": "200", "EVMVersion": "",
            "Proxy": "0", "Implementation": "", "SwarmSource": ""}]}
        tdir = self.fetch_fixture("a", ADDR_A, fixture)
        self.assertEqual(self.cf("assemble").returncode, 0)
        self.assertTrue(os.path.isfile(self.tfile(tdir, "Flat.sol")))

    def test_rebuild_restores_a_tampered_tree(self):
        tdir = self.fetch_fixture("a", ADDR_A, std_json({"src/Tiny.sol": TINY_SOL}))
        self.assertEqual(self.cf("assemble").returncode, 0)
        tree = self.tfile(tdir, "src/Tiny.sol")
        with open(tree, "a", encoding="utf-8") as f:
            f.write("// accidental edit\n")
        # plain rerun is a no-op (stage already advanced)…
        self.assertEqual(self.cf("assemble").returncode, 0)
        with open(tree, encoding="utf-8") as f:
            self.assertIn("accidental edit", f.read())
        # …--rebuild deterministically restores the explorer bytes
        self.assertEqual(self.cf("assemble", "--rebuild", "a").returncode, 0)
        with open(tree, encoding="utf-8") as f:
            self.assertEqual(f.read(), TINY_SOL)


if __name__ == "__main__":
    unittest.main()
