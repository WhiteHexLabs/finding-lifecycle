"""Tests for `verify`: bytecode comparison, masking, tamper detection.

Offline cases use compiler version 0.8.99 (never installed) so the exact-input
cross-check deterministically reports SKIPPED; forge cases run the real toolchain
when available."""

import json
import os
import shutil
import unittest

import yaml

try:
    from ._common import ADDR_A, Base, TINY_SOL, row, std_json
except ImportError:
    from _common import ADDR_A, Base, TINY_SOL, row, std_json

HAVE_FORGE = shutil.which("forge") is not None

IMM_SOL = ("pragma solidity ^0.8.26;\n\ncontract Imm {\n"
           "    uint256 public immutable VALUE;\n"
           "    constructor() { VALUE = 42; }\n}\n")


class VerifyBase(Base):
    def setUp(self):
        super().setUp()
        self.init()
        self.server.codes[ADDR_A] = "0xdeadbeef"

    def pipeline_to_built(self, tid, fixture, contract):
        self.server.fixtures[ADDR_A] = fixture
        self.wtargets([row(tid, ADDR_A)])
        self.assertEqual(self.cf("fetch").returncode, 0)
        self.assertEqual(self.cf("assemble").returncode, 0)
        st = self.state()
        return os.path.join(self.root, "projects", st["batch"], "targets", tid)

    def place_artifact(self, tdir, contract, code_hex, immutables=None):
        dep = {"object": code_hex}
        if immutables is not None:
            dep["immutableReferences"] = immutables
        art = {"abi": [], "deployedBytecode": dep}
        path = os.path.join(tdir, "out", f"{contract}.sol", f"{contract}.json")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(art, f)
        return path

    def set_onchain(self, code_hex):
        path = os.path.join(self.root, "fetch-cache", "1",
                            f"{ADDR_A.lower()}.getcode.json")
        doc = {"code": code_hex, "block_number": "0x1", "rpc": "test"}
        with open(path, "w", encoding="utf-8") as f:
            json.dump(doc, f)

    def report(self, tid):
        with open(os.path.join(self.root, "verification", f"{tid}.yaml"),
                  encoding="utf-8") as f:
            return yaml.safe_load(f)


class TestVerifyOffline(VerifyBase):
    def setUp(self):
        super().setUp()
        self.fixture = std_json({"src/Tiny.sol": TINY_SOL},
                                compiler="v0.8.99+commit.00000000")

    def built(self, code, immutables=None, onchain="0xdeadbeef"):
        tdir = self.pipeline_to_built("a", self.fixture, "Tiny")
        self.place_artifact(tdir, "Tiny", code, immutables)
        self.set_state("a", "BUILT")
        self.set_onchain(onchain)
        return tdir

    def test_match_exact(self):
        self.built("0xdeadbeef")
        r = self.cf("verify")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.state()["targets"]["a"]["state"], "VERIFIED")
        rep = self.report("a")
        self.assertEqual(rep["schema"], "whitehexlabs.verification/v1")
        self.assertEqual(rep["bytecode"], "MATCH_EXACT")
        self.assertEqual(rep["source_identity"], "PASS")
        self.assertEqual(rep["build_cross_check"], "SKIPPED")  # no solc 0.8.99 anywhere
        self.assertEqual(rep["verdict"], "PASS")

    def test_match_after_immutable_mask(self):
        local = "0x" + "aa" * 10
        onchain = "0x" + "aa" * 2 + "ffff" + "aa" * 6   # bytes[2:4] differ (immutable slot)
        self.built(local, immutables={"7": [{"start": 2, "length": 2}]},
                   onchain=onchain)
        r = self.cf("verify")
        self.assertEqual(r.returncode, 0, r.stderr)
        rep = self.report("a")
        self.assertEqual(rep["bytecode"], "MATCH_AFTER_IMMUTABLE_MASK")
        self.assertEqual(rep["immutable_mask"]["ranges"], 1)
        self.assertEqual(rep["immutable_mask"]["ast_ids"], ["7"])
        self.assertEqual(rep["verdict"], "PASS")

    def test_mismatch_fails_closed_with_diagnostics(self):
        self.built("0x" + "aa" * 10, onchain="0x" + "bb" * 10)
        r = self.cf("verify")
        self.assertEqual(r.returncode, 1)
        self.assertIn("[MISMATCH]", r.stderr)
        self.assertIn("do NOT audit this tree", r.stderr)
        self.assertEqual(self.state()["targets"]["a"]["state"], "FAILED:VERIFY")

    def test_tampered_source_fails_source_identity(self):
        tdir = self.built("0xdeadbeef")
        src = os.path.join(tdir, "src", "src", "Tiny.sol")
        with open(src, "a", encoding="utf-8") as f:
            f.write("// sneaky edit\n")
        r = self.cf("verify")
        self.assertEqual(r.returncode, 1)
        self.assertIn("[SOURCE_TAMPER]", r.stderr)
        self.assertEqual(self.state()["targets"]["a"]["state"], "FAILED:VERIFY")
        self.assertIn("rerun `assemble --rebuild", r.stderr)

    def test_missing_artifact(self):
        self.pipeline_to_built("a", self.fixture, "Tiny")
        self.set_state("a", "BUILT")
        r = self.cf("verify")
        self.assertEqual(r.returncode, 1)
        self.assertIn("[BUILD]", r.stderr)
        self.assertIn("artifact missing", r.stderr)

    def test_unlinked_library_placeholder(self):
        self.built("0x73__$aabbcc$__$ff", onchain="0x73__$aabbcc$__$ff")
        r = self.cf("verify")
        self.assertEqual(r.returncode, 1)
        self.assertIn("[LIBRARY_UNLINKED]", r.stderr)


@unittest.skipUnless(HAVE_FORGE, "forge not installed")
class TestVerifyWithForge(VerifyBase):
    def build_real(self, tid, source, contract):
        self.server.fixtures[ADDR_A] = std_json({f"src/{contract}.sol": source},
                                                contract_name=contract)
        self.wtargets([row(tid, ADDR_A)])
        for cmd in ("fetch", "assemble", "build"):
            r = self.cf(cmd)
            self.assertEqual(r.returncode, 0, f"{cmd}: {r.stderr}")
        st = self.state()
        tdir = os.path.join(self.root, "projects", st["batch"], "targets", tid)
        return tdir

    def solc_exact(self, tdir, contract):
        """The verification-time compilation: what a real explorer-verified
        deployment actually put on chain. NOTE: solc --standard-json emits the
        object WITHOUT an 0x prefix — normalize here so callers can assume one."""
        import subprocess
        binary = os.path.expanduser("~/.svm/0.8.26/solc-0.8.26")
        if not os.path.isfile(binary):
            binary = "solc"
        with open(os.path.join(tdir, "artifacts", "input.json"), "rb") as f:
            proc = subprocess.run([binary, "--standard-json"], stdin=f,
                                  capture_output=True)
        doc = json.loads(proc.stdout)
        for per_file in doc["contracts"].values():
            if contract in per_file:
                dep = per_file[contract]["evm"]["deployedBytecode"]
                obj = dep["object"]
                obj = obj[2:] if obj.startswith("0x") else obj
                return "0x" + obj, dep.get("immutableReferences") or {}
        raise AssertionError(f"{contract} not in solc output")

    def test_e2e_match_exact_and_cross_check(self):
        tdir = self.build_real("tiny", TINY_SOL, "Tiny")
        exact, _ = self.solc_exact(tdir, "Tiny")
        self.set_onchain(exact)
        r = self.cf("verify")
        self.assertEqual(r.returncode, 0, r.stderr)
        rep = self.report("tiny")
        self.assertEqual(rep["bytecode"], "MATCH_EXACT")
        self.assertFalse(rep["metadata_masked"])
        self.assertEqual(rep["build_cross_check"], "PASS")  # real solc vs forge tree
        self.assertTrue(rep["metadata_tail"])

    def test_e2e_immutable_masking(self):
        tdir = self.build_real("imm", IMM_SOL, "Imm")
        exact, refs = self.solc_exact(tdir, "Imm")
        ranges = [sp for spans in refs.values() for sp in spans]
        self.assertTrue(ranges)
        onchain = bytearray(bytes.fromhex(exact[2:]))
        for sp in ranges:  # deployment-specific immutable value baked in
            onchain[sp["start"]:sp["start"] + sp["length"]] = \
                (42).to_bytes(sp["length"], "big")
        self.set_onchain("0x" + onchain.hex())
        r = self.cf("verify")
        self.assertEqual(r.returncode, 0, r.stderr)
        rep = self.report("imm")
        self.assertEqual(rep["bytecode"], "MATCH_AFTER_IMMUTABLE_MASK")
        self.assertEqual(rep["verdict"], "PASS")

    def test_e2e_flipped_byte_is_mismatch(self):
        tdir = self.build_real("tiny2", TINY_SOL, "Tiny")
        exact, _ = self.solc_exact(tdir, "Tiny")
        obj = bytearray(bytes.fromhex(exact[2:]))
        obj[0] ^= 0xFF
        self.set_onchain("0x" + obj.hex())
        r = self.cf("verify")
        self.assertEqual(r.returncode, 1)
        self.assertIn("[MISMATCH]", r.stderr)
        self.assertEqual(self.state()["targets"]["tiny2"]["state"], "FAILED:VERIFY")


if __name__ == "__main__":
    unittest.main()
