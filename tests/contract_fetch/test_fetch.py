"""Tests for `fetch`: explorer + RPC fetching, caching, fail-closed rows."""

import json
import os
import unittest

try:
    from ._common import (ADDR_A, ADDR_B, ADDR_IMPL, Base, NIGHTLY, RATE_LIMITED,
                          TINY_SOL, UNVERIFIED, VYPER, fetch_env, multi_file, row,
                          std_json)
except ImportError:
    from _common import (ADDR_A, ADDR_B, ADDR_IMPL, Base, NIGHTLY, RATE_LIMITED,
                         TINY_SOL, UNVERIFIED, VYPER, fetch_env, multi_file, row,
                         std_json)


class TestFetch(Base):
    def setUp(self):
        super().setUp()
        self.init()
        self.server.codes[ADDR_A] = "0xdeadbeef"
        self.server.codes[ADDR_B] = "0x" + "00" * 4
        self.server.codes[ADDR_IMPL] = "0x" + "21" * 8

    def cache(self, addr, chain=1, kind="getsourcecode"):
        return os.path.join(self.root, "fetch-cache", str(chain),
                            f"{addr.lower()}.{kind}.json")

    def test_standard_json_target(self):
        self.server.fixtures[ADDR_A] = std_json({"src/Tiny.sol": TINY_SOL})
        self.wtargets([row("a", ADDR_A)])
        r = self.cf("fetch")
        self.assertEqual(r.returncode, 0, r.stderr)
        st = self.state()
        self.assertEqual(st["targets"]["a"]["state"], "FETCHED")
        f = st["targets"]["a"]["fetch"]
        self.assertEqual(f["format"], "standard-json")
        self.assertEqual(f["contract_name"], "Tiny")
        self.assertEqual(f["settings"]["version"], "0.8.26")
        self.assertTrue(f["settings"]["optimizer"])
        self.assertEqual(f["settings"]["runs"], 200)
        self.assertEqual(f["block_number"], "0xbc614e")
        self.assertTrue(os.path.isfile(self.cache(ADDR_A)))
        with open(self.cache(ADDR_A, kind="getcode"), encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["code"], "0xdeadbeef")
        self.assertTrue(st["batch"] and st["batch"].startswith("20"))

    def test_multi_file_and_single_file_formats(self):
        self.server.fixtures[ADDR_A] = multi_file({"src/A.sol": "contract A {}\n"})
        self.server.fixtures[ADDR_B] = std_json({"X.sol": "contract X {}\n"})
        self.server.fixtures[ADDR_B] = {
            "status": "1", "message": "OK",
            "result": [{"SourceCode": "contract X {}\\n", "ABI": "[]",
                        "ContractName": "X", "CompilerVersion": "v0.8.19+commit.b60b008e",
                        "OptimizationUsed": "0", "Runs": "200", "EVMVersion": "",
                        "Proxy": "0", "Implementation": "", "SwarmSource": ""}]}
        self.wtargets([row("a", ADDR_A), row("b", ADDR_B)])
        r = self.cf("fetch")
        self.assertEqual(r.returncode, 0, r.stderr)
        st = self.state()
        self.assertEqual(st["targets"]["a"]["fetch"]["format"], "multi-file")
        b = st["targets"]["b"]["fetch"]
        self.assertEqual(b["format"], "single-file-flattened")
        self.assertFalse(b["settings"]["optimizer"])
        self.assertIsNone(b["settings"]["evm_version"])

    def test_unverified_fails_closed(self):
        self.server.fixtures[ADDR_A] = UNVERIFIED
        self.wtargets([row("a", ADDR_A)])
        r = self.cf("fetch")
        self.assertEqual(r.returncode, 1)
        self.assertIn("[UNVERIFIED]", r.stderr)
        self.assertIn("replace the address or set excluded", r.stderr)
        self.assertEqual(self.state()["targets"]["a"]["state"], "FAILED:FETCH")

    def test_vyper_and_nightly_fail_closed(self):
        self.server.fixtures[ADDR_A] = VYPER
        self.server.fixtures[ADDR_B] = NIGHTLY
        self.wtargets([row("a", ADDR_A), row("b", ADDR_B)])
        r = self.cf("fetch")
        self.assertEqual(r.returncode, 1)
        self.assertIn("[VYPER]", r.stderr)
        self.assertIn("[NIGHTLY]", r.stderr)
        st = self.state()["targets"]
        self.assertEqual(st["a"]["state"], "FAILED:FETCH")
        self.assertEqual(st["b"]["state"], "FAILED:FETCH")

    def test_proxy_derives_implementation_target(self):
        self.server.fixtures[ADDR_A] = std_json(
            {"src/P.sol": TINY_SOL}, proxy="1", impl=ADDR_IMPL, contract_name="P")
        self.server.fixtures[ADDR_IMPL] = std_json({"src/Impl.sol": TINY_SOL},
                                                   contract_name="Impl")
        self.wtargets([row("a", ADDR_A)])
        r = self.cf("fetch")
        self.assertEqual(r.returncode, 0, r.stderr)
        st = self.state()["targets"]
        self.assertEqual(st["a"]["state"], "FETCHED")
        self.assertTrue(st["a"]["fetch"]["proxy"]["is_proxy"])
        impl = st["a--impl"]
        self.assertEqual(impl["state"], "FETCHED")
        self.assertEqual(impl["derived_from"], "a")
        self.assertEqual(impl["row"]["address"], ADDR_IMPL)
        self.assertEqual(impl["row"]["project"], "P")

    def test_rate_limit_backoff_then_success(self):
        self.server.fixtures[ADDR_A] = [RATE_LIMITED, RATE_LIMITED,
                                        std_json({"src/Tiny.sol": TINY_SOL})]
        self.wtargets([row("a", ADDR_A)])
        r = self.cf("fetch")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertGreaterEqual(self.server.requests, 3)
        self.assertEqual(self.state()["targets"]["a"]["state"], "FETCHED")

    def test_missing_api_key_is_runtime_error(self):
        self.server.fixtures[ADDR_A] = std_json({"src/Tiny.sol": TINY_SOL})
        self.wtargets([row("a", ADDR_A)])
        env = fetch_env()
        env.pop("ETHERSCAN_API_KEY")
        r = self.cf("fetch", env=env)
        self.assertEqual(r.returncode, 2)
        self.assertIn("ETHERSCAN_API_KEY", r.stderr)

    def test_second_run_is_cached_and_offline(self):
        self.server.fixtures[ADDR_A] = std_json({"src/Tiny.sol": TINY_SOL})
        self.wtargets([row("a", ADDR_A)])
        self.assertEqual(self.cf("fetch").returncode, 0)
        before = self.server.requests
        self.server.fixtures.clear()          # any further request would 404
        r = self.cf("fetch")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.server.requests, before)
        self.assertIn("nothing to fetch", r.stdout)

    def test_changed_targets_file_after_batch_start_fails(self):
        self.server.fixtures[ADDR_A] = std_json({"src/Tiny.sol": TINY_SOL})
        self.wtargets([row("a", ADDR_A)])
        self.assertEqual(self.cf("fetch").returncode, 0)
        self.wtargets([row("a", ADDR_A, funds="$2.0M")])  # content changed
        r = self.cf("fetch")
        self.assertEqual(r.returncode, 2)
        self.assertIn("changed since this batch started", r.stderr)

    def test_refresh_busts_cache(self):
        self.server.fixtures[ADDR_A] = std_json({"src/Tiny.sol": TINY_SOL})
        self.wtargets([row("a", ADDR_A)])
        self.assertEqual(self.cf("fetch").returncode, 0)
        self.assertEqual(self.cf("fetch", "--refresh", ADDR_A).returncode, 0)

    def test_empty_onchain_code_fails(self):
        self.server.fixtures[ADDR_A] = std_json({"src/Tiny.sol": TINY_SOL})
        self.server.codes[ADDR_A] = "0x"      # EOA: no contract there
        self.wtargets([row("a", ADDR_A)])
        r = self.cf("fetch")
        self.assertEqual(r.returncode, 1)
        self.assertIn("no/empty code", r.stderr)

    def test_retry_after_failure_uses_cache_for_explorer(self):
        self.server.fixtures[ADDR_A] = std_json({"src/Tiny.sol": TINY_SOL})
        self.server.codes[ADDR_A] = "0x"          # EOA: first run fails at RPC
        self.wtargets([row("a", ADDR_A)])
        self.assertEqual(self.cf("fetch").returncode, 1)
        self.server.requests = 0
        self.server.codes[ADDR_A] = "0xfeed"
        r = self.cf("fetch")                              # FAILED:FETCH -> retried
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.state()["targets"]["a"]["state"], "FETCHED")
        # explorer response came from cache; only the two RPC calls hit the server
        self.assertEqual(self.server.requests, 2)

    def test_excluded_rows_are_never_fetched(self):
        self.server.fixtures[ADDR_A] = std_json({"src/Tiny.sol": TINY_SOL})
        self.wtargets([row("a", ADDR_A, excluded=True, exclude_reason="dup")])
        r = self.cf("fetch")
        self.assertEqual(r.returncode, 0, r.stderr)
        st = self.state()["targets"]
        self.assertEqual(st["a"]["state"], "EXCLUDED")
        self.assertEqual(self.server.requests, 0)
        self.assertEqual(self.cf("check").returncode, 0)  # excluded rows do not block


if __name__ == "__main__":
    unittest.main()
