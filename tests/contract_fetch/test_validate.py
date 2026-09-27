"""Tests for `validate`: targets.yaml schema and semantic checks."""

import json
import os
import unittest

try:
    from ._common import ADDR_A, ADDR_B, Base, row
except ImportError:
    from _common import ADDR_A, ADDR_B, Base, row


class TestValidate(Base):
    def setUp(self):
        super().setUp()
        self.init()

    def test_accepts_valid_file(self):
        self.wtargets([row("a", ADDR_A), row("b", ADDR_B, funds="N/A")])
        r = self.cf("validate")
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(self.cf("validate", "--json").stdout)
        self.assertEqual(out["rows"], 2)
        self.assertEqual(out["active"], 2)
        self.assertEqual(out["total_funds_usd"], 1_000_000)

    def test_rejects_wrong_schema(self):
        self.wtargets([row("a", ADDR_A)], schema="whitehexlabs.targets/v2")
        r = self.cf("validate")
        self.assertEqual(r.returncode, 1)
        self.assertIn("[schema]", r.stderr)

    def test_rejects_empty_and_missing_targets(self):
        self.wtargets([])
        self.assertEqual(self.cf("validate").returncode, 1)
        os.remove(os.path.join(self.root, "targets.yaml"))
        self.assertEqual(self.cf("validate").returncode, 2)

    def test_rejects_duplicate_id_and_pair(self):
        self.wtargets([row("a", ADDR_A), row("a", ADDR_B),
                       row("b", ADDR_A)])
        r = self.cf("validate")
        self.assertEqual(r.returncode, 1)
        self.assertIn("[id]", r.stderr)
        self.assertIn("[duplicate]", r.stderr)

    def test_same_address_different_chain_ok(self):
        self.wtargets([row("a", ADDR_A, chain=1), row("b", ADDR_A, chain=42161)])
        self.assertEqual(self.cf("validate").returncode, 0, self.cf("validate").stderr)

    def test_rejects_bad_address_and_checksum(self):
        bad_format = row("a", "0x1234")
        bad_checksum = row("b", "0x" + "Ab" * 20)  # mixed case, not EIP-55
        self.wtargets([bad_format, bad_checksum])
        r = self.cf("validate")
        self.assertEqual(r.returncode, 1)
        self.assertIn("[address]", r.stderr)
        self.assertIn("checksum mismatch", r.stderr)

    def test_rejects_unknown_chain(self):
        self.wtargets([row("a", ADDR_A, chain=324)])  # zkSync excluded in v1
        r = self.cf("validate")
        self.assertEqual(r.returncode, 1)
        self.assertIn("[chain]", r.stderr)
        self.assertIn("whitelist", r.stderr)

    def test_rejects_bad_dates(self):
        self.wtargets([row("a", ADDR_A, added="30 March 2026"),
                       row("b", ADDR_B, added="2026-13-40")])
        r = self.cf("validate")
        self.assertEqual(r.returncode, 1)
        self.assertEqual(r.stderr.count("[date]"), 2)

    def test_funds_parsing_and_disagreement(self):
        self.wtargets([
            row("a", ADDR_A, funds="$35.8M", funds_usd=35800000),
            row("b", ADDR_B, funds="$474.3K", funds_usd=999),
            row("c", "0x" + "cc" * 20, funds="seventeen dollars"),
        ])
        r = self.cf("validate")
        self.assertEqual(r.returncode, 1)
        self.assertIn("disagrees", r.stderr)
        self.assertIn("cannot parse funds_raw", r.stderr)

    def test_excluded_requires_reason(self):
        self.wtargets([row("a", ADDR_A, excluded=True, exclude_reason=""),
                       row("b", ADDR_B, excluded=True, exclude_reason="unverified upstream")])
        r = self.cf("validate")
        self.assertEqual(r.returncode, 1)
        self.assertEqual(r.stderr.count("[excluded]"), 1)
        self.assertIn("exclude_reason", r.stderr)

    def test_prefers_targets_selected_when_present(self):
        self.wtargets([row("a", ADDR_A)], name="targets.yaml")
        self.wtargets([row("b", ADDR_B)], name="targets-selected.yaml")
        out = json.loads(self.cf("validate", "--json").stdout)
        self.assertEqual(out["file"], "targets-selected.yaml")
        self.assertEqual(out["rows"], 1)


if __name__ == "__main__":
    unittest.main()
