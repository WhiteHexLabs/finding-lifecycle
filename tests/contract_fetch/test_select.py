"""Tests for `select`: deterministic ranking and provenance."""

import json
import os
import unittest

import yaml

try:
    from ._common import ADDR_A, ADDR_B, Base, row
except ImportError:
    from _common import ADDR_A, ADDR_B, Base, row

C = "0x" + "cc" * 20
D = "0x" + "dd" * 20


class TestSelect(Base):
    def setUp(self):
        super().setUp()
        self.init()

    def sel(self, *extra, parent="targets.yaml"):
        return self.cf("select", "--targets", parent, "-o", "targets-selected.yaml", *extra)

    def loaded(self):
        with open(os.path.join(self.root, "targets-selected.yaml"), encoding="utf-8") as f:
            return yaml.safe_load(f)

    def test_sorts_by_funds_desc_missing_last(self):
        self.wtargets([
            row("small", ADDR_A, funds="$10K"),
            row("none", ADDR_B, funds="N/A"),
            row("big", C, funds="$35.8M"),
            row("mid", D, funds="$474.3K"),
        ])
        self.assertEqual(self.sel("--sort", "funds").returncode, 0)
        ids = [t["id"] for t in self.loaded()["targets"]]
        self.assertEqual(ids, ["big", "mid", "small", "none"])

    def test_min_funds_and_top(self):
        self.wtargets([
            row("a", ADDR_A, funds="$1M"),
            row("b", ADDR_B, funds="$2M"),
            row("c", C, funds="$3M"),
        ])
        r = self.sel("--min-funds", "1500000", "--top", "1")
        self.assertEqual(r.returncode, 0, r.stderr)
        ids = [t["id"] for t in self.loaded()["targets"]]
        self.assertEqual(ids, ["c"])

    def test_min_added_on_filter(self):
        self.wtargets([
            row("old", ADDR_A, added="2026-01-01"),
            row("new", ADDR_B, added="2026-09-01"),
        ])
        self.assertEqual(self.sel("--min-added-on", "2026-08-01").returncode, 0)
        ids = [t["id"] for t in self.loaded()["targets"]]
        self.assertEqual(ids, ["new"])

    def test_sort_added_on_desc_missing_last(self):
        self.wtargets([
            row("older", ADDR_A, added="2026-01-01"),
            row("no-date", ADDR_B, added=None),
            row("newer", C, added="2026-09-01"),
        ])
        self.assertEqual(self.sel("--sort", "added_on").returncode, 0)
        ids = [t["id"] for t in self.loaded()["targets"]]
        self.assertEqual(ids, ["newer", "older", "no-date"])

    def test_provenance_header(self):
        parent = self.wtargets([row("a", ADDR_A)])
        import hashlib
        with open(parent, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        self.assertEqual(self.sel().returncode, 0)
        doc = self.loaded()
        self.assertEqual(doc["schema"], "whitehexlabs.targets/v1")
        self.assertEqual(doc["selected_from"], "targets.yaml")
        self.assertEqual(doc["selected_from_sha256"], digest)
        self.assertEqual(doc["selection"]["sort"], "funds")

    def test_rejects_invalid_parent(self):
        self.wtargets([row("a", ADDR_A, chain=324)])
        r = self.sel()
        self.assertEqual(r.returncode, 1)
        self.assertIn("gate targets: FAIL", r.stderr)

    def test_rejects_output_equal_to_parent(self):
        self.wtargets([row("a", ADDR_A)])
        r = self.cf("select", "--targets", "targets.yaml", "-o", "targets.yaml")
        self.assertEqual(r.returncode, 2)
        self.assertIn("must differ", r.stderr)

    def test_bad_min_added_on_format(self):
        self.wtargets([row("a", ADDR_A)])
        r = self.sel("--min-added-on", "01-08-2026")
        self.assertEqual(r.returncode, 2)

    def test_json_output_reports_totals(self):
        self.wtargets([row("a", ADDR_A, funds="$2M"), row("b", ADDR_B, funds="$1M")])
        r = self.sel("--json")
        out = json.loads(r.stdout)
        self.assertEqual(out["selected"], 2)
        self.assertEqual(out["total_funds_usd"], 3_000_000)


if __name__ == "__main__":
    unittest.main()
