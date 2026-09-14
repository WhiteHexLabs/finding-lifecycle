"""Controlled local-chain exercise test (plan.md section 5).

Runs demo/drive.py end to end when Foundry (forge/anvil/cast) is available;
otherwise skips. This validates the workflow with a real local chain, real
pinned fork and the real CLI — it does not replace mainnet forensics.
"""

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DRIVE = os.path.join(REPO, "demo", "drive.py")

FOUNDARY = all(shutil.which(t) for t in ("forge", "anvil", "cast"))


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@unittest.skipUnless(FOUNDARY, "foundry (forge/anvil/cast) not installed")
class TestDemo(unittest.TestCase):
    def test_success_and_refutation_samples(self):
        with tempfile.TemporaryDirectory(prefix="fl-demo-") as tmp:
            case = os.path.join(tmp, "case")
            r = subprocess.run(
                [sys.executable, DRIVE, "--case-root", case,
                 "--rpc-port", str(free_port())],
                capture_output=True, text=True, timeout=600,
            )
            self.assertEqual(r.returncode, 0, r.stdout[-4000:] + r.stderr[-4000:])
            with open(os.path.join(case, "index.md"), encoding="utf-8") as f:
                index = f.read()
            self.assertIn("SUBMITTED", index)
            self.assertIn("REFUTED", index)


if __name__ == "__main__":
    unittest.main()
