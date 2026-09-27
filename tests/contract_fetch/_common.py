"""Shared harness for contract-fetch tests: real CLI via subprocess + mock
explorer/RPC server, mirroring the repo's behavioral-test conventions."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCRIPT = os.path.join(REPO, "skills", "contract-fetch", "scripts", "fetch.py")

ADDR_A = "0x" + "aa" * 20
ADDR_B = "0x" + "bb" * 20
ADDR_IMPL = "0x" + "11" * 20

BLOCK_HEX = "0xbc614e"  # 12345678


def run(args, env=None):
    return subprocess.run([sys.executable, SCRIPT] + [str(a) for a in args],
                          capture_output=True, text=True, env=env)


def fetch_env():
    env = dict(os.environ)
    env["ETHERSCAN_API_KEY"] = "test-key"
    env["CF_BACKOFF_BASE"] = "0.01"
    env.pop("CF_SOLC_PATH", None)
    return env


class MockServer:
    """Serves the Etherscan V2 getsourcecode endpoint and a JSON-RPC endpoint."""

    def __init__(self):
        self.fixtures = {}   # lowercase address -> response doc, or list (sequential, last repeats)
        self.codes = {}      # lowercase address -> eth_getCode result
        self.requests = 0
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, status, body):
                data = json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                outer.requests += 1
                parts = urlparse(self.path)
                q = parse_qs(parts.query)
                if parts.path == "/v2/api" and q.get("action") == ["getsourcecode"]:
                    addr = (q.get("address") or [""])[0].lower()
                    fx = outer.fixtures.get(addr)
                    if isinstance(fx, list):
                        fx = fx.pop(0) if len(fx) > 1 else fx[0]
                    if fx is None:
                        self._send(404, {"error": "no fixture"})
                    else:
                        self._send(200, fx)
                    return
                self._send(404, {"error": "not found"})

            def do_POST(self):
                outer.requests += 1
                length = int(self.headers.get("Content-Length", 0))
                doc = json.loads(self.rfile.read(length))
                method = doc.get("method")
                if method == "eth_getCode":
                    addr = str(doc.get("params", [""])[0]).lower()
                    self._send(200, {"jsonrpc": "2.0", "id": 1,
                                     "result": outer.codes.get(addr, "0x")})
                elif method == "eth_blockNumber":
                    self._send(200, {"jsonrpc": "2.0", "id": 1, "result": BLOCK_HEX})
                else:
                    self._send(200, {"jsonrpc": "2.0", "id": 1,
                                     "error": {"message": f"unknown {method}"}})

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    @property
    def api_base(self):
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    @property
    def rpc_url(self):
        return self.api_base + "/rpc"

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


# ---------------------------------------------------------------------------
# explorer response fixtures

def gs_response(source_code, contract_name="Tiny", compiler="v0.8.26+commit.8a97fa7a",
                opt="1", runs="200", evm="cancun", proxy="0", impl="", abi="[]"):
    return {"status": "1", "message": "OK", "result": [{
        "SourceCode": source_code, "ABI": abi, "ContractName": contract_name,
        "CompilerVersion": compiler, "OptimizationUsed": opt, "Runs": runs,
        "EVMVersion": evm, "Library": "", "LicenseType": "MIT",
        "Proxy": proxy, "Implementation": impl, "SwarmSource": "",
    }]}


TINY_SOL = "pragma solidity ^0.8.26;\n\ncontract Tiny {}\n"
IMMUTABLE_SOL = (
    "pragma solidity ^0.8.26;\n\n"
    "contract Imm {\n"
    "    uint256 public immutable VALUE;\n\n"
    "    constructor() {\n"
    "        VALUE = 42;\n    }\n"
    "}\n"
)


def std_json(files, settings=None, **kw):
    inner = {
        "language": "Solidity",
        "sources": {k: {"content": v} for k, v in files.items()},
        "settings": settings or {
            "optimizer": {"enabled": True, "runs": 200},
            "evmVersion": "cancun",
            "outputSelection": {"*": {"*": [
                "abi", "evm.bytecode", "evm.deployedBytecode", "metadata"]}},
        },
    }
    return gs_response("{" + json.dumps(inner) + "}", **kw)


def multi_file(files, **kw):
    return gs_response(json.dumps({"sources": {k: {"content": v}
                                               for k, v in files.items()}}), **kw)


RATE_LIMITED = {"status": "0", "message": "NOTOK", "result": "Max rate limit reached"}
UNVERIFIED = gs_response("", abi="Contract source code not verified")
VYPER = gs_response("struct X:\n    a: uint256\n", contract_name="X",
                    compiler="vyper:0.4.0+commit.e9db8d9f")
NIGHTLY = gs_response("contract N {}", contract_name="N",
                      compiler="0.8.20-nightly.2023.11.21")


def row(tid, addr, chain=1, funds="$1.0M", added="2026-03-30", **over):
    r = {
        "id": tid, "project": "P", "platform": "immunefi",
        "source_url": "https://immunefi.com/example", "chain": chain,
        "address": addr, "funds_raw": funds, "added_on": added,
        "description": "row", "excluded": False, "exclude_reason": "", "notes": "",
    }
    if funds is not None:
        r["funds_usd"] = over.pop("funds_usd", None) or _funds(funds)
    r.update(over)
    return r


def _funds(raw):
    import re
    s = str(raw).replace(",", "").replace("$", "").strip().lower()
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([kmb]?)", s)
    if not m:
        return None
    return int(round(float(m.group(1)) * {"": 1, "k": 1e3, "m": 1e6, "b": 1e9}[m.group(2)]))


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="cfetch-test-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.root = os.path.join(self.tmp, "fetch")
        self.server = MockServer()
        self.addCleanup(self.server.stop)

    # -- helpers --------------------------------------------------------
    def wtargets(self, rows, rpc=None, name="targets.yaml", **top):
        doc = {"schema": "whitehexlabs.targets/v1", "batch_note": "",
               "rpc": rpc or {}, "targets": rows}
        doc.update(top)
        path = os.path.join(self.root, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            yaml.safe_dump(doc, f, sort_keys=False, allow_unicode=True)
        return path

    def cf(self, cmd, *extra, env=None):
        args = [cmd, "--fetch-root", self.root]
        if cmd in ("fetch",):
            args += ["--api-base", self.server.api_base,
                     "--rpc-url", self.server.rpc_url, "--rps", "100"]
        return run(args + [str(x) for x in extra], env=env or fetch_env())

    def state(self):
        with open(os.path.join(self.root, "state.yaml"), encoding="utf-8") as f:
            return yaml.safe_load(f)

    def set_state(self, tid, value, **extra):
        st = self.state()
        entry = st["targets"].setdefault(tid, {"row": {"id": tid}, "state": value})
        entry["state"] = value
        entry.update(extra)
        with open(os.path.join(self.root, "state.yaml"), "w", encoding="utf-8") as f:
            yaml.safe_dump(st, f, sort_keys=False)

    def init(self, *extra):
        return self.cf("init", *extra)

    def read_yaml(self, rel):
        with open(os.path.join(self.root, rel), encoding="utf-8") as f:
            return yaml.safe_load(f)
