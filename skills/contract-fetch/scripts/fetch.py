#!/usr/bin/env python3
"""contract-fetch CLI.

Pre-audit batch source fetching from block explorers: transcribed bounty
scope tables become a validated target list; verified sources are fetched
and reconstructed into a compilable Foundry workspace; local code is proven
byte-identical to the explorer's verified code (runtime bytecode equality
including the metadata hash, which commits to every source file's keccak
and therefore to identical line numbers).

Design contracts (docs/contract-fetch-design.md, references/):
  - exit codes: 0 success, 1 gate not passed, 2 input or runtime error
  - there is no --force; unverified / vyper / mismatching targets fail closed
  - downloaded sources are immutable evidence: never edited, only hashed
  - the Etherscan API key lives in the environment, never in artifacts
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import posixpath
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

try:
    import yaml
except ImportError:  # pragma: no cover
    print("fetch.py requires PyYAML (pip3 install pyyaml)", file=sys.stderr)
    sys.exit(2)

# ---------------------------------------------------------------------------
# constants

EXIT_OK, EXIT_GATE, EXIT_ERROR = 0, 1, 2

SCHEMA_TARGETS = "whitehexlabs.targets/v1"
SCHEMA_TARGET = "whitehexlabs.target/v1"
SCHEMA_STATE = "whitehexlabs.fetch-state/v1"
SCHEMA_VERIFICATION = "whitehexlabs.verification/v1"
SCHEMA_MANIFEST = "whitehexlabs.sources-manifest/v1"
SCHEMA_BUILD_REPORT = "whitehexlabs.build-report/v1"

STATE_FILE = "state.yaml"
TARGETS_FILE = "targets.yaml"
SELECTED_FILE = "targets-selected.yaml"

STATES = ["SELECTED", "FETCHED", "ASSEMBLED", "BUILT", "VERIFIED", "READY"]
FAILED_PREFIX = "FAILED:"

# explorer link domain -> Etherscan V2 chainid (docs §2.2)
DOMAIN_CHAINS = {
    "etherscan.io": 1,
    "bscscan.com": 56,
    "polygonscan.com": 137,
    "optimistic.etherscan.io": 10,
    "basescan.org": 8453,
    "arbiscan.io": 42161,
    "snowtrace.io": 43114,
    "ftmscan.com": 250,
}
CHAIN_NAMES = {
    1: "ethereum", 10: "op", 56: "bnb", 137: "polygon", 250: "fantom",
    8453: "base", 42161: "arbitrum", 43114: "avalanche",
}
DEFAULT_RPCS = {
    1: "https://eth.llamarpc.com",
    10: "https://mainnet.optimism.io",
    56: "https://bsc-dataseed.bnbchain.org",
    137: "https://polygon-rpc.com",
    250: "https://rpc.ftm.tools",
    8453: "https://mainnet.base.org",
    42161: "https://arb1.arbitrum.io/rpc",
    43114: "https://api.avax.network/ext/bc/C/rpc",
}

API_BASE_DEFAULT = "https://api.etherscan.io"
API_KEY_ENV = "ETHERSCAN_API_KEY"
SOLC_PATH_ENV = "CF_SOLC_PATH"
BACKOFF_BASE_ENV = "CF_BACKOFF_BASE"

ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SOLC_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
IMPORT_PLAIN_RE = re.compile(r'import\s+["\']([^"\']+)["\']')
IMPORT_FROM_RE = re.compile(r'from\s+["\']([^"\']+)["\']')
BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)

NEXT_STEPS = {
    "UNVERIFIED": "the address has no verified source on the explorer; "
                  "replace the address or set excluded: true with a reason in targets.yaml",
    "VYPER": "Vyper is out of scope in v1; set excluded: true with a reason",
    "NIGHTLY": "nightly compiler builds cannot be reproduced; set excluded: true with a reason",
    "EXPLORER": "explorer API error; retry, check the address/chain pair, or use --refresh",
    "RPC": "eth_getCode failed; retry, configure rpc: in targets.yaml or pass --rpc-url",
    "PARSE": "unrecognized verification payload; record the response and report the format",
    "PATH": "source path cannot be reconstructed safely (traversal/collision); report it",
    "DANGLING_IMPORT": "an import resolves to nothing in the verified tree; report it",
    "SOLC": "compiler version missing or malformed in the explorer record",
    "BUILD": "forge build failed; inspect build-report.yaml (sources are never edited)",
    "LIBRARY_UNLINKED": "artifact contains unlinked library placeholders; report it",
    "MISMATCH": "local recompile does not match on-chain bytecode; do NOT audit this tree",
    "SOURCE_TAMPER": "a reconstructed file changed after assemble; "
                     "rerun `assemble --rebuild <id>` to restore the tree",
    "RECONSTRUCTION": "exact-input compile disagrees with the tree build; rerun assemble and report",
}

# ---------------------------------------------------------------------------
# errors and small utilities

class FetchError(Exception):
    """Input or runtime error -> exit 2."""


class GateFailure(Exception):
    """Gate not passed -> exit 1."""

    def __init__(self, gate_id, issues, next_steps=()):
        super().__init__(gate_id)
        self.gate_id = gate_id
        self.issues = list(issues)
        self.next_steps = list(next_steps)


class TargetFailure(Exception):
    """Per-target failure carrying a category for state + gate reporting."""

    def __init__(self, category, detail):
        super().__init__(detail)
        self.category = category
        self.detail = detail

    def issue(self, target_id):
        return {"category": self.category, "target": target_id, "detail": self.detail}

    def next_step(self):
        return NEXT_STEPS.get(self.category, "inspect the recorded state entry")


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def atomic_write(path: str, data: str) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=parent, prefix=".tmp-", suffix=".cfetch")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def atomic_write_bytes(path: str, data: bytes) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=parent, prefix=".tmp-", suffix=".cfetch")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def dump_yaml(obj) -> str:
    return yaml.safe_dump(obj, sort_keys=False, allow_unicode=True, default_flow_style=False)


def emit(payload: dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=False, default=str))
    else:
        for line in payload.get("lines", []):
            print(line)


# ---------------------------------------------------------------------------
# keccak-256 (solc metadata / EIP-55 depend on keccak, not NIST SHA3)

_KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
# rotation offsets indexed [x][y]
_KECCAK_ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]
_KECCAK_MASK = (1 << 64) - 1


def _rotl64(v: int, n: int) -> int:
    return ((v << n) | (v >> (64 - n))) & _KECCAK_MASK


def _keccak_f(st: list) -> None:
    for rc in _KECCAK_RC:
        c = [st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl64(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                st[x + 5 * y] ^= d[x]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl64(st[x + 5 * y], _KECCAK_ROT[x][y])
        for x in range(5):
            for y in range(5):
                st[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y] & _KECCAK_MASK)
        st[0] ^= rc


def keccak256(data: bytes) -> bytes:
    rate = 136  # 1088 bits for a 256-bit hash
    padded = bytearray(data)
    pad_len = rate - (len(padded) % rate)
    padded += b"\x00" * pad_len
    padded[len(data)] ^= 0x01  # keccak domain padding (not SHA3's 0x06)
    padded[-1] ^= 0x80
    st = [0] * 25
    for off in range(0, len(padded), rate):
        block = padded[off:off + rate]
        for i in range(rate // 8):
            st[i] ^= int.from_bytes(block[i * 8:(i + 1) * 8], "little")
        _keccak_f(st)
    return b"".join(st[i].to_bytes(8, "little") for i in range(4))


def keccak_hex(data: bytes) -> str:
    return "0x" + keccak256(data).hex()


def addr_checksum(addr: str) -> str:
    body = addr[2:].lower()
    digest = keccak256(body.encode("ascii")).hex()
    out = ["0x"]
    for i, ch in enumerate(body):
        if ch.isdigit():
            out.append(ch)
        else:
            out.append(ch.upper() if int(digest[i], 16) >= 8 else ch)
    return "".join(out)


# ---------------------------------------------------------------------------
# targets file

def repo_path(*parts) -> str:
    """Path relative to the skill root (skills/contract-fetch/)."""
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, "..", *parts)


def targets_path(root: str, override=None, prefer_selected=True) -> str:
    if override:
        p = override if os.path.isabs(override) else os.path.join(root, override)
        if not os.path.isfile(p):
            raise FetchError(f"targets file not found: {p}")
        return p
    for name in ([SELECTED_FILE, TARGETS_FILE] if prefer_selected else [TARGETS_FILE]):
        p = os.path.join(root, name)
        if os.path.isfile(p):
            return p
    raise FetchError(
        f"no targets file under {root}: fill in {TARGETS_FILE} "
        f"(template: skills/contract-fetch/templates/targets.yaml)")


def load_targets(path: str) -> dict:
    if not os.path.isfile(path):
        raise FetchError(f"targets file not found: {path}")
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        raise FetchError(f"invalid YAML in {path}: {exc}")
    if not isinstance(data, dict):
        raise FetchError(f"top-level YAML must be a mapping: {path}")
    # PyYAML timestamps arrive as date objects; normalize to ISO strings
    for row in data.get("targets") or []:
        if isinstance(row, dict):
            added = row.get("added_on")
            if hasattr(added, "isoformat"):
                row["added_on"] = added.isoformat()
    return data


def parse_funds(raw):
    s = str(raw or "").strip().replace(",", "").replace("$", "").strip()
    if not s or s.lower() in {"n/a", "na", "-", "tbd", "unknown"}:
        return None
    m = re.fullmatch(r"(?i)(\d+(?:\.\d+)?)\s*([kmb]?)", s)
    if not m:
        raise FetchError(f"cannot parse funds value: {raw!r} "
                         f"(expected forms like $35.8M, $474.3K, $1,200,000, N/A)")
    mult = {"": 1, "k": 10 ** 3, "m": 10 ** 6, "b": 10 ** 9}[m.group(2).lower()]
    return int(round(float(m.group(1)) * mult))


def validate_targets(doc: dict) -> list:
    issues = []

    def bad(category, detail):
        issues.append({"category": category, "detail": detail})

    if doc.get("schema") != SCHEMA_TARGETS:
        bad("schema", f"schema must be {SCHEMA_TARGETS}, got {doc.get('schema')!r}")
    rows = doc.get("targets")
    if not isinstance(rows, list) or not rows:
        bad("schema", "targets must be a non-empty list")
        return issues

    seen_ids, seen_pairs = set(), set()
    for i, row in enumerate(rows):
        where = f"targets[{i}]"
        if not isinstance(row, dict):
            bad("schema", f"{where}: each row must be a mapping")
            continue
        tid = row.get("id")
        if not isinstance(tid, str) or not SLUG_RE.match(tid or ""):
            bad("id", f"{where}: id must be a kebab-case slug (got {tid!r})")
        elif tid in seen_ids:
            bad("id", f"{where}: duplicate id {tid!r}")
        else:
            seen_ids.add(tid)
            where = f"targets[{tid}]"
        for field in ("project", "platform", "source_url"):
            if not isinstance(row.get(field), str) or not row.get(field, "").strip():
                bad("schema", f"{where}: missing {field}")
        addr = row.get("address")
        if not isinstance(addr, str) or not ADDR_RE.match(addr or ""):
            bad("address", f"{where}: address must be 0x + 40 hex (got {addr!r})")
        elif addr != addr.lower() and addr != addr_checksum(addr):
            bad("address", f"{where}: EIP-55 checksum mismatch for {addr}")
        chain = row.get("chain")
        if chain not in CHAIN_NAMES:
            known = ", ".join(str(c) for c in sorted(CHAIN_NAMES))
            bad("chain", f"{where}: chain {chain!r} not in whitelist [{known}]")
        if isinstance(addr, str) and isinstance(chain, int):
            pair = (chain, addr.lower())
            if pair in seen_pairs:
                bad("duplicate", f"{where}: (chain {chain}, {addr.lower()}) already listed")
            seen_pairs.add(pair)
        added = row.get("added_on")
        if added is not None:
            if not isinstance(added, str) or not DATE_RE.match(added):
                bad("date", f"{where}: added_on must be YYYY-MM-DD (got {added!r})")
            else:
                try:
                    datetime.strptime(added, "%Y-%m-%d")
                except ValueError:
                    bad("date", f"{where}: added_on is not a real date: {added!r}")
        funds_raw = row.get("funds_raw")
        funds_usd = row.get("funds_usd")
        if funds_raw is not None:
            try:
                parsed = parse_funds(funds_raw)
                if parsed is None and funds_raw not in (None, ""):
                    if str(funds_raw).strip().upper() in {"N/A", "NA", "-", "TBD", "UNKNOWN", ""}:
                        parsed = None
                    else:
                        bad("funds", f"{where}: cannot parse funds_raw {funds_raw!r}")
                if parsed is not None and funds_usd is not None and int(funds_usd) != parsed:
                    bad("funds", f"{where}: funds_usd {funds_usd} disagrees with funds_raw {funds_raw!r}")
            except FetchError:
                bad("funds", f"{where}: cannot parse funds_raw {funds_raw!r}")
        if row.get("excluded") is True and not str(row.get("exclude_reason") or "").strip():
            bad("excluded", f"{where}: excluded: true requires a non-empty exclude_reason")
    return issues


# ---------------------------------------------------------------------------
# state

def state_path(root: str) -> str:
    return os.path.join(root, STATE_FILE)


def load_state(root: str) -> dict:
    p = state_path(root)
    if not os.path.isfile(p):
        raise FetchError(f"not a fetch root (missing {STATE_FILE}): {root} — run init first")
    try:
        with open(p, encoding="utf-8") as f:
            st = yaml.safe_load(f) or {}
    except yaml.YAMLError as exc:
        raise FetchError(f"invalid YAML in {p}: {exc}")
    if st.get("schema") != SCHEMA_STATE:
        raise FetchError(f"unsupported state schema in {p}: {st.get('schema')!r}")
    st.setdefault("batch", None)
    st.setdefault("batch_targets_file", None)
    st.setdefault("batch_targets_sha256", None)
    st.setdefault("targets", {})
    return st


def save_state(root: str, st: dict) -> None:
    atomic_write(state_path(root), dump_yaml(st))


def state_entry(st: dict, tid: str) -> dict:
    return st["targets"].setdefault(tid, {})


def set_state(st: dict, tid: str, value: str, extra=None) -> None:
    entry = state_entry(st, tid)
    entry["state"] = value
    entry["updated"] = now_iso()
    if extra:
        entry.update(extra)
    if value.startswith(FAILED_PREFIX):
        entry.setdefault("issues", [])
        entry.setdefault("next_steps", [])


def fail_target(st: dict, tid: str, exc: TargetFailure, stage: str) -> None:
    entry = state_entry(st, tid)
    entry["state"] = FAILED_PREFIX + stage
    entry["updated"] = now_iso()
    entry["issues"] = [exc.detail]
    entry["next_steps"] = [exc.next_step()]


# ---------------------------------------------------------------------------
# HTTP

def _backoff_base() -> float:
    return float(os.environ.get(BACKOFF_BASE_ENV, "1.0"))


class RateLimiter:
    def __init__(self, rps: float):
        self.min_interval = 1.0 / rps if rps > 0 else 0.0
        self._last = 0.0

    def wait(self):
        now = time.monotonic()
        delta = now - self._last
        if delta < self.min_interval:
            time.sleep(self.min_interval - delta)
        self._last = time.monotonic()


def http_get(url: str, timeout: int) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "contract-fetch/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def explorer_get(api_base: str, chain: int, address: str, api_key: str,
                 limiter: RateLimiter, timeout: int) -> dict:
    """GET /v2/api getsourcecode with rate limiting and backoff (docs §5.1)."""
    query = urllib.parse.urlencode({
        "chainid": str(chain),
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "apikey": api_key,
    })
    url = f"{api_base.rstrip('/')}/v2/api?{query}"
    last_err = None
    for attempt in range(4):  # 1 try + 3 retries
        limiter.wait()
        try:
            doc = http_get(url, timeout)
            result = doc.get("result")
            if (str(doc.get("status")) != "1" and isinstance(result, str)
                    and "rate limit" in result.lower()):
                last_err = f"rate limit in body: {result[:60]}"
            else:
                return doc
        except urllib.error.HTTPError as exc:
            if exc.code not in (429, 500, 502, 503):
                raise TargetFailure("EXPLORER", f"explorer HTTP {exc.code} for {address}")
            last_err = f"HTTP {exc.code}"
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            last_err = str(exc)
        time.sleep(_backoff_base() * (2 ** attempt))
    raise TargetFailure("EXPLORER", f"explorer request failed after retries: {last_err}")


def rpc_call(rpc_url: str, method: str, params: list, timeout: int):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                       "params": params}).encode("utf-8")
    req = urllib.request.Request(rpc_url, data=body,
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "contract-fetch/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            doc = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
        raise TargetFailure("RPC", f"{method} failed against {rpc_url}: {exc}")
    if doc.get("error"):
        raise TargetFailure("RPC", f"{method}: {doc['error']}")
    return doc.get("result")


# ---------------------------------------------------------------------------
# explorer response parsing (docs §5.3)

def normalize_source_path(key: str) -> str:
    p = (key or "").strip().replace("\\", "/")
    if not p:
        raise TargetFailure("PATH", "empty source path in verified input")
    p = posixpath.normpath(p.lstrip("/"))
    if p.startswith("..") or posixpath.isabs(p) or "/../" in f"/{p}/":
        raise TargetFailure("PATH", f"source path escapes the tree: {key!r}")
    return p


def parse_explorer_response(doc: dict) -> dict:
    """Return {format, contract_name, sources{path: content}, settings{...}, proxy}."""
    if str(doc.get("status")) != "1":
        result = doc.get("result")
        msg = result if isinstance(result, str) else doc.get("message")
        if isinstance(msg, str) and "rate limit" in msg.lower():
            raise TargetFailure("EXPLORER", f"rate-limited even after retries: {msg}")
        raise TargetFailure("EXPLORER", f"explorer status {doc.get('status')!r}: {msg}")
    rows = doc.get("result")
    if not isinstance(rows, list) or not rows:
        raise TargetFailure("EXPLORER", "explorer returned no result rows")
    r = rows[0]
    src = r.get("SourceCode") or ""
    abi = r.get("ABI") or ""
    if not src.strip() or "not verified" in abi.lower():
        raise TargetFailure("UNVERIFIED", "contract source is not verified on the explorer")
    compiler = str(r.get("CompilerVersion") or "")
    if compiler.lower().startswith("vyper"):
        raise TargetFailure("VYPER", f"vyper contract ({compiler}) is out of scope in v1")
    if "nightly" in compiler.lower():
        raise TargetFailure("NIGHTLY", f"nightly compiler cannot be reproduced: {compiler}")
    version = compiler.lstrip("v").split("+")[0]
    if not SOLC_VERSION_RE.match(version):
        raise TargetFailure("SOLC", f"unrecognized compiler version: {compiler!r}")
    contract_name = str(r.get("ContractName") or "").strip() or "Contract"
    top_opt = r.get("OptimizationUsed") == "1"
    top_runs = r.get("Runs")
    top_evm = (r.get("EVMVersion") or "").strip() or None

    def settings_from(payload: dict) -> dict:
        s = payload.get("settings") or {}
        opt = s.get("optimizer") or {}
        return {
            "version": version,
            "optimizer": bool(opt.get("enabled", top_opt)),
            "runs": int(opt.get("runs", top_runs or 200)),
            "via_ir": bool(s.get("viaIR", False)),
            "evm_version": s.get("evmVersion") or top_evm,
            "libraries": s.get("libraries") or {},
            "remappings": s.get("remappings") or [],
        }

    fmt = None
    payload = None
    if src.startswith("{{") and src.endswith("}}"):
        fmt = "standard-json"
        try:
            payload = json.loads(src[1:-1])
        except json.JSONDecodeError as exc:
            raise TargetFailure("PARSE", f"standard-json payload does not parse: {exc}")
    elif src.startswith("{"):
        fmt = "multi-file"
        try:
            payload = json.loads(src)
        except json.JSONDecodeError as exc:
            raise TargetFailure("PARSE", f"multi-file payload does not parse: {exc}")

    if payload is not None:
        if str(payload.get("language", "Solidity")).lower() not in ("solidity", ""):
            raise TargetFailure("VYPER", f"non-solidity language: {payload.get('language')!r}")
        raw_sources = payload.get("sources") or {}
        sources = {}
        for key, val in raw_sources.items():
            content = val.get("content") if isinstance(val, dict) else val
            if not isinstance(content, str):
                raise TargetFailure("PARSE", f"source {key!r} has no inline content "
                                             "(keccak-only entries cannot be reconstructed)")
            norm = normalize_source_path(key)
            if norm in sources:
                raise TargetFailure("PATH",
                                    f"source paths collide after normalization: {key!r}")
            sources[norm] = content
        if not sources:
            raise TargetFailure("PARSE", "verified payload contains no sources")
        return {"format": fmt, "contract_name": contract_name, "sources": sources,
                "settings": settings_from(payload), "proxy": proxy_info(r)}

    return {"format": "single-file-flattened", "contract_name": contract_name,
            "sources": {f"{contract_name}.sol": src},
            "settings": settings_from({}), "proxy": proxy_info(r)}


def proxy_info(row: dict) -> dict:
    if str(row.get("Proxy")) == "1":
        impl = str(row.get("Implementation") or "")
        return {"is_proxy": True, "implementation": impl or None}
    return {"is_proxy": False, "implementation": None}


# ---------------------------------------------------------------------------
# fetch root paths

def cache_getsourcecode(root: str, chain: int, address: str) -> str:
    return os.path.join(root, "fetch-cache", str(chain), f"{address.lower()}.getsourcecode.json")


def cache_getcode(root: str, chain: int, address: str) -> str:
    return os.path.join(root, "fetch-cache", str(chain), f"{address.lower()}.getcode.json")


def batch_dir(root: str, batch: str) -> str:
    return os.path.join(root, "projects", batch)


def target_dir(root: str, batch: str, tid: str) -> str:
    return os.path.join(batch_dir(root, batch), "targets", tid)


def batch_for(root: str) -> str:
    st = load_state(root)
    if not st.get("batch"):
        raise FetchError("no batch recorded yet — run fetch first")
    return st["batch"]


# ---------------------------------------------------------------------------
# source scanning / remappings (docs §6.4)

def strip_solidity_comments(text: str) -> str:
    text = BLOCK_COMMENT_RE.sub(" ", text)
    out = []
    for line in text.splitlines():
        cut = line.find("//")
        out.append(line if cut < 0 else line[:cut])
    return "\n".join(out)


def collect_imports(sources: dict) -> dict:
    """{source path: [import strings]} from comment-stripped Solidity."""
    imports = {}
    for path, content in sources.items():
        cleaned = strip_solidity_comments(content)
        found = set(IMPORT_PLAIN_RE.findall(cleaned)) | set(IMPORT_FROM_RE.findall(cleaned))
        imports[path] = sorted(i for i in found if not i.startswith("npm:/"))
    return imports


def parse_declared_remappings(decls) -> dict:
    """standard-json settings.remappings → {prefix: in-tree target dir}.

    The deployer's own remappings are part of the verified input, so they are
    legitimate resolution evidence — but only a mapping whose target directory
    exists in the reconstructed tree can resolve an import (e.g. a
    Foundry-repo payload shipping lib/ deps). Others are ignored: an import
    they cannot satisfy stays dangling, fail-closed.
    """
    out = {}
    for d in decls or []:
        if not isinstance(d, str) or "=" not in d:
            continue
        prefix, target = d.split("=", 1)
        if not prefix.endswith("/") or not target.endswith("/"):
            continue
        out[prefix] = normalize_source_path(target)
    return out


def resolve_bare_import(imp: str, src_root: str, declared: dict):
    """Resolve a bare import in the verified tree: verbatim path first, then
    the payload's declared remappings. Returns the in-tree relative path of
    an existing file, or None."""
    if os.path.isfile(os.path.join(src_root, imp)):
        return imp
    for prefix, target in declared.items():
        if imp.startswith(prefix):
            resolved = posixpath.normpath(f"{target}/{imp[len(prefix):]}")
            if os.path.isfile(os.path.join(src_root, resolved)):
                return resolved
    return None


def remap_segments(imports: dict, src_root: str, declared: dict | None = None) -> list:
    declared = declared or {}
    segments = set()
    for found in imports.values():
        for imp in found:
            if imp.startswith("./") or imp.startswith("../"):
                continue
            seg = imp.split("/")[0]
            if seg and (os.path.isdir(os.path.join(src_root, seg))
                        or any(imp.startswith(p) for p in declared)):
                segments.add(seg)
    return sorted(segments)


def check_dangling(imports: dict, src_root: str, segments: list,
                   declared: dict | None = None) -> list:
    segset = set(segments)
    declared = declared or {}
    dangling = []
    for path, found in sorted(imports.items()):
        base_dir = posixpath.dirname(path)
        for imp in found:
            if imp.startswith("./") or imp.startswith("../"):
                resolved = posixpath.normpath(posixpath.join(base_dir, imp))
                ok = os.path.isfile(os.path.join(src_root, resolved))
            elif imp.split("/")[0] in segset:
                ok = resolve_bare_import(imp, src_root, declared) is not None
            else:
                ok = os.path.isfile(os.path.join(src_root, imp))
            if not ok:
                dangling.append(f"{path}: import {imp!r} resolves to nothing in the tree")
    return dangling


def foundry_remappings(imports: dict, src_root: str, declared: dict, tid: str) -> list:
    """Foundry remappings for the generated profile, relative to the batch dir.

    A segment whose imports all resolve verbatim in the tree keeps the plain
    tree mapping; a segment resolved through the payload's declared remappings
    gets a mapping pointing at the declared target inside the tree."""
    bare = sorted({i for found in imports.values() for i in found
                   if not i.startswith(("./", "../")) and i.split("/")[0]})
    out = []
    for seg in sorted({i.split("/")[0] for i in bare}):
        seg_imports = [i for i in bare if i.split("/")[0] == seg]
        if os.path.isdir(os.path.join(src_root, seg)) and \
                all(os.path.isfile(os.path.join(src_root, i)) for i in seg_imports):
            out.append(f"{seg}/=targets/{tid}/src/{seg}/")
            continue
        for p, target in declared.items():
            if any(i.startswith(p) for i in seg_imports):
                out.append(f"{p}=targets/{tid}/src/{target}/")
                break
        else:
            out.append(f"{seg}/=targets/{tid}/src/{seg}/")
    return out


def toml_str(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render_foundry_toml(entries: list) -> str:
    """entries: [{id, compiler{version, optimizer, runs, via_ir, evm_version}, remappings[]}]"""
    lines = [
        "# Generated by contract-fetch assemble — do not edit by hand.",
        "# One profile per target; settings mirror the explorer verification record.",
    ]
    for e in entries:
        c = e["compiler"]
        tid = e["id"]
        lines += [
            "",
            f"[profile.{tid}]",
            f"src = {toml_str('targets/' + tid + '/src')}",
            f"out = {toml_str('targets/' + tid + '/out')}",
            f"solc = {toml_str(c['version'])}",
            f"optimizer = {'true' if c.get('optimizer') else 'false'}",
            f"optimizer_runs = {int(c.get('runs') or 200)}",
        ]
        if c.get("via_ir"):
            lines.append("via_ir = true")
        if c.get("evm_version") and str(c["evm_version"]).lower() != "default":
            # "Default" is solc-json's null placeholder; forge config rejects it,
            # so omit the line and let forge pick the compiler's default.
            lines.append(f"evm_version = {toml_str(c['evm_version'])}")
        if e.get("remappings"):
            rendered = ", ".join(toml_str(r) for r in e["remappings"])
            lines.append(f"remappings = [{rendered}]")
        lines.append('extra_output = ["evm.deployedBytecode.immutableReferences"]')
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# subcommands

def cmd_init(a) -> int:
    root = a.fetch_root
    if os.path.exists(root) and not os.path.isdir(root):
        raise FetchError(f"fetch root exists and is not a directory: {root}")
    for sub in ("fetch-cache", "projects", "verification"):
        os.makedirs(os.path.join(root, sub), exist_ok=True)
    tpl_src = repo_path("templates", "targets.yaml")
    tpl = os.path.abspath(tpl_src)
    tpath = os.path.join(root, TARGETS_FILE)
    if not os.path.isfile(tpath):
        if not os.path.isfile(tpl):
            raise FetchError(f"template missing: {tpl}")
        shutil.copyfile(tpl, tpath)
    spath = state_path(root)
    if not os.path.isfile(spath):
        atomic_write(spath, dump_yaml({
            "schema": SCHEMA_STATE,
            "batch": None,
            "batch_targets_file": None,
            "batch_targets_sha256": None,
            "targets": {},
        }))
    emit({"lines": [
        f"initialized fetch root: {root}",
        f"next: transcribe Assets-in-Scope rows into {TARGETS_FILE} "
        "(see references/discovery-sources.md), then validate",
    ], "fetch_root": root}, a.json)
    return EXIT_OK


def cmd_validate(a) -> int:
    root = a.fetch_root
    path = targets_path(root, a.targets)
    doc = load_targets(path)
    issues = validate_targets(doc)
    if issues:
        cats = {i["category"] for i in issues}
        steps = []
        if "chain" in cats:
            steps.append("chain must be an Etherscan V2 chainid from the whitelist "
                         "(docs/contract-fetch-design.md §2.2)")
        if "funds" in cats:
            steps.append("funds_raw must be a verbatim Funds cell like $35.8M / $474.3K "
                         "/ $1,200,000 / N/A")
        if "excluded" in cats:
            steps.append("excluded: true rows need a non-empty exclude_reason")
        if not steps:
            steps.append("fix every listed row until validate passes")
        raise GateFailure("targets", issues, steps)
    rows = doc["targets"]
    active = [r for r in rows if r.get("excluded") is not True]
    total_funds = sum(int(r["funds_usd"]) for r in active
                      if isinstance(r.get("funds_usd"), int))
    chains = {}
    for r in active:
        chains[CHAIN_NAMES.get(r["chain"], str(r["chain"]))] = \
            chains.get(CHAIN_NAMES.get(r["chain"], str(r["chain"])), 0) + 1
    lines = [f"targets OK: {len(rows)} rows "
             f"({len(rows) - len(active)} excluded), file {os.path.basename(path)}",
             f"chains: " + ", ".join(f"{k}={v}" for k, v in sorted(chains.items())),
             f"total funds at risk (numeric rows): ${total_funds:,}"]
    emit({"lines": lines, "file": os.path.basename(path), "rows": len(rows),
          "active": len(active), "excluded": len(rows) - len(active),
          "chains": chains, "total_funds_usd": total_funds}, a.json)
    return EXIT_OK


def cmd_select(a) -> int:
    root = a.fetch_root
    parent = targets_path(root, a.targets, prefer_selected=False)
    doc = load_targets(parent)
    issues = validate_targets(doc)
    if issues:
        raise GateFailure("targets", issues, [
            "fix targets.yaml until validate passes, then rerun select"])
    rows = list(doc["targets"])

    def funds_key(r):
        f = r.get("funds_usd")
        if not isinstance(f, int):
            parsed = parse_funds(r.get("funds_raw"))
            f = parsed if isinstance(parsed, int) else None
        return (0, -f, r["id"]) if isinstance(f, int) else (1, 0, r["id"])

    def added_key(r):
        added = str(r.get("added_on") or "")
        if DATE_RE.match(added):
            return (0, tuple(-int(x) for x in added.split("-")), r["id"])
        return (1, (0, 0, 0), r["id"])

    keys = {"funds": funds_key, "added_on": added_key, "id": lambda r: (0, r["id"])}
    selected = list(rows)
    if a.min_funds is not None:
        selected = [r for r in selected
                    if isinstance(r.get("funds_usd"), int) and r["funds_usd"] >= a.min_funds]
    if a.min_added_on:
        if not DATE_RE.match(a.min_added_on):
            raise FetchError(f"--min-added-on must be YYYY-MM-DD (got {a.min_added_on!r})")
        selected = [r for r in selected
                    if str(r.get("added_on") or "") >= a.min_added_on]
    selected.sort(key=keys[a.sort])
    if a.top is not None and a.top >= 0:
        selected = selected[:a.top]

    out_path = os.path.join(root, a.output)
    if os.path.abspath(out_path) == os.path.abspath(parent):
        raise FetchError("output file must differ from the parent targets file")
    out_doc = {
        "schema": SCHEMA_TARGETS,
        "selected_from": os.path.basename(parent),
        "selected_from_sha256": sha256_file(parent),
        "selection": {
            "sort": a.sort, "min_funds": a.min_funds,
            "min_added_on": a.min_added_on, "top": a.top, "generated": now_iso(),
        },
        "batch_note": doc.get("batch_note", ""),
        "rpc": doc.get("rpc", {}),
        "targets": selected,
    }
    atomic_write(out_path, dump_yaml(out_doc))
    funds = sum(int(r["funds_usd"]) for r in selected if isinstance(r.get("funds_usd"), int))
    emit({"lines": [
        f"selected {len(selected)}/{len(rows)} rows -> {a.output}",
        f"sort={a.sort}" + (f", top={a.top}" if a.top is not None else "")
        + (f", min_funds=${a.min_funds:,}" if a.min_funds is not None else "")
        + (f", min_added_on={a.min_added_on}" if a.min_added_on else ""),
        f"total funds at risk (numeric rows): ${funds:,}",
    ], "output": a.output, "selected": len(selected), "total": len(rows),
        "total_funds_usd": funds}, a.json)
    return EXIT_OK


def cmd_fetch(a) -> int:
    root = a.fetch_root
    st = load_state(root)
    path = targets_path(root, a.targets)
    doc = load_targets(path)
    issues = validate_targets(doc)
    if issues:
        raise GateFailure("targets", issues, ["fix the targets file until validate passes"])

    digest = sha256_file(path)
    if st.get("batch"):
        if st.get("batch_targets_sha256") != digest:
            raise FetchError(
                "targets file changed since this batch started "
                f"({st.get('batch_targets_file')} sha {st.get('batch_targets_sha256')[:8]}… "
                f"now {digest[:8]}…); start a new fetch root for the new selection, "
                "or restore the original file")
    else:
        st["batch"] = datetime.now(timezone.utc).strftime("%Y%m%d") + "-" + digest[:8]
        st["batch_targets_file"] = os.path.basename(path)
        st["batch_targets_sha256"] = digest

    for row in doc["targets"]:
        tid = row["id"]
        entry = state_entry(st, tid)
        if not entry:
            entry["row"] = row
            entry["state"] = "EXCLUDED" if row.get("excluded") is True else "SELECTED"
            entry["updated"] = now_iso()
        elif entry.get("row") != row and entry.get("state") in ("SELECTED", "EXCLUDED"):
            entry["row"] = row
            entry["state"] = "EXCLUDED" if row.get("excluded") is True else "SELECTED"
    save_state(root, st)  # registration + batch freeze must survive an empty queue

    limiter = RateLimiter(a.rps)
    refresh_all = a.refresh_all
    refresh = {x.lower() for x in (a.refresh or [])}

    eligible_states = ("SELECTED", FAILED_PREFIX + "FETCH")
    queue = []
    for r in doc["targets"]:
        if r.get("excluded") is True:
            continue
        entry = st["targets"].get(r["id"], {})
        if (entry.get("state") in eligible_states or refresh_all
                or r["address"].lower() in refresh):
            queue.append(r["id"])
    processed = set()
    failures = []
    ok_lines = []

    def rpc_url_for(chain: int) -> str:
        if a.rpc_url:
            return a.rpc_url
        rpc_map = doc.get("rpc") or {}
        if str(chain) in rpc_map:
            return rpc_map[str(chain)]
        if chain in rpc_map:
            return rpc_map[chain]
        if chain not in DEFAULT_RPCS:
            raise TargetFailure("RPC", f"no RPC endpoint configured for chain {chain}")
        return DEFAULT_RPCS[chain]

    while queue:
        tid = queue.pop(0)
        if tid in processed:
            continue
        processed.add(tid)
        entry = st["targets"].get(tid, {})
        row = entry["row"]
        wants_refresh = refresh_all or row["address"].lower() in refresh
        if entry.get("state") not in ("SELECTED", FAILED_PREFIX + "FETCH") and not wants_refresh:
            continue
        chain, address = row["chain"], row["address"].lower()
        try:
            # 1. explorer response (cache-first)
            gsc_path = cache_getsourcecode(root, chain, address)
            hit = os.path.isfile(gsc_path)
            if refresh_all or address in refresh:
                hit = False
            if hit:
                try:
                    with open(gsc_path, encoding="utf-8") as f:
                        gsc_doc = json.load(f)
                except (OSError, json.JSONDecodeError):
                    hit = False
            if not hit:
                api_key = os.environ.get(API_KEY_ENV, "")
                if not api_key:
                    raise FetchError(f"missing {API_KEY_ENV}: export your Etherscan V2 key "
                                     "or pre-populate fetch-cache for offline runs")
                gsc_doc = explorer_get(a.api_base, chain, address, api_key, limiter, a.timeout)
                atomic_write_bytes(gsc_path, json.dumps(gsc_doc, indent=1).encode("utf-8"))
            parsed = parse_explorer_response(gsc_doc)

            # 2. chain state via RPC (cache-first)
            code_path = cache_getcode(root, chain, address)
            code_doc = None
            if os.path.isfile(code_path) and not (refresh_all or address in refresh):
                try:
                    with open(code_path, encoding="utf-8") as f:
                        code_doc = json.load(f)
                except (OSError, json.JSONDecodeError):
                    code_doc = None
            if code_doc is None:
                rpc_url = rpc_url_for(chain)
                code = rpc_call(rpc_url, "eth_getCode", [row["address"], "latest"], a.timeout)
                if not isinstance(code, str) or not code.startswith("0x") or code == "0x":
                    raise TargetFailure(
                        "RPC", f"eth_getCode returned no/empty code for {address} — "
                               "no contract at this address on this chain?")
                block = rpc_call(rpc_url, "eth_blockNumber", [], a.timeout)
                code_doc = {"code": code, "block_number": block, "rpc": rpc_url}
                atomic_write_bytes(code_path, json.dumps(code_doc, indent=1).encode("utf-8"))

            # 3. proxy: follow the implementation as a derived target
            derived = None
            if parsed["proxy"]["is_proxy"]:
                impl = parsed["proxy"]["implementation"]
                if impl and ADDR_RE.match(impl):
                    impl_id = tid + "--impl"
                    if impl_id not in st["targets"] and impl.lower() != address:
                        parent_row = row
                        impl_row = {
                            "id": impl_id,
                            "project": parent_row["project"],
                            "platform": parent_row["platform"],
                            "source_url": parent_row["source_url"],
                            "chain": chain,
                            "address": impl.lower(),
                            "funds_raw": None,
                            "funds_usd": None,
                            "added_on": parent_row.get("added_on"),
                            "description": f"implementation of {tid}",
                            "excluded": False,
                            "exclude_reason": "",
                            "notes": "derived from proxy target",
                        }
                        st["targets"][impl_id] = {"row": impl_row, "state": "SELECTED",
                                                  "updated": now_iso(),
                                                  "derived_from": tid}
                        derived = impl_id
                        queue.append(impl_id)
                else:
                    pass  # bare proxy with no listed implementation: nothing to derive

            set_state(st, tid, "FETCHED", {
                "row": row,
                "derived_from": entry.get("derived_from"),
                "fetch": {
                    "format": parsed["format"],
                    "contract_name": parsed["contract_name"],
                    "settings": parsed["settings"],
                    "proxy": parsed["proxy"],
                    "getsourcecode_sha256": sha256_file(gsc_path),
                    "getcode_sha256": sha256_file(code_path),
                    "block_number": code_doc.get("block_number"),
                },
            })
            ok_lines.append(
                f"[ok] {tid} {CHAIN_NAMES.get(chain, chain)} {address[:10]}…{address[-6:]} "
                f"{parsed['format']} {parsed['contract_name']}"
                + (f" -> impl {derived}" if derived else ""))
        except TargetFailure as exc:
            fail_target(st, tid, exc, "FETCH")
            failures.append(exc.issue(tid))
        save_state(root, st)

    next_steps = sorted({NEXT_STEPS.get(i["category"], "inspect the state entry")
                         for i in failures})
    if failures:
        raise GateFailure("fetch", failures, next_steps)
    emit({"lines": ok_lines or ["nothing to fetch (no targets in SELECTED/FAILED:FETCH state)"],
          "batch": st["batch"], "fetched": len(ok_lines),
          "targets": {t: e.get("state") for t, e in st["targets"].items()}}, a.json)
    return EXIT_OK


def cmd_assemble(a) -> int:
    root = a.fetch_root
    st = load_state(root)
    batch = batch_for(root)
    bdir = batch_dir(root, batch)
    failures = []
    ok_lines = []
    rebuild = set(a.rebuild or [])

    for tid, entry in list(st["targets"].items()):
        eligible = entry.get("state") in ("FETCHED", FAILED_PREFIX + "ASSEMBLE")
        forced = tid in rebuild and "fetch" in entry
        if not (eligible or forced):
            continue
        row = entry["row"]
        chain, address = row["chain"], row["address"].lower()
        try:
            with open(cache_getsourcecode(root, chain, address), encoding="utf-8") as f:
                gsc_doc = json.load(f)
            parsed = parse_explorer_response(gsc_doc)
            tdir = target_dir(root, batch, tid)
            src_root = os.path.join(tdir, "src")
            if os.path.isdir(src_root):
                shutil.rmtree(src_root)  # deterministic rebuild of the tree
            files = []
            for rel, content in sorted(parsed["sources"].items()):
                dest = os.path.join(src_root, *rel.split("/"))
                data = content.encode("utf-8")
                atomic_write_bytes(dest, data)
                files.append({
                    "path": f"src/{rel}",
                    "keccak256": keccak_hex(data),
                    "sha256": sha256_bytes(data),
                    "lines": content.count("\n") + (0 if content.endswith("\n") or not content else 1),
                })
            # byte-fidelity guard: disk == explorer, by construction (docs §6.1)
            for f in files:
                with open(os.path.join(tdir, *f["path"].split("/")), "rb") as fh:
                    disk = fh.read()
                if keccak_hex(disk) != f["keccak256"]:
                    raise TargetFailure("PATH", f"reconstructed file diverged: {f['path']}")

            settings = parsed["settings"]
            fmt = parsed["format"]
            if fmt == "standard-json":
                inner = (gsc_doc["result"][0]["SourceCode"])[1:-1]
                input_doc = json.loads(inner)
                input_exact = True
            else:
                s = {"optimizer": {"enabled": settings["optimizer"], "runs": settings["runs"]}}
                if settings["evm_version"]:
                    s["evmVersion"] = settings["evm_version"]
                if settings["via_ir"]:
                    s["viaIR"] = True
                if settings["libraries"]:
                    s["libraries"] = settings["libraries"]
                input_doc = {
                    "language": "Solidity",
                    "sources": {k: {"content": v} for k, v in parsed["sources"].items()},
                    "settings": {**s, "outputSelection": {"*": {
                        "*": ["abi", "evm.bytecode", "evm.deployedBytecode", "metadata"],
                        "": ["ast"],
                    }}},
                }
                input_exact = False
            artifacts = os.path.join(tdir, "artifacts")
            atomic_write_bytes(os.path.join(artifacts, "input.json"),
                               (json.dumps(input_doc, indent=1) + "\n").encode("utf-8"))
            atomic_write_bytes(os.path.join(artifacts, "explorer.json"),
                               (json.dumps(gsc_doc["result"][0], indent=1) + "\n").encode("utf-8"))

            imports = collect_imports(parsed["sources"])
            declared = parse_declared_remappings(settings.get("remappings"))
            segments = remap_segments(imports, src_root, declared)
            dangling = check_dangling(imports, src_root, segments, declared)
            if dangling:
                raise TargetFailure("DANGLING_IMPORT", "; ".join(dangling[:5])
                                    + (f" (+{len(dangling) - 5} more)" if len(dangling) > 5 else ""))

            atomic_write(os.path.join(tdir, "target.yaml"), dump_yaml({
                "schema": SCHEMA_TARGET,
                "id": tid,
                "chain": chain,
                "address": row["address"],
                "contract_name": parsed["contract_name"],
                "compiler": settings,
                "format": fmt,
                "input_exact": input_exact,
                "proxy": parsed["proxy"],
                "derived_from": entry.get("derived_from"),
                "fetch": {
                    "getsourcecode_sha256": entry["fetch"]["getsourcecode_sha256"],
                    "getcode_sha256": entry["fetch"]["getcode_sha256"],
                    "block_number": entry["fetch"].get("block_number"),
                },
                "files": files,
            }))
            set_state(st, tid, "ASSEMBLED")
            ok_lines.append(f"[ok] {tid}: {len(files)} files, solc {settings['version']}, "
                            + (f"remappings {', '.join(segments)}" if segments else "no remappings"))
        except TargetFailure as exc:
            fail_target(st, tid, exc, "ASSEMBLE")
            failures.append(exc.issue(tid))
        except OSError as exc:
            tf = TargetFailure("EXPLORER", f"cache unreadable: {exc}")
            fail_target(st, tid, tf, "ASSEMBLE")
            failures.append(tf.issue(tid))
        save_state(root, st)

    # regenerate foundry.toml over every assembled target (idempotent)
    entries = []
    for tid, entry in st["targets"].items():
        if entry.get("state") in ("ASSEMBLED", FAILED_PREFIX + "BUILD", "BUILT",
                                  FAILED_PREFIX + "VERIFY", "VERIFIED", "READY"):
            tdir = target_dir(root, batch, tid)
            ty = load_yaml_target(os.path.join(tdir, "target.yaml"))
            src_root = os.path.join(tdir, "src")
            sources = {}
            for f in ty["files"]:
                rel = f["path"][len("src/"):]
                with open(os.path.join(tdir, *f["path"].split("/")), encoding="utf-8") as fh:
                    sources[rel] = fh.read()
            imports = collect_imports(sources)
            declared = parse_declared_remappings(ty["compiler"].get("remappings"))
            entries.append({
                "id": tid,
                "compiler": ty["compiler"],
                "remappings": foundry_remappings(imports, src_root, declared, tid),
            })
    if entries:
        atomic_write(os.path.join(bdir, "foundry.toml"), render_foundry_toml(entries))

    if failures:
        raise GateFailure("assemble", failures,
                          sorted({NEXT_STEPS.get(i["category"], "inspect the state entry")
                                  for i in failures}))
    emit({"lines": ok_lines or ["nothing to assemble (no targets in FETCHED/FAILED:ASSEMBLE state)"],
          "batch": batch, "assembled": len(ok_lines),
          "foundry_toml": bool(entries)}, a.json)
    return EXIT_OK


def load_yaml_target(path: str) -> dict:
    if not os.path.isfile(path):
        raise FetchError(f"target record missing: {path}")
    with open(path, encoding="utf-8") as f:
        doc = yaml.safe_load(f)
    if not isinstance(doc, dict):
        raise FetchError(f"target record is not a mapping: {path}")
    return doc


# ---------------------------------------------------------------------------
# build

def cmd_build(a) -> int:
    root = a.fetch_root
    st = load_state(root)
    batch = batch_for(root)
    bdir = batch_dir(root, batch)
    if not shutil.which("forge"):
        raise FetchError("forge not found on PATH — install Foundry to run the build gate")
    try:
        forge_version = subprocess.run(["forge", "--version"], capture_output=True,
                                       text=True, timeout=60).stdout.strip().splitlines()[0]
    except (OSError, subprocess.SubprocessError, IndexError):
        forge_version = "unknown"

    failures, entries, ok_lines = [], [], []
    for tid, entry in st["targets"].items():
        if entry.get("state") not in ("ASSEMBLED", FAILED_PREFIX + "BUILD"):
            continue
        started = time.monotonic()
        try:
            env = {**os.environ, "FOUNDRY_PROFILE": tid}
            proc = subprocess.run(
                ["forge", "build", "--force"],
                cwd=bdir, capture_output=True, text=True, timeout=a.timeout, env=env)
            duration = round(time.monotonic() - started, 1)
            if proc.returncode == 0:
                set_state(st, tid, "BUILT", {"build": {"verdict": "BUILD_PASS",
                                                       "duration_s": duration}})
                entry["build"]["forge_version"] = forge_version
                ok_lines.append(f"[ok] {tid} BUILD_PASS ({duration}s)")
                entries.append({"id": tid, "verdict": "BUILD_PASS", "duration_s": duration})
            else:
                excerpt = (proc.stderr or proc.stdout or "").strip()
                excerpt = "\n".join(excerpt.splitlines()[-15:])
                tf = TargetFailure("BUILD", f"forge build failed (rc={proc.returncode}):\n{excerpt}")
                fail_target(st, tid, tf, "BUILD")
                entry["build"] = {"verdict": "BUILD_FAIL", "duration_s": duration}
                failures.append(tf.issue(tid))
                entries.append({"id": tid, "verdict": "BUILD_FAIL", "duration_s": duration,
                                "excerpt": excerpt})
        except subprocess.TimeoutExpired:
            tf = TargetFailure("BUILD", f"forge build timed out after {a.timeout}s")
            fail_target(st, tid, tf, "BUILD")
            entry["build"] = {"verdict": "BUILD_FAIL", "timeout": True}
            failures.append(tf.issue(tid))
            entries.append({"id": tid, "verdict": "BUILD_FAIL", "timeout_s": a.timeout})
        save_state(root, st)

    atomic_write(os.path.join(bdir, "build-report.yaml"), dump_yaml({
        "schema": SCHEMA_BUILD_REPORT,
        "batch": batch,
        "forge_version": forge_version,
        "generated": now_iso(),
        "entries": entries,
    }))
    if failures:
        raise GateFailure("build", failures,
                          ["inspect projects/<batch>/build-report.yaml — sources are never edited; "
                           "a BUILD_FAIL target must be excluded with a reason or reported"])
    emit({"lines": ok_lines or ["nothing to build (no targets in ASSEMBLED/FAILED:BUILD state)"],
          "batch": batch, "built": len(ok_lines), "forge_version": forge_version}, a.json)
    return EXIT_OK


# ---------------------------------------------------------------------------
# verify

def raw_deployed(artifact: dict) -> str:
    value = artifact.get("deployedBytecode")
    if isinstance(value, dict):
        value = value.get("object", "")
    return str(value or "")


def hex_code(value) -> str:
    """Normalize a deployedBytecode representation to bare lowercase hex."""
    if isinstance(value, dict):
        value = value.get("object", "")
    value = str(value or "")
    if value.startswith("0x"):
        value = value[2:]
    value = value.lower()
    if value and not re.fullmatch(r"([0-9a-f]|_)*", value):
        raise TargetFailure("PARSE", "bytecode is not hex")
    return value.replace("_", "")


def flat_ranges(refs) -> list:
    ranges = []
    for ast_id, spans in (refs or {}).items():
        for sp in spans or []:
            ranges.append({"ast_id": str(ast_id), "start": int(sp["start"]),
                           "length": int(sp["length"])})
    ranges.sort(key=lambda r: r["start"])
    return ranges


def immutable_ranges(artifact: dict) -> list:
    refs = artifact.get("immutableReferences") or {}
    dep = artifact.get("deployedBytecode")
    if isinstance(dep, dict) and isinstance(dep.get("immutableReferences"), dict):
        refs = dep["immutableReferences"]
    return flat_ranges(refs)


def mask_ranges(code: str, ranges: list) -> str:
    out = bytearray(bytes.fromhex(code))
    for rg in ranges:
        s, ln = rg["start"], rg["length"]
        out[s:s + ln] = b"\x00" * ln
    return out.hex()


def metadata_tail(code: str):
    """Extract the CBOR metadata block appended by solc (diagnostics only)."""
    if len(code) < 4:
        return None
    try:
        tail_len = int(code[-4:], 16)
        if tail_len <= 0 or (tail_len + 2) * 2 > len(code):
            return None
        return code[-((tail_len + 2) * 2):]
    except ValueError:
        return None


def first_diff(a: str, b: str):
    for i in range(0, min(len(a), len(b)), 2):
        if a[i:i + 2] != b[i:i + 2]:
            return i // 2
    return min(len(a), len(b)) // 2


def resolve_solc(version: str):
    """CF_SOLC_PATH > ~/.svm/<v>/solc-<v> > PATH solc (version must match)."""
    cand = os.environ.get(SOLC_PATH_ENV)
    if cand and os.path.isfile(cand) and _solc_version_matches(cand, version):
        return cand
    svm = os.path.join(os.path.expanduser("~"), ".svm", version, f"solc-{version}")
    if os.path.isfile(svm) and os.access(svm, os.X_OK):
        return svm
    which = shutil.which("solc")
    if which and _solc_version_matches(which, version):
        return which
    return None


def _solc_version_matches(binary: str, version: str) -> bool:
    try:
        out = subprocess.run([binary, "--version"], capture_output=True, text=True,
                             timeout=30).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    m = re.search(r"Version:\s*(\d+\.\d+\.\d+)", out)
    return bool(m) and m.group(1) == version


def solc_standard_json(binary: str, input_path: str, timeout: int,
                       cwd: str | None = None) -> dict:
    with open(input_path, "rb") as f:
        proc = subprocess.run([binary, "--standard-json"], stdin=f, cwd=cwd,
                              capture_output=True, timeout=timeout)
    if proc.returncode != 0:
        raise FetchError(f"solc --standard-json failed: {proc.stderr.decode('utf-8', 'replace')[:500]}")
    try:
        return json.loads(proc.stdout.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise FetchError(f"solc output does not parse: {exc}")


def exact_input_bytecode(output: dict, contract_name: str):
    """Deployed-bytecode object + immutable refs from a solc standard-json run."""
    contracts = (output.get("contracts") or {})
    names = []
    for path, per_file in contracts.items():
        for name in per_file:
            names.append(name)
            if name == contract_name:
                dep = per_file[name].get("evm", {}).get("deployedBytecode", {})
                return {"object": hex_code(dep.get("object", "")),
                        "immutableReferences": dep.get("immutableReferences") or {}}
    if names:
        raise TargetFailure("PARSE", f"contract {contract_name!r} not in exact-input output "
                                     f"(found {sorted(set(names))})")
    return None


# solc metadata CBOR prefix: a2 | "d" "ipfs" | 58 22 | 1220 | <32-byte hash>
_METADATA_BLOB_PREFIX = "a2646970667358221220"
_DSOLC_HEX = "64736f6c63"


def mask_metadata(code: str) -> str:
    """Zero the CBOR metadata tail (unit paths legitimately differ between the
    verified input and the reconstructed tree, so metadata hashes cannot be
    compared across the two compilations — code bytes can)."""
    tail = metadata_tail(code)
    if tail is not None and tail:
        cut = len(tail)
        code = code[:-cut] + "00" * (cut // 2)
    # A runtime can also embed per-compile metadata hashes in its data region
    # (compiled-in constants that carry a metadata blob of this unit set).
    # Zero every embedded ipfs hash too — sanity-checked by the trailing
    # "dsolc" marker — so only compile-stable bytes are compared.
    out, i = [], 0
    while True:
        j = code.find(_METADATA_BLOB_PREFIX, i)
        if j < 0:
            out.append(code[i:])
            break
        hash_at = j + len(_METADATA_BLOB_PREFIX)
        blob_ok = code.startswith(_DSOLC_HEX, hash_at + 64)
        out.append(code[i:hash_at])
        out.append("00" * 32 if blob_ok else code[hash_at:hash_at + 64])
        i = hash_at + 64
    return "".join(out)


def artifact_path(root: str, batch: str, tid: str, contract_name: str) -> str:
    return os.path.join(target_dir(root, batch, tid), "out",
                        f"{contract_name}.sol", f"{contract_name}.json")


def cmd_verify(a) -> int:
    root = a.fetch_root
    st = load_state(root)
    batch = batch_for(root)
    failures, ok_lines = [], []

    for tid, entry in st["targets"].items():
        if entry.get("state") not in ("BUILT", FAILED_PREFIX + "VERIFY"):
            continue
        try:
            tdir = target_dir(root, batch, tid)
            ty = load_yaml_target(os.path.join(tdir, "target.yaml"))
            name = ty["contract_name"]
            apath = artifact_path(root, batch, tid, name)
            if not os.path.isfile(apath):
                raise TargetFailure("BUILD", f"forge artifact missing: {apath}")
            with open(apath, encoding="utf-8") as f:
                artifact = json.load(f)
            raw = raw_deployed(artifact)
            if "$__" in raw or "__$" in raw:
                raise TargetFailure("LIBRARY_UNLINKED",
                                    "artifact contains unlinked library placeholders")
            tree = hex_code(raw)

            code_cache = cache_getcode(root, ty["chain"], ty["address"].lower())
            with open(code_cache, encoding="utf-8") as f:
                onchain_doc = json.load(f)
            onchain = hex_code(onchain_doc.get("code"))

            # exact-input compilation: authoritative when the solc binary exists,
            # because only it reproduces the verification-time unit paths (and
            # therefore the metadata hash) of the on-chain bytecode.
            # Run from the tree root: remappings declared inside the verified
            # input resolve against the process cwd, so the tree supplies the
            # files the deployer's own remappings point at.
            cross = {"build_cross_check": "SKIPPED",
                     "reason": "no matching solc binary found"}
            exact = None
            solc_bin = resolve_solc(ty["compiler"]["version"])
            if solc_bin:
                try:
                    output = solc_standard_json(
                        solc_bin, os.path.join(tdir, "artifacts", "input.json"),
                        a.timeout, cwd=os.path.join(tdir, "src"))
                    exact = exact_input_bytecode(output, name)
                    if exact is None:
                        cross = {"build_cross_check": "SKIPPED",
                                 "reason": "exact-input output has no contracts "
                                           "(outputSelection in the verified input)"}
                except FetchError as exc:
                    cross = {"build_cross_check": "SKIPPED", "reason": str(exc)}

            if exact is not None:
                ranges = flat_ranges(exact["immutableReferences"])
                primary = exact["object"]
                # the tree build compiles the same sources under project paths;
                # its metadata hash differs BY DESIGN, so compare code with the
                # metadata tail masked on both sides
                if mask_metadata(tree) != mask_metadata(primary):
                    raise TargetFailure(
                        "RECONSTRUCTION",
                        "exact-input compile disagrees with the forge tree build "
                        "(code bytes, metadata excluded); the reconstructed tree "
                        "is suspect — rerun assemble and report")
                cross = {"build_cross_check": "PASS", "solc": solc_bin}
            else:
                ranges = immutable_ranges(artifact)
                primary = tree

            if primary == onchain:
                bytecode, metadata_masked = "MATCH_EXACT", False
            elif mask_ranges(primary, ranges) == mask_ranges(onchain, ranges):
                bytecode, metadata_masked = "MATCH_AFTER_IMMUTABLE_MASK", False
            elif exact is None and mask_metadata(primary) == mask_metadata(onchain):
                # no solc to prove metadata linkage; executable code still equal
                bytecode, metadata_masked = "MATCH_CODE_ONLY", True
            else:
                pm, om = mask_ranges(primary, ranges), mask_ranges(onchain, ranges)
                diag = []
                lt, ot = metadata_tail(primary), metadata_tail(onchain)
                diag.append(f"metadata tail equal: {lt is not None and lt == ot}")
                diag.append(f"first differing byte offset: {first_diff(pm, om)}")
                if lt != ot:
                    diag.append("metadata differs => sources or settings differ "
                                "(optimizer/via_ir/evm_version)")
                else:
                    diag.append("metadata matches but code differs => settings differ")
                raise TargetFailure(
                    "MISMATCH",
                    f"local runtime != on-chain runtime; {len(primary) // 2} vs "
                    f"{len(onchain) // 2} bytes; " + "; ".join(diag))

            # source identity: disk bytes must still match what assemble recorded
            tampered = []
            for f in ty["files"]:
                disk_path = os.path.join(tdir, *f["path"].split("/"))
                if not os.path.isfile(disk_path):
                    tampered.append(f"{f['path']}: missing")
                    continue
                with open(disk_path, "rb") as fh:
                    if keccak_hex(fh.read()) != f["keccak256"]:
                        tampered.append(f"{f['path']}: content changed")
            source_identity = "FAIL" if tampered else "PASS"
            if source_identity == "FAIL":
                raise TargetFailure("SOURCE_TAMPER", "; ".join(tampered[:5]))

            report = {
                "schema": SCHEMA_VERIFICATION,
                "target": tid,
                "address": ty["address"],
                "chain": ty["chain"],
                "block_number": ty["fetch"].get("block_number"),
                "onchain_runtime_sha256": sha256_bytes(bytes.fromhex(onchain)),
                "local_runtime_sha256": sha256_bytes(bytes.fromhex(primary)),
                "tree_runtime_sha256": sha256_bytes(bytes.fromhex(tree)),
                "bytecode": bytecode,
                "metadata_masked": metadata_masked,
                "immutable_mask": {"ranges": len(ranges),
                                   "ast_ids": [r["ast_id"] for r in ranges]},
                "source_identity": source_identity,
                "metadata_tail": metadata_tail(primary),
                "format": ty["format"],
                "input_exact": ty.get("input_exact", False),
                **cross,
                "verdict": "PASS",
                "generated": now_iso(),
            }
            atomic_write(os.path.join(root, "verification", f"{tid}.yaml"),
                         dump_yaml(report))
            set_state(st, tid, "VERIFIED", {"verification": {
                "bytecode": bytecode, "metadata_masked": metadata_masked,
                "source_identity": source_identity,
                "build_cross_check": cross["build_cross_check"], "verdict": "PASS"}})
            ok_lines.append(f"[ok] {tid} {bytecode} source={source_identity} "
                            f"cross={cross['build_cross_check']}")
        except TargetFailure as exc:
            fail_target(st, tid, exc, "VERIFY")
            failures.append(exc.issue(tid))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            tf = TargetFailure("PARSE", f"verify failed: {type(exc).__name__}: {exc}")
            fail_target(st, tid, tf, "VERIFY")
            failures.append(tf.issue(tid))
        save_state(root, st)

    if failures:
        raise GateFailure("verify", failures,
                          sorted({NEXT_STEPS.get(i["category"], "inspect verification/")
                                  for i in failures}))
    emit({"lines": ok_lines or ["nothing to verify (no targets in BUILT/FAILED:VERIFY state)"],
          "batch": batch, "verified": len(ok_lines)}, a.json)
    return EXIT_OK


# ---------------------------------------------------------------------------
# manifest + check

def build_verdict_of(entry: dict) -> str:
    b = entry.get("build") or {}
    if b.get("verdict"):
        return b["verdict"]
    state = entry.get("state", "")
    order = ["READY", "VERIFIED", "BUILT", "ASSEMBLED", "FETCHED", "SELECTED"]
    if state.startswith(FAILED_PREFIX):
        return "NOT_BUILT" if "BUILD" in state or "ASSEMBLE" in state or "FETCH" in state else "BUILD_FAIL"
    try:
        return "BUILD_PASS" if order.index(state) >= order.index("BUILT") else "NOT_BUILT"
    except ValueError:
        return "NOT_BUILT"


def cmd_manifest(a) -> int:
    root = a.fetch_root
    st = load_state(root)
    batch = batch_for(root)
    entries, lines = [], []
    for tid, entry in st["targets"].items():
        row = entry.get("row") or {}
        state = entry.get("state", "SELECTED")
        build = build_verdict_of(entry)
        ver = (entry.get("verification") or {}).get("bytecode")
        if not ver and state.startswith(FAILED_PREFIX + "VERIFY"):
            ver = "MISMATCH_OR_FAIL"
        rec = {
            "id": tid,
            "project": row.get("project"),
            "platform": row.get("platform"),
            "source_url": row.get("source_url"),
            "chain": row.get("chain"),
            "address": row.get("address"),
            "funds_raw": row.get("funds_raw"),
            "funds_usd": row.get("funds_usd"),
            "added_on": row.get("added_on"),
            "derived_from": entry.get("derived_from"),
            "state": state,
            "build": build,
            "verification": ver,
            "audit_recommended": state == "VERIFIED" or state == "READY",
        }
        if state in ("ASSEMBLED", FAILED_PREFIX + "BUILD", "BUILT",
                     FAILED_PREFIX + "VERIFY", "VERIFIED", "READY"):
            rec["src"] = os.path.join("projects", batch, "targets", tid, "src")
            rec["compiler"] = (entry.get("fetch") or {}).get("settings", {}).get("version")
        if os.path.isfile(os.path.join(root, "verification", f"{tid}.yaml")):
            rec["verification_report"] = os.path.join("verification", f"{tid}.yaml")
        if state == "VERIFIED":
            set_state(st, tid, "READY")
            rec["state"] = "READY"
        entries.append(rec)
        mark = "READY" if rec["audit_recommended"] else state
        lines.append(f"[{mark}] {tid} build={rec['build']} verification={rec['verification']}")
    save_state(root, st)
    atomic_write(os.path.join(root, "sources-manifest.yaml"), dump_yaml({
        "schema": SCHEMA_MANIFEST,
        "batch": batch,
        "generated": now_iso(),
        "targets": entries,
    }))
    ready = sum(1 for e in entries if e["audit_recommended"])
    emit({"lines": [f"manifest: {len(entries)} targets, {ready} audit-ready "
                    f"-> sources-manifest.yaml"] + lines,
          "batch": batch, "targets": len(entries), "ready": ready}, a.json)
    return EXIT_OK


CHECK_HINTS = {
    "SELECTED": "run fetch (needs ETHERSCAN_API_KEY on cache miss)",
    "FETCHED": "run assemble",
    "ASSEMBLED": "run build",
    "BUILT": "run verify",
    "VERIFIED": "run manifest to mark READY",
}


def cmd_check(a) -> int:
    root = a.fetch_root
    st = load_state(root)
    issues, next_steps = [], []
    counts = {}
    for tid, entry in sorted(st["targets"].items()):
        state = entry.get("state", "SELECTED")
        if state == "EXCLUDED" or (entry.get("row") or {}).get("excluded") is True:
            continue
        counts[state] = counts.get(state, 0) + 1
        if state == "READY":
            continue
        if state.startswith(FAILED_PREFIX):
            steps = entry.get("next_steps") or ["inspect the state entry"]
            detail = "; ".join(entry.get("issues") or ["failed"])
        else:
            steps = [CHECK_HINTS.get(state, "run the next pipeline stage")]
            detail = f"pipeline state {state}"
        issues.append({"category": "not_ready", "target": tid, "detail": detail})
        next_steps.extend(f"{tid}: {s}" for s in steps)
    if issues:
        raise GateFailure("check", issues, next_steps or
                          ["resolve every failed target (exclude with a reason or fix the row)"])
    emit({"lines": [f"check OK: {sum(counts.values())} targets READY",
                    ] + [f"  {k}: {v}" for k, v in sorted(counts.items())],
          "ready": sum(counts.values()), "states": counts}, a.json)
    return EXIT_OK


# ---------------------------------------------------------------------------
# CLI

def add_common(sp):
    sp.add_argument("--fetch-root", required=True, help="fetch root directory")
    sp.add_argument("--json", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="fetch.py", description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="command", required=True, metavar="command")

    sp = sub.add_parser("init", help="scaffold a fetch root")
    add_common(sp)
    sp.set_defaults(func=cmd_init)

    sp = sub.add_parser("validate", help="validate targets.yaml")
    add_common(sp)
    sp.add_argument("--targets", help="targets file (default: targets-selected.yaml else targets.yaml)")
    sp.set_defaults(func=cmd_validate)

    sp = sub.add_parser("select", help="filter + sort targets into a pruned file")
    add_common(sp)
    sp.add_argument("--targets", help="parent targets file (default: targets.yaml)")
    sp.add_argument("--sort", choices=["funds", "added_on", "id"], default="funds")
    sp.add_argument("--min-funds", dest="min_funds", type=int)
    sp.add_argument("--min-added-on", dest="min_added_on")
    sp.add_argument("--top", type=int)
    sp.add_argument("-o", "--output", required=True, help="output file name under the fetch root")
    sp.set_defaults(func=cmd_select)

    sp = sub.add_parser("fetch", help="fetch verified sources + on-chain code")
    add_common(sp)
    sp.add_argument("--targets")
    sp.add_argument("--refresh", action="append", default=[],
                    help="address whose cache entry to bust (repeatable)")
    sp.add_argument("--refresh-all", dest="refresh_all", action="store_true")
    sp.add_argument("--rps", type=float, default=5.0, help="explorer requests per second")
    sp.add_argument("--api-base", dest="api_base", default=API_BASE_DEFAULT,
                    help="explorer API base URL (testing)")
    sp.add_argument("--rpc-url", dest="rpc_url", help="JSON-RPC endpoint override")
    sp.add_argument("--timeout", type=int, default=30, help="per-request timeout seconds")
    sp.set_defaults(func=cmd_fetch)

    sp = sub.add_parser("assemble", help="reconstruct source trees + foundry workspace")
    add_common(sp)
    sp.add_argument("--rebuild", action="append", default=[],
                    help="force tree reconstruction for this target id (repeatable)")
    sp.set_defaults(func=cmd_assemble)

    sp = sub.add_parser("build", help="forge build per target profile")
    add_common(sp)
    sp.add_argument("--timeout", type=int, default=600)
    sp.set_defaults(func=cmd_build)

    sp = sub.add_parser("verify", help="bytecode + source-identity verification")
    add_common(sp)
    sp.add_argument("--timeout", type=int, default=120)
    sp.set_defaults(func=cmd_verify)

    sp = sub.add_parser("manifest", help="write sources-manifest.yaml, mark READY")
    add_common(sp)
    sp.set_defaults(func=cmd_manifest)

    sp = sub.add_parser("check", help="gate: every non-excluded target READY")
    add_common(sp)
    sp.set_defaults(func=cmd_check)

    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except GateFailure as gf:
        if not getattr(args, "json", False):
            print(f"gate {gf.gate_id}: FAIL", file=sys.stderr)
            for issue in gf.issues:
                if isinstance(issue, dict):
                    tag = issue.get("category", "-")
                    target = f" {issue['target']}" if issue.get("target") else ""
                    print(f"  [{tag}]{target} {issue['detail']}", file=sys.stderr)
                else:
                    print(f"  - {issue}", file=sys.stderr)
            if gf.next_steps:
                print("next steps:", file=sys.stderr)
                for s in gf.next_steps:
                    print(f"  - {s}", file=sys.stderr)
        else:
            print(json.dumps({"gate": gf.gate_id, "status": "FAIL",
                              "issues": gf.issues, "next_steps": gf.next_steps}, indent=2))
        return EXIT_GATE
    except FetchError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except BrokenPipeError:
        return EXIT_ERROR
    except Exception as exc:  # unexpected runtime failure -> defined exit code
        print(f"internal error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
