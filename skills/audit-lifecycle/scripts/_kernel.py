"""Shared kernel for the audit-lifecycle skill's two CLIs (audit.py,
lifecycle.py).

Before the skill merge each CLI carried a byte-identical copy of these
helpers — the tree digest even had to stay bit-identical across the two
scripts because directory hashes cross the handoff bundle boundary.
They live here once now.

The validation helpers raise ToolError; each CLI subclasses it as its
own error (AuditError / LifecycleError) and maps ToolError to exit
code 2, so messages and exit behavior are unchanged.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from datetime import datetime, timezone

try:
    import yaml
except ImportError:  # pragma: no cover
    print("_kernel.py requires PyYAML", file=__import__("sys").stderr)
    raise


class ToolError(Exception):
    """Input or runtime error -> exit 2."""


class GateFailure(Exception):
    """Gate not passed -> exit 1."""

    def __init__(self, gate_id, issues, next_steps=()):
        super().__init__(gate_id)
        self.gate_id = gate_id
        self.issues = list(issues)
        self.next_steps = list(next_steps)


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
    fd, tmp = tempfile.mkstemp(dir=parent, prefix=".tmp-", suffix=".write")
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


def as_dict(value, what) -> dict:
    if not isinstance(value, dict):
        raise ToolError(f"{what}: expected a mapping, got {type(value).__name__}")
    return value


def as_list(value, what) -> list:
    if not isinstance(value, list):
        raise ToolError(f"{what}: expected a list, got {type(value).__name__}")
    return value


def as_str(value, what) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ToolError(f"{what}: expected a non-empty string")
    return value


def check_enum(value, allowed, what):
    if value not in allowed:
        raise ToolError(f"{what}: expected one of {list(allowed)}, got {value!r}")
    return value


def restrict_keys(d: dict, allowed: set, what) -> None:
    unknown = set(d) - allowed
    if unknown:
        raise ToolError(f"{what}: unknown key(s): {sorted(unknown)}")


def load_yaml_file(path: str, what):
    if not os.path.isfile(path):
        raise ToolError(f"{what}: file not found: {path}")
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        raise ToolError(f"{what}: invalid YAML in {path}: {exc}")
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ToolError(f"{what}: top-level YAML must be a mapping: {path}")
    return data


def emit(payload: dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=False, default=str))
    else:
        for line in payload.get("lines", []):
            print(line)


def tree_digest(dirpath: str):
    """Deterministic directory digest: sha256 over sorted
    `<normalized-rel-posix-path>\\0<file-sha256>\\n` records. No mtimes."""
    records = []
    for dirpath_, _dirnames, filenames in os.walk(dirpath):
        for name in filenames:
            full = os.path.join(dirpath_, name)
            rel = os.path.relpath(full, dirpath).replace(os.sep, "/")
            records.append((rel, sha256_file(full)))
    records.sort()
    stream = "".join(f"{rel}\0{digest}\n" for rel, digest in records)
    return sha256_bytes(stream.encode("utf-8")), len(records)


class DirectoryLock:
    """Exclusive write lock for a root directory; stale locks are stolen."""

    STALE_AFTER = 600

    def __init__(self, root: str, filename: str, err, label: str):
        self.root = root
        self.path = os.path.join(root, filename)
        self.err = err
        self.label = label
        self.acquired = False

    def _stale(self) -> bool:
        try:
            with open(self.path, encoding="utf-8") as f:
                pid = int(f.read().split()[0])
            age = time.time() - os.path.getmtime(self.path)
            if age > self.STALE_AFTER:
                return True
            try:
                os.kill(pid, 0)
                return False
            except ProcessLookupError:
                return True
            except PermissionError:
                return False  # live process owned by another user
        except (OSError, ValueError, IndexError):
            return True

    def __enter__(self):
        for attempt in range(2):
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
                os.write(fd, f"{os.getpid()} {now_iso()}".encode())
                os.close(fd)
                self.acquired = True
                return self
            except FileExistsError:
                if attempt == 0 and self._stale():
                    try:
                        os.unlink(self.path)
                    except FileNotFoundError:
                        pass
                    continue
                raise self.err(
                    f"{self.label} is locked by another session: {self.path}")
        raise self.err(f"could not acquire lock: {self.path}")

    def __exit__(self, *exc):
        if self.acquired:
            try:
                os.unlink(self.path)
            except FileNotFoundError:
                pass
        return False
