#!/usr/bin/env python3
"""audit-orchestrator CLI.

Orchestrates configured local audit skills: config validation, ordered
step execution bookkeeping, per-step execution prompts, artifact
normalization/freezing, aggregated-analysis validation and a versioned
handoff bundle for finding-lifecycle.

The CLI never executes skill content — the operator (the current session)
reads each SKILL.md and follows it; `record` freezes the declared outcome
plus artifact copies.

Design contracts (see references/*.md):
  - exit codes: 0 success, 1 gate not passed, 2 input or runtime error
  - there is no --force; gates cannot be skipped
  - hash validity only proves artifacts are unchanged
  - canonical step artifacts are immutable evidence once recorded
  - the audited target source is never modified and never copied as an
    artifact
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone

try:
    import yaml
except ImportError:  # pragma: no cover
    print("audit.py requires PyYAML", file=sys.stderr)
    sys.exit(2)

# ---------------------------------------------------------------------------
# constants

AUDIT_CONFIG_NAME = "audit-skills.yaml"
AUDIT_RESULT_STATUSES = ["COMPLETED", "FAILED", "BLOCKED"]
STEP_STATUSES = ["PENDING", "COMPLETED", "FAILED", "BLOCKED"]

RESULT_SCHEMA = "whitehexlabs.audit-result/v1"
ARTIFACTS_SCHEMA = "whitehexlabs.audit-artifacts/v1"
HANDOFF_SCHEMA = "whitehexlabs.audit-handoff/v1"
CANDIDATE_SCHEMA = "whitehexlabs.audit-candidate/v1"

ARTIFACT_TYPES = [
    "report", "log", "findings", "poc", "trace", "coverage",
    "subagent-results", "analysis", "other",
]

ANALYSIS_H1 = "# Audit Analysis"
ANALYSIS_H2 = [
    "## Audit Run",
    "## Target and Scope",
    "## Audit Skills Executed",
    "## Coverage Summary",
    "## Consolidated Findings",
    "## Duplicate / Overlapping Leads",
    "## Disagreements Between Auditors",
    "## Coverage Gaps and Limitations",
    "## Zero-Finding Statement",
]
ANALYSIS_MIN_CHARS = 200

CANDIDATE_ID_RE = re.compile(r"^A-\d{3,}$")

# Key-material markers rejected inside declared artifacts. Bare 64-hex
# values (block/code/tx hashes) are ubiquitous legitimate audit evidence
# and are deliberately not scanned here; the deep secrets scan with
# justified exceptions happens in finding-lifecycle's PACKAGED gate.
SECRET_PATTERNS = [
    ("private_key_marker", re.compile(r"(?i)private[_ \-]?key\s*[:=]")),
    ("pem_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("mnemonic_marker", re.compile(r"(?i)(seed|mnemonic)[ _]phrase")),
    ("rpc_credential", re.compile(r"(?i)(api[_-]?key|access[_-]?token)\s*[:=]")),
]

EXIT_OK, EXIT_GATE, EXIT_ERROR = 0, 1, 2

_HERE = os.path.dirname(os.path.abspath(__file__))
SELF_SKILL_MD = os.path.realpath(os.path.join(_HERE, os.pardir, "SKILL.md"))
LIFECYCLE_SKILL_MD = os.path.realpath(os.path.join(
    _HERE, os.pardir, os.pardir, "finding-lifecycle", "SKILL.md"))


# ---------------------------------------------------------------------------
# errors and small utilities

class AuditError(Exception):
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
    fd, tmp = tempfile.mkstemp(dir=parent, prefix=".tmp-", suffix=".audit")
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


def safe_rel(root: str, rel, what="path") -> str:
    """Resolve a root-relative path, rejecting escapes."""
    if not isinstance(rel, str) or not rel.strip():
        raise AuditError(f"{what}: empty path")
    if os.path.isabs(rel) or rel.startswith("~"):
        raise AuditError(f"{what}: absolute paths are not allowed: {rel!r}")
    base = os.path.realpath(root)
    target = os.path.realpath(os.path.join(base, rel))
    if target != base and not target.startswith(base + os.sep):
        raise AuditError(f"{what}: path escapes the work root: {rel!r}")
    return target


def as_dict(value, what) -> dict:
    if not isinstance(value, dict):
        raise AuditError(f"{what}: expected a mapping, got {type(value).__name__}")
    return value


def as_list(value, what) -> list:
    if not isinstance(value, list):
        raise AuditError(f"{what}: expected a list, got {type(value).__name__}")
    return value


def as_str(value, what) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AuditError(f"{what}: expected a non-empty string")
    return value


def check_enum(value, allowed, what):
    if value not in allowed:
        raise AuditError(f"{what}: expected one of {list(allowed)}, got {value!r}")
    return value


def restrict_keys(d: dict, allowed: set, what) -> None:
    unknown = set(d) - allowed
    if unknown:
        raise AuditError(f"{what}: unknown key(s): {sorted(unknown)}")


def load_yaml_file(path: str, what):
    if not os.path.isfile(path):
        raise AuditError(f"{what}: file not found: {path}")
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        raise AuditError(f"{what}: invalid YAML in {path}: {exc}")
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise AuditError(f"{what}: top-level YAML must be a mapping: {path}")
    return data


def emit(payload: dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=False, default=str))
    else:
        for line in payload.get("lines", []):
            print(line)


# ---------------------------------------------------------------------------
# work-root lock

class WorkRootLock:
    """Exclusive write lock for a work root; stale locks are stolen."""

    STALE_AFTER = 600

    def __init__(self, root: str):
        self.root = root
        self.path = os.path.join(root, ".audit.lock")
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
                raise AuditError(
                    f"work root is locked by another session: {self.path}")
        raise AuditError(f"could not acquire lock: {self.path}")

    def __exit__(self, *exc):
        if self.acquired:
            try:
                os.unlink(self.path)
            except FileNotFoundError:
                pass
        return False


# ---------------------------------------------------------------------------
# config

def resolve_external_path(base_dir: str, value, what: str) -> str:
    """Resolve a config path: relative to base_dir, absolute or ~/ allowed."""
    if not isinstance(value, str) or not value.strip():
        raise AuditError(f"{what}: expected a non-empty path")
    v = os.path.expanduser(value)
    if not os.path.isabs(v):
        v = os.path.join(base_dir, v)
    return os.path.realpath(v)


def load_audit_config(root: str):
    """Load audit-skills.yaml; returns (normalized config or None, path)."""
    path = os.path.join(root, AUDIT_CONFIG_NAME)
    if not os.path.isfile(path):
        return None, path
    cfg = load_yaml_file(path, AUDIT_CONFIG_NAME)
    restrict_keys(cfg, {"target_root", "scope", "skills"}, AUDIT_CONFIG_NAME)
    target_root = resolve_external_path(root, cfg.get("target_root"),
                                        f"{AUDIT_CONFIG_NAME}: target_root")
    if not os.path.isdir(target_root):
        raise AuditError(
            f"{AUDIT_CONFIG_NAME}: target_root is not an existing directory: {target_root}")
    scope = as_list(cfg.get("scope"), f"{AUDIT_CONFIG_NAME}: scope")
    if not scope:
        raise AuditError(
            f"{AUDIT_CONFIG_NAME}: scope must be a non-empty list of files/directories "
            "inside target_root")
    scope_paths = []
    for i, entry in enumerate(scope):
        p = resolve_external_path(target_root, entry, f"{AUDIT_CONFIG_NAME}: scope[{i}]")
        if not (p == target_root or p.startswith(target_root + os.sep)):
            raise AuditError(
                f"{AUDIT_CONFIG_NAME}: scope[{i}] escapes target_root: {entry!r}")
        if not os.path.exists(p):
            raise AuditError(
                f"{AUDIT_CONFIG_NAME}: scope[{i}] not found under target_root: {entry!r}")
        scope_paths.append(p)
    skills = as_list(cfg.get("skills"), f"{AUDIT_CONFIG_NAME}: skills")
    if not skills:
        raise AuditError(
            f"{AUDIT_CONFIG_NAME}: skills list is empty — configure at least one local "
            "SKILL.md; an empty configured audit must not fall back to report import")
    skill_paths = []
    for i, s in enumerate(skills):
        p = resolve_external_path(root, s, f"{AUDIT_CONFIG_NAME}: skills[{i}]")
        if p in skill_paths:
            raise AuditError(f"{AUDIT_CONFIG_NAME}: duplicate skill path: {s!r}")
        if p in (SELF_SKILL_MD, LIFECYCLE_SKILL_MD):
            raise AuditError(
                f"{AUDIT_CONFIG_NAME}: skills must not include the orchestrator or "
                "finding-lifecycle itself")
        skill_paths.append(p)
    return {"path": os.path.realpath(path), "target_root": target_root,
            "scope": scope_paths, "skills": skill_paths}, path


# ---------------------------------------------------------------------------
# run state

def audits_root(root: str) -> str:
    return os.path.join(root, "audits")


def run_dir(root: str, run_id: str) -> str:
    return os.path.join(audits_root(root), run_id)


def step_dir(root: str, run_id: str, step: int) -> str:
    return os.path.join(run_dir(root, run_id), "steps", str(step))


def list_audit_runs(root: str) -> list:
    d = audits_root(root)
    if not os.path.isdir(d):
        return []
    return sorted(n for n in os.listdir(d)
                  if n.startswith("run-") and os.path.isdir(os.path.join(d, n)))


def load_audit_run(root: str):
    """Load the newest batch's run.yaml; None when no batch exists."""
    runs = list_audit_runs(root)
    if not runs:
        return None
    run_id = runs[-1]
    rel = f"audits/{run_id}/run.yaml"
    data = load_yaml_file(os.path.join(audits_root(root), run_id, "run.yaml"), rel)
    restrict_keys(data, {"run_id", "created_at", "revision", "config", "target",
                         "steps", "history", "finalization"}, rel)
    if data.get("run_id") != run_id:
        raise AuditError(f"{rel}: run_id {data.get('run_id')!r} does not match directory")
    rev = data.get("revision")
    if not isinstance(rev, int) or rev < 1:
        raise AuditError(f"{rel}: revision must be a positive integer")
    if rev != len(data.get("history") or []):
        raise AuditError(
            f"{rel}: consistency conflict: revision {rev} != {len(data.get('history') or [])} "
            "history events; repair before any further mutation")
    steps = as_list(data.get("steps"), f"{rel}: steps")
    for i, st in enumerate(steps):
        st = as_dict(st, f"{rel}: steps[{i}]")
        as_str(st.get("skill"), f"{rel}: steps[{i}].skill")
        check_enum(st.get("status"), STEP_STATUSES, f"{rel}: steps[{i}].status")
        st.setdefault("attempts", [])
    return data


def save_audit_run(root: str, run: dict) -> None:
    atomic_write(os.path.join(run_dir(root, run["run_id"]), "run.yaml"),
                 yaml.safe_dump(run, sort_keys=False, allow_unicode=True, width=120))


# ---------------------------------------------------------------------------
# scope fingerprint and freshness

def audit_scope_files(target_root, scope, root) -> list:
    """Manifest of files covered by the audit; batch artifacts never count."""
    exclude = os.path.realpath(audits_root(root))
    files = []

    def excluded(p):
        rp = os.path.realpath(p)
        return rp == exclude or rp.startswith(exclude + os.sep)

    for entry in scope or []:
        if os.path.isdir(entry):
            for dirpath, dirnames, filenames in os.walk(entry):
                dirnames[:] = sorted(d for d in dirnames if not d.startswith("."))
                for f in sorted(filenames):
                    if f.startswith("."):
                        continue
                    p = os.path.realpath(os.path.join(dirpath, f))
                    if not excluded(p):
                        files.append(p)
        elif os.path.exists(entry) and not excluded(entry):
            files.append(entry)
    return sorted(set(files))


def scope_fingerprint(files) -> str:
    """Deterministic digest over the scope file manifest
    (a list of {path, sha256} records)."""
    stream = ""
    for f in files:
        if isinstance(f, dict):
            stream += f"{f['path']}\0{f.get('sha256') or sha256_file(f['path'])}\n"
        else:
            stream += f"{f}\0{sha256_file(f)}\n"
    return sha256_bytes(stream.encode("utf-8"))


def audit_freshness_issues(root: str, run: dict) -> list:
    """Drift between the batch fingerprint and the current world."""
    issues = []
    cfg = run.get("config") or {}
    cfg_path = cfg.get("path")
    if isinstance(cfg_path, str) and os.path.isfile(cfg_path):
        if sha256_file(cfg_path) != cfg.get("sha256"):
            issues.append(f"audit config changed: {AUDIT_CONFIG_NAME} "
                          "(start a new batch with `prepare --new`)")
    target = run.get("target") or {}
    old = {f.get("path"): f.get("sha256") for f in target.get("files") or []}
    new = {p: sha256_file(p)
           for p in audit_scope_files(target.get("root"), target.get("scope"), root)}
    drifted = sorted(set(old) ^ set(new)) + sorted(
        p for p in set(old) & set(new) if old[p] != new[p])
    for p in drifted:
        issues.append(f"audited target scope drifted: {p}")
    if drifted:
        issues.append("target content/file set changed since prepare; "
                      "a skill must never modify the audited target — investigate, "
                      "restore or accept the new state, then start a new batch "
                      "with `prepare --new`")
    for st in run.get("steps") or []:
        p = st.get("skill")
        expected = st.get("skill_sha256")
        if not os.path.isfile(p):
            if expected:
                issues.append(f"skill entry missing: {p} "
                              "(start a new batch with `prepare --new`)")
        elif expected is None:
            issues.append(f"skill entry now present but never fingerprinted: {p}; "
                          "start a new batch with `prepare --new`")
        elif sha256_file(p) != expected:
            issues.append(f"skill entry changed: {p} "
                          "(start a new batch with `prepare --new`)")
    return issues


# ---------------------------------------------------------------------------
# execution prompt (orchestration overlay; never replaces the skill's SKILL.md)

def skill_name(skill_path: str) -> str:
    try:
        with open(skill_path, encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return os.path.basename(os.path.dirname(skill_path)) or skill_path
    lines = text.splitlines()
    if lines and lines[0].strip() == "---":
        for line in lines[1:]:
            if line.strip() == "---":
                break
            m = re.match(r"^name:\s*(.+?)\s*$", line)
            if m:
                return m.group(1).strip("\"'")
    return os.path.basename(os.path.dirname(skill_path)) or skill_path


def render_execution_prompt(root: str, run: dict, st: dict) -> str:
    cfg = run.get("config") or {}
    target = run.get("target") or {}
    n = st["step"]
    work_rel = f"audits/{run['run_id']}/steps/{n}/work"
    scope_lines = "\n".join(f"  - {p}" for p in target.get("scope") or [])
    rev = run.get("revision", 1)
    return f"""You are executing audit run {run['run_id']}, step {n}.

Audit Skill:
  {st['skill']}

Target:
  {target.get('root')}

Scope:
{scope_lines}

Preferred work directory:
  {os.path.join(root, work_rel)}

Execution requirements:

1. Follow the audit methodology defined by the audit Skill.
2. Do not modify the audited target source.
3. If the audit Skill supports a configurable output/work directory,
   use the preferred work directory above.
4. If the Skill requires its own fixed output directory, do not break
   the Skill merely to force relocation; run it normally and report
   the actual output paths in result.yaml.
5. Produce one primary audit report.
6. Produce an execution log when available.
7. Declare useful supporting artifacts such as:
   structured findings, PoCs, traces, coverage, sub-agent outputs.
8. Write or provide the data required for result.yaml.
9. Do not claim the protocol is safe when zero findings are identified.

Result contract (result.yaml, schema {RESULT_SCHEMA}):

  schema: {RESULT_SCHEMA}
  status: COMPLETED | FAILED | BLOCKED
  note: substantive summary (>= 20 characters: what ran, what was covered, why)
  primary:
    report: <path to the one primary report>   # required for COMPLETED
    log: <path to the execution log>           # recommended
  artifacts:
    - path: <path to a supporting artifact (file or directory)>
      type: {'|'.join(ARTIFACT_TYPES)}
      note: why this artifact matters

The legacy result shape {{status, note, report, log}} remains accepted.
Paths resolve relative to the work root; absolute and ~/ paths allowed.
If you cannot determine the primary report unambiguously, record the
step BLOCKED with a note naming the candidates — never guess.

After execution, record with:
  audit.py record --work-root {root} --step {n} --input <result.yaml> \\
      --expected-revision <rev; currently {rev}>
"""


def write_execution_prompt(root: str, run: dict, st: dict) -> str:
    rel = f"audits/{run['run_id']}/steps/{st['step']}/execution-prompt.md"
    atomic_write(safe_rel(root, rel, "execution prompt"),
                 render_execution_prompt(root, run, st))
    os.makedirs(os.path.join(step_dir(root, run["run_id"], st["step"]), "work"),
                exist_ok=True)
    return rel


def ensure_prompt_for_next_step(root: str, run: dict) -> None:
    for st in run.get("steps") or []:
        if st.get("status") == "COMPLETED":
            continue
        p = os.path.join(step_dir(root, run["run_id"], st["step"]),
                         "execution-prompt.md")
        if not os.path.isfile(p):
            write_execution_prompt(root, run, st)
        break


# ---------------------------------------------------------------------------
# artifacts: hashing, manifests, verification

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


def artifact_slug(name: str) -> str:
    slug = re.sub(r"[^0-9A-Za-z]+", "-", os.path.basename(name)).strip("-").lower()
    return slug or "artifact"


def manifest_artifact_path(step: int, attempt: int, name: str) -> str:
    return f"attempts/{attempt}/artifacts/{name}"


def load_manifest(root: str, run: dict, step: int):
    rel = f"audits/{run['run_id']}/steps/{step}/artifact-manifest.yaml"
    return load_yaml_file(safe_rel(root, rel, "artifact manifest"), rel)


def verify_artifact_manifest(root: str, run: dict, step: int) -> list:
    """Validate one step's canonical artifact manifest against disk."""
    rel = f"audits/{run['run_id']}/steps/{step}/artifact-manifest.yaml"
    issues = []
    try:
        m = load_manifest(root, run, step)
    except AuditError as exc:
        return [f"step {step}: artifact manifest unreadable: {exc}"]
    sdir = step_dir(root, run["run_id"], step)
    if m.get("schema") != ARTIFACTS_SCHEMA:
        issues.append(f"step {step}: artifact manifest schema must be {ARTIFACTS_SCHEMA}")
    if m.get("run_id") != run["run_id"]:
        issues.append(f"step {step}: artifact manifest run_id mismatch")
    if m.get("step") != step:
        issues.append(f"step {step}: artifact manifest step mismatch: {m.get('step')!r}")
    if m.get("status") != "COMPLETED":
        issues.append(f"step {step}: artifact manifest status must be COMPLETED")
    arts = as_list(m.get("artifacts"), f"{rel}: artifacts")
    if not arts:
        issues.append(f"step {step}: artifact manifest lists no artifacts")
    seen_ids = set()
    n_reports = 0
    for i, e in enumerate(arts):
        e = as_dict(e, f"{rel}: artifacts[{i}]")
        aid = e.get("id")
        if aid in seen_ids:
            issues.append(f"step {step}: duplicate artifact id {aid!r}")
        seen_ids.add(aid)
        if e.get("type") not in ARTIFACT_TYPES:
            issues.append(f"step {step}: artifact {aid!r} has unknown type {e.get('type')!r}")
        apath = e.get("path")
        if not isinstance(apath, str) or not apath.strip():
            issues.append(f"step {step}: artifact {aid!r} has no path")
            continue
        if os.path.isabs(apath):
            issues.append(f"step {step}: artifact {aid!r} path must be step-relative, got {apath!r}")
            continue
        full = os.path.realpath(os.path.join(sdir, apath))
        if not full.startswith(os.path.realpath(sdir) + os.sep):
            issues.append(f"step {step}: artifact {aid!r} path escapes the step dir: {apath!r}")
            continue
        if not os.path.exists(full):
            issues.append(f"step {step}: artifact {aid!r} missing: {apath}")
            continue
        if os.path.isdir(full):
            tdigest, count = tree_digest(full)
            if e.get("tree_sha256") != tdigest:
                issues.append(f"step {step}: artifact {aid!r} tree hash mismatch: {apath}")
            if e.get("file_count") != count:
                issues.append(f"step {step}: artifact {aid!r} file_count mismatch: {apath}")
        elif os.path.isfile(full):
            if sha256_file(full) != e.get("sha256"):
                issues.append(f"step {step}: artifact {aid!r} hash mismatch: {apath}")
        else:
            issues.append(f"step {step}: artifact {aid!r} is not a regular file or directory: {apath}")
        if e.get("type") == "report":
            n_reports += 1
    if n_reports < 1:
        issues.append(f"step {step}: artifact manifest must include a report artifact")
    return issues


def legacy_attempt_issues(root: str, run: dict, st: dict, step: int) -> list:
    """Legacy batches (pre-manifest): verify frozen attempt report/log copies."""
    issues = []
    attempts = st.get("attempts") or []
    if not attempts:
        return [f"step {step}: COMPLETED without a recorded attempt"]
    att = attempts[-1]
    spec = att.get("report")
    if not isinstance(spec, dict) or not spec.get("path"):
        return [f"step {step}: completed attempt has no report recorded"]
    for key in ("report", "log"):
        spec = att.get(key)
        if not isinstance(spec, dict) or not spec.get("path"):
            continue
        try:
            p = safe_rel(root, spec["path"], f"step {step} {key}")
        except AuditError as exc:
            issues.append(f"step {step}: {key}: {exc}")
            continue
        if not os.path.isfile(p):
            issues.append(f"step {step}: {key} missing: {spec['path']}")
        elif sha256_file(p) != spec.get("sha256"):
            issues.append(f"step {step}: {key} hash mismatch: {spec['path']}")
    return issues


def synthesize_legacy_manifest(root: str, run: dict, st: dict, step: int) -> None:
    """Expose a legacy completed step's frozen copies as canonical manifest
    entries. Never fabricates missing artifacts: the report must exist; the
    log is included only when frozen."""
    attempts = st.get("attempts") or []
    att = attempts[-1]
    artifacts = []
    spec = att.get("report")
    if isinstance(spec, dict) and spec.get("path"):
        p = safe_rel(root, spec["path"], f"step {step} report")
        artifacts.append({
            "id": "primary-report", "type": "report",
            "path": os.path.relpath(p, step_dir(root, run["run_id"], step)).replace(os.sep, "/"),
            "sha256": spec.get("sha256") or sha256_file(p),
            "origin": "legacy-frozen-copy",
        })
    spec = att.get("log")
    if isinstance(spec, dict) and spec.get("path"):
        p = safe_rel(root, spec["path"], f"step {step} log")
        artifacts.append({
            "id": "execution-log", "type": "log",
            "path": os.path.relpath(p, step_dir(root, run["run_id"], step)).replace(os.sep, "/"),
            "sha256": spec.get("sha256") or sha256_file(p),
            "origin": "legacy-frozen-copy",
        })
    if not artifacts:
        raise AuditError(
            f"step {step}: legacy completed step has no frozen report to expose; "
            "rerun the step in a new batch")
    manifest = {
        "schema": ARTIFACTS_SCHEMA,
        "run_id": run["run_id"], "step": step,
        "attempt": len(attempts), "status": "COMPLETED",
        "skill": {"name": skill_name(st["skill"]), "path": st["skill"],
                  "sha256": st.get("skill_sha256")},
        "target": {"fingerprint_sha256": scope_fingerprint(run.get("target", {}).get("files", []))},
        "artifacts": artifacts,
    }
    rel = f"audits/{run['run_id']}/steps/{step}/artifact-manifest.yaml"
    atomic_write(safe_rel(root, rel, "artifact manifest"),
                 yaml.safe_dump(manifest, sort_keys=False, allow_unicode=True, width=120))


def manifest_path(root: str, run_id: str, step: int) -> str:
    return os.path.join(step_dir(root, run_id, step), "artifact-manifest.yaml")


def audit_artifact_issues(root: str, run: dict) -> list:
    """Frozen per-step artifacts must exist and still hash correctly."""
    issues = []
    for st in run.get("steps") or []:
        n = st.get("step")
        if st.get("status") != "COMPLETED":
            issues.append(f"step {n} is {st.get('status')}")
            continue
        if os.path.isfile(manifest_path(root, run["run_id"], n)):
            issues += verify_artifact_manifest(root, run, n)
        else:
            issues += legacy_attempt_issues(root, run, st, n)
    return issues


def audit_progress(run: dict):
    steps = run.get("steps") or []
    done = [st for st in steps if st.get("status") == "COMPLETED"]
    nxt = next((st for st in steps if st.get("status") != "COMPLETED"), None)
    return len(done), len(steps), nxt


def audit_steps_payload(run: dict) -> list:
    return [{"step": st.get("step"), "skill": st.get("skill"),
             "status": st.get("status"), "attempts": len(st.get("attempts") or [])}
            for st in run.get("steps") or []]


# ---------------------------------------------------------------------------
# result.yaml (skill -> orchestrator interface); v1 + legacy adapter

def load_audit_result(path: str) -> dict:
    doc = load_yaml_file(path, "audit result")
    if "schema" in doc or "primary" in doc or "artifacts" in doc:
        restrict_keys(doc, {"schema", "status", "note", "primary", "artifacts"},
                      "audit result")
        if doc.get("schema") != RESULT_SCHEMA:
            raise AuditError(
                f"audit result: unsupported schema {doc.get('schema')!r}; expected {RESULT_SCHEMA}")
        primary = as_dict(doc.get("primary") or {}, "audit result: primary")
        restrict_keys(primary, {"report", "log"}, "audit result: primary")
        artifacts = []
        for i, e in enumerate(as_list(doc.get("artifacts") or [],
                                      "audit result: artifacts")):
            e = as_dict(e, f"audit result: artifacts[{i}]")
            restrict_keys(e, {"path", "type", "note"}, f"audit result: artifacts[{i}]")
            artifacts.append({
                "path": as_str(e.get("path"), f"audit result: artifacts[{i}].path"),
                "type": check_enum(e.get("type"), ARTIFACT_TYPES,
                                   f"audit result: artifacts[{i}].type"),
                "note": e.get("note") if isinstance(e.get("note"), str) else "",
            })
        normalized = {"schema": RESULT_SCHEMA,
                      "primary": {"report": primary.get("report"),
                                  "log": primary.get("log")},
                      "artifacts": artifacts}
    else:
        restrict_keys(doc, {"status", "note", "report", "log"}, "audit result")
        normalized = {"schema": "legacy",
                      "primary": {"report": doc.get("report"), "log": doc.get("log")},
                      "artifacts": []}
    normalized["status"] = check_enum(doc.get("status"), AUDIT_RESULT_STATUSES,
                                      "audit result: status")
    note = as_str(doc.get("note"), "audit result: note")
    if len(note.strip()) < 20:
        raise AuditError(
            "audit result: note must be substantive (>= 20 characters): what ran, "
            "what was covered, and why it ended in this status")
    normalized["note"] = note
    for key in ("report", "log"):
        v = normalized["primary"][key]
        if v is not None and (not isinstance(v, str) or not v.strip()):
            raise AuditError(f"audit result: primary.{key} must be a path or null")
    return normalized


def resolve_source(root: str, value, what: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AuditError(f"{what}: expected a path")
    expanded = os.path.expanduser(value)
    src = os.path.realpath(expanded if os.path.isabs(expanded)
                           else os.path.join(root, expanded))
    if not os.path.exists(src):
        raise AuditError(f"{what}: file not found: {src}")
    return src


def _symlinks_under(path: str) -> list:
    found = []
    if os.path.islink(path):
        found.append(path)
    if os.path.isdir(path) and not os.path.islink(path):
        for dirpath, dirnames, filenames in os.walk(path):
            for name in dirnames + filenames:
                full = os.path.join(dirpath, name)
                if os.path.islink(full):
                    found.append(full)
    return found


def scan_artifact_secrets(path: str) -> list:
    """Marker-based key-material scan over an artifact file or directory."""
    flagged = []
    files = []
    if os.path.isfile(path):
        files = [path]
    elif os.path.isdir(path):
        for dirpath, _dirnames, filenames in os.walk(path):
            files += [os.path.join(dirpath, f) for f in filenames]
    for p in files:
        try:
            if os.path.getsize(p) > 4 * 1024 * 1024:
                continue
            with open(p, encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except OSError:
            continue
        for pid, pattern in SECRET_PATTERNS:
            if pattern.search(text):
                flagged.append((p, pid))
    return flagged


def validate_declared_sources(root: str, run: dict, result: dict) -> list:
    """Resolve and validate every declared source path before copying."""
    target_root = os.path.realpath((run.get("target") or {}).get("root") or "\0none")
    declared = []
    primary = result["primary"]
    if primary.get("report") is not None:
        declared.append(("primary.report", primary["report"], "report"))
    if primary.get("log") is not None:
        declared.append(("primary.log", primary["log"], "log"))
    for i, e in enumerate(result["artifacts"]):
        declared.append((f"artifacts[{i}].{e['type']}", e["path"], e["type"]))

    resolved = []
    for what, raw, atype in declared:
        src = resolve_source(root, raw, f"audit result: {what}")
        if src == target_root or src.startswith(target_root + os.sep):
            raise AuditError(
                f"audit result: {what} lives inside the audited target tree; "
                "audit artifacts must never be written into the target")
        if what in ("primary.report", "primary.log") and not os.path.isfile(src):
            raise AuditError(f"audit result: {what} must be a regular file")
        links = _symlinks_under(src)
        if links:
            raise AuditError(
                f"audit result: {what} contains symlink(s); symlinks are rejected "
                f"as artifact sources: {links[0]}")
        flagged = scan_artifact_secrets(src)
        if flagged:
            p, pid = flagged[0]
            raise AuditError(
                f"audit result: {what} looks like key/credential material "
                f"({pid} in {os.path.basename(p)}); never copy secrets into audit "
                "evidence — remove the secret and re-record")
        resolved.append((what, src, atype))
    return resolved


def copy_canonical_artifacts(root: str, run: dict, step: int, attempt_no: int,
                             resolved: list) -> list:
    """Copy declared sources into the attempt's canonical artifacts dir.

    Returns manifest artifact entries (path relative to the step dir)."""
    att_dir_rel = f"audits/{run['run_id']}/steps/{step}/attempts/{attempt_no}/artifacts"
    att_dir = safe_rel(root, att_dir_rel, "attempt artifacts dir")
    os.makedirs(att_dir, exist_ok=True)

    used_names = {}
    entries = []

    def dest_name(stem: str, ext: str) -> str:
        name = stem + ext
        n = used_names.get(name, 0) + 1
        used_names[name] = n
        return name if n == 1 else f"{stem}-{n}{ext}"

    for what, src, atype in resolved:
        if what == "primary.report":
            ext = os.path.splitext(src)[1] or ".md"
            name = dest_name("report", ext)
            aid = "primary-report"
        elif what == "primary.log":
            ext = os.path.splitext(src)[1] or ".log"
            name = dest_name("log", ext)
            aid = "execution-log"
        else:
            base = os.path.basename(src.rstrip(os.sep))
            stem, ext = os.path.splitext(base)
            name = dest_name(stem or "artifact", ext)
            aid = None
        dest = os.path.join(att_dir, name)
        if os.path.isdir(src):
            shutil.copytree(src, dest, symlinks=False)
        else:
            shutil.copyfile(src, dest)
        if aid is None:
            aid = f"{atype}-{artifact_slug(name)}"
            k = 2
            while any(e["id"] == aid for e in entries):
                aid = f"{atype}-{artifact_slug(name)}-{k}"
                k += 1
        entry = {"id": aid, "type": atype,
                 "path": manifest_artifact_path(step, attempt_no, name)}
        if os.path.isdir(dest):
            tdigest, count = tree_digest(dest)
            entry["tree_sha256"] = tdigest
            entry["file_count"] = count
        else:
            entry["sha256"] = sha256_file(dest)
        entries.append(entry)
    return entries


# ---------------------------------------------------------------------------
# analysis.md and audit candidates (agent-authored; CLI-validated)

def analysis_issues(root: str, run: dict) -> list:
    rel = f"audits/{run['run_id']}/analysis.md"
    p = os.path.join(run_dir(root, run["run_id"]), "analysis.md")
    if not os.path.isfile(p):
        return [f"aggregated analysis missing: write {rel} first"]
    with open(p, encoding="utf-8") as f:
        text = f.read()
    issues = []
    if len(text.strip()) < ANALYSIS_MIN_CHARS:
        issues.append(f"{rel}: too short to be substantive (< {ANALYSIS_MIN_CHARS} chars)")
    headings = {line.strip() for line in text.splitlines()
                if line.strip().startswith("#")}
    if ANALYSIS_H1 not in headings:
        issues.append(f"{rel}: missing required heading {ANALYSIS_H1!r}")
    for h in ANALYSIS_H2:
        if h not in headings:
            issues.append(f"{rel}: missing required section {h!r}")
    return issues


def candidate_files(root: str, run: dict) -> list:
    d = os.path.join(run_dir(root, run["run_id"]), "candidates")
    if not os.path.isdir(d):
        return []
    return sorted(os.path.join(d, n) for n in os.listdir(d) if n.endswith(".yaml"))


def validate_candidate(root: str, run: dict, path: str) -> dict:
    """Validate one audit candidate; raises AuditError on contract violations."""
    doc = load_yaml_file(path, "audit candidate")
    what = os.path.basename(path)
    restrict_keys(doc, {"schema", "id", "title", "claim", "root_cause", "sources",
                        "preconditions", "affected_code", "disagreements",
                        "coverage_gaps", "severity_hint", "confidence_hint"},
                  f"audit candidate {what}")
    if doc.get("schema") != CANDIDATE_SCHEMA:
        raise AuditError(f"audit candidate {what}: schema must be {CANDIDATE_SCHEMA}")
    cid = as_str(doc.get("id"), f"audit candidate {what}: id")
    if not CANDIDATE_ID_RE.match(cid):
        raise AuditError(f"audit candidate {what}: id must match A-<digits>, got {cid!r}")
    if os.path.basename(path) != f"{cid}.yaml":
        raise AuditError(f"audit candidate {what}: filename must be {cid}.yaml")
    as_str(doc.get("title"), f"audit candidate {cid}: title")
    as_str(doc.get("claim"), f"audit candidate {cid}: claim")
    rc = as_dict(doc.get("root_cause") or {}, f"audit candidate {cid}: root_cause")
    restrict_keys(rc, {"summary", "mechanism"}, f"audit candidate {cid}: root_cause")
    as_str(rc.get("summary"), f"audit candidate {cid}: root_cause.summary")
    as_str(rc.get("mechanism"), f"audit candidate {cid}: root_cause.mechanism")

    steps_by_no = {st.get("step"): st for st in run.get("steps") or []}
    sources = as_list(doc.get("sources"), f"audit candidate {cid}: sources")
    if not sources:
        raise AuditError(f"audit candidate {cid}: sources must not be empty")
    cand_dir = os.path.dirname(os.path.abspath(path))
    for i, s in enumerate(sources):
        s = as_dict(s, f"audit candidate {cid}: sources[{i}]")
        restrict_keys(s, {"step", "skill_name", "original_finding_id",
                          "artifact_manifest", "report", "locations", "note"},
                      f"audit candidate {cid}: sources[{i}]")
        step_no = s.get("step")
        if not isinstance(step_no, int) or step_no not in steps_by_no:
            raise AuditError(
                f"audit candidate {cid}: sources[{i}].step {step_no!r} is not a step of this run")
        am = as_str(s.get("artifact_manifest"),
                    f"audit candidate {cid}: sources[{i}].artifact_manifest")
        if os.path.isabs(am):
            raise AuditError(
                f"audit candidate {cid}: sources[{i}].artifact_manifest must be a "
                "run-relative path to a canonical manifest, not absolute")
        resolved = os.path.realpath(os.path.join(cand_dir, am))
        expected = os.path.realpath(manifest_path(root, run["run_id"], step_no))
        if resolved != expected:
            raise AuditError(
                f"audit candidate {cid}: sources[{i}].artifact_manifest must reference "
                f"the canonical manifest audits/{run['run_id']}/steps/{step_no}/"
                "artifact-manifest.yaml of its own step")
        if not os.path.isfile(resolved):
            raise AuditError(
                f"audit candidate {cid}: sources[{i}].artifact_manifest not found: {am}")
        as_str(s.get("skill_name"), f"audit candidate {cid}: sources[{i}].skill_name")
        report = as_dict(s.get("report") or {}, f"audit candidate {cid}: sources[{i}].report")
        restrict_keys(report, {"artifact_id"},
                      f"audit candidate {cid}: sources[{i}].report")
        rid_art = as_str(report.get("artifact_id"),
                         f"audit candidate {cid}: sources[{i}].report.artifact_id")
        m = load_yaml_file(resolved, "artifact manifest")
        arts = {e.get("id"): e for e in as_list(m.get("artifacts"), "manifest artifacts")}
        if rid_art not in arts:
            raise AuditError(
                f"audit candidate {cid}: sources[{i}].report.artifact_id {rid_art!r} "
                f"not present in step {step_no}'s artifact manifest")
        as_list(s.get("locations") or [], f"audit candidate {cid}: sources[{i}].locations")

    for key in ("preconditions", "affected_code", "disagreements", "coverage_gaps"):
        as_list(doc.get(key) or [], f"audit candidate {cid}: {key}")
    for key in ("severity_hint", "confidence_hint"):
        v = doc.get(key)
        if v is not None and not isinstance(v, str):
            raise AuditError(f"audit candidate {cid}: {key} must be a string or null")
    return doc


def load_candidates(root: str, run: dict, issues: list) -> list:
    out = []
    ids = set()
    for path in candidate_files(root, run):
        try:
            doc = validate_candidate(root, run, path)
        except AuditError as exc:
            issues.append(str(exc))
            continue
        if doc["id"] in ids:
            issues.append(f"duplicate candidate id: {doc['id']}")
        ids.add(doc["id"])
        out.append((path, doc))
    return out


# ---------------------------------------------------------------------------
# handoff

def handoff_manifest_path(root: str, run: dict) -> str:
    return os.path.join(run_dir(root, run["run_id"]), "handoff", "manifest.yaml")


def handoff_issues(root: str, run: dict) -> list:
    """Verify a finalized handoff against disk; empty list = intact."""
    fin = run.get("finalization")
    if not fin:
        return []
    rid = run["run_id"]
    mpath = handoff_manifest_path(root, run)
    if not os.path.isfile(mpath):
        return ["finalized handoff manifest missing: " + mpath]
    issues = []
    if sha256_file(mpath) != fin.get("manifest_sha256"):
        issues.append("handoff manifest changed since finalization")
    m = load_yaml_file(mpath, "handoff manifest")
    if m.get("schema") != HANDOFF_SCHEMA:
        issues.append(f"handoff manifest schema must be {HANDOFF_SCHEMA}")
    if m.get("run_id") != rid:
        issues.append("handoff manifest run_id mismatch")
    if m.get("status") != "FINALIZED":
        issues.append("handoff manifest status must be FINALIZED")
    hdir = os.path.dirname(mpath)
    rdir = run_dir(root, rid)

    def resolve(rel, what):
        if not isinstance(rel, str) or not rel.strip():
            issues.append(f"handoff manifest: {what} missing")
            return None
        p = os.path.realpath(os.path.join(hdir, rel))
        if not (p == rdir or p.startswith(rdir + os.sep)):
            issues.append(f"handoff manifest: {what} escapes the run dir: {rel!r}")
            return None
        return p

    audit_block = as_dict(m.get("audit") or {}, "handoff manifest: audit")
    analysis = as_dict(audit_block.get("analysis") or {}, "handoff manifest: audit.analysis")
    ap = resolve(analysis.get("path"), "audit.analysis.path")
    if ap is not None:
        if not os.path.isfile(ap):
            issues.append("finalized analysis.md missing")
        elif sha256_file(ap) != analysis.get("sha256"):
            issues.append("finalized analysis.md hash mismatch")

    steps = as_list(m.get("steps"), "handoff manifest: steps")
    for i, s in enumerate(steps):
        s = as_dict(s, f"handoff manifest: steps[{i}]")
        am = as_dict(s.get("artifact_manifest") or {},
                     f"handoff manifest: steps[{i}].artifact_manifest")
        p = resolve(am.get("path"), f"steps[{i}].artifact_manifest.path")
        if p is None:
            continue
        if not os.path.isfile(p):
            issues.append(f"step {s.get('step')}: artifact manifest missing: {am.get('path')}")
        elif sha256_file(p) != am.get("sha256"):
            issues.append(f"step {s.get('step')}: artifact manifest hash mismatch")
        else:
            issues += verify_artifact_manifest(root, run, s.get("step"))

    cands = as_list(m.get("candidates"), "handoff manifest: candidates")
    if m.get("candidate_count") != len(cands):
        issues.append("handoff manifest candidate_count != len(candidates)")
    ids = set()
    for i, c in enumerate(cands):
        c = as_dict(c, f"handoff manifest: candidates[{i}]")
        cid = c.get("id")
        if cid in ids:
            issues.append(f"duplicate candidate id in handoff: {cid!r}")
        ids.add(cid)
        p = resolve(c.get("path"), f"candidates[{i}].path")
        if p is None:
            continue
        if not os.path.isfile(p):
            issues.append(f"candidate {cid}: file missing: {c.get('path')}")
        elif sha256_file(p) != c.get("sha256"):
            issues.append(f"candidate {cid}: hash mismatch")
    return issues


# ---------------------------------------------------------------------------
# commands

def require_work_root(a) -> str:
    root = getattr(a, "work_root", None) or getattr(a, "case_root", None)
    if not root or not os.path.isdir(root):
        raise AuditError(f"work root directory not found: {root!r}")
    return os.path.realpath(root)


def add_root_args(sp):
    sp.add_argument("--work-root", required=True, help="audit work root directory")
    sp.add_argument("--case-root", help="deprecated alias for --work-root")


def _merge_root_args(argv):
    """When only the deprecated --case-root alias is present, feed its value
    to --work-root (inserted after the subcommand name for argparse)."""
    has_work = any(a == "--work-root" or a.startswith("--work-root=") for a in argv)
    case_val = None
    for j, a in enumerate(argv):
        if a == "--case-root" and j + 1 < len(argv):
            case_val = argv[j + 1]
        elif a.startswith("--case-root="):
            case_val = a.split("=", 1)[1]
    if case_val is None or has_work:
        return argv, False
    sub = next((a for a in argv if not a.startswith("-")), None)
    if sub is None:
        return argv, False
    i = argv.index(sub)
    return argv[:i + 1] + ["--work-root", case_val] + argv[i + 1:], True


def cmd_prepare(a) -> int:
    root = require_work_root(a)
    cfg, _cfg_path = load_audit_config(root)
    with WorkRootLock(root):
        current = load_audit_run(root)
        if current is not None and not a.new:
            issues = audit_freshness_issues(root, current)
            if issues:
                raise GateFailure("audit:prepare", issues, [
                    "this batch no longer matches the config/target/skills",
                    "start a new batch: `prepare --new` (old batches stay on disk)",
                ])
            ensure_prompt_for_next_step(root, current)
            done, total, nxt = audit_progress(current)
            rdir = run_dir(root, current["run_id"])
            lines = [f"recovered audit batch {current['run_id']} ({done}/{total} completed)"]
            if nxt is not None:
                prompt = os.path.join(step_dir(root, current["run_id"], nxt["step"]),
                                      "execution-prompt.md")
                lines.append(f"  next step {nxt['step']}: {nxt['skill']} ({nxt['status']})")
                lines.append(f"  execution prompt: {prompt}")
                lines.append(f"  preferred work dir: {os.path.join(rdir, 'steps', str(nxt['step']), 'work')}")
                lines.append("  after executing that skill: `record --step "
                             f"{nxt['step']} --input result.yaml --expected-revision "
                             f"{current['revision']}`")
            else:
                lines.append("  all steps completed; run `check`, author analysis.md + "
                             "candidates/, then `finalize`")
            emit({"lines": lines, "run_id": current["run_id"], "recovered": True,
                  "revision": current["revision"],
                  "steps": audit_steps_payload(current)}, a.json)
            return EXIT_OK

        if cfg is None:
            raise AuditError(
                f"no {AUDIT_CONFIG_NAME} found in the work root; the orchestrator "
                f"needs one (template: templates/{AUDIT_CONFIG_NAME})")
        run_id = None
        for _ in range(5):
            candidate = ("run-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
                         + "-" + uuid.uuid4().hex[:4])
            if not os.path.exists(os.path.join(audits_root(root), candidate)):
                run_id = candidate
                break
        if run_id is None:  # pragma: no cover — timestamp+uuid collision storm
            raise AuditError("could not allocate a unique audit run id; retry")
        os.makedirs(os.path.join(audits_root(root), run_id, "steps"), exist_ok=True)
        files = [{"path": p, "sha256": sha256_file(p)}
                 for p in audit_scope_files(cfg["target_root"], cfg["scope"], root)]
        steps = []
        for i, sp in enumerate(cfg["skills"], start=1):
            os.makedirs(os.path.join(audits_root(root), run_id, "steps", str(i)),
                        exist_ok=True)
            st = {"step": i, "skill": sp, "skill_sha256": None,
                  "status": "PENDING", "attempts": []}
            if os.path.isfile(sp):
                st["skill_sha256"] = sha256_file(sp)
            else:
                st["status"] = "BLOCKED"
                st["attempts"].append({
                    "at": now_iso(), "status": "BLOCKED",
                    "note": f"skill entry file not found: {sp}",
                    "report": None, "log": None})
            steps.append(st)
        run = {
            "run_id": run_id,
            "created_at": now_iso(),
            "revision": 1,
            "config": {"path": cfg["path"], "sha256": sha256_file(cfg["path"]),
                       "target_root": cfg["target_root"], "scope": cfg["scope"],
                       "skills": cfg["skills"]},
            "target": {"root": cfg["target_root"], "scope": cfg["scope"], "files": files},
            "steps": steps,
            "history": [{"at": now_iso(), "event": "created",
                         "detail": {"skills": len(steps), "scope_files": len(files)}}],
        }
        for st in steps:
            write_execution_prompt(root, run, st)
            step_meta = {
                "step": st["step"], "skill": st["skill"],
                "skill_sha256": st["skill_sha256"],
                "work_dir": f"audits/{run_id}/steps/{st['step']}/work",
                "execution_prompt": f"audits/{run_id}/steps/{st['step']}/execution-prompt.md",
            }
            atomic_write(os.path.join(step_dir(root, run_id, st["step"]), "step.yaml"),
                         yaml.safe_dump(step_meta, sort_keys=False, width=120))
        save_audit_run(root, run)
    blocked = [st["step"] for st in steps if st["status"] == "BLOCKED"]
    lines = [f"audit batch {run_id} created: {len(steps)} skill(s), "
             f"{len(files)} scope file(s) hashed"]
    for st in steps:
        lines.append(f"  step {st['step']}: {st['status']} — {st['skill']}")
    lines.append(f"  execution prompts: {os.path.join(audits_root(root), run_id, 'steps', '<N>', 'execution-prompt.md')}")
    lines.append("next: read step 1's execution-prompt.md AND its SKILL.md, execute the "
                 "audit against the scope, write result.yaml, then `record` it")
    if blocked:
        lines.append(f"NOTE: step(s) {blocked} are BLOCKED (missing SKILL.md); the batch "
                     "cannot pass `check` until they are fixed via a new batch")
    emit({"lines": lines, "run_id": run_id, "steps": audit_steps_payload(run),
          "scope_files": [f["path"] for f in files]}, a.json)
    return EXIT_OK


def cmd_record(a) -> int:
    root = require_work_root(a)
    with WorkRootLock(root):
        run = load_audit_run(root)
        if run is None:
            raise AuditError("no audit batch under audits/; run `prepare` first")
        if run.get("finalization"):
            raise AuditError(
                "this batch is finalized; finalized runs are immutable — start a "
                "new batch with `prepare --new`")
        if not isinstance(a.expected_revision, int) or a.expected_revision != run["revision"]:
            raise AuditError(
                f"revision conflict: expected {a.expected_revision}, run.yaml is at "
                f"{run['revision']}; re-read the batch and retry with the current revision")
        issues = audit_freshness_issues(root, run)
        if issues:
            raise GateFailure("audit:record", issues, [
                "this batch no longer matches the config/target/skills",
                "start a new batch: `prepare --new`",
            ])
        steps = as_list(run["steps"], "run.yaml: steps")
        if not (1 <= a.step <= len(steps)):
            raise AuditError(f"--step out of range (1..{len(steps)})")
        st = steps[a.step - 1]
        if st["status"] == "COMPLETED":
            raise AuditError(
                f"step {a.step} is already COMPLETED; completed steps are not re-executed "
                "(reruns happen in a new batch)")
        prior = steps[:a.step - 1]
        if not st.get("attempts"):
            skipped = [p["step"] for p in prior if not p.get("attempts")]
            if skipped:
                raise AuditError(
                    f"cannot record step {a.step}: earlier step(s) {skipped} have no "
                    "execution result yet; record them first (out-of-order recording "
                    "is rejected)")
        else:
            unresolved = [p["step"] for p in prior if p.get("status") != "COMPLETED"]
            if unresolved:
                raise AuditError(
                    f"cannot retry step {a.step} yet: earlier step(s) {unresolved} are not "
                    "COMPLETED; rerun failed/blocked items in their original order")

        result = load_audit_result(a.input)
        status = result["status"]
        if status == "COMPLETED":
            if not st.get("skill_sha256"):
                raise AuditError(
                    f"step {a.step}: cannot record COMPLETED — its skill entry was not "
                    "readable at prepare time; fix the skill path and start a new batch")
            if not result["primary"]["report"]:
                raise AuditError(
                    "audit result: primary.report is required for COMPLETED (zero "
                    "findings still need the real report and coverage note)")

        # validate declared sources before touching canonical storage
        resolved = validate_declared_sources(root, run, result)

        seq = len(st.get("attempts") or []) + 1
        entries = copy_canonical_artifacts(root, run, a.step, seq, resolved)

        attempt = {"at": now_iso(), "status": status, "note": result["note"],
                   "result_schema": result["schema"],
                   "report": None, "log": None}
        by_role = {}
        for e in entries:
            by_role[e["id"]] = e
        for role, key in (("primary-report", "report"), ("execution-log", "log")):
            e = by_role.get(role)
            if e:
                step_rel = f"audits/{run['run_id']}/steps/{a.step}"
                full = safe_rel(root, os.path.join(step_rel, e["path"]), "step artifact")
                attempt[key] = {"path": os.path.join(step_rel, e["path"]),
                                "sha256": e.get("sha256")}
        attempt["artifacts"] = [{"id": e["id"], "type": e["type"], "path": e["path"]}
                                for e in entries]

        # archive the result declaration itself (per attempt + current pointer)
        sdir = step_dir(root, run["run_id"], a.step)
        with open(a.input, encoding="utf-8") as f:
            result_text = f.read()
        atomic_write(os.path.join(sdir, "attempts", str(seq), "result.yaml"), result_text)
        atomic_write(os.path.join(sdir, "result.yaml"), result_text)

        if status == "COMPLETED":
            manifest = {
                "schema": ARTIFACTS_SCHEMA,
                "run_id": run["run_id"], "step": a.step, "attempt": seq,
                "status": "COMPLETED",
                "skill": {"name": skill_name(st["skill"]), "path": st["skill"],
                          "sha256": st["skill_sha256"]},
                "target": {"fingerprint_sha256": scope_fingerprint(run["target"]["files"])},
                "artifacts": entries,
            }
            atomic_write(manifest_path(root, run["run_id"], a.step),
                         yaml.safe_dump(manifest, sort_keys=False, allow_unicode=True,
                                        width=120))

        st["attempts"].append(attempt)
        st["status"] = status
        run["history"].append({"at": now_iso(), "event": "recorded",
                               "detail": {"step": a.step, "status": status,
                                          "attempt": seq,
                                          "artifacts": len(entries)}})
        run["revision"] += 1
        save_audit_run(root, run)
        ensure_prompt_for_next_step(root, run)

    done, total, nxt = audit_progress(run)
    lines = [f"recorded step {a.step} as {status} (attempt {seq}; revision {run['revision']}); "
             f"batch {run['run_id']}: {done}/{total} completed",
             f"  canonical artifacts: audits/{run['run_id']}/steps/{a.step}/attempts/{seq}/artifacts/"]
    if nxt is not None:
        lines.append(f"next: step {nxt['step']} — {nxt['skill']}")
        lines.append(f"  execution prompt: audits/{run['run_id']}/steps/{nxt['step']}/execution-prompt.md")
    elif done == total:
        lines.append("all steps completed; next: `check` -> author analysis.md + "
                     "candidates/ -> `finalize`")
    else:
        lines.append("every step has a first result; FAILED/BLOCKED steps must be "
                     "resolved (original order) before `check` passes")
    emit({"lines": lines, "run_id": run["run_id"], "step": a.step, "status": status,
          "revision": run["revision"], "attempt": seq,
          "artifacts": [{"id": e["id"], "type": e["type"]} for e in entries]}, a.json)
    return EXIT_OK


def cmd_check(a) -> int:
    root = require_work_root(a)
    run = load_audit_run(root)
    if run is None:
        if os.path.isfile(os.path.join(root, AUDIT_CONFIG_NAME)):
            raise GateFailure("audit:check",
                              [f"{AUDIT_CONFIG_NAME} exists but no batch was prepared"],
                              ["run: prepare"])
        raise GateFailure("audit:check",
                          ["no audit batch and no audit config in this work root"],
                          [f"configure {AUDIT_CONFIG_NAME} for the sequential audit entry"])
    issues = audit_freshness_issues(root, run) + audit_artifact_issues(root, run)
    if run.get("finalization"):
        issues += handoff_issues(root, run)
    if issues:
        raise GateFailure("audit:check", issues, [
            "finish every step (FAILED/BLOCKED items may be rerun in original order "
            "after the first pass)",
            "if the config, target or skill entries changed: `prepare --new`",
        ])
    done, total, _ = audit_progress(run)
    if run.get("finalization"):
        lines = [f"audit batch {run['run_id']}: {done}/{total} steps completed — PASS "
                 "(finalized handoff intact)",
                 f"finalized handoff: {handoff_manifest_path(root, run)}"]
    else:
        lines = [f"audit batch {run['run_id']}: {done}/{total} steps completed — PASS",
                 f"next: aggregate — read every step report via "
                 f"audits/{run['run_id']}/steps/*/artifact-manifest.yaml, write "
                 f"audits/{run['run_id']}/analysis.md (required sections; merge "
                 "duplicates by root cause), author candidates/A-001.yaml…, then "
                 "`finalize`"]
    emit({"lines": lines, "run_id": run["run_id"], "status": "PASS",
          "finalized": bool(run.get("finalization")),
          "steps": audit_steps_payload(run)}, a.json)
    return EXIT_OK


def cmd_finalize(a) -> int:
    root = require_work_root(a)
    with WorkRootLock(root):
        run = load_audit_run(root)
        if run is None:
            raise GateFailure("audit:finalize",
                              ["no audit batch under audits/; run `prepare` first"])
        rid = run["run_id"]

        if run.get("finalization"):
            issues = audit_freshness_issues(root, run) + handoff_issues(root, run)
            if issues:
                raise GateFailure("audit:finalize", issues, [
                    "a finalized batch and its bound inputs are immutable; investigate "
                    "the drift, then start a new batch with `prepare --new`",
                ])
            emit({"lines": [f"audit batch {rid} is already finalized; handoff verified intact",
                            f"aggregated report: {os.path.join(run_dir(root, rid), 'analysis.md')}",
                            f"finalized handoff: {handoff_manifest_path(root, run)}",
                            "You can stop here or import the handoff into finding-lifecycle."],
                  "run_id": rid, "status": "FINALIZED", "idempotent": True}, a.json)
            return EXIT_OK

        if not isinstance(a.expected_revision, int) or a.expected_revision != run["revision"]:
            raise AuditError(
                f"revision conflict: expected {a.expected_revision}, run.yaml is at "
                f"{run['revision']}; re-read the batch and retry with the current revision")

        issues = audit_freshness_issues(root, run)
        for st in run.get("steps") or []:
            if st.get("status") != "COMPLETED":
                issues.append(f"step {st.get('step')} is {st.get('status')}")
        if issues:
            raise GateFailure("audit:finalize", issues, [
                "finalize requires a fresh batch with every step COMPLETED",
                "if the config, target or skill entries changed: `prepare --new`",
            ])

        # migration adapter: expose legacy frozen copies as canonical manifests
        for st in run.get("steps") or []:
            n = st["step"]
            if not os.path.isfile(manifest_path(root, rid, n)):
                try:
                    synthesize_legacy_manifest(root, run, st, n)
                except AuditError as exc:
                    issues.append(str(exc))
        issues += audit_artifact_issues(root, run)
        if issues:
            raise GateFailure("audit:finalize", issues, [
                "canonical artifact manifests must be valid before finalization"])

        agg_issues = analysis_issues(root, run)
        candidates = load_candidates(root, run, agg_issues)
        if agg_issues:
            raise GateFailure("audit:aggregate", agg_issues, [
                f"author audits/{rid}/analysis.md with all required sections "
                "(see references/workflow.md §AGGREGATE)",
                "zero findings is valid — record the conclusion in the Zero-Finding "
                "Statement and author no candidates",
            ])

        handoff_dir = os.path.join(run_dir(root, rid), "handoff")
        cand_dir = os.path.join(handoff_dir, "candidates")
        os.makedirs(cand_dir, exist_ok=True)
        cand_entries = []
        for path, doc in candidates:
            shutil.copyfile(path, os.path.join(cand_dir, f"{doc['id']}.yaml"))
            cand_entries.append({"id": doc["id"], "path": f"candidates/{doc['id']}.yaml",
                                 "sha256": sha256_file(os.path.join(cand_dir, f"{doc['id']}.yaml"))})

        analysis_path = os.path.join(run_dir(root, rid), "analysis.md")
        steps_entries = []
        for st in run.get("steps") or []:
            mp = manifest_path(root, rid, st["step"])
            steps_entries.append({
                "step": st["step"],
                "skill_name": skill_name(st["skill"]),
                "skill_sha256": st.get("skill_sha256"),
                "artifact_manifest": {
                    "path": f"../steps/{st['step']}/artifact-manifest.yaml",
                    "sha256": sha256_file(mp),
                },
            })
        manifest = {
            "schema": HANDOFF_SCHEMA,
            "run_id": rid,
            "status": "FINALIZED",
            "created_at": now_iso(),
            "target": {
                "scope": (run.get("target") or {}).get("scope") or [],
                "fingerprint_sha256": scope_fingerprint((run.get("target") or {}).get("files", [])),
            },
            "audit": {
                "config_sha256": (run.get("config") or {}).get("sha256"),
                "analysis": {"path": "../analysis.md", "sha256": sha256_file(analysis_path)},
            },
            "steps": steps_entries,
            "candidates": cand_entries,
            "candidate_count": len(cand_entries),
        }
        mpath = handoff_manifest_path(root, run)
        atomic_write(mpath, yaml.safe_dump(manifest, sort_keys=False, allow_unicode=True,
                                           width=120))

        run["finalization"] = {
            "at": now_iso(),
            "manifest_sha256": sha256_file(mpath),
            "analysis_sha256": sha256_file(analysis_path),
            "candidate_count": len(cand_entries),
        }
        run["history"].append({"at": now_iso(), "event": "finalized",
                               "detail": {"manifest": "handoff/manifest.yaml",
                                          "candidates": len(cand_entries)}})
        run["revision"] += 1
        save_audit_run(root, run)

    lines = ["Audit complete.",
             f"Aggregated report: {os.path.join(run_dir(root, rid), 'analysis.md')}",
             f"Finalized handoff: {handoff_manifest_path(root, run)}",
             "You can stop here or import the handoff into finding-lifecycle:"]
    if cand_entries:
        for c in cand_entries:
            lines.append(f"  candidate {c['id']}")
        lines.append("  lifecycle.py import-audit --case-root <dir> "
                     f"--handoff {handoff_manifest_path(root, run)}")
    else:
        lines.append("  zero candidates — record the conclusion and stop, or import "
                     "for provenance")
    emit({"lines": lines, "run_id": rid, "status": "FINALIZED",
          "revision": run["revision"],
          "handoff": handoff_manifest_path(root, run),
          "analysis": os.path.join(run_dir(root, rid), "analysis.md"),
          "candidates": [c["id"] for c in cand_entries]}, a.json)
    return EXIT_OK


# ---------------------------------------------------------------------------
# plumbing

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="audit.py",
        description="audit orchestrator CLI (no --force; gates cannot be skipped)")
    sub = p.add_subparsers(dest="command", required=True, metavar="command")

    sp = sub.add_parser("prepare", help="create or recover the current audit batch")
    add_root_args(sp)
    sp.add_argument("--new", action="store_true",
                    help="start a new batch, keeping old batches on disk")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_prepare)

    sp = sub.add_parser("record", help="record one skill execution result")
    add_root_args(sp)
    sp.add_argument("--step", type=int, required=True)
    sp.add_argument("--input", required=True,
                    help="result.yaml (v1 schema or legacy {status, note, report, log})")
    sp.add_argument("--expected-revision", type=int, required=True)
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_record)

    sp = sub.add_parser("check",
                        help="verify the current audit batch is complete and fresh")
    add_root_args(sp)
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_check)

    sp = sub.add_parser("finalize",
                        help="validate aggregation and emit the versioned handoff")
    add_root_args(sp)
    sp.add_argument("--expected-revision", type=int, required=True)
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_finalize)

    return p


def main(argv=None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    argv, used_alias = _merge_root_args(raw)
    if used_alias:
        print("NOTE: --case-root is a deprecated alias; use --work-root", file=sys.stderr)
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except GateFailure as gf:
        if not getattr(args, "json", False):
            print(f"gate {gf.gate_id}: FAIL", file=sys.stderr)
            for issue in gf.issues:
                if isinstance(issue, dict):
                    print(f"  [{issue['category']}] {issue['detail']}", file=sys.stderr)
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
    except AuditError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except BrokenPipeError:
        return EXIT_ERROR
    except Exception as exc:  # unexpected runtime failure -> defined exit code
        print(f"internal error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
