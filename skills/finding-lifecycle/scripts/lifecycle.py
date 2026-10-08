#!/usr/bin/env python3
"""finding-lifecycle CLI.

Post-audit lifecycle for smart-contract vulnerability findings: a
Markdown ledger per finding is the single source of truth; this tool only
performs validated, locked, atomic, revision-checked transitions.

This skill never executes audit skills. Findings enter through:
  0A. `import-audit` — a finalized audit-orchestrator handoff bundle
  0B. `ingest`       — name-based discovery of arbitrary audit artifacts
  0C. `register`     — a manually authored finding-source.yaml

Design contracts (see references/contracts.md):
  - exit codes: 0 success, 1 gate not passed, 2 input or runtime error
  - there is no --force; evidence gates cannot be skipped
  - hash validity only proves artifacts are unchanged; every gate also
    requires a substantive review record (reviewer + reason citing artifacts)
  - the mechanism guards against operational mistakes, not against a
    deliberate writer with file access
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
import zipfile
from datetime import date, datetime, timezone

try:
    import yaml
except ImportError:  # pragma: no cover
    print("lifecycle.py requires PyYAML", file=sys.stderr)
    sys.exit(2)

# ---------------------------------------------------------------------------
# constants

STAGES = [
    "DISCOVERED",
    "PRIOR_ART_CHECKED",
    "CROSS_CHECKED",
    "FORK_PROVEN",
    "TRIAGED",
    "PACKAGED",
    "SELF_REVIEWED",
    "SUBMITTED",
]
DISPOSITIONS = [
    "OPEN",
    "MERGED",
    "INELIGIBLE",
    "REFUTED",
    "ACCEPTED",
    "REJECTED",
    "WITHDRAWN",
]
APPEAL_STATES = ["NONE", "DRAFTED", "SENT", "RESOLVED"]

EXIT_OK, EXIT_GATE, EXIT_ERROR = 0, 1, 2

FID_RE = re.compile(r"^F-[0-9a-f]{32}$")
HEX64_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
DIGEST_RE = re.compile(r"^(0x)?[0-9a-fA-F]{64}$")
ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

ALLOWED_FM_KEYS = {
    "id", "title", "program_id", "created_at", "updated_at",
    "stage", "disposition", "revision",
    "sources", "targets", "root_cause", "duplicate_of", "refutation",
    "severity", "program_snapshot", "prior_art",
    "evidence", "gates", "blockers", "corrections",
    "submission", "appeal", "history",
}

DEFAULT_INPUTS = {
    "PRIOR_ART_CHECKED": "evidence/{fid}/prior-art.yaml",
    "CROSS_CHECKED": "evidence/{fid}/cross-check.yaml",
    "FORK_PROVEN": "evidence/{fid}/fork-proof.yaml",
    "TRIAGED": "evidence/{fid}/triage.yaml",
    "PACKAGED": "packages/{fid}/manifest.yaml",
    "SELF_REVIEWED": "evidence/{fid}/self-review.yaml",
    "SUBMITTED": "lifecycle.py record submission --input evidence/{fid}/submission.yaml",
}

STAGE_HINTS = {
    "PRIOR_ART_CHECKED": [
        "collect audit-report links from the project's official docs site and the bounty platform program page",
        "download every report into evidence/{fid}/prior-art/ and record its hash",
        "search each report for the root cause (function names, mechanism keywords); record a result per report",
        "write evidence/{fid}/prior-art.yaml",
    ],
    "CROSS_CHECKED": [
        "enumerate affected deployment variants; verify source/proxy/runtime bytecode mapping",
        "attempt to refute the claim on each variant; separate victim damage from attacker profit",
        "write evidence/{fid}/cross-check.yaml and evidence/{fid}/assessment.md",
    ],
    "FORK_PROVEN": [
        "pin the fork (chain id, block number, block hash, code hashes, tool versions)",
        "reproduce the attack end-to-end on real addresses; save test + run log",
        "quantify PnL separately for attacker profit and victim damage; keep unknown costs unknown",
        "write evidence/{fid}/fork-proof.yaml",
    ],
    "TRIAGED": [
        "set final severity against a severity_matrix entry; cite evidence paths",
        "settle every eligibility item to PASS or NOT_APPLICABLE (UNKNOWN blocks; FAIL -> close INELIGIBLE)",
        "record novelty search results and freeze the rules snapshot hash",
        "write evidence/{fid}/triage.yaml",
    ],
    "PACKAGED": [
        "write one English report per root cause; assemble the self-contained PoC package",
        "run the package in a clean directory; save the log containing RESULT: PASS",
        "run the secrets scan; pin dependencies; write packages/{fid}/manifest.yaml",
        "if program.yaml delivery.platform names a material platform "
        "(immunefi, hackenproof, code4rena, codehawks, sherlock, cantina): "
        "write packages/{fid}/<platform>/ form-field files "
        "(templates/<platform>/; formats and PoC bars in "
        "references/platform-standards.md) and declare them in the "
        "manifest materials block",
    ],
    "SELF_REVIEWED": [
        "run independent review rounds until one raises zero required changes (workflow section 6)",
        "each later round starts by landing-verifying the previous round's fixes, then lifecycle.py lint",
        "write evidence/{fid}/self-review.yaml (rounds[] plus final checks) bound to the final package hash",
    ],
    "SUBMITTED": [
        "re-check rules and channel privacy; verify account limits and KYC status",
        "assemble the submission dir (lifecycle.py export --id … in priority order) and paste "
        "the form-field materials through the private channel; keep the receipt",
        "lifecycle.py record submission --input evidence/{fid}/submission.yaml",
    ],
}

SECRET_PATTERNS = [
    ("privkey_hex", re.compile(r"0x[0-9a-fA-F]{64}")),
    ("private_key_marker", re.compile(r"(?i)private[_ \-]?key")),
    ("pem_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("mnemonic_marker", re.compile(r"(?i)(seed|mnemonic)[ _]phrase")),
]

# Submission platforms with a fixed form-field material format. When
# program.yaml `delivery.platform` names one of these, the PACKAGED gate
# requires the per-finding form-field files and `export` assembles them.
# Each spec maps materials.fields[].field -> canonical path relative to
# packages/<id>/<platform>/, plus the mechanical content anchors (required
# section headers; `upload_line` = must carry an "Upload: <file>" line naming
# the attached bundle). `zip_name` is the exported attachment filename
# ("{slug}" expands to materials.slug). Optional spec keys:
# `severity_levels` — the platform's individual-submission severity levels;
# `export` refuses severities outside this set (consolidated-report levels
# like CodeHawks Low or C4 QA/Gas are assembled outside export).
# `permalink_fields` — field names where every github.com URL must be a
# commit-pinned permalink (github.com/<org>/<repo>/(blob|tree)/<40hex>/…),
# the contest-judging requirement that code references cannot be altered.
MATERIAL_SPECS = {
    # Immunefi three-file format (Aera/DAWN layout): one txt per web-form
    # field, pasted manually.
    "immunefi": {
        "zip_name": "package.zip",
        "fields": {
            "title": {"path": "1-title.txt"},
            "description": {"path": "2-description.txt", "headers": [
                "## Brief/Intro", "## Vulnerability Details",
                "## Impact Details", "## References"]},
            "poc": {"path": "3-poc.txt", "headers": [
                "### Threat modeled", "### Reproduce",
                "### Expected output", "### What the test proves"]},
        },
    },
    # HackenProof submission layout: four web-form fields under fields/ plus
    # the standalone full write-up; the supporting-files field names the
    # uploaded bundle zip.
    "hackenproof": {
        "zip_name": "{slug}-poc-bundle.zip",
        "fields": {
            "title": {"path": "fields/1-title.txt"},
            "vulnerability_details": {"path": "fields/2-vulnerability-details.md", "headers": [
                "**Severity.**", "## Root cause", "## Precondition",
                "## PoC", "## Impact", "## Fix"]},
            "validation_steps": {"path": "fields/3-validation-steps.md", "headers": [
                "## How to run", "## Expected output",
                "## What each test proves"]},
            "supporting_files": {"path": "fields/4-supporting-files.txt",
                                 "upload_line": True},
            "submission": {"path": "submission.md", "headers": ["## Reproduction"]},
        },
    },
    # Code4rena contest submission: the website form takes one markdown body
    # per High/Medium finding; a runnable coded PoC is required by default.
    # QA and Gas findings are consolidated into one report per warden and
    # are assembled outside export (references/platform-standards.md).
    "code4rena": {
        "zip_name": "{slug}-poc.zip",
        "severity_levels": {"high", "medium"},
        "fields": {
            "title": {"path": "1-title.txt"},
            "details": {"path": "2-finding.md", "headers": [
                "## Impact", "## Proof of Concept",
                "## Recommended Mitigation Steps"]},
        },
    },
    # CodeHawks (Cyfrin) contest submission: web form, markdown template
    # verbatim from their "How to Write and Submit a Finding" docs; Medium/
    # High are individual reports, Low findings are consolidated separately.
    "codehawks": {
        "zip_name": "{slug}-poc.zip",
        "severity_levels": {"high", "medium"},
        "fields": {
            "title": {"path": "1-title.txt"},
            "details": {"path": "2-finding.md", "headers": [
                "## Summary", "## Vulnerability Details", "## Impact",
                "## Tools Used", "## Recommended Mitigation"]},
        },
    },
    # Sherlock contest submission: one GitHub Issue per finding in the
    # private contest repo. The house headers below guarantee the judging
    # inputs (issue, impact, attack path, PoC); the actual Audit Item issue
    # template of the live contest wins if it differs. Code references must
    # be commit-pinned permalinks — judges explicitly guard against
    # branch-link source swapping.
    "sherlock": {
        "zip_name": "{slug}-poc.zip",
        "severity_levels": {"high", "medium"},
        "permalink_fields": {"issue_body"},
        "fields": {
            "title": {"path": "1-title.txt"},
            "issue_body": {"path": "2-issue-body.md", "headers": [
                "## Issue", "## Impact", "## Attack path", "## PoC"]},
        },
    },
    # Cantina competition submission: web form with Title + Description
    # (cause, effects, PoC/supporting material); High/Medium submissions
    # require a coded PoC that compiles and demonstrates the impact.
    "cantina": {
        "zip_name": "{slug}-poc.zip",
        "severity_levels": {"critical", "high", "medium", "low"},
        "fields": {
            "title": {"path": "1-title.txt"},
            "description": {"path": "2-description.md", "headers": [
                "## Root cause", "## PoC", "## Impact"]},
        },
    },
}
MATERIAL_PLATFORMS = set(MATERIAL_SPECS)

# Per-platform field map for the export README index.
EXPORT_README_FIELDS = {
    "immunefi": [
        "- `1-title.txt` — paste into the Title field",
        "- `2-description.txt` — paste into the Details field "
        "(`## Brief/Intro`, `## Vulnerability Details`, `## Impact Details`, `## References`)",
        "- `3-poc.txt` — paste into the PoC field "
        "(`### Threat modeled`, `### Reproduce`, `### Expected output`, `### What the test proves`)",
        "- `package.zip` — the private attachment (hash recorded per package below)",
    ],
    "hackenproof": [
        "- `fields/1-title.txt` — paste into the Title field (one impact-first line)",
        "- `fields/2-vulnerability-details.md` — paste into the Vulnerability details field "
        "(`**Severity.**` lead, then `## Root cause`, `## Precondition`, `## PoC`, "
        "`## Impact`, `## Fix`)",
        "- `fields/3-validation-steps.md` — paste into the Validation steps field "
        "(`## How to run`, `## Expected output`, `## What each test proves`)",
        "- `fields/4-supporting-files.txt` — paste into the Supporting files field "
        "(its `Upload:` line names the bundle below)",
        "- `submission.md` — the full standalone write-up (the details field plus "
        "`## Reproduction`)",
        "- `<slug>-poc-bundle.zip` — the uploaded bundle (self-contained Foundry PoC "
        "project; hash recorded per package below)",
    ],
    "code4rena": [
        "- `1-title.txt` — paste into the Title field (one impact-first line)",
        "- `2-finding.md` — paste into the finding Details body "
        "(`## Impact`, `## Proof of Concept`, `## Recommended Mitigation Steps`); "
        "High/Medium needs the coded PoC inside the Proof of Concept section",
        "- `<slug>-poc.zip` — the PoC bundle when the form accepts an attachment; "
        "otherwise embed/link it per the contest rules (hash recorded per package below)",
    ],
    "codehawks": [
        "- `1-title.txt` — paste into the Title field (one impact-first line)",
        "- `2-finding.md` — paste into the Report body "
        "(`## Summary`, `## Vulnerability Details`, `## Impact`, `## Tools Used`, "
        "`## Recommended Mitigation`); Medium/High are individual submissions",
        "- `<slug>-poc.zip` — the PoC bundle (hash recorded per package below)",
    ],
    "sherlock": [
        "- `1-title.txt` — the GitHub Issue title; label the issue Medium or High",
        "- `2-issue-body.md` — the Audit Item issue body "
        "(`## Issue`, `## Impact`, `## Attack path`, `## PoC`); every github.com "
        "code reference must be a commit-pinned permalink",
        "- `<slug>-poc.zip` — the PoC bundle referenced from the body (inline PoC "
        "code in the issue is also acceptable; hash recorded per package below)",
    ],
    "cantina": [
        "- `1-title.txt` — paste into the Title field (one impact-first line)",
        "- `2-description.md` — paste into the Description field "
        "(`## Root cause`, `## PoC`, `## Impact`); select the matching Severity "
        "in the form — High/Medium require the coded PoC to compile and show impact",
        "- `<slug>-poc.zip` — the PoC bundle (hash recorded per package below)",
    ],
}
UPLOAD_LINE_RE = re.compile(r"(?m)^Upload: \S")
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,39}[a-z0-9]$")
GITHUB_URL_RE = re.compile(r"(?i)https?://(?:www\.)?github\.com/[^\s<>\"']+")
# A commit-pinned permalink: github.com/<org>/<repo>/(blob|tree)/<7-40 hex>/…
GITHUB_PERMALINK_RE = re.compile(
    r"(?i)^https?://(?:www\.)?github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/"
    r"(?:blob|tree)/[0-9a-f]{7,40}/[^\s]+$")


# ---------------------------------------------------------------------------
# errors and small utilities

class LifecycleError(Exception):
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


def field_hash(value) -> str:
    canonical = json.dumps(value, sort_keys=True, ensure_ascii=True, default=str)
    return sha256_bytes(canonical.encode("utf-8"))


def atomic_write(path: str, data: str) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=parent, prefix=".tmp-", suffix=".lifecycle")
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
    """Resolve a case-root-relative path, rejecting escapes."""
    if not isinstance(rel, str) or not rel.strip():
        raise LifecycleError(f"{what}: empty path")
    if os.path.isabs(rel) or rel.startswith("~"):
        raise LifecycleError(f"{what}: absolute paths are not allowed: {rel!r}")
    base = os.path.realpath(root)
    target = os.path.realpath(os.path.join(base, rel))
    if target != base and not target.startswith(base + os.sep):
        raise LifecycleError(f"{what}: path escapes the case root: {rel!r}")
    return target


def parse_iso(value, what) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise LifecycleError(f"{what}: missing or invalid datetime")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise LifecycleError(f"{what}: not an ISO-8601 datetime: {value!r}")


def parse_date(value, what) -> date:
    if value is None:
        return None
    try:
        return date.fromisoformat(str(value))
    except ValueError:
        raise LifecycleError(f"{what}: not an ISO date: {value!r}")


def as_dict(value, what) -> dict:
    if not isinstance(value, dict):
        raise LifecycleError(f"{what}: expected a mapping, got {type(value).__name__}")
    return value


def as_list(value, what) -> list:
    if not isinstance(value, list):
        raise LifecycleError(f"{what}: expected a list, got {type(value).__name__}")
    return value


def as_str(value, what) -> str:
    if not isinstance(value, str) or not value.strip():
        raise LifecycleError(f"{what}: expected a non-empty string")
    return value


def check_enum(value, allowed, what):
    if value not in allowed:
        raise LifecycleError(f"{what}: expected one of {list(allowed)}, got {value!r}")
    return value


def restrict_keys(d: dict, allowed: set, what) -> None:
    unknown = set(d) - allowed
    if unknown:
        raise LifecycleError(f"{what}: unknown key(s): {sorted(unknown)}")


def check_addr(value, what) -> str:
    if not isinstance(value, str) or not ADDR_RE.match(value):
        raise LifecycleError(f"{what}: not a valid address: {value!r}")
    return value.lower()


def check_hex64(value, what) -> str:
    if not isinstance(value, str) or not HEX64_RE.match(value):
        raise LifecycleError(f"{what}: expected a 0x-prefixed 64-hex digest: {value!r}")
    return value.lower()


def hex_plain(value, what) -> str:
    """Validate a 0x-prefixed digest and return it bare (64 hex chars)."""
    return check_hex64(value, what)[2:]


def norm_digest(value, what) -> str:
    """Accept a 0x-prefixed or bare 64-hex digest; return bare lowercase."""
    if not isinstance(value, str) or not DIGEST_RE.match(value):
        raise LifecycleError(f"{what}: expected a 64-hex digest (0x-prefixed or bare): {value!r}")
    return value.removeprefix("0x").lower()


def load_yaml_file(path: str, what):
    if not os.path.isfile(path):
        raise LifecycleError(f"{what}: file not found: {path}")
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        raise LifecycleError(f"{what}: invalid YAML in {path}: {exc}")
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise LifecycleError(f"{what}: top-level YAML must be a mapping: {path}")
    return data


def emit(payload: dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=False, default=str))
    else:
        for line in payload.get("lines", []):
            print(line)


# ---------------------------------------------------------------------------
# case lock

class CaseLock:
    """Exclusive write lock for a case root; stale locks are stolen."""

    STALE_AFTER = 600

    def __init__(self, root: str):
        self.root = root
        self.path = os.path.join(root, ".lifecycle.lock")
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
                raise LifecycleError(
                    f"case root is locked by another session: {self.path}"
                )
        raise LifecycleError(f"could not acquire lock: {self.path}")

    def __exit__(self, *exc):
        if self.acquired:
            try:
                os.unlink(self.path)
            except FileNotFoundError:
                pass
        return False


# ---------------------------------------------------------------------------
# program.yaml

def validate_program(prog: dict) -> dict:
    prog = as_dict(prog, "program.yaml")
    ident = as_dict(prog.get("program"), "program.yaml: program")
    as_str(ident.get("id"), "program.yaml: program.id")
    snapshot = ident.get("snapshot") or {}
    snapshot = as_dict(snapshot, "program.yaml: program.snapshot")
    if snapshot.get("sha256") is not None:
        norm_digest(snapshot["sha256"], "program.yaml: program.snapshot.sha256")

    scope = as_dict(prog.get("scope"), "program.yaml: scope")
    chains = as_list(scope.get("chains"), "program.yaml: scope.chains")
    if not chains:
        raise LifecycleError("program.yaml: scope.chains must not be empty")
    targets = as_list(scope.get("targets"), "program.yaml: scope.targets")
    if not targets:
        raise LifecycleError("program.yaml: scope.targets must not be empty")
    for i, t in enumerate(targets):
        t = as_dict(t, f"program.yaml: scope.targets[{i}]")
        check_addr(t.get("address"), f"program.yaml: scope.targets[{i}].address")

    matrix = as_list(prog.get("severity_matrix"), "program.yaml: severity_matrix")
    if not matrix:
        raise LifecycleError("program.yaml: severity_matrix must not be empty")
    ids = set()
    for i, entry in enumerate(matrix):
        entry = as_dict(entry, f"program.yaml: severity_matrix[{i}]")
        as_str(entry.get("id"), f"program.yaml: severity_matrix[{i}].id")
        as_str(entry.get("level"), f"program.yaml: severity_matrix[{i}].level")
        if entry["id"] in ids:
            raise LifecycleError(f"program.yaml: duplicate matrix id {entry['id']!r}")
        ids.add(entry["id"])

    as_list(prog.get("exclusions"), "program.yaml: exclusions")
    as_list(prog.get("novelty_sources"), "program.yaml: novelty_sources")

    delivery = prog.get("delivery")
    if delivery is not None:
        delivery = as_dict(delivery, "program.yaml: delivery")
        if delivery.get("platform") is not None:
            check_enum(delivery["platform"], MATERIAL_PLATFORMS | {"other"},
                       "program.yaml: delivery.platform")
    return prog


def load_program(root: str) -> dict:
    path = os.path.join(root, "program.yaml")
    prog = load_yaml_file(path, "program.yaml")
    return validate_program(prog)


def program_matrix_levels(prog: dict) -> dict:
    return {e["id"]: e["level"] for e in prog.get("severity_matrix", [])}


def program_platform(prog: dict):
    """delivery.platform when set (e.g. 'immunefi'), else None."""
    delivery = prog.get("delivery")
    if not isinstance(delivery, dict):
        return None
    return delivery.get("platform") or None


# ---------------------------------------------------------------------------
# ledger

def ledger_path(root: str, fid: str) -> str:
    if not FID_RE.match(fid):
        raise LifecycleError(f"malformed finding id: {fid!r}")
    return os.path.join(root, "findings", fid + ".md")


def split_frontmatter(text: str, path: str):
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        raise LifecycleError(f"{path}: missing opening '---' frontmatter fence")
    end = None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            end = i
            break
    if end is None:
        raise LifecycleError(f"{path}: missing closing '---' frontmatter fence")
    try:
        fm = yaml.safe_load("\n".join(lines[1:end])) or {}
    except yaml.YAMLError as exc:
        raise LifecycleError(f"{path}: invalid frontmatter YAML: {exc}")
    if not isinstance(fm, dict):
        raise LifecycleError(f"{path}: frontmatter must be a mapping")
    body = "\n".join(lines[end + 1:])
    return fm, body


def validate_frontmatter(fm: dict, path: str) -> None:
    unknown = set(fm) - ALLOWED_FM_KEYS
    if unknown:
        raise LifecycleError(f"{path}: unknown frontmatter key(s): {sorted(unknown)}")
    required = {
        "id", "title", "program_id", "stage", "disposition", "revision",
        "sources", "targets", "evidence", "gates", "history",
    }
    missing = required - set(fm)
    if missing:
        raise LifecycleError(f"{path}: missing required frontmatter key(s): {sorted(missing)}")
    check_enum(fm["stage"], STAGES, f"{path}: stage")
    check_enum(fm["disposition"], DISPOSITIONS, f"{path}: disposition")
    rev = fm["revision"]
    if not isinstance(rev, int) or rev < 1:
        raise LifecycleError(f"{path}: revision must be a positive integer")
    hist = fm["history"]
    if not isinstance(hist, list):
        raise LifecycleError(f"{path}: history must be a list")
    if rev != len(hist):
        raise LifecycleError(
            f"{path}: consistency conflict: revision {rev} != {len(hist)} history events; "
            "run `resume` and repair before any further mutation"
        )


def load_ledger(root: str, fid: str):
    path = ledger_path(root, fid)
    if not os.path.isfile(path):
        raise LifecycleError(f"ledger not found: {path}")
    with open(path, encoding="utf-8") as f:
        text = f.read()
    fm, body = split_frontmatter(text, path)
    validate_frontmatter(fm, path)
    if fm["id"] != fid:
        raise LifecycleError(f"{path}: frontmatter id {fm['id']!r} does not match filename")
    return fm, body


def save_ledger(root: str, fm: dict, body: str) -> None:
    fm = dict(fm)
    fm["updated_at"] = now_iso()
    dumped = yaml.safe_dump(fm, sort_keys=False, allow_unicode=True,
                            default_flow_style=False, width=120)
    text = "---\n" + dumped + "---\n\n" + body.lstrip("\n")
    atomic_write(ledger_path(root, fm["id"]), text)


def list_findings(root: str):
    d = os.path.join(root, "findings")
    if not os.path.isdir(d):
        return []
    out = []
    for name in sorted(os.listdir(d)):
        if name.endswith(".md") and FID_RE.match(name[:-3]):
            out.append(name[:-3])
    return out


def default_submission_block():
    return {
        "platform_id": None, "submitted_at": None, "channel": None,
        "package_sha256": None, "receipt": None, "account_limits": None,
        "kyc": None, "response": None,
    }


def default_appeal_block():
    return {
        "status": "NONE", "deadline": None, "materials": [],
        "sent_receipt": None, "outcome": None,
    }


def upsert_evidence(doc: dict, rel: str, digest: str, purpose: str, produced_by: str) -> None:
    entries = doc.setdefault("evidence", [])
    for ev in entries:
        if ev.get("path") == rel:
            ev.update({"sha256": digest, "purpose": purpose,
                       "produced_by": produced_by, "recorded_at": now_iso()})
            return
    entries.append({
        "path": rel, "sha256": digest, "purpose": purpose,
        "produced_by": produced_by, "recorded_at": now_iso(),
    })


def cas_check(doc: dict, expected) -> None:
    if not isinstance(expected, int):
        raise LifecycleError("--expected-revision is required for mutating commands")
    if doc["revision"] != expected:
        raise LifecycleError(
            f"revision conflict: expected {expected}, ledger is at {doc['revision']}; "
            "re-read the ledger and retry with the current revision"
        )


def append_history(doc: dict, event: str, detail: dict) -> None:
    doc.setdefault("history", []).append({"at": now_iso(), "event": event, "detail": detail})
    doc["revision"] += 1


# ---------------------------------------------------------------------------
# verification context

class Ctx:
    def __init__(self, root: str, program: dict, doc: dict):
        self.root = root
        self.program = program
        self.doc = doc
        self.issues = []          # [{"category": ..., "detail": ...}]
        self.inputs = []          # gate input hashes
        self.evidence_updates = []  # [(rel, purpose, produced_by)]
        self.merges = {}          # ledger field updates applied on success
        self._input_keys = set()

    def issue(self, category: str, detail: str) -> None:
        self.issues.append({"category": category, "detail": detail})

    def add_path(self, rel: str, purpose: str, produced_by: str) -> str:
        """Register an artifact: verify existence, hash it, record it."""
        p = safe_rel(self.root, rel, purpose)
        if not os.path.isfile(p):
            self.issue("missing", f"{purpose}: file not found: {rel}")
            return None
        digest = sha256_file(p)
        key = ("path", rel)
        if key not in self._input_keys:
            self._input_keys.add(key)
            self.inputs.append({"path": rel, "sha256": digest})
        self.evidence_updates.append((rel, purpose, produced_by))
        return digest

    def add_field(self, field: str, value) -> None:
        key = ("field", field)
        if key not in self._input_keys:
            self._input_keys.add(key)
            self.inputs.append({"field": field, "sha256": field_hash(value)})

    def verify_file_hash(self, rel: str, expected: str, purpose: str) -> None:
        p = safe_rel(self.root, rel, purpose)
        if not os.path.isfile(p):
            self.issue("missing", f"{purpose}: file not found: {rel}")
            return
        digest = sha256_file(p)
        if expected is None or digest != expected:
            self.issue(
                "hash_mismatch",
                f"{purpose}: hash mismatch for {rel}: manifest {expected}, actual {digest}",
            )


def verify_integrity(ctx: Ctx) -> None:
    """Re-verify recorded evidence hashes and all PASSED gate input hashes."""
    doc = ctx.doc
    for ev in doc.get("evidence", []):
        rel = ev.get("path")
        try:
            p = safe_rel(ctx.root, rel, "recorded evidence")
        except LifecycleError as exc:
            ctx.issue("invalid", str(exc))
            continue
        if not os.path.isfile(p):
            ctx.issue("missing", f"recorded evidence file missing: {rel}")
            continue
        if sha256_file(p) != ev.get("sha256"):
            ctx.issue("hash_mismatch", f"recorded evidence hash changed: {rel}")
    cur_idx = STAGES.index(doc["stage"])
    for g in doc.get("gates", []):
        if g.get("status") != "PASSED":
            continue
        gidx = STAGES.index(g["stage"])
        if gidx > cur_idx:
            ctx.issue("invalid", f"gate {g.get('id')}: stage beyond current stage")
            continue
        for inp in g.get("inputs", []):
            if "path" in inp:
                try:
                    p = safe_rel(ctx.root, inp["path"], f"gate {g.get('id')} input")
                except LifecycleError as exc:
                    ctx.issue("invalid", str(exc))
                    continue
                if not os.path.isfile(p):
                    ctx.issue("missing", f"gate {g['id']}: input file missing: {inp['path']}")
                    continue
                if sha256_file(p) != inp.get("sha256"):
                    ctx.issue(
                        "invalid",
                        f"gate {g['id']} INVALID: input {inp['path']} changed "
                        f"(expected {inp.get('sha256')})",
                    )
            elif "field" in inp:
                if field_hash(doc.get(inp["field"])) != inp.get("sha256"):
                    ctx.issue(
                        "invalid",
                        f"gate {g['id']} INVALID: ledger field {inp['field']!r} changed",
                    )


def current_zip(ctx: Ctx):
    """Locate the recorded package zip; return (rel, digest) or None."""
    for ev in ctx.doc.get("evidence", []):
        if ev.get("purpose") == "package-zip":
            p = safe_rel(ctx.root, ev["path"], "package zip")
            if not os.path.isfile(p):
                ctx.issue("missing", f"package zip missing: {ev['path']}")
                return None
            digest = sha256_file(p)
            if digest != ev.get("sha256"):
                ctx.issue("hash_mismatch", f"package zip changed: {ev['path']}")
            return ev["path"], digest
    ctx.issue("missing", "no package-zip recorded (complete PACKAGED first)")
    return None


# ---------------------------------------------------------------------------
# input document loading

def load_stage_input(root: str, fid: str, stage: str, override, ctx=None):
    rel = override or DEFAULT_INPUTS[stage].format(fid=fid)
    p = safe_rel(root, rel, "stage input")
    if not os.path.isfile(p):
        if ctx is not None:
            # a missing stage document is incomplete work, not a bad input
            ctx.issue("missing", f"stage input not found: {rel}")
            return rel, None
        raise LifecycleError(f"{stage} input: file not found: {p}")
    doc = load_yaml_file(p, f"{stage} input")
    return rel, doc


# ---------------------------------------------------------------------------
# stage verifiers

def verify_prior_art(ctx: Ctx, inp: dict) -> None:
    """Dedup against the project's own published audit reports.

    Overlap with a published audit usually means a known issue: close as
    INELIGIBLE with the report + an overlap note as evidence. Continuing is
    only allowed with an explicit still_eligible rule reference.
    """
    restrict_keys(inp, {"discovery", "reports", "checks",
                        "no_reports_found", "no_reports_note",
                        "no_reports_confirmation", "conclusion"},
                  "prior-art.yaml")

    discovery = as_list(inp.get("discovery") or [], "prior-art.yaml: discovery")
    if not discovery:
        ctx.issue("incomplete", "prior-art.yaml: discovery missing — record where audit "
                                "links were looked for (official docs site and/or program page)")
    for i, d in enumerate(discovery):
        d = as_dict(d, f"prior-art.yaml: discovery[{i}]")
        check_enum(d.get("kind"), {"docs_site", "program_page", "other"},
                   f"prior-art.yaml: discovery[{i}].kind")
        as_str(d.get("url"), f"prior-art.yaml: discovery[{i}].url")
        as_str(d.get("fetched_at"), f"prior-art.yaml: discovery[{i}].fetched_at")
        d.setdefault("note", "")

    reports = as_list(inp.get("reports") or [], "prior-art.yaml: reports")
    if not reports:
        declared = inp.get("no_reports_found")
        note = inp.get("no_reports_note")
        if declared is not True:
            ctx.issue("incomplete", "prior-art.yaml: no reports listed; either list the audit "
                                    "reports found or declare no_reports_found with a note")
        elif not isinstance(note, str) or not note.strip():
            ctx.issue("incomplete", "prior-art.yaml: no_reports_found requires no_reports_note "
                                    "(which channels were checked and what was found)")
        else:
            # absence is the highest-stakes judgment in this gate: a missed
            # report can void a submission. Require two distinct discovery
            # channels AND an independent confirmation of the empty result.
            kinds = {d.get("kind") for d in discovery if isinstance(d, dict)}
            if len(kinds) < 2:
                ctx.issue("incomplete", "prior-art.yaml: no_reports_found needs >=2 distinct "
                                        "discovery channels (e.g. docs_site + program_page); "
                                        f"got {sorted(str(k) for k in kinds)}")
            conf = inp.get("no_reports_confirmation")
            if not isinstance(conf, dict):
                ctx.issue("incomplete", "prior-art.yaml: no_reports_found requires "
                                        "no_reports_confirmation {by, at, note} — an independent "
                                        "re-search before the gate passes; without it, record a blocker")
            else:
                conf = as_dict(conf, "prior-art.yaml: no_reports_confirmation")
                as_str(conf.get("by"), "prior-art.yaml: no_reports_confirmation.by (independent identity)")
                as_str(conf.get("at"), "prior-art.yaml: no_reports_confirmation.at (ISO date)")
                as_str(conf.get("note"), "prior-art.yaml: no_reports_confirmation.note")

    norm_reports = []
    for i, r in enumerate(reports):
        r = as_dict(r, f"prior-art.yaml: reports[{i}]")
        title = as_str(r.get("title"), f"prior-art.yaml: reports[{i}].title")
        rel = as_str(r.get("path"), f"prior-art.yaml: reports[{i}].path")
        expected = r.get("sha256")
        if not isinstance(expected, str) or not re.fullmatch(r"(0x)?[0-9a-fA-F]{64}", expected):
            raise LifecycleError(f"prior-art.yaml: reports[{i}].sha256 must be a 64-hex digest")
        ctx.verify_file_hash(rel, expected.removeprefix("0x").lower(), f"prior-art report {title}")
        ctx.add_path(rel, f"prior-art-report:{title}", "stage:PRIOR_ART_CHECKED")
        norm_reports.append({"title": title, "path": rel,
                             "sha256": expected.removeprefix("0x").lower(),
                             "url": r.get("url"), "auditor": r.get("auditor"),
                             "date": r.get("date")})

    checks = as_list(inp.get("checks") or [], "prior-art.yaml: checks")
    by_report = {}
    for i, c in enumerate(checks):
        c = as_dict(c, f"prior-art.yaml: checks[{i}]")
        ref = as_str(c.get("report"), f"prior-art.yaml: checks[{i}].report")
        result = check_enum(c.get("result"), {"NO_MATCH", "MATCH", "PARTIAL", "NOT_SEARCHABLE"},
                            f"prior-art.yaml: checks[{i}].result")
        detail = c.get("detail")
        if not isinstance(detail, str) or not detail.strip():
            ctx.issue("incomplete", f"prior-art.yaml: checks[{i}] ({ref}): detail missing")
        searched = as_list(c.get("searched_for") or [], f"prior-art.yaml: checks[{i}].searched_for")
        if not searched:
            ctx.issue("incomplete", f"prior-art.yaml: checks[{i}] ({ref}): searched_for missing — "
                                    "record the root-cause keywords used")
        if result == "NOT_SEARCHABLE":
            ctx.issue("incomplete", f"prior-art.yaml: checks[{i}] ({ref}): NOT_SEARCHABLE is "
                                    "unresolved — record a blocker (unknown blocks the gate)")
        if result in ("MATCH", "PARTIAL"):
            se = c.get("still_eligible")
            if not isinstance(se, dict):
                ctx.issue("incomplete",
                          f"prior-art.yaml: checks[{i}] ({ref}): {result} with the project's own "
                          "audit — close as INELIGIBLE with evidence, or provide "
                          "still_eligible {rule_ref, explanation} if the rules allow it")
            else:
                se = as_dict(se, f"prior-art.yaml: checks[{i}].still_eligible")
                as_str(se.get("rule_ref"), f"prior-art.yaml: checks[{i}].still_eligible.rule_ref")
                as_str(se.get("explanation"), f"prior-art.yaml: checks[{i}].still_eligible.explanation")
        if ref in by_report:
            ctx.issue("invalid", f"prior-art.yaml: duplicate check for report {ref!r}")
        by_report[ref] = result

    for r in norm_reports:
        if r["title"] not in by_report:
            ctx.issue("incomplete", f"prior-art.yaml: no check recorded for report {r['title']!r}")
    for ref in by_report:
        if ref not in {r["title"] for r in norm_reports}:
            ctx.issue("invalid", f"prior-art.yaml: check references unknown report {ref!r}")

    conclusion = check_enum(inp.get("conclusion"), {"NEW", "KNOWN"}, "prior-art.yaml: conclusion")
    if conclusion == "KNOWN":
        ctx.issue("incomplete", "prior-art.yaml: conclusion KNOWN — close as INELIGIBLE with the "
                                "overlap evidence instead of advancing")

    merged = {
        "checked_at": now_iso(),
        "conclusion": conclusion,
        "discovery": discovery,
        "reports": norm_reports,
    }
    ctx.merges["prior_art"] = merged
    ctx.add_field("prior_art", merged)


def verify_cross_check(ctx: Ctx, inp: dict) -> None:
    restrict_keys(inp, {"targets", "root_cause", "refutation_attempts",
                        "damage_vs_profit", "assessment", "uncovered_variants"},
                  "cross-check.yaml")
    targets = inp.get("targets")
    if not targets:
        ctx.issue("incomplete", "cross-check.yaml: targets missing — affected deployment set must be explicit")
        targets = []
    norm_targets = []
    for i, t in enumerate(targets):
        t = as_dict(t, f"cross-check.yaml: targets[{i}]")
        if t.get("chain_id") is None or not isinstance(t["chain_id"], int) or t["chain_id"] <= 0:
            raise LifecycleError(f"cross-check.yaml: targets[{i}].chain_id must be a positive integer")
        addr = check_addr(t.get("address"), f"cross-check.yaml: targets[{i}].address")
        code = check_hex64(t.get("code_sha256"), f"cross-check.yaml: targets[{i}].code_sha256 (runtime bytecode hash)")
        for opt in ("proxy_address", "implementation_address"):
            if t.get(opt) is not None:
                check_addr(t[opt], f"cross-check.yaml: targets[{i}].{opt}")
        norm_targets.append({
            "chain_id": t["chain_id"], "address": addr,
            "proxy_address": t.get("proxy_address"),
            "implementation_address": t.get("implementation_address"),
            "block": t.get("block"), "code_sha256": code,
        })

    rc = inp.get("root_cause")
    if rc is None:
        ctx.issue("incomplete", "cross-check.yaml: root_cause missing")
        rc = {}
    rc = as_dict(rc, "cross-check.yaml: root_cause")
    claim = rc.get("claim")
    if not isinstance(claim, str) or not claim.strip():
        ctx.issue("incomplete", "cross-check.yaml: root_cause.claim must state the root cause on real deployments")
    variants = rc.get("variants", [])
    if variants is not None:
        variants = as_list(variants, "cross-check.yaml: root_cause.variants")
    norm_rc = {"claim": claim or "", "variants": variants or []}

    attempts = inp.get("refutation_attempts")
    if not attempts:
        ctx.issue("incomplete", "cross-check.yaml: refutation_attempts missing — every claim must list attempts to break it")
    else:
        for i, a_ in enumerate(as_list(attempts, "cross-check.yaml: refutation_attempts")):
            a_ = as_dict(a_, f"cross-check.yaml: refutation_attempts[{i}]")
            as_str(a_.get("attempt"), f"cross-check.yaml: refutation_attempts[{i}].attempt")
            as_str(a_.get("outcome"), f"cross-check.yaml: refutation_attempts[{i}].outcome")

    dvp = as_dict(inp.get("damage_vs_profit") or {}, "cross-check.yaml: damage_vs_profit")
    for key in ("victim_damage", "attacker_profit"):
        if not isinstance(dvp.get(key), str) or not dvp[key].strip():
            ctx.issue("incomplete", f"cross-check.yaml: damage_vs_profit.{key} must be stated")

    if not inp.get("assessment"):
        ctx.issue("incomplete", "cross-check.yaml: assessment path missing")
    else:
        ctx.add_path(as_str(inp["assessment"], "cross-check.yaml: assessment"), "assessment", "stage:CROSS_CHECKED")

    ctx.merges["targets"] = norm_targets
    ctx.merges["root_cause"] = norm_rc
    ctx.add_field("targets", norm_targets)
    ctx.add_field("root_cause", norm_rc)


def verify_fork_proof(ctx: Ctx, inp: dict) -> None:
    restrict_keys(inp, {"fork", "targets_checked", "capabilities", "controls", "poc", "pnl"},
                  "fork-proof.yaml")
    doc = ctx.doc
    if not doc.get("targets"):
        ctx.issue("invalid", "ledger has no targets; complete CROSS_CHECKED first")
        return

    fork = as_dict(inp.get("fork") or {}, "fork-proof.yaml: fork")
    if not isinstance(fork.get("chain_id"), int) or fork.get("chain_id", 0) <= 0:
        raise LifecycleError("fork-proof.yaml: fork.chain_id must be a positive integer")
    if not isinstance(fork.get("block_number"), int) or fork.get("block_number", -1) < 0:
        raise LifecycleError("fork-proof.yaml: fork.block_number must be a non-negative integer")
    check_hex64(fork.get("block_hash"), "fork-proof.yaml: fork.block_hash")
    as_str(fork.get("rpc_url_ref"), "fork-proof.yaml: fork.rpc_url_ref (reference like 'env MAINNET_RPC_URL', never a keyed URL)")
    versions = as_dict(fork.get("tool_versions") or {}, "fork-proof.yaml: fork.tool_versions")
    if not versions:
        raise LifecycleError("fork-proof.yaml: fork.tool_versions must record tool versions (e.g. forge)")

    checked = as_list(inp.get("targets_checked", []), "fork-proof.yaml: targets_checked")
    checked_lower = {a.lower() for a in checked if isinstance(a, str)}
    for t in doc["targets"]:
        if t["address"].lower() not in checked_lower:
            ctx.issue("incomplete", f"fork-proof.yaml: target {t['address']} not covered by targets_checked")

    caps = as_list(inp.get("capabilities", []), "fork-proof.yaml: capabilities")
    for i, c in enumerate(caps):
        c = as_dict(c, f"fork-proof.yaml: capabilities[{i}]")
        check_enum(c.get("name"), {"deal", "prank", "warp", "oracle_mock", "other"},
                   f"fork-proof.yaml: capabilities[{i}].name")
        as_str(c.get("used_for"), f"fork-proof.yaml: capabilities[{i}].used_for")
        as_str(c.get("justification"), f"fork-proof.yaml: capabilities[{i}].justification")

    controls = as_list(inp.get("controls", []), "fork-proof.yaml: controls")
    for i, c in enumerate(controls):
        c = as_dict(c, f"fork-proof.yaml: controls[{i}]")
        as_str(c.get("control"), f"fork-proof.yaml: controls[{i}].control")
        if not isinstance(c.get("applicable"), bool):
            raise LifecycleError(f"fork-proof.yaml: controls[{i}].applicable must be a boolean")
        as_str(c.get("verified"), f"fork-proof.yaml: controls[{i}].verified")

    poc = as_dict(inp.get("poc") or {}, "fork-proof.yaml: poc")
    check_enum(poc.get("result"), {"PASS", "FAIL", "NOT_RUN"}, "fork-proof.yaml: poc.result")
    if poc.get("result") != "PASS":
        ctx.issue("incomplete", f"fork-proof.yaml: poc.result is {poc.get('result')!r} — expected PASS; "
                                "an unrunnable PoC is a blocker, not a pass")
    test_rel = poc.get("test_file")
    log_rel = poc.get("run_log")
    if not isinstance(test_rel, str) or not test_rel.strip():
        ctx.issue("incomplete", "fork-proof.yaml: poc.test_file missing")
        test_rel = None
    if not isinstance(log_rel, str) or not log_rel.strip():
        ctx.issue("incomplete", "fork-proof.yaml: poc.run_log missing")
        log_rel = None
    if test_rel:
        ctx.add_path(test_rel, "poc-test", "stage:FORK_PROVEN")
    log_digest = None
    if log_rel:
        log_digest = ctx.add_path(log_rel, "poc-run-log", "stage:FORK_PROVEN")
    assertions = as_list(poc.get("expected_assertions") or [], "fork-proof.yaml: poc.expected_assertions")
    if not assertions:
        ctx.issue("incomplete", "fork-proof.yaml: poc.expected_assertions missing — name the assertions the run must show")
    if log_digest is not None:
        with open(safe_rel(ctx.root, log_rel, "poc run log"), encoding="utf-8", errors="ignore") as f:
            log_text = f.read()
        for a_ in assertions:
            if str(a_) not in log_text:
                ctx.issue("incomplete", f"run log does not contain expected assertion {a_!r}")

    pnl = as_dict(inp.get("pnl") or {}, "fork-proof.yaml: pnl")
    as_str(pnl.get("currency"), "fork-proof.yaml: pnl.currency")
    for side in ("attacker", "victim"):
        entries = as_list(pnl.get(side) or [], f"fork-proof.yaml: pnl.{side}")
        if not entries:
            ctx.issue("incomplete", f"fork-proof.yaml: pnl.{side} empty — profit and damage must be quantified separately")
        for i, e in enumerate(entries):
            e = as_dict(e, f"fork-proof.yaml: pnl.{side}[{i}]")
            as_str(e.get("item"), f"fork-proof.yaml: pnl.{side}[{i}].item")
            known = e.get("known")
            if not isinstance(known, bool):
                raise LifecycleError(f"fork-proof.yaml: pnl.{side}[{i}].known must be a boolean")
            amount = e.get("amount")
            if not known:
                if str(amount).strip().lower() != "unknown":
                    ctx.issue("incomplete", f"fork-proof.yaml: pnl.{side}[{i}]: unknown costs must be 'unknown', not zero")
            elif amount is None or str(amount).strip() == "":
                ctx.issue("incomplete", f"fork-proof.yaml: pnl.{side}[{i}]: known amounts must be stated")

    ctx.add_field("targets", doc["targets"])


def verify_triage(ctx: Ctx, inp: dict) -> None:
    restrict_keys(inp, {"severity", "eligibility", "novelty", "program_snapshot"}, "triage.yaml")
    doc = ctx.doc

    sev = as_dict(inp.get("severity") or {}, "triage.yaml: severity")
    final = as_str(sev.get("final"), "triage.yaml: severity.final")
    matrix_entry = as_str(sev.get("matrix_entry"), "triage.yaml: severity.matrix_entry")
    justification = as_str(sev.get("justification"), "triage.yaml: severity.justification")
    levels = program_matrix_levels(ctx.program)
    if matrix_entry not in levels:
        ctx.issue("incomplete", f"triage.yaml: severity.matrix_entry {matrix_entry!r} not in program severity_matrix")
    elif levels[matrix_entry] != final:
        ctx.issue("incomplete",
                  f"triage.yaml: severity.final {final!r} does not match matrix entry {matrix_entry} level {levels[matrix_entry]!r}")
    ev_paths = [ev.get("path", "") for ev in doc.get("evidence", [])]
    if not any(p and p in justification for p in ev_paths):
        ctx.issue("incomplete", "triage.yaml: severity.justification must cite a recorded evidence path")

    elig = as_list(inp.get("eligibility") or [], "triage.yaml: eligibility")
    if not elig:
        ctx.issue("incomplete", "triage.yaml: eligibility missing — every rule item must be judged")
    for i, e in enumerate(elig):
        e = as_dict(e, f"triage.yaml: eligibility[{i}]")
        as_str(e.get("aspect"), f"triage.yaml: eligibility[{i}].aspect")
        as_str(e.get("rule_ref"), f"triage.yaml: eligibility[{i}].rule_ref")
        status = check_enum(e.get("status"), {"PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE"},
                            f"triage.yaml: eligibility[{i}].status")
        as_str(e.get("explanation"), f"triage.yaml: eligibility[{i}].explanation")
        if status == "UNKNOWN":
            ctx.issue("incomplete", f"triage.yaml: eligibility[{i}] ({e['aspect']}) is UNKNOWN — resolve or record a blocker; UNKNOWN blocks the gate")
        elif status == "FAIL":
            ctx.issue("incomplete", f"triage.yaml: eligibility[{i}] ({e['aspect']}) is FAIL — close as INELIGIBLE with evidence instead of advancing")
        ev_rel = e.get("evidence")
        if isinstance(ev_rel, str) and ev_rel.strip():
            ctx.add_path(ev_rel, f"eligibility:{e['aspect']}", "stage:TRIAGED")

    novelty = as_dict(inp.get("novelty") or {}, "triage.yaml: novelty")
    searched = as_list(novelty.get("sources_searched") or [], "triage.yaml: novelty.sources_searched")
    if not searched:
        ctx.issue("incomplete", "triage.yaml: novelty.sources_searched missing — record the prior-art search (or its explicit absence)")
    for i, s in enumerate(searched):
        s = as_dict(s, f"triage.yaml: novelty.sources_searched[{i}]")
        as_str(s.get("source"), f"triage.yaml: novelty.sources_searched[{i}].source")
        as_str(s.get("result"), f"triage.yaml: novelty.sources_searched[{i}].result")
    as_str(novelty.get("known_issues_found"), "triage.yaml: novelty.known_issues_found (state 'none' if nothing found)")

    snap_declared = as_dict(inp.get("program_snapshot") or {}, "triage.yaml: program_snapshot")
    prog_snap = as_dict((ctx.program.get("program") or {}).get("snapshot") or {},
                        "program.yaml: program.snapshot")
    snap_rel = prog_snap.get("path")
    if not snap_rel:
        ctx.issue("incomplete", "program.yaml: program.snapshot.path missing — freeze the rules snapshot")
    else:
        snap_file = safe_rel(ctx.root, snap_rel, "rules snapshot")
        if not os.path.isfile(snap_file):
            ctx.issue("missing", f"rules snapshot file not found: {snap_rel}")
        else:
            actual = sha256_file(snap_file)
            declared_prog = prog_snap.get("sha256")
            if declared_prog is None or norm_digest(declared_prog, "program.yaml: snapshot.sha256") != actual:
                ctx.issue("hash_mismatch",
                          f"program.yaml snapshot.sha256 {declared_prog} != actual {actual} for {snap_rel}")
            declared = snap_declared.get("sha256")
            if not isinstance(declared, str) or declared.lower().removeprefix("0x") != actual:
                ctx.issue("incomplete", "triage.yaml: program_snapshot.sha256 must record the frozen snapshot hash")
            ctx.add_path(snap_rel, "rules-snapshot", "stage:TRIAGED")

    merged_severity = {
        "candidate": (doc.get("severity") or {}).get("candidate"),
        "final": final, "matrix_entry": matrix_entry, "justification": justification,
    }
    ctx.merges["severity"] = merged_severity
    ctx.merges["program_snapshot"] = {"sha256": snap_declared.get("sha256"), "checked_at": now_iso()}
    ctx.add_field("severity", merged_severity)


def scan_secrets(paths, root):
    flagged = []
    for rel in paths:
        p = safe_rel(root, rel, "secrets scan")
        if not os.path.isfile(p):
            continue
        with open(p, encoding="utf-8", errors="ignore") as f:
            text = f.read()
        for pid, pattern in SECRET_PATTERNS:
            if pattern.search(text):
                flagged.append((rel, pid))
    return flagged


def verify_package(ctx: Ctx, inp: dict, manifest_rel: str) -> None:
    restrict_keys(inp, {"package", "materials"}, f"{manifest_rel}")
    pkg = as_dict(inp.get("package") or {}, f"{manifest_rel}: package")
    fid = ctx.doc["id"]

    report = as_dict(pkg.get("report") or {}, f"{manifest_rel}: package.report")
    report_rel = as_str(report.get("path"), f"{manifest_rel}: package.report.path")
    if not report_rel.endswith(".md"):
        ctx.issue("incomplete", f"{manifest_rel}: package.report.path must be a markdown file")
    if report.get("language") != "en":
        ctx.issue("incomplete", f"{manifest_rel}: package.report.language must be 'en' (one English report per root cause)")
    as_str(report.get("root_cause_id"), f"{manifest_rel}: package.report.root_cause_id")

    files = as_list(pkg.get("files") or [], f"{manifest_rel}: package.files")
    if not files:
        ctx.issue("incomplete", f"{manifest_rel}: package.files missing")
    rels = []
    for i, f_ in enumerate(files):
        f_ = as_dict(f_, f"{manifest_rel}: package.files[{i}]")
        rel = as_str(f_.get("path"), f"{manifest_rel}: package.files[{i}].path")
        as_str(f_.get("purpose"), f"{manifest_rel}: package.files[{i}].purpose")
        expected = f_.get("sha256")
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise LifecycleError(f"{manifest_rel}: package.files[{i}].sha256 must be a 64-hex digest")
        ctx.verify_file_hash(rel, expected, f"package file {rel}")
        ctx.add_path(rel, f"package-artifact:{f_['purpose']}", "stage:PACKAGED")
        rels.append(rel)
    if report_rel not in rels:
        ctx.issue("incomplete", f"{manifest_rel}: report {report_rel} must be listed in package.files")

    zip_spec = as_dict(pkg.get("zip") or {}, f"{manifest_rel}: package.zip")
    zip_rel = as_str(zip_spec.get("path"), f"{manifest_rel}: package.zip.path")
    zip_expected = norm_digest(zip_spec.get("sha256"), f"{manifest_rel}: package.zip.sha256")
    zip_file = safe_rel(ctx.root, zip_rel, "package zip")
    prefix = f"packages/{fid}/"
    if not os.path.isfile(zip_file):
        ctx.issue("missing", f"package zip not found: {zip_rel}")
    else:
        actual = sha256_file(zip_file)
        if actual != zip_expected:
            ctx.issue("hash_mismatch", f"package zip hash mismatch for {zip_rel}: manifest {zip_expected}, actual {actual}")
        try:
            with zipfile.ZipFile(zip_file) as zf:
                names = set(zf.namelist())
        except (zipfile.BadZipFile, OSError) as exc:
            ctx.issue("invalid", f"package zip unreadable: {zip_rel}: {exc}")
            names = set()
        for rel in rels:
            member = rel[len(prefix):] if rel.startswith(prefix) else rel
            if names and member not in names:
                ctx.issue("incomplete", f"package zip does not contain {member} (for {rel})")
    ctx.add_path(zip_rel, "package-zip", "stage:PACKAGED")

    material_rels = verify_materials(ctx, manifest_rel, inp.get("materials"))

    clean = as_dict(pkg.get("clean_run") or {}, f"{manifest_rel}: package.clean_run")
    as_str(clean.get("performed_in"), f"{manifest_rel}: package.clean_run.performed_in (where the clean run happened)")
    log_rel = as_str(clean.get("log_path"), f"{manifest_rel}: package.clean_run.log_path")
    check_enum(clean.get("result"), {"PASS", "FAIL", "NOT_RUN"}, f"{manifest_rel}: package.clean_run.result")
    if clean.get("result") != "PASS":
        ctx.issue("incomplete", f"{manifest_rel}: package.clean_run.result is {clean.get('result')!r}; the package must run in a clean directory")
    log_digest = ctx.add_path(log_rel, "clean-run-log", "stage:PACKAGED")
    if log_digest is not None:
        with open(safe_rel(ctx.root, log_rel, "clean run log"), encoding="utf-8", errors="ignore") as f:
            if "RESULT: PASS" not in f.read():
                ctx.issue("incomplete", f"clean run log lacks the 'RESULT: PASS' marker: {log_rel}")

    flagged = scan_secrets(rels + material_rels, ctx.root)
    scan = as_dict(pkg.get("secrets_scan") or {}, f"{manifest_rel}: package.secrets_scan")
    exceptions = as_list(scan.get("exceptions") or [], f"{manifest_rel}: package.secrets_scan.exceptions")
    exc_keys = set()
    for i, x in enumerate(exceptions):
        x = as_dict(x, f"{manifest_rel}: package.secrets_scan.exceptions[{i}]")
        as_str(x.get("file"), f"{manifest_rel}: secrets_scan.exceptions[{i}].file")
        as_str(x.get("pattern_id"), f"{manifest_rel}: secrets_scan.exceptions[{i}].pattern_id")
        as_str(x.get("reason"), f"{manifest_rel}: secrets_scan.exceptions[{i}].reason")
        exc_keys.add((x["file"], x["pattern_id"]))
    for rel, pid in flagged:
        if (rel, pid) not in exc_keys:
            ctx.issue("incomplete", f"secrets scan flagged {rel} ({pid}); add a justified exception or remove the secret")
    for key in exc_keys:
        if key not in set(flagged):
            ctx.issue("incomplete", f"secrets_scan exception {key} does not match any actual finding")

    deps = as_dict(pkg.get("dependencies") or {}, f"{manifest_rel}: package.dependencies")
    as_list(deps.get("pinned") or [], f"{manifest_rel}: package.dependencies.pinned")
    as_list(deps.get("external_prereqs") or [], f"{manifest_rel}: package.dependencies.external_prereqs")
    if not isinstance(pkg.get("self_contained"), bool):
        raise LifecycleError(f"{manifest_rel}: package.self_contained must be a boolean")
    if not pkg["self_contained"]:
        note = pkg.get("limitations_note")
        if not isinstance(note, str) or not note.strip():
            ctx.issue("incomplete", f"{manifest_rel}: self_contained=false requires limitations_note (declared external dependencies)")

    ctx.add_path(manifest_rel, "package-manifest", "stage:PACKAGED")


def verify_materials(ctx: Ctx, manifest_rel: str, materials) -> list:
    """Platform form-field materials declared in the package manifest.

    Immunefi layout: packages/<id>/immunefi/{1-title,2-description,3-poc}.txt.
    HackenProof layout: packages/<id>/hackenproof/fields/{1-title.txt,
    2-vulnerability-details.md, 3-validation-steps.md, 4-supporting-files.txt}
    plus submission.md (the full write-up with its Reproduction section).
    Pasted/uploaded at submission time. The files live beside package.zip
    (not inside it). Returns the material paths for the secrets scan.
    Mechanical checks only — content judgement stays with the reviewer.
    """
    plat = program_platform(ctx.program)
    spec = MATERIAL_SPECS.get(plat)
    if materials is None:
        if spec:
            expected = ", ".join(f"{plat}/{fspec['path']}"
                                 for fspec in spec["fields"].values())
            ctx.issue("incomplete",
                      f"{manifest_rel}: materials missing — program.yaml delivery.platform is "
                      f"{plat!r}; the package must carry the form-field files ({expected}) "
                      "plus a materials block declaring their hashes)")
        return []
    materials = as_dict(materials, f"{manifest_rel}: materials")
    restrict_keys(materials, {"platform", "slug", "fields", "form_targets",
                              "attachments"}, f"{manifest_rel}: materials")
    mplat = check_enum(materials.get("platform"), MATERIAL_PLATFORMS,
                       f"{manifest_rel}: materials.platform")
    if plat != mplat:
        ctx.issue("invalid",
                  f"{manifest_rel}: materials.platform {mplat!r} does not match program.yaml "
                  f"delivery.platform {plat!r}")
    slug = as_str(materials.get("slug"), f"{manifest_rel}: materials.slug")
    if not SLUG_RE.fullmatch(slug):
        ctx.issue("incomplete",
                  f"{manifest_rel}: materials.slug must be a short lowercase hyphen slug "
                  f"(2-41 chars, [a-z0-9-]), got {slug!r} — it names the export directory")
    spec = MATERIAL_SPECS[mplat]
    pkg_dir = os.path.dirname(manifest_rel)

    fields = as_list(materials.get("fields") or [], f"{manifest_rel}: materials.fields")
    rels = []
    seen = []
    for i, f_ in enumerate(fields):
        f_ = as_dict(f_, f"{manifest_rel}: materials.fields[{i}]")
        name = check_enum(f_.get("field"), set(spec["fields"]),
                          f"{manifest_rel}: materials.fields[{i}].field")
        if name in seen:
            ctx.issue("incomplete", f"{manifest_rel}: materials field {name!r} declared twice")
        seen.append(name)
        rel = as_str(f_.get("path"), f"{manifest_rel}: materials.fields[{i}].path")
        expected = f_.get("sha256")
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise LifecycleError(f"{manifest_rel}: materials.fields[{i}].sha256 must be a 64-hex digest")
        ctx.verify_file_hash(rel, expected, f"material {name}")
        ctx.add_path(rel, f"material:{name}", "stage:PACKAGED")
        rels.append(rel)
        canonical = f"{pkg_dir}/{mplat}/{spec['fields'][name]['path']}"
        if rel != canonical:
            ctx.issue("incomplete",
                      f"{manifest_rel}: materials field {name!r} must be the {canonical} file, got {rel}")
    missing = [n for n in spec["fields"] if n not in seen]
    if missing:
        ctx.issue("incomplete",
                  f"{manifest_rel}: materials must declare exactly these fields: "
                  f"{', '.join(spec['fields'])} (missing: {', '.join(missing)})")

    for rel, name in zip(rels, seen):
        p = safe_rel(ctx.root, rel, f"material {name}")
        if not os.path.isfile(p):
            continue
        with open(p, encoding="utf-8", errors="ignore") as f:
            text = f.read()
        if not text.strip():
            ctx.issue("incomplete", f"material {name} is empty: {rel}")
        for header in spec["fields"][name].get("headers", ()):
            if header not in text:
                ctx.issue("incomplete",
                          f"material {name} ({rel}) lacks the required section header {header!r}")
        if spec["fields"][name].get("upload_line") \
                and not UPLOAD_LINE_RE.search(text):
            ctx.issue("incomplete",
                      f"material {name} ({rel}) must name the uploaded bundle in an "
                      "'Upload: <file>' line")
        if name in (spec.get("permalink_fields") or ()):
            for m in GITHUB_URL_RE.finditer(text):
                url = m.group(0).rstrip(".,;:)")
                if GITHUB_PERMALINK_RE.fullmatch(url):
                    continue
                ctx.issue("incomplete",
                          f"material {name} ({rel}) cites {url!r} — every github.com "
                          "reference must be a commit-pinned permalink "
                          "(github.com/<org>/<repo>/blob/<40-hex>/…#L…); branch links "
                          "can be altered after submission")

    # which contract to pick in each platform form field (dropdown answers,
    # verified against an authoritative source; surfaced by export)
    for i, ft in enumerate(as_list(materials.get("form_targets") or [],
                                   f"{manifest_rel}: materials.form_targets")):
        ft = as_dict(ft, f"{manifest_rel}: materials.form_targets[{i}]")
        as_str(ft.get("field"), f"{manifest_rel}: materials.form_targets[{i}].field "
                                "(the platform form field/dropdown name)")
        check_addr(ft.get("address"), f"{manifest_rel}: materials.form_targets[{i}].address")
        as_str(ft.get("source"), f"{manifest_rel}: materials.form_targets[{i}].source "
                                 "(where the address was verified, e.g. provenance + registry read)")

    # files uploaded beside the bundle zip (extend the lint attachment set;
    # copied into the export directory)
    for i, at in enumerate(as_list(materials.get("attachments") or [],
                                   f"{manifest_rel}: materials.attachments")):
        at = as_dict(at, f"{manifest_rel}: materials.attachments[{i}]")
        rel = as_str(at.get("path"), f"{manifest_rel}: materials.attachments[{i}].path")
        expected = at.get("sha256")
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise LifecycleError(f"{manifest_rel}: materials.attachments[{i}].sha256 must be a 64-hex digest")
        ctx.verify_file_hash(rel, expected, f"material attachment {rel}")
        ctx.add_path(rel, f"material-attachment:{os.path.basename(rel)}", "stage:PACKAGED")
        rels.append(rel)
        at.setdefault("note", "")

    return rels


def verify_self_review(ctx: Ctx, inp: dict) -> None:
    restrict_keys(inp, {"reviewer", "package_sha256", "checks",
                        "adverse_facts", "unresolved_objections", "rounds"},
                  "self-review.yaml")
    reviewer = as_dict(inp.get("reviewer") or {}, "self-review.yaml: reviewer")
    as_str(reviewer.get("identity"), "self-review.yaml: reviewer.identity")
    check_enum(reviewer.get("kind"), {"independent_session", "independent_agent"},
               "self-review.yaml: reviewer.kind")

    # multi-round loop (workflow section 6). A flat legacy self-review with no
    # rounds[] key stays valid as an implicit single round.
    rounds = inp.get("rounds")
    if rounds is not None:
        rounds = as_list(rounds, "self-review.yaml: rounds")
        if not rounds:
            ctx.issue("incomplete", "self-review.yaml: rounds present but empty — record at least one round")
        for i, r in enumerate(rounds):
            r = as_dict(r, f"self-review.yaml: rounds[{i}]")
            if r.get("round") != i + 1:
                ctx.issue("incomplete", f"self-review.yaml: rounds[{i}].round must be {i + 1} "
                                        "(1-based, consecutive)")
            landing = as_dict(r.get("landing_check") or {},
                              f"self-review.yaml: rounds[{i}].landing_check")
            result = check_enum(landing.get("result"), {"PASS", "N_A", "FAIL"},
                                f"self-review.yaml: rounds[{i}].landing_check.result")
            if result == "FAIL":
                ctx.issue("incomplete", f"self-review.yaml: rounds[{i}].landing_check FAIL — "
                                        "the previous round's fixes did not land; loop again")
            if i == 0:
                if result != "N_A":
                    ctx.issue("incomplete", "self-review.yaml: rounds[0].landing_check must be N_A "
                                            "(nothing to verify before round 1)")
            elif result != "PASS" or landing.get("of_round") != i:
                ctx.issue("incomplete", f"self-review.yaml: rounds[{i}] must landing-verify "
                                        f"round {i} with result PASS")
            for j, o in enumerate(as_list(r.get("objections") or [],
                                          f"self-review.yaml: rounds[{i}].objections")):
                o = as_dict(o, f"self-review.yaml: rounds[{i}].objections[{j}]")
                as_str(o.get("id"), f"self-review.yaml: rounds[{i}].objections[{j}].id")
                verdict = check_enum(o.get("verdict"), {"fixed", "kept_with_rationale"},
                                     f"self-review.yaml: rounds[{i}].objections[{j}].verdict")
                note = o.get("note")
                if verdict == "kept_with_rationale" and (not isinstance(note, str) or not note.strip()):
                    ctx.issue("incomplete", f"self-review.yaml: rounds[{i}].objections[{j}] is "
                                            "kept_with_rationale and must carry a note")
            if not isinstance(r.get("clean_round"), bool):
                ctx.issue("incomplete", f"self-review.yaml: rounds[{i}].clean_round must be a boolean")
        if rounds:
            last = rounds[-1]
            if last.get("clean_round") is not True:
                ctx.issue("incomplete", "self-review.yaml: the final round must be clean_round: true — "
                                        "run more rounds until one raises zero required changes")
            elif any(isinstance(o, dict) and o.get("verdict") == "fixed"
                     for o in (last.get("objections") or [])):
                ctx.issue("incomplete", "self-review.yaml: final round declares fixes AND clean_round — "
                                        "fixes need a landing-verification round after them")

    zip_info = current_zip(ctx)
    declared = norm_digest(inp.get("package_sha256"), "self-review.yaml: package_sha256")
    if zip_info is not None and declared != zip_info[1]:
        ctx.issue("hash_mismatch",
                  f"self-review.yaml: package_sha256 {declared} != current package zip {zip_info[1]}; "
                  "review must bind the FINAL frozen package")

    checks = as_dict(inp.get("checks") or {}, "self-review.yaml: checks")
    rerun = as_dict(checks.get("rerun") or {}, "self-review.yaml: checks.rerun")
    if rerun.get("performed") is not True:
        ctx.issue("incomplete", "self-review.yaml: checks.rerun.performed must be true — rerun from the frozen package")
    check_enum(rerun.get("result"), {"PASS", "FAIL", "NOT_POSSIBLE"}, "self-review.yaml: checks.rerun.result")
    if rerun.get("result") != "PASS":
        ctx.issue("incomplete", f"self-review.yaml: checks.rerun.result is {rerun.get('result')!r}")
    if rerun.get("log_path"):
        ctx.add_path(as_str(rerun["log_path"], "self-review.yaml: checks.rerun.log_path"),
                     "self-review-rerun-log", "stage:SELF_REVIEWED")
    for key in ("amounts", "preconditions"):
        part = as_dict(checks.get(key) or {}, f"self-review.yaml: checks.{key}")
        if part.get("status") != "VERIFIED":
            ctx.issue("incomplete", f"self-review.yaml: checks.{key}.status must be VERIFIED (got {part.get('status')!r})")
        as_str(part.get("notes"), f"self-review.yaml: checks.{key}.notes")
    wording = as_dict(checks.get("wording") or {}, "self-review.yaml: checks.wording")
    as_list(wording.get("changes") or [], "self-review.yaml: checks.wording.changes")

    as_list(inp.get("adverse_facts") or [], "self-review.yaml: adverse_facts")
    unresolved = as_list(inp.get("unresolved_objections") or [], "self-review.yaml: unresolved_objections")
    if unresolved:
        ctx.issue("incomplete", f"self-review.yaml: {len(unresolved)} unresolved objection(s) block the gate")


def verify_submission_block(ctx: Ctx, sub: dict, record_mode: bool = False) -> None:
    """Validate the submission block; gates the SUBMITTED advance."""
    if not isinstance(sub, dict) or not isinstance(sub.get("platform_id"), str) \
            or not sub.get("platform_id", "").strip():
        ctx.issue("incomplete", "submission not recorded yet; run "
                                "`lifecycle.py record submission --input evidence/<id>/submission.yaml` first")
        return
    as_str(sub.get("platform_id"), "submission: platform_id")
    parse_iso(sub.get("submitted_at"), "submission: submitted_at")
    channel = as_dict(sub.get("channel") or {}, "submission: channel")
    check_enum(channel.get("kind"), {"private_repo", "platform_portal", "other"}, "submission: channel.kind")
    as_str(channel.get("detail"), "submission: channel.detail")
    privacy = as_dict(channel.get("privacy_check") or {}, "submission: channel.privacy_check")
    if privacy.get("performed") is not True:
        ctx.issue("incomplete", "submission: channel.privacy_check.performed must be true (re-verify right before delivery)")
    if privacy.get("result") != "PRIVATE":
        ctx.issue("incomplete", "submission: channel.privacy_check.result must be PRIVATE; unknown visibility blocks submission")

    zip_info = current_zip(ctx)
    declared = norm_digest(sub.get("package_sha256"), "submission: package_sha256")
    if zip_info is not None and declared != zip_info[1]:
        ctx.issue("hash_mismatch", f"submission: package_sha256 {declared} != current package zip {zip_info[1]}")

    receipt = as_dict(sub.get("receipt") or {}, "submission: receipt")
    receipt_rel = as_str(receipt.get("path"), "submission: receipt.path")
    receipt_hash = norm_digest(receipt.get("sha256"), "submission: receipt.sha256")
    ctx.verify_file_hash(receipt_rel, receipt_hash, "submission receipt")
    if not record_mode:
        ctx.add_path(receipt_rel, "submission-receipt", "stage:SUBMITTED")

    limits = as_dict(sub.get("account_limits") or {}, "submission: account_limits")
    if limits.get("checked") is not True:
        ctx.issue("incomplete", "submission: account_limits.checked must be true (manual ledger of submissions)")
    as_str(limits.get("result"), "submission: account_limits.result")
    kyc = as_dict(sub.get("kyc") or {}, "submission: kyc")
    check_enum(kyc.get("status"), {"NOT_REQUIRED", "PENDING", "COMPLETED", "UNKNOWN"}, "submission: kyc.status")


VERIFIERS = {
    "PRIOR_ART_CHECKED": verify_prior_art,
    "CROSS_CHECKED": verify_cross_check,
    "FORK_PROVEN": verify_fork_proof,
    "TRIAGED": verify_triage,
}


# ---------------------------------------------------------------------------
# material lint — the fix-batch regression battery (contracts section 9)
#
# Review rounds and polish edits are themselves a defect source: rewrites have
# deleted PoC run instructions out of a validation field, injected review
# narration into reports and pointed supporting-files fields at local-only
# artifacts. lint re-checks the mechanical classes after EVERY edit batch.

LINT_ADDR_TEXT_RE = re.compile(r"(?<![0-9A-Za-z])0x[0-9a-fA-F]{40}(?![0-9a-fA-F])")
LINT_URL_RE = re.compile(r"https?://\S+")
LINT_FILE_RE = re.compile(
    r"(?<![\w/.-])(?:\./)?(?:[\w][\w.-]*/)*[\w][\w.-]*"
    r"\.(?:txt|md|log|json|pdf|zip|sh|toml|ya?ml|sol|ts|js)(?![\w-])")

VOICE_PATTERNS = [
    ("internal-finding-id", re.compile(r"\bF-[0-9a-f]{32}\b")),
    ("review-narration", re.compile(r"(?i)\b(?:this|our|the)\s+review\b")),
    ("review-narration", re.compile(r"(?i)\b(?:previous|prior|review)\s+rounds?\b")),
    ("review-narration", re.compile(r"(?i)\bpost[- ]review\b")),
    ("correction-narration", re.compile(r"(?i)\bcorrected\b|\bsynchronized\b")),
    ("internal-process", re.compile(r"(?i)\bde-?AI\b|\binternal\s+(?:numbering|review|notes?)\b")),
    ("workspace-phrasing", re.compile(r"(?i)\b(?:workspace|workdir|local[- ]only)\b")),
    ("reviewer-meta", re.compile(r"(?i)\bindependent\s+(?:session|agent|reviewer)\b")),
]

UNIVERSAL_PATTERNS = [
    ("prior-art-negation", re.compile(
        r"(?i)\bnot\s+(?:been\s+)?(?:identified|covered|reported|mentioned|disclosed|found|addressed)"
        r"\s+in\s+(?:any|all|four|three|both|the\s+\w+)")),
    ("no-audit-claim", re.compile(
        r"(?i)\bno\s+(?:published|prior|previous|known)?\s*(?:audit|report)s?"
        r"\s+(?:found|mention|cover|discuss|address)\b")),
    ("never-claim", re.compile(r"(?i)\bnever\s+(?:happened|occurred|been|executed|triggered|called|used)\b")),
    ("all-production", re.compile(r"(?i)\b(?:in|across)\s+all\s+(?:production|observed|recorded|historic)")),
    ("every-subject", re.compile(
        r"(?i)\bevery\s+(?:user|exit|redemption|transaction|deposit|withdrawal|call|invocation)")),
]

LINT_CHECK_IDS = {"addr", "attachment", "sections", "voice", "universal"}


def load_lint_allowlist(root: str) -> list:
    path = os.path.join(root, "lint-allowlist.yaml")
    if not os.path.isfile(path):
        return []
    doc = load_yaml_file(path, "lint-allowlist.yaml")
    entries = []
    for i, e in enumerate(as_list(doc.get("allow") or [], "lint-allowlist.yaml: allow")):
        e = as_dict(e, f"lint-allowlist.yaml: allow[{i}]")
        check_id = check_enum(e.get("check"), LINT_CHECK_IDS,
                              f"lint-allowlist.yaml: allow[{i}].check")
        pattern = as_str(e.get("pattern"),
                         f"lint-allowlist.yaml: allow[{i}].pattern (literal substring)")
        reason = as_str(e.get("reason"), f"lint-allowlist.yaml: allow[{i}].reason")
        scope = e.get("file")
        if scope is not None:
            scope = as_str(scope, f"lint-allowlist.yaml: allow[{i}].file")
        entries.append({"check": check_id, "pattern": pattern, "reason": reason,
                        "file": scope, "matched": False})
    return entries


def _allowlisted(entries, check_id, rel, match_text, line_text) -> bool:
    hay = f"{match_text} {line_text}".lower()
    for e in entries:
        if e["check"] != check_id or (e["file"] and e["file"] != rel):
            continue
        if e["pattern"].lower() in hay:
            e["matched"] = True
            return True
    return False


def lint_finding(root: str, doc: dict, program: dict) -> dict:
    """Lint the submission-facing surfaces (report + platform field files).

    Read-only; returns surfaces, findings (check/severity/file/line/detail)
    and the allowlist (with matched flags for stale-entry detection). BLOCK
    findings fail the run; WARN findings do not (contracts section 9).
    """
    fid = doc["id"]
    manifest_rel = f"packages/{fid}/manifest.yaml"
    manifest = load_yaml_file(safe_rel(root, manifest_rel, "package manifest"),
                              manifest_rel)
    pkg = as_dict(manifest.get("package") or {}, f"{manifest_rel}: package")
    materials = manifest.get("materials")
    plat = program_platform(program)
    spec = MATERIAL_SPECS.get(plat)

    surfaces = []  # (rel, label)
    report_rel = (as_dict(pkg.get("report") or {}, f"{manifest_rel}: package.report")).get("path")
    if isinstance(report_rel, str) and report_rel.strip():
        surfaces.append((report_rel, "report"))
    field_specs = []  # (rel, field-name)
    if isinstance(materials, dict):
        for f_ in as_list(materials.get("fields") or [], f"{manifest_rel}: materials.fields"):
            if isinstance(f_, dict) and isinstance(f_.get("path"), str) and f_["path"].strip():
                field_specs.append((f_["path"], f_.get("field")))
                surfaces.append((f_["path"], f"material:{f_.get('field')}"))

    findings = []

    def add(check, severity, rel, line, detail):
        findings.append({"check": check, "severity": severity, "file": rel,
                         "line": line, "detail": detail})

    texts = {}
    for rel, _label in surfaces:
        p = safe_rel(root, rel, "lint surface")
        if not os.path.isfile(p):
            add("sections", "BLOCK", rel, 0, "file missing from the package")
            continue
        with open(p, encoding="utf-8", errors="ignore") as f:
            texts[rel] = f.read()

    allowlist = load_lint_allowlist(root)

    def line_of(text, pos):
        return text.count("\n", 0, pos) + 1

    # addr: every 40-hex address must be a declared target (wrong-address
    # transcriptions have survived three review rounds across four packages)
    allowed_addrs = set()
    for t in doc.get("targets") or []:
        if isinstance(t, dict):
            for k in ("address", "proxy_address", "implementation_address"):
                v = t.get(k)
                if isinstance(v, str):
                    allowed_addrs.add(v.lower())
    for t in ((program.get("scope") or {}).get("targets") or []):
        if isinstance(t, dict) and isinstance(t.get("address"), str):
            allowed_addrs.add(t["address"].lower())
    if isinstance(materials, dict):
        for ft in materials.get("form_targets") or []:
            if isinstance(ft, dict) and isinstance(ft.get("address"), str):
                allowed_addrs.add(ft["address"].lower())

    for rel, _label in surfaces:
        text = texts.get(rel)
        if not text:
            continue
        for m in LINT_ADDR_TEXT_RE.finditer(text):
            addr = m.group(0).lower()
            if addr in allowed_addrs:
                continue
            ln = line_of(text, m.start())
            line_text = text.splitlines()[ln - 1]
            if _allowlisted(allowlist, "addr", rel, addr, line_text):
                continue
            add("addr", "BLOCK", rel, ln,
                f"address {addr} is not a cross-check target, scope target or declared "
                "form target — verify it or allowlist it with a reason")

    # attachment: every file reference must be recipient-visible (inside the
    # bundle zip, a declared attachment, or the bundle/export name itself)
    members = set()
    zip_rel = (as_dict(pkg.get("zip") or {}, f"{manifest_rel}: package.zip")).get("path")
    if isinstance(zip_rel, str) and zip_rel.strip():
        zp = safe_rel(root, zip_rel, "package zip")
        if os.path.isfile(zp):
            try:
                with zipfile.ZipFile(zp) as zf:
                    members = {n for n in zf.namelist() if not n.endswith("/")}
            except (zipfile.BadZipFile, OSError):
                pass
    if isinstance(materials, dict) and spec:
        members.add(spec["zip_name"].format(slug=materials.get("slug") or ""))
    if isinstance(materials, dict):
        for at in materials.get("attachments") or []:
            if isinstance(at, dict) and isinstance(at.get("path"), str):
                members.add(at["path"])
                members.add(os.path.basename(at["path"]))
    members.update(rel for rel, _ in surfaces)

    def ref_hit(token):
        t = token[2:] if token.startswith("./") else token
        if t in members:
            return True
        return any(m.endswith("/" + t) or t.endswith("/" + m) for m in members)

    for rel, _label in surfaces:
        text = texts.get(rel)
        if not text:
            continue
        stripped = LINT_URL_RE.sub(" ", text)
        for m in LINT_FILE_RE.finditer(stripped):
            token = m.group(0)
            if ref_hit(token):
                continue
            ln = line_of(stripped, m.start())
            lines = stripped.splitlines()
            line_text = lines[ln - 1] if lines else ""
            if _allowlisted(allowlist, "attachment", rel, token, line_text):
                continue
            add("attachment", "BLOCK", rel, ln,
                f"file reference {token!r} is not in the attachment set (zip members, "
                "declared attachments or the bundle name) — the recipient cannot see it")

    # sections: the platform form contract survives every edit (the
    # "rewrite deleted the run instructions" regression)
    if spec and field_specs:
        declared = {name: rel for rel, name in field_specs}
        for name, fspec in spec["fields"].items():
            rel = declared.get(name)
            if rel is None:
                add("sections", "BLOCK", manifest_rel, 0,
                    f"material field {name!r} not declared — the platform form needs it")
                continue
            text = texts.get(rel)
            if text is None:
                continue
            for header in fspec.get("headers", ()):
                if header not in text:
                    add("sections", "BLOCK", rel, 0,
                        f"required section {header!r} missing — an edit dropped it "
                        f"({name} field)")
            if fspec.get("upload_line") and text and not UPLOAD_LINE_RE.search(text):
                add("sections", "BLOCK", rel, 0,
                    f"the 'Upload: <file>' line naming the bundle is missing ({name} field)")
            if name in (spec.get("permalink_fields") or ()):
                for m in GITHUB_URL_RE.finditer(text):
                    url = m.group(0).rstrip(".,;:)")
                    if GITHUB_PERMALINK_RE.fullmatch(url):
                        continue
                    ln = line_of(text, m.start())
                    lines = text.splitlines()
                    line_text = lines[ln - 1] if lines else ""
                    if _allowlisted(allowlist, "sections", rel, url, line_text):
                        continue
                    add("sections", "BLOCK", rel, ln,
                        f"github reference {url!r} is not a commit-pinned permalink "
                        f"({name} field) — contest judging requires "
                        "github.com/<org>/<repo>/blob/<40-hex>/…#L…")

    # voice: submission-facing text states findings, not its own history
    for rel, _label in surfaces:
        text = texts.get(rel)
        if not text:
            continue
        for pid, pattern in VOICE_PATTERNS:
            for m in pattern.finditer(text):
                ln = line_of(text, m.start())
                lines = text.splitlines()
                line_text = lines[ln - 1] if lines else ""
                if _allowlisted(allowlist, "voice", rel, m.group(0), line_text):
                    continue
                add("voice", "BLOCK", rel, ln,
                    f"internal/process vocabulary ({pid}): {m.group(0)!r} — remove it or "
                    "allowlist it with a reason")
        for pid, pattern in UNIVERSAL_PATTERNS:
            for m in pattern.finditer(text):
                ln = line_of(text, m.start())
                lines = text.splitlines()
                line_text = lines[ln - 1] if lines else ""
                if _allowlisted(allowlist, "universal", rel, m.group(0), line_text):
                    continue
                add("universal", "WARN", rel, ln,
                    f"universal claim ({pid}): {m.group(0)!r} — must cite the per-report "
                    "prior-art NO_MATCH entries or a source derivation, or be scoped down")

    for e in allowlist:
        if not e["matched"]:
            add("universal", "WARN", "lint-allowlist.yaml", 0,
                f"stale allowlist entry ({e['check']}): {e['pattern']!r} matched nothing — "
                "remove it before it rots into noise")

    return {"surfaces": surfaces, "findings": findings, "allowlist": allowlist}


# ---------------------------------------------------------------------------
# reason substance

def check_review_substance(reviewer: str, reason: str, ctx: Ctx) -> None:
    as_str(reviewer, "--reviewer")
    as_str(reason, "--reason")
    if len(reason.strip()) < 30:
        raise LifecycleError("--reason must be a substantive review note (>= 30 characters)")
    tokens = []
    for inp in ctx.inputs:
        if "path" in inp:
            tokens.append(inp["path"])
            tokens.append(os.path.basename(inp["path"]))
    if not tokens:
        return  # no artifacts consumed by this gate; length check above suffices
    for ev in ctx.doc.get("evidence", []):
        if isinstance(ev.get("path"), str):
            tokens.append(ev["path"])
            tokens.append(os.path.basename(ev["path"]))
    if not any(t and t in reason for t in tokens):
        raise LifecycleError(
            "--reason must cite at least one artifact consumed by this gate "
            "(e.g. an evidence path such as " + (tokens[0] if tokens else "evidence/...") + ")"
        )


# ---------------------------------------------------------------------------
# index

def next_step_text(doc: dict, program: dict) -> str:
    disp = doc["disposition"]
    appeal = (doc.get("appeal") or {}).get("status", "NONE")
    deadline = (doc.get("appeal") or {}).get("deadline")
    if disp != "OPEN":
        if appeal in ("DRAFTED", "SENT"):
            return f"appeal {appeal} (deadline {deadline or 'unknown'})"
        if disp == "MERGED":
            return f"merged into {doc.get('duplicate_of')}"
        return f"closed: {disp}"
    idx = STAGES.index(doc["stage"])
    if idx == len(STAGES) - 1:
        resp = ((doc.get("submission") or {}).get("response") or {})
        if resp:
            return f"platform decision {resp.get('decision')} recorded"
        return "await platform response; record response/appeal receipts"
    target = STAGES[idx + 1]
    hint = DEFAULT_INPUTS[target].format(fid=doc["id"])
    return f"advance -> {target} (produce {hint})"


def rebuild_index(root: str) -> None:
    program = load_program(root)
    rows = []
    hashes = []
    for fid in list_findings(root):
        path = ledger_path(root, fid)
        try:
            fm, _ = load_ledger(root, fid)
        except LifecycleError as exc:
            rows.append((fid, f"UNREADABLE: {exc}", "-", "-", "-", "-", "-"))
            hashes.append(f"{fid}: unreadable")
            continue
        blockers = [b for b in (fm.get("blockers") or []) if not b.get("resolved_at")]
        rows.append((
            fid, fm.get("title", ""), fm["stage"], fm["disposition"],
            (fm.get("appeal") or {}).get("status", "NONE"),
            str(len(blockers)),
            next_step_text(fm, program),
        ))
        hashes.append(f"{fid}: {sha256_file(path)}")
    lines = [
        f"# Finding index — {program['program']['id']}",
        "",
        "_Derived file; the ledger files are authoritative. Rebuild with `lifecycle.py index --case-root <root>`._",
        "",
        "| ID | Title | Stage | Disposition | Appeal | Blockers | Next step |",
        "|----|-------|-------|-------------|--------|----------|-----------|",
    ]
    for r in rows:
        lines.append("| " + " | ".join(str(c).replace("|", "\\|") for c in r) + " |")
    lines += ["", "<!-- ledger-sha256", *hashes, "-->"]
    atomic_write(os.path.join(root, "index.md"), "\n".join(lines) + "\n")


def rebuild_index_tolerant(root: str) -> bool:
    try:
        rebuild_index(root)
        return True
    except Exception as exc:  # index failure never rolls back the ledger
        print(f"NOTE: ledger saved, index needs repair ({exc}); "
              f"run: lifecycle.py index --case-root {root}", file=sys.stderr)
        return False


# ---------------------------------------------------------------------------
# register

REQUIRED_PRESCREEN = {"scope", "authority", "exclusion", "duplication"}


def render_finding_body(inp: dict, fid: str, program_id: str) -> str:
    prescreen = inp.get("prescreen") or []
    src = inp.get("sources") or {}
    lines = [
        f"# {inp.get('title', '(untitled)')}",
        "",
        "> Snapshot rendered at registration. The frontmatter is authoritative;",
        "> update state only through the CLI.",
        "",
        "## Claim",
        "", str(inp.get("claim", "")), "",
        "## Sources",
        "", f"- program: `{program_id}`",
        f"- auditor: {src.get('auditor', '(unknown)')}",
        f"- original finding id: {src.get('original_finding_id', '(none)')}",
        f"- audit round: {src.get('audit_round', '(none)')}", "",
        "## Pre-screen at registration",
        "",
        "| aspect | status | evidence | explanation |",
        "|--------|--------|----------|-------------|",
    ]
    for item in prescreen:
        lines.append(
            f"| {item.get('aspect','')} | {item.get('status','')} | "
            f"{str(item.get('evidence','')).replace('|', '\\|')} | "
            f"{str(item.get('explanation','')).replace('|', '\\|')} |"
        )
    lines += [
        "",
        "## Next steps",
        "",
        "- dedup against the project's published audits: produce `evidence/%s/prior-art.yaml`" % fid,
        "- then produce `evidence/%s/cross-check.yaml` and `assessment.md`" % fid,
        "",
    ]
    return "\n".join(lines)


def reject_todo(label: str, value) -> None:
    """Reject unresolved `ingest` draft placeholders."""
    if isinstance(value, str) and value.strip().upper().startswith("TODO"):
        raise LifecycleError(
            f"finding source: {label} is an unresolved TODO; complete the ingest draft "
            "before registering")


AUDIT_CONFIG_NAME = "audit-skills.yaml"
HANDOFF_SCHEMA = "whitehexlabs.audit-handoff/v1"
ARTIFACTS_SCHEMA = "whitehexlabs.audit-artifacts/v1"


def warn_legacy_audit_config(root: str) -> None:
    """A legacy audit-skills.yaml only warns; audit execution moved out."""
    if os.path.isfile(os.path.join(root, AUDIT_CONFIG_NAME)):
        print("NOTE: audit-skills.yaml is no longer executed by finding-lifecycle.\n"
              "Use audit-orchestrator for audit execution.", file=sys.stderr)


def cmd_register(a) -> int:
    root = require_case(a)
    warn_legacy_audit_config(root)
    program = load_program(root)
    inp = load_yaml_file(a.src, "finding source")
    restrict_keys(inp, {"title", "claim", "program_id", "sources", "prescreen", "targets"},
                  "finding source")
    title = as_str(inp.get("title"), "finding source: title")
    claim = as_str(inp.get("claim"), "finding source: claim")
    reject_todo("title", title)
    reject_todo("claim", claim)
    if inp.get("program_id") is not None and inp["program_id"] != program["program"]["id"]:
        raise LifecycleError(
            f"finding source program_id {inp['program_id']!r} != case program {program['program']['id']!r}")

    sources = as_dict(inp.get("sources") or {}, "finding source: sources")
    if not (sources.get("auditor") or sources.get("original_finding_id") or sources.get("files")):
        raise LifecycleError("finding source: sources must include auditor, original_finding_id, or files (traceable origin)")
    reject_todo("sources.auditor", sources.get("auditor"))
    files_list = as_list(sources.get("files") or [], "finding source: sources.files")

    prescreen = as_list(inp.get("prescreen") or [], "finding source: prescreen")
    aspects = {}
    for i, item in enumerate(prescreen):
        item = as_dict(item, f"finding source: prescreen[{i}]")
        aspect = as_str(item.get("aspect"), f"finding source: prescreen[{i}].aspect")
        status = check_enum(item.get("status"), {"PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE"},
                            f"finding source: prescreen[{i}].status")
        as_str(item.get("evidence"), f"finding source: prescreen[{i}].evidence")
        as_str(item.get("explanation"), f"finding source: prescreen[{i}].explanation")
        reject_todo(f"prescreen[{i}].evidence", item.get("evidence"))
        reject_todo(f"prescreen[{i}].explanation", item.get("explanation"))
        aspects[aspect] = status
    missing_aspects = REQUIRED_PRESCREEN - set(aspects)
    if missing_aspects:
        raise LifecycleError(f"finding source: prescreen must cover {sorted(REQUIRED_PRESCREEN)}; missing {sorted(missing_aspects)}")
    if aspects.get("duplication") != "PASS":
        raise LifecycleError("finding source: prescreen duplication must be PASS; resolve duplicates by merging instead of registering")

    targets = []
    for i, t in enumerate(as_list(inp.get("targets") or [], "finding source: targets")):
        t = as_dict(t, f"finding source: targets[{i}]")
        check_addr(t.get("address"), f"finding source: targets[{i}].address")

    fid = "F-" + uuid.uuid4().hex
    ev_dir = os.path.join(root, "evidence", fid)
    os.makedirs(os.path.join(ev_dir, "sources"), exist_ok=True)

    source_files = []
    for i, f_ in enumerate(files_list):
        f_ = as_dict(f_, f"finding source: sources.files[{i}]")
        origin = as_str(f_.get("path"), f"finding source: sources.files[{i}].path (read from anywhere)")
        expanded = os.path.expanduser(origin)
        if not os.path.isabs(expanded):
            in_root = os.path.join(root, expanded)
            origin = in_root if os.path.isfile(in_root) else expanded
        note = f_.get("note", "")
        base = os.path.basename(origin)
        dest_rel = f"evidence/{fid}/sources/{base}"
        dest = safe_rel(root, dest_rel, "sources copy")
        n = 1
        while os.path.exists(dest):
            dest_rel = f"evidence/{fid}/sources/{n}-{base}"
            dest = safe_rel(root, dest_rel, "sources copy")
            n += 1
        if not os.path.isfile(origin):
            raise LifecycleError(f"finding source: sources.files[{i}].path not found: {origin}")
        shutil.copyfile(origin, dest)
        source_files.append({"path": dest_rel, "sha256": sha256_file(dest), "note": note})

    reg_input_rel = f"evidence/{fid}/register-input.yaml"
    with open(safe_rel(root, reg_input_rel, "register input"), "w", encoding="utf-8") as f:
        yaml.safe_dump(inp, f, sort_keys=False, allow_unicode=True)

    doc = {
        "id": fid, "title": title, "program_id": program["program"]["id"],
        "created_at": now_iso(), "updated_at": now_iso(),
        "stage": "DISCOVERED", "disposition": "OPEN", "revision": 0,
        "sources": {
            "auditor": sources.get("auditor"),
            "original_finding_id": sources.get("original_finding_id"),
            "audit_round": sources.get("audit_round"),
            "files": source_files,
        },
        "targets": targets,
        "root_cause": {"claim": claim, "variants": []},
        "duplicate_of": None,
        "severity": {"candidate": sources.get("candidate_severity"), "final": None,
                     "matrix_entry": None, "justification": None},
        "program_snapshot": {"sha256": None, "checked_at": None},
        "prior_art": None,
        "evidence": [],
        "gates": [],
        "blockers": [],
        "corrections": [],
        "submission": default_submission_block(),
        "appeal": default_appeal_block(),
        "history": [],
    }
    upsert_evidence(doc, reg_input_rel, sha256_file(safe_rel(root, reg_input_rel, "register input")),
                    "register-input", "register")
    for sf in source_files:
        upsert_evidence(doc, sf["path"], sf["sha256"], f"source-doc:{sf.get('note','')}", "register")
    append_history(doc, "registered", {
        "prescreen": aspects,
        "sources": {k: sources.get(k) for k in ("auditor", "original_finding_id", "audit_round")},
    })

    with CaseLock(root):
        save_ledger(root, doc, render_finding_body(inp, fid, program["program"]["id"]))
    rebuild_index_tolerant(root)

    fail_aspects = [k for k, v in aspects.items() if v == "FAIL"]
    lines = [f"registered {fid} (revision 1) at stage DISCOVERED"]
    if fail_aspects:
        lines.append(f"NOTE: pre-screen FAIL on {fail_aspects}; close as INELIGIBLE with evidence if confirmed")
    emit({"lines": lines, "id": fid, "revision": doc["revision"]}, a.json)
    return EXIT_OK


# ---------------------------------------------------------------------------
# ingest: name-based discovery of audit artifacts

JUNK_DIR_NAMES = {".git", ".idea", ".zcode", ".vscode", "node_modules", "out",
                  "cache", "lib", "target", "__pycache__", "broadcast"}
SKIP_FILE_EXTS = {".zip", ".tar", ".gz", ".7z", ".tgz", ".png", ".jpg", ".jpeg",
                  ".gif", ".svg", ".ico", ".lock", ".bin", ".db"}


def _inside(root_real: str, p: str) -> bool:
    return p == root_real or p.startswith(root_real + os.sep)


def _scannable_file(name: str) -> bool:
    if name.startswith("."):
        return False
    ext = os.path.splitext(name)[1].lower()
    return ext not in SKIP_FILE_EXTS


def render_ingest_draft(origin: str, files, pattern: str) -> str:
    base = os.path.basename(origin.rstrip(os.sep)) or origin
    file_lines = "\n".join(
        f'    - path: "{f}"\n      note: "discovered by ingest (name matched \'{pattern}\')"'
        for f in files)
    return f'''# Draft scaffolded by `ingest` from: {origin}
# Discovery is NAME-BASED ONLY — nothing here has been parsed or judged.
# Complete every TODO, split into ONE FILE PER FINDING if the source contains
# several distinct root causes, then register each completed file:
#   lifecycle.py register --case-root <root> --from <this-file>
# `register` rejects unresolved TODO fields by design.
title: "TODO: one-line vulnerability claim ({base})"
claim: "TODO: what the vulnerability is, on which deployment, under which preconditions"
sources:
  auditor: "TODO: which audit skill / session produced this"
  original_finding_id: null
  audit_round: null
  files:
{file_lines}
prescreen:
  - {{aspect: scope, status: UNKNOWN, evidence: "TODO", explanation: "TODO: is the target within program scope"}}
  - {{aspect: authority, status: UNKNOWN, evidence: "TODO", explanation: "TODO: does the attack require any privileged role"}}
  - {{aspect: exclusion, status: UNKNOWN, evidence: "TODO", explanation: "TODO: does any exclusion clause apply"}}
  - {{aspect: duplication, status: UNKNOWN, evidence: "TODO", explanation: "TODO: check index.md and prior findings; must become PASS before registering"}}
targets: []
'''


def cmd_ingest(a) -> int:
    root = require_case(a)
    warn_legacy_audit_config(root)
    root_real = os.path.realpath(root)
    scan = os.path.realpath(a.scan_dir or os.getcwd())
    if not os.path.isdir(scan):
        raise LifecycleError(f"--scan-dir not found: {a.scan_dir!r}")
    pattern = (a.pattern or "audit").strip().lower()
    if not pattern:
        raise LifecycleError("--pattern must not be empty")

    bundles = []  # [{origin, files}]
    for dirpath, dirnames, filenames in os.walk(scan):
        dirnames[:] = [d for d in sorted(dirnames)
                       if d not in JUNK_DIR_NAMES and not d.startswith(".")
                       and not _inside(root_real, os.path.realpath(os.path.join(dirpath, d)))]
        rel = os.path.relpath(dirpath, scan)
        comps = [] if rel == "." else rel.split(os.sep)
        dir_matched = any(pattern in c.lower() for c in comps)
        if dir_matched:
            owner = next((b["origin"] for b in bundles
                          if dirpath.startswith(b["origin"] + os.sep)), None)
            if owner is None:
                bundles.append({"origin": dirpath, "files": []})
                owner = dirpath
            bundle = next(b for b in bundles if b["origin"] == owner)
            bundle["files"].extend(
                os.path.join(dirpath, f) for f in sorted(filenames)
                if _scannable_file(f))
        else:
            for f in sorted(filenames):
                if pattern in f.lower() and _scannable_file(f):
                    bundles.append({"origin": os.path.join(dirpath, f),
                                    "files": [os.path.join(dirpath, f)]})
    bundles = [b for b in bundles if b["files"]]

    ingest_dir = os.path.join(root, "ingest")
    os.makedirs(ingest_dir, exist_ok=True)
    lines = [f"scanned {scan} for *{pattern}*: {len(bundles)} bundle(s) found"]
    drafts = []
    for b in bundles:
        origin = b["origin"]
        slug = re.sub(r"[^0-9A-Za-z]+", "-", os.path.basename(origin.rstrip(os.sep)))
        slug = (slug.strip("-").lower() or "bundle")[:40]
        tag = sha256_bytes(origin.encode("utf-8"))[:8]
        name = f"finding-source.{slug}-{tag}.yaml"
        draft_path = os.path.join(ingest_dir, name)
        if os.path.exists(draft_path):
            lines.append(f"  draft exists (skipped): ingest/{name} <- {origin}")
            drafts.append({"draft": f"ingest/{name}", "origin": origin,
                           "files": b["files"], "status": "exists"})
            continue
        with open(draft_path, "w", encoding="utf-8") as f:
            f.write(render_ingest_draft(origin, b["files"], pattern))
        lines.append(f"  draft: ingest/{name} <- {origin} ({len(b['files'])} file(s))")
        drafts.append({"draft": f"ingest/{name}", "origin": origin,
                       "files": b["files"], "status": "created"})
    if bundles:
        lines.append("next: complete every TODO in the drafts (one file per finding), "
                     "set the duplication prescreen to PASS, then `register --from` each")
    else:
        lines.append("nothing matched; pass --pattern to search for other name substrings")
    emit({"lines": lines, "scan": scan, "pattern": pattern,
          "bundles": [{"origin": b["origin"], "files": b["files"]} for b in bundles],
          "drafts": drafts}, a.json)
    return EXIT_OK


# ---------------------------------------------------------------------------
# import-audit: canonical handoff import (audit-orchestrator -> lifecycle)

def _handoff_resolve(base: str, confine: str, rel, what: str) -> str:
    """Resolve a handoff-relative path (against `base`) while staying inside
    the handoff run root (`confine`); reject traversal and escapes."""
    if not isinstance(rel, str) or not rel.strip():
        raise LifecycleError(f"handoff manifest: {what} missing")
    if os.path.isabs(rel):
        raise LifecycleError(f"handoff manifest: {what} must be relative: {rel!r}")
    p = os.path.realpath(os.path.join(base, rel))
    c = os.path.realpath(confine)
    if p != c and not p.startswith(c + os.sep):
        raise LifecycleError(f"handoff manifest: {what} escapes the handoff run root: {rel!r}")
    return p


def _verify_tree(path: str, expected_tree: str, expected_count, what: str) -> None:
    """Deterministic tree digest identical to audit-orchestrator's."""
    records = []
    for dirpath, _dirnames, filenames in os.walk(path):
        for name in filenames:
            full = os.path.join(dirpath, name)
            relp = os.path.relpath(full, path).replace(os.sep, "/")
            records.append((relp, sha256_file(full)))
    records.sort()
    stream = "".join(f"{r}\0{d}\n" for r, d in records)
    digest = sha256_bytes(stream.encode("utf-8"))
    if digest != expected_tree or len(records) != expected_count:
        raise LifecycleError(f"{what}: directory tree hash mismatch: {path}")


def verify_handoff(manifest_path: str) -> dict:
    """Verify a finalized handoff bundle end to end; returns the manifest.

    Checks: schema, FINALIZED status, analysis existence+hash, artifact
    manifests existence+hash, canonical artifact existence+hash/tree-hash,
    candidate count+uniqueness+hashes. Path traversal and symlink escape
    are rejected by resolution. Raises LifecycleError on any violation."""
    manifest_path = os.path.realpath(manifest_path)
    if not os.path.isfile(manifest_path):
        raise LifecycleError(f"handoff manifest not found: {manifest_path}")
    m = load_yaml_file(manifest_path, "handoff manifest")
    restrict_keys(m, {"schema", "run_id", "status", "created_at", "target",
                      "audit", "steps", "candidates", "candidate_count"},
                  "handoff manifest")
    if m.get("schema") != HANDOFF_SCHEMA:
        raise LifecycleError(
            f"handoff manifest: unsupported schema {m.get('schema')!r}; expected {HANDOFF_SCHEMA}")
    if m.get("status") != "FINALIZED":
        raise LifecycleError(
            f"handoff manifest: status must be FINALIZED, got {m.get('status')!r}")
    run_id = as_str(m.get("run_id"), "handoff manifest: run_id")
    if not re.fullmatch(r"run-[0-9A-Za-z._-]+", run_id):
        raise LifecycleError(f"handoff manifest: malformed run_id {run_id!r}")
    hdir = os.path.dirname(manifest_path)
    rdir = os.path.dirname(hdir)  # audits/<run-id>/

    audit_block = as_dict(m.get("audit") or {}, "handoff manifest: audit")
    analysis = as_dict(audit_block.get("analysis") or {},
                       "handoff manifest: audit.analysis")
    apath = _handoff_resolve(hdir, rdir, analysis.get("path"), "audit.analysis.path")
    if not os.path.isfile(apath):
        raise LifecycleError(f"handoff analysis missing: {analysis.get('path')!r}")
    if sha256_file(apath) != analysis.get("sha256"):
        raise LifecycleError("handoff analysis hash mismatch")

    steps = as_list(m.get("steps"), "handoff manifest: steps")
    if not steps:
        raise LifecycleError("handoff manifest: steps must not be empty")
    for i, s in enumerate(steps):
        s = as_dict(s, f"handoff manifest: steps[{i}]")
        am = as_dict(s.get("artifact_manifest") or {},
                     f"handoff manifest: steps[{i}].artifact_manifest")
        mp = _handoff_resolve(hdir, rdir, am.get("path"),
                              f"steps[{i}].artifact_manifest.path")
        if not os.path.isfile(mp):
            raise LifecycleError(
                f"step {s.get('step')}: artifact manifest missing: {am.get('path')!r}")
        if sha256_file(mp) != am.get("sha256"):
            raise LifecycleError(f"step {s.get('step')}: artifact manifest hash mismatch")
        # every canonical artifact the manifest binds must exist and hash right
        am_doc = load_yaml_file(mp, "artifact manifest")
        if am_doc.get("schema") != ARTIFACTS_SCHEMA:
            raise LifecycleError(
                f"step {s.get('step')}: artifact manifest schema must be {ARTIFACTS_SCHEMA}")
        sdir = os.path.dirname(mp)
        for j, e in enumerate(as_list(am_doc.get("artifacts"),
                                      "artifact manifest: artifacts")):
            e = as_dict(e, f"artifact manifest: artifacts[{j}]")
            relp = e.get("path")
            if not isinstance(relp, str) or not relp.strip() or os.path.isabs(relp):
                raise LifecycleError(
                    f"step {s.get('step')}: artifact {e.get('id')!r} has an invalid path")
            full = os.path.realpath(os.path.join(sdir, relp))
            if not full.startswith(os.path.realpath(sdir) + os.sep):
                raise LifecycleError(
                    f"step {s.get('step')}: artifact {e.get('id')!r} escapes its step dir")
            if not os.path.exists(full):
                raise LifecycleError(
                    f"step {s.get('step')}: source artifact missing: {relp}")
            if os.path.isdir(full):
                _verify_tree(full, e.get("tree_sha256"), e.get("file_count"),
                             f"step {s.get('step')}: artifact {e.get('id')!r}")
            elif sha256_file(full) != e.get("sha256"):
                raise LifecycleError(
                    f"step {s.get('step')}: source artifact hash mismatch: {relp}")

    cands = as_list(m.get("candidates"), "handoff manifest: candidates")
    if m.get("candidate_count") != len(cands):
        raise LifecycleError("handoff manifest: candidate_count != len(candidates)")
    ids = set()
    for i, c in enumerate(cands):
        c = as_dict(c, f"handoff manifest: candidates[{i}]")
        cid = as_str(c.get("id"), f"handoff manifest: candidates[{i}].id")
        if cid in ids:
            raise LifecycleError(f"handoff manifest: duplicate candidate id {cid!r}")
        ids.add(cid)
        cp = _handoff_resolve(hdir, rdir, c.get("path"), f"candidates[{i}].path")
        if not os.path.isfile(cp):
            raise LifecycleError(f"candidate {cid}: file missing: {c.get('path')!r}")
        if sha256_file(cp) != c.get("sha256"):
            raise LifecycleError(f"candidate {cid}: hash mismatch")
    return m


def render_handoff_draft(run_id: str, cand: dict, files: list) -> str:
    file_lines = "\n".join(
        f'    - path: "{f}"\n      note: "scaffolded by import-audit from handoff {run_id}"'
        for f in files)
    return f'''# Draft scaffolded by `import-audit` from finalized handoff {run_id}.
# Provenance fields are pre-filled from audit candidate {cand.get("id")};
# every TODO must still be completed by hand (import never registers or
# pre-screens findings), then:
#   lifecycle.py register --case-root <root> --from <this-file>
title: {json.dumps(cand.get("title"))}
claim: {json.dumps(cand.get("claim"))}
sources:
  auditor: "audit-orchestrator"
  original_finding_id: "{cand.get("id")}"
  audit_round: "{run_id}"
  files:
{file_lines}
prescreen:
  - {{aspect: scope, status: UNKNOWN, evidence: "TODO", explanation: "TODO: is the target within program scope"}}
  - {{aspect: authority, status: UNKNOWN, evidence: "TODO", explanation: "TODO: does the attack require any privileged role"}}
  - {{aspect: exclusion, status: UNKNOWN, evidence: "TODO", explanation: "TODO: does any exclusion clause apply"}}
  - {{aspect: duplication, status: UNKNOWN, evidence: "TODO", explanation: "TODO: check index.md and prior findings; must become PASS before registering"}}
targets: []
'''


def cmd_import_audit(a) -> int:
    root = require_case(a)
    warn_legacy_audit_config(root)
    m = verify_handoff(a.handoff)
    run_id = m["run_id"]
    manifest_path = os.path.realpath(a.handoff)
    manifest_hash = sha256_file(manifest_path)
    hdir = os.path.dirname(manifest_path)
    rdir = os.path.dirname(hdir)  # audits/<run-id>/

    dest_root = os.path.join(root, "imports", "audit", run_id)
    dest_manifest = os.path.join(dest_root, "manifest.yaml")

    # idempotency keyed by the finalized manifest hash; fail closed on drift
    if os.path.isfile(dest_manifest):
        existing = sha256_file(dest_manifest)
        if existing == manifest_hash:
            drafts = sorted(
                f"ingest/{run_id}/{n}" for n in
                (os.listdir(os.path.join(root, "ingest", run_id))
                 if os.path.isdir(os.path.join(root, "ingest", run_id)) else []))
            emit({"lines": [f"handoff {run_id} already imported (manifest hash matches); "
                            "no changes"] + ([f"  draft: {d}" for d in drafts] or []),
                  "run_id": run_id, "status": "already-imported",
                  "drafts": drafts}, a.json)
            return EXIT_OK
        raise LifecycleError(
            f"imports/audit/{run_id}/manifest.yaml exists with a different hash; "
            "previously imported audit evidence is never overwritten — investigate "
            "or import under a new run id")

    with CaseLock(root):
        os.makedirs(os.path.join(dest_root, "candidates"), exist_ok=True)
        os.makedirs(os.path.join(dest_root, "artifact-manifests"), exist_ok=True)
        os.makedirs(os.path.join(dest_root, "sources"), exist_ok=True)

        # immutable copies: manifest, analysis, candidates
        shutil.copyfile(manifest_path, dest_manifest)
        analysis = as_dict((m.get("audit") or {}).get("analysis") or {},
                           "handoff manifest: audit.analysis")
        shutil.copyfile(_handoff_resolve(hdir, rdir, analysis.get("path"), "analysis path"),
                        os.path.join(dest_root, "analysis.md"))
        for c in as_list(m.get("candidates"), "handoff manifest: candidates"):
            src = _handoff_resolve(hdir, rdir, c.get("path"), "candidate path")
            shutil.copyfile(src, os.path.join(dest_root, "candidates",
                                              f"{c['id']}.yaml"))

        # per-step artifact manifests + every canonical artifact they bind
        imported_reports = {}  # step -> imported primary report path (case-relative)
        for s in as_list(m.get("steps"), "handoff manifest: steps"):
            am = as_dict(s.get("artifact_manifest") or {}, "step artifact_manifest")
            mp = _handoff_resolve(hdir, rdir, am.get("path"), "artifact_manifest path")
            am_doc = load_yaml_file(mp, "artifact manifest")
            shutil.copyfile(mp, os.path.join(dest_root, "artifact-manifests",
                                             f"step-{s['step']}.yaml"))
            sdir = os.path.dirname(mp)
            for e in as_list(am_doc.get("artifacts"), "artifact manifest: artifacts"):
                e = as_dict(e, "artifact entry")
                src = os.path.realpath(os.path.join(sdir, e["path"]))
                rel_in_step = e["path"]
                dest = os.path.join(dest_root, "sources", f"step-{s['step']}",
                                    rel_in_step)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                if os.path.isdir(src):
                    shutil.copytree(src, dest, dirs_exist_ok=True)
                else:
                    shutil.copyfile(src, dest)
                if e.get("id") == "primary-report":
                    imported_reports[s["step"]] = os.path.relpath(dest, root)

    # finding-source drafts: one per candidate, provenance pre-filled,
    # prescreen left UNKNOWN/TODO (never guessed, never auto-registered)
    cand_docs = {}
    for c in as_list(m.get("candidates"), "handoff manifest: candidates"):
        cp = _handoff_resolve(hdir, rdir, c.get("path"), "candidate path")
        cand_docs[c["id"]] = load_yaml_file(cp, "audit candidate")
    ingest_dir = os.path.join(root, "ingest", run_id)
    drafts = []
    analysis_rel = os.path.relpath(os.path.join(dest_root, "analysis.md"), root)
    for cid, doc in sorted(cand_docs.items()):
        os.makedirs(ingest_dir, exist_ok=True)
        files = [analysis_rel]
        steps_used = sorted({s.get("step") for s in as_list(doc.get("sources") or [],
                                                            "candidate sources")
                            if isinstance(s, dict) and isinstance(s.get("step"), int)})
        for step_no in steps_used:
            if step_no in imported_reports:
                files.append(imported_reports[step_no])
        draft_rel = f"ingest/{run_id}/finding-source.{cid}.yaml"
        draft_path = os.path.join(root, draft_rel)
        if not os.path.exists(draft_path):
            with open(draft_path, "w", encoding="utf-8") as f:
                f.write(render_handoff_draft(run_id, doc, files))
        drafts.append(draft_rel)

    lines = [f"imported finalized audit handoff {run_id}: "
             f"{m.get('candidate_count')} candidate(s)",
             f"  evidence: imports/audit/{run_id}/ (independent of the audit workspace)"]
    if drafts:
        lines.append("next: complete every TODO in the drafts (one per candidate), "
                     "set the duplication prescreen to PASS, then `register --from` each")
    else:
        lines.append("zero candidates — analysis preserved for provenance; nothing to register")
    emit({"lines": lines, "run_id": run_id, "status": "imported",
          "import_root": f"imports/audit/{run_id}",
          "candidates": sorted(cand_docs), "drafts": drafts}, a.json)
    return EXIT_OK


# ---------------------------------------------------------------------------
# check / advance

def gate_context(root: str, a, need_program=True):
    doc, _ = load_ledger(root, a.id)
    program = load_program(root) if need_program else {}
    ctx = Ctx(root, program, doc)
    return doc, ctx


def run_gate(root: str, a, command: str):
    doc, ctx = gate_context(root, a)
    if doc["disposition"] != "OPEN":
        raise LifecycleError(f"{a.id} is closed ({doc['disposition']}); reopen before advancing")
    idx = STAGES.index(doc["stage"])
    if idx == len(STAGES) - 1:
        raise LifecycleError(f"{a.id} is already at SUBMITTED (terminal stage)")
    target = STAGES[idx + 1]
    if getattr(a, "stage", None) and a.stage != target:
        raise LifecycleError(f"--stage {a.stage} is not the next stage (next is {target})")

    verify_integrity(ctx)
    if ctx.issues:
        # a prior gate went stale (changed artifact/field) — fail before
        # even looking at the next stage input; reopen to repair
        raise GateFailure("integrity", ctx.issues, [
            "prior gate inputs changed; run `resume` to inspect, then `reopen` from the affected stage",
        ])
    if target in VERIFIERS:
        _, inp = load_stage_input(root, a.id, target, a.input, ctx=ctx)
        if inp is not None:
            VERIFIERS[target](ctx, inp)
    elif target == "PACKAGED":
        rel = a.input or DEFAULT_INPUTS["PACKAGED"].format(fid=a.id)
        p = safe_rel(root, rel, "stage input")
        if not os.path.isfile(p):
            ctx.issue("missing", f"stage input not found: {rel}")
        else:
            inp = load_yaml_file(p, "PACKAGED input")
            verify_package(ctx, inp, rel)
    elif target == "SELF_REVIEWED":
        _, inp = load_stage_input(root, a.id, target, a.input, ctx=ctx)
        if inp is not None:
            verify_self_review(ctx, inp)
    elif target == "SUBMITTED":
        verify_submission_block(ctx, doc.get("submission"))
    else:  # pragma: no cover
        raise LifecycleError(f"no verifier for stage {target}")

    gate_id = f"advance:{target}"
    if ctx.issues:
        hints = [h.format(fid=a.id) for h in STAGE_HINTS[target]]
        raise GateFailure(gate_id, ctx.issues, hints)
    return doc, ctx, target, gate_id


def cmd_check(a) -> int:
    root = require_case(a)
    try:
        _, ctx, target, gate_id = run_gate(root, a, "check")
    except GateFailure as gf:
        emit_gate_failure(gf, a)
        return EXIT_GATE
    emit({
        "lines": [f"{a.id}: gate {gate_id}: PASS — ready to advance"],
        "finding": a.id, "gate": gate_id, "status": "PASS",
        "inputs": ctx.inputs,
    }, a.json)
    return EXIT_OK


def emit_gate_failure(gf: GateFailure, a) -> None:
    lines = [f"{a.id}: gate {gf.gate_id}: FAIL ({len(gf.issues)} issue(s))"]
    for issue in gf.issues:
        lines.append(f"  [{issue['category']}] {issue['detail']}")
    if gf.next_steps:
        lines.append("next steps:")
        lines += [f"  - {s}" for s in gf.next_steps]
    payload = {"lines": lines, "finding": getattr(a, "id", None), "gate": gf.gate_id,
               "status": "FAIL", "issues": gf.issues, "next_steps": gf.next_steps}
    emit(payload, getattr(a, "json", False))


def cmd_lint(a) -> int:
    """Material lint — the post-edit regression battery (contracts §9)."""
    root = require_case(a)
    doc, _ = load_ledger(root, a.id)
    if STAGES.index(doc["stage"]) < STAGES.index("PACKAGED"):
        raise LifecycleError(f"{a.id}: lint runs on packaged findings (current stage "
                             f"{doc['stage']}); complete PACKAGED first")
    program = load_program(root)
    result = lint_finding(root, doc, program)
    findings = result["findings"]
    blocks = [f for f in findings if f["severity"] == "BLOCK"]
    warns = [f for f in findings if f["severity"] == "WARN"]
    status = "FAIL" if blocks else "PASS"
    lines = [f"{a.id}: lint {status} — {len(blocks)} BLOCK, {len(warns)} WARN "
             f"over {len(result['surfaces'])} surface(s)"]
    for f in findings:
        loc = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
        lines.append(f"  [{f['severity']}] {f['check']} {loc}: {f['detail']}")
    if warns and not blocks:
        lines.append("WARN findings do not fail the run; review each before submitting")
    lines.append(f"LINT: {status}")
    if a.save_log:
        log_path = safe_rel(root, a.save_log, "lint log")
        atomic_write(log_path, "\n".join(lines) + "\n")
        lines.append(f"lint log saved: {a.save_log}")
    emit({"lines": lines, "finding": a.id, "status": status,
          "blocks": len(blocks), "warnings": len(warns), "findings": findings,
          "surfaces": [{"path": rel, "label": label} for rel, label in result["surfaces"]]},
         a.json)
    return EXIT_GATE if blocks else EXIT_OK


def cmd_advance(a) -> int:
    root = require_case(a)
    with CaseLock(root):
        # plan 2.3: lock first, check the expected revision, then re-verify gates
        pre, _ = load_ledger(root, a.id)
        cas_check(pre, a.expected_revision)
        doc, ctx, target, gate_id = None, None, None, None
        try:
            doc, ctx, target, gate_id = run_gate(root, a, "advance")
        except GateFailure as gf:
            emit_gate_failure(gf, a)
            return EXIT_GATE
        check_review_substance(a.reviewer, a.reason, ctx)

        for field, value in ctx.merges.items():
            doc[field] = value
        for rel, purpose, produced_by in ctx.evidence_updates:
            p = safe_rel(root, rel, purpose)
            upsert_evidence(doc, rel, sha256_file(p), purpose, produced_by)
        doc["gates"].append({
            "id": gate_id, "stage": target, "status": "PASSED", "at": now_iso(),
            "reviewer": a.reviewer, "reason": a.reason, "inputs": ctx.inputs,
        })
        prev = doc["stage"]
        doc["stage"] = target
        append_history(doc, "advanced", {"from": prev, "to": target, "gate": gate_id,
                                         "reviewer": a.reviewer})
        _, body = load_ledger(root, a.id)
        save_ledger(root, doc, body)
    rebuild_index_tolerant(root)
    emit({"lines": [f"{a.id}: advanced {prev} -> {target} (revision {doc['revision']})"],
          "finding": a.id, "stage": target, "revision": doc["revision"]}, a.json)
    return EXIT_OK


# ---------------------------------------------------------------------------
# close / reopen

def merge_creates_cycle(root: str, fid: str, into: str) -> bool:
    seen = set()
    cur = into
    while cur is not None:
        if cur == fid or cur in seen:
            return True
        seen.add(cur)
        try:
            other, _ = load_ledger(root, cur)
        except LifecycleError:
            raise LifecycleError(f"merge target unreadable: {cur}")
        cur = other.get("duplicate_of")
    return False


def cmd_close(a) -> int:
    root = require_case(a)
    with CaseLock(root):
        doc, body = load_ledger(root, a.id)
        cas_check(doc, a.expected_revision)
        if doc["disposition"] != "OPEN":
            raise LifecycleError(f"{a.id} is already closed ({doc['disposition']})")
        disp = check_enum(a.disposition, DISPOSITIONS, "--disposition")
        detail = {"disposition": disp}

        if disp == "MERGED":
            into = as_str(a.into, "--into (the surviving finding id)")
            if into == a.id:
                raise LifecycleError("cannot merge a finding into itself")
            ledger_path(root, into)  # validates the id format
            if merge_creates_cycle(root, a.id, into):
                raise LifecycleError(f"merging into {into} would create a duplicate_of cycle")
            doc["duplicate_of"] = into
            detail["merged_into"] = into
        elif disp == "INELIGIBLE":
            reason = as_str(a.reason, "--reason")
            ev = as_str(a.evidence, "--evidence (rule/eligibility evidence file)")
            p = safe_rel(root, ev, "ineligibility evidence")
            if not os.path.isfile(p):
                raise LifecycleError(f"evidence file not found: {ev}")
            upsert_evidence(doc, ev, sha256_file(p), "ineligibility-evidence", f"close:{disp}")
            detail["reason"] = reason
            detail["evidence"] = ev
        elif disp == "REFUTED":
            # plan 2.2: REFUTED needs fork counter-evidence plus an explicit
            # conclusion boundary; a genuine false positive never passes the
            # FORK_PROVEN attack gate, so no stage precondition is imposed —
            # the refutation artifacts themselves carry the fork evidence.
            # Static doubt without a fork attempt stays a blocker.
            poc = as_str(a.refutation_poc, "--refutation-poc")
            log = as_str(a.refutation_log, "--refutation-log")
            boundary = as_str(a.boundary, "--boundary (conclusion boundary)")
            if len(boundary.strip()) < 20:
                raise LifecycleError("--boundary must state the refutation scope (deployment, block, premises)")
            log_p = safe_rel(root, log, "refutation log")
            if not os.path.isfile(log_p):
                raise LifecycleError(f"refutation log not found: {log}")
            with open(log_p, encoding="utf-8", errors="ignore") as f:
                if "RESULT: REFUTED" not in f.read():
                    raise LifecycleError("refutation log must contain the 'RESULT: REFUTED' marker "
                                         "demonstrating the blocking mechanism")
            poc_p = safe_rel(root, poc, "refutation poc")
            if not os.path.isfile(poc_p):
                raise LifecycleError(f"refutation PoC not found: {poc}")
            upsert_evidence(doc, poc, sha256_file(poc_p), "refutation-poc", f"close:{disp}")
            upsert_evidence(doc, log, sha256_file(log_p), "refutation-log", f"close:{disp}")
            doc["refutation"] = {"boundary": boundary, "poc": poc, "log": log}
            detail["boundary"] = boundary
        elif disp in ("ACCEPTED", "REJECTED"):
            sub = doc.get("submission") or {}
            if not sub.get("platform_id"):
                raise LifecycleError(f"{disp} requires a recorded submission (platform decision on a submitted report)")
            ev = as_str(a.evidence, "--evidence (platform decision notice)")
            p = safe_rel(root, ev, "platform decision evidence")
            if not os.path.isfile(p):
                raise LifecycleError(f"evidence file not found: {ev}")
            upsert_evidence(doc, ev, sha256_file(p), "platform-decision", f"close:{disp}")
            detail["evidence"] = ev
            if a.reason:
                detail["reason"] = a.reason
        elif disp == "WITHDRAWN":
            detail["reason"] = as_str(a.reason, "--reason")

        doc["disposition"] = disp
        append_history(doc, "closed", detail)
        save_ledger(root, doc, body)
    rebuild_index_tolerant(root)
    emit({"lines": [f"{a.id}: closed as {disp} (revision {doc['revision']})"],
          "finding": a.id, "disposition": disp, "revision": doc["revision"]}, a.json)
    return EXIT_OK


def cmd_reopen(a) -> int:
    root = require_case(a)
    with CaseLock(root):
        doc, body = load_ledger(root, a.id)
        cas_check(doc, a.expected_revision)
        if doc["disposition"] == "OPEN":
            raise LifecycleError(f"{a.id} is OPEN; nothing to reopen")
        reason = as_str(a.reason, "--reason")
        affect = check_enum(a.affect_stage, STAGES[1:], "--affect-stage")
        aidx = STAGES.index(affect)
        cur_idx = STAGES.index(doc["stage"])
        if aidx > cur_idx:
            raise LifecycleError(f"--affect-stage {affect} is beyond the current stage {doc['stage']}")
        new_stage = STAGES[aidx - 1]

        invalidated = []
        for g in doc.get("gates", []):
            if g.get("status") == "PASSED" and STAGES.index(g["stage"]) >= aidx:
                g["status"] = "INVALID"
                g["invalidated_at"] = now_iso()
                g["invalidation_reason"] = reason
                invalidated.append(g["id"])

        detail = {"reason": reason, "affect_stage": affect,
                  "from_stage": doc["stage"], "to_stage": new_stage,
                  "invalidated_gates": invalidated,
                  "previous_disposition": doc["disposition"]}
        if a.evidence:
            ev = as_str(a.evidence, "--evidence")
            p = safe_rel(root, ev, "reopen evidence")
            if not os.path.isfile(p):
                raise LifecycleError(f"evidence file not found: {ev}")
            upsert_evidence(doc, ev, sha256_file(p), "reopen-evidence", "reopen")
            detail["evidence"] = ev
        if doc.get("submission", {}).get("platform_id"):
            detail["prior_submission"] = doc["submission"]
            doc["submission"] = default_submission_block()
        if (doc.get("appeal") or {}).get("status") != "NONE":
            detail["prior_appeal"] = doc["appeal"]
            doc["appeal"] = default_appeal_block()
        doc["duplicate_of"] = None
        doc["refutation"] = None
        doc["disposition"] = "OPEN"
        doc["stage"] = new_stage
        append_history(doc, "reopened", detail)
        save_ledger(root, doc, body)
    rebuild_index_tolerant(root)
    lines = [f"{a.id}: reopened at {new_stage} (revision {doc['revision']}); "
             f"{len(invalidated)} gate(s) invalidated"]
    emit({"lines": lines, "finding": a.id, "stage": new_stage,
          "revision": doc["revision"]}, a.json)
    return EXIT_OK


# ---------------------------------------------------------------------------
# resume / index

def pending_summary(doc: dict, program: dict):
    pending = []
    if doc["disposition"] == "OPEN":
        idx = STAGES.index(doc["stage"])
        if idx < len(STAGES) - 1:
            target = STAGES[idx + 1]
            pending.append(f"next: advance -> {target}")
            pending += [f"  - {h.format(fid=doc['id'])}" for h in STAGE_HINTS[target]]
        else:
            pending.append("awaiting platform response (record response / appeal receipts)")
    else:
        pending.append(f"closed: {doc['disposition']}")
    appeal = doc.get("appeal") or {}
    if appeal.get("status") in ("DRAFTED", "SENT"):
        dl = parse_date(appeal.get("deadline"), "appeal.deadline")
        if dl is not None and dl < date.today():
            pending.append(f"URGENT: appeal deadline {dl} has passed")
        else:
            pending.append(f"appeal {appeal['status']} (deadline {appeal.get('deadline') or 'unknown'})")
    sub = doc.get("submission") or {}
    if sub.get("platform_id") and not (sub.get("response") or {}).get("decision"):
        sla = ((program.get("response") or {}).get("sla")) if isinstance(program.get("response"), dict) else None
        pending.append(f"submitted {sub.get('platform_id')} on {sub.get('submitted_at')}; SLA: {sla or 'unknown'}")
    for b in doc.get("blockers") or []:
        if not b.get("resolved_at"):
            pending.append(f"blocker: {b['item']} -> {b['next_step']}")
    return pending


def cmd_resume(a) -> int:
    root = require_case(a)
    warn_legacy_audit_config(root)
    program = load_program(root)
    fids = [a.id] if a.id else list_findings(root)
    if not fids:
        emit({"lines": ["no findings registered"], "findings": []}, a.json)
        return EXIT_OK
    structural = 0
    report = {"findings": []}
    lines = []
    for fid in fids:
        try:
            doc, _ = load_ledger(root, fid)
            ctx = Ctx(root, program, doc)
            verify_integrity(ctx)
        except LifecycleError as exc:
            lines.append(f"{fid}: UNREADABLE — {exc}")
            report["findings"].append({"id": fid, "error": str(exc)})
            structural += 1
            continue
        issues = ctx.issues
        if issues:
            structural += 1
        pending = pending_summary(doc, program)
        lines.append(f"{fid}: stage={doc['stage']} disposition={doc['disposition']} revision={doc['revision']}")
        for issue in issues:
            lines.append(f"  [{issue['category']}] {issue['detail']}")
        lines.extend(f"  {p}" for p in pending)
        report["findings"].append({
            "id": fid, "stage": doc["stage"], "disposition": doc["disposition"],
            "revision": doc["revision"], "issues": issues, "pending": pending,
        })
    ok = rebuild_index_tolerant(root)
    if not ok:
        lines.append("index rebuild still failing; fix the cause and run `index` again")
        structural += 1
    report["lines"] = lines
    emit(report, a.json)
    return EXIT_GATE if structural else EXIT_OK


def cmd_index(a) -> int:
    root = require_case(a)
    rebuild_index(root)
    print(f"index rebuilt: {os.path.join(root, 'index.md')}")
    return EXIT_OK


# ---------------------------------------------------------------------------
# export subcommand

EXPORT_DIR_RE = re.compile(r"^(\d{2})-([a-z0-9-]+)-([a-z]+)$")


def _export_read_manifest(root: str, fid: str) -> dict:
    rel = f"packages/{fid}/manifest.yaml"
    p = safe_rel(root, rel, "package manifest")
    if not os.path.isfile(p):
        raise LifecycleError(f"{fid}: no package manifest at {rel} — complete PACKAGED first")
    manifest = load_yaml_file(p, rel)
    if not isinstance(manifest.get("materials"), dict):
        raise LifecycleError(f"{fid}: {rel} declares no materials block; cannot export")
    return manifest


def cmd_export(a) -> int:
    """Assemble the submission dir from packaged findings (read-only assembly).

    No ledger state changes: export copies the frozen materials out where the
    operator pastes them into the platform form. Order of --id args is the
    submission priority (01, 02, ...).
    """
    root = require_case(a)
    prog = load_program(root)
    plat = program_platform(prog)
    if plat not in MATERIAL_PLATFORMS:
        raise LifecycleError(
            "export requires program.yaml delivery.platform to name a material platform "
            f"(one of {sorted(MATERIAL_PLATFORMS)}); this case has {plat!r}")
    out_root = a.out or os.path.join(root, "submission")

    plan = []  # (nn, dirname, fid, doc, manifest)
    slugs = {}
    for i, fid in enumerate(a.ids, start=1):
        if fid in [e[2] for e in plan]:
            raise LifecycleError(f"--id {fid} given twice")
        doc, _body = load_ledger(root, fid)
        if STAGES.index(doc["stage"]) < STAGES.index("PACKAGED"):
            raise LifecycleError(f"{fid}: stage {doc['stage']} — only PACKAGED findings export")
        manifest = _export_read_manifest(root, fid)
        materials = manifest["materials"]
        slug = as_str(materials.get("slug"), "materials.slug")
        if not SLUG_RE.fullmatch(slug):
            raise LifecycleError(f"{fid}: materials.slug {slug!r} is not a lowercase hyphen slug")
        if slug in slugs:
            raise LifecycleError(f"slug {slug!r} used by both {slugs[slug]} and {fid}")
        slugs[slug] = fid
        severity = (doc.get("severity") or {}).get("final")
        if not isinstance(severity, str) or not severity.strip():
            raise LifecycleError(f"{fid}: severity.final is unset — TRIAGED must precede export")
        levels = MATERIAL_SPECS[plat].get("severity_levels")
        if levels and severity.lower() not in levels:
            raise LifecycleError(
                f"{fid}: severity.final {severity!r} is not an individual-submission "
                f"severity on {plat!r} (accepted: {', '.join(sorted(levels))}); "
                "consolidated-report levels (QA/Gas/Low) are assembled outside export "
                "— see references/platform-standards.md")
        dirname = f"{i:02d}-{slug}-{severity.lower()}"
        plan.append((i, dirname, fid, doc, manifest))

    # ordering-consistency guard against stale numbered dirs from earlier runs
    if os.path.isdir(out_root):
        existing = {}
        for name in sorted(os.listdir(out_root)):
            m = EXPORT_DIR_RE.match(name)
            if m and os.path.isdir(os.path.join(out_root, name)):
                existing[name] = (m.group(1), m.group(2), m.group(3))
        planned_names = {d for _n, d, _f, _doc, _m in plan}
        planned_suffixes = {d.split("-", 1)[1] for d in planned_names}
        for name, (nn, slug_part, sev) in existing.items():
            if name in planned_names:
                continue
            if f"{slug_part}-{sev}" in planned_suffixes:
                raise LifecycleError(
                    f"ordering changed: existing {name} but this run numbers the same "
                    f"slug differently; remove the stale directory or keep the previous "
                    f"--id order")

    lines = []
    readme_rows = []
    field_help = EXPORT_README_FIELDS[plat]
    for nn, dirname, fid, doc, manifest in plan:
        materials = manifest["materials"]
        slug = as_str(materials.get("slug"), "materials.slug")
        target = os.path.join(out_root, dirname)
        if os.path.isdir(target):
            shutil.rmtree(target)
        os.makedirs(target, exist_ok=True)
        copied = []
        for f_ in as_list(materials.get("fields"), "materials.fields"):
            f_ = as_dict(f_, "materials.fields entry")
            name = as_str(f_.get("field"), "materials.fields[].field")
            if name not in MATERIAL_SPECS[plat]["fields"]:
                raise LifecycleError(f"{fid}: unknown materials field {name!r} "
                                     f"for platform {plat!r}")
            rel = as_str(f_.get("path"), "materials.fields[].path")
            expected = f_.get("sha256")
            src = safe_rel(root, rel, "material file")
            if not os.path.isfile(src):
                raise LifecycleError(f"{fid}: material file missing: {rel}")
            actual = sha256_file(src)
            if actual != expected:
                raise LifecycleError(
                    f"{fid}: material {rel} hash changed since packaging "
                    f"(manifest {expected}, actual {actual}); reopen PACKAGED instead of "
                    "exporting drifted materials")
            dest_rel = MATERIAL_SPECS[plat]["fields"][name]["path"]
            dest = os.path.join(target, dest_rel)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            shutil.copyfile(src, dest)
            copied.append(dest_rel)
        zip_spec = as_dict(manifest.get("package", {}).get("zip"), "package.zip")
        zip_rel = as_str(zip_spec.get("path"), "package.zip.path")
        zip_src = safe_rel(root, zip_rel, "package zip")
        if not os.path.isfile(zip_src):
            raise LifecycleError(f"{fid}: package zip missing: {zip_rel}")
        zip_hash = sha256_file(zip_src)
        if zip_spec.get("sha256") and zip_hash != zip_spec["sha256"]:
            raise LifecycleError(f"{fid}: package zip {zip_rel} hash changed since packaging")
        zip_name = MATERIAL_SPECS[plat]["zip_name"].format(slug=slug)
        shutil.copyfile(zip_src, os.path.join(target, zip_name))
        copied_attachments = []
        for at_ in as_list(materials.get("attachments") or [], "materials.attachments"):
            at_ = as_dict(at_, "materials.attachments entry")
            arel = as_str(at_.get("path"), "materials.attachments[].path")
            asrc = safe_rel(root, arel, "material attachment")
            if not os.path.isfile(asrc):
                raise LifecycleError(f"{fid}: material attachment missing: {arel}")
            ahash = sha256_file(asrc)
            if at_.get("sha256") and ahash != at_.get("sha256"):
                raise LifecycleError(f"{fid}: material attachment {arel} hash changed "
                                     "since packaging; reopen PACKAGED instead")
            pkg_prefix = f"packages/{fid}/"
            sub = arel[len(pkg_prefix):] if arel.startswith(pkg_prefix) else os.path.basename(arel)
            dest = os.path.join(target, sub)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            shutil.copyfile(asrc, dest)
            copied_attachments.append(sub)
        form_targets = as_list(materials.get("form_targets") or [],
                               "materials.form_targets")
        lines.append(f"{dirname}/: {', '.join(sorted(copied))} + {zip_name} "
                     f"(sha256 {zip_hash})"
                     + (f" + {', '.join(copied_attachments)}" if copied_attachments else ""))
        readme_rows.append({
            "dirname": dirname, "fid": fid,
            "severity": (doc.get("severity") or {}).get("final"),
            "title": doc.get("title"), "zip_sha256": zip_hash, "zip_name": zip_name,
            "form_targets": form_targets,
        })

    readme = os.path.join(out_root, "README.md")
    if a.readme or not os.path.isfile(readme):
        prog_name = (prog.get("program") or {}).get("name") or (prog.get("program") or {}).get("id")
        out = [f"# Submission packages — {prog_name} ({plat})", ""]
        out.append(f"Assembled by `lifecycle.py export` on {now_iso()}; directory order is "
                   "the submission priority given to the export command. Each directory is "
                   "self-contained and maps to the platform form fields:")
        out.append("")
        out.extend(field_help)
        out.append("")
        for row in readme_rows:
            out.append(f"## {row['dirname']}/")
            out.append("")
            out.append(f"- finding: `{row['fid']}`")
            out.append(f"- severity: {row['severity']}")
            out.append(f"- title: {row['title']}")
            out.append(f"- {row['zip_name']} sha256: `{row['zip_sha256']}`")
            for ft in row.get("form_targets") or []:
                ft = as_dict(ft, "materials.form_targets entry")
                out.append(f"- form target — {ft.get('field')}: `{ft.get('address')}` "
                            f"(verified per {ft.get('source')})")
            out.append("")
        exported = {e[2] for e in plan}
        withheld = []
        for other in list_findings(root):
            if other in exported:
                continue
            try:
                odoc, _ = load_ledger(root, other)
            except LifecycleError:
                continue
            if STAGES.index(odoc["stage"]) >= STAGES.index("TRIAGED"):
                withheld.append((other, odoc["stage"], odoc["disposition"],
                                 odoc.get("title", "")))
        if withheld:
            out.append("## Not exported this run")
            out.append("")
            for oid, ostage, odisp, otitle in withheld:
                out.append(f"- `{oid}` — {odisp}, {ostage} — {otitle}")
            out.append("")
        out.append("Regenerate this index with `lifecycle.py export --readme …`; directories "
                   "for dropped findings are left in place — remove them by hand.")
        out.append("")
        with open(readme, "w", encoding="utf-8") as f:
            f.write("\n".join(out))
        lines.append("README.md written")

    emit({"lines": [f"exported {len(plan)} package(s) to {out_root}"] + lines}, a.json)
    return EXIT_OK


# ---------------------------------------------------------------------------
# record subcommands

def record_common(root: str, a):
    doc, body = load_ledger(root, a.id)
    cas_check(doc, a.expected_revision)
    return doc, body


def cmd_record_blocker(a) -> int:
    root = require_case(a)
    with CaseLock(root):
        doc, body = record_common(root, a)
        item = as_str(a.item, "--item")
        step = as_str(a.next_step, "--next-step")
        doc.setdefault("blockers", []).append(
            {"item": item, "next_step": step, "raised_at": now_iso(), "resolved_at": None})
        append_history(doc, "recorded_blocker", {"item": item, "next_step": step})
        save_ledger(root, doc, body)
    rebuild_index_tolerant(root)
    emit({"lines": [f"{a.id}: blocker recorded (revision {doc['revision']})"]}, a.json)
    return EXIT_OK


def cmd_record_resolve(a) -> int:
    root = require_case(a)
    with CaseLock(root):
        doc, body = record_common(root, a)
        blockers = doc.setdefault("blockers", [])
        idx = a.index
        if not isinstance(idx, int) or idx < 0 or idx >= len(blockers):
            raise LifecycleError(f"--index out of range (0..{len(blockers) - 1 if blockers else 0})")
        if blockers[idx].get("resolved_at"):
            raise LifecycleError(f"blocker #{idx} is already resolved")
        blockers[idx]["resolved_at"] = now_iso()
        append_history(doc, "resolved_blocker", {"index": idx, "item": blockers[idx]["item"]})
        save_ledger(root, doc, body)
    rebuild_index_tolerant(root)
    emit({"lines": [f"{a.id}: blocker #{a.index} resolved (revision {doc['revision']})"]}, a.json)
    return EXIT_OK


def cmd_record_submission(a) -> int:
    root = require_case(a)
    with CaseLock(root):
        doc, body = record_common(root, a)
        rel = a.input or f"evidence/{a.id}/submission.yaml"
        p = safe_rel(root, rel, "submission input")
        inp = load_yaml_file(p, "submission input")
        restrict_keys(inp, {"platform_id", "submitted_at", "channel", "package_sha256",
                            "receipt", "account_limits", "kyc"}, "submission.yaml")
        ctx = Ctx(root, load_program(root), doc)
        verify_submission_block(ctx, inp, record_mode=True)
        if ctx.issues:
            raise GateFailure("record:submission", ctx.issues)
        doc["submission"] = inp
        receipt = (inp.get("receipt") or {})
        upsert_evidence(doc, receipt["path"], sha256_file(safe_rel(root, receipt["path"], "receipt")),
                        "submission-receipt", "record:submission")
        append_history(doc, "submission_recorded", {
            "platform_id": inp.get("platform_id"),
            "submitted_at": inp.get("submitted_at"),
            "package_sha256": inp.get("package_sha256"),
            "channel": (inp.get("channel") or {}).get("kind"),
        })
        save_ledger(root, doc, body)
    rebuild_index_tolerant(root)
    emit({"lines": [f"{a.id}: submission receipt recorded (revision {doc['revision']}); "
                    f"advance to SUBMITTED when ready"]}, a.json)
    return EXIT_OK


def cmd_record_response(a) -> int:
    root = require_case(a)
    with CaseLock(root):
        doc, body = record_common(root, a)
        sub = doc.get("submission") or {}
        if not sub.get("platform_id"):
            raise LifecycleError("no submission recorded; a platform decision needs a submitted report")
        decision = check_enum(a.decision, {"ACCEPTED", "REJECTED"}, "--decision")
        ev = as_str(a.evidence, "--evidence (platform response notice)")
        p = safe_rel(root, ev, "platform response evidence")
        if not os.path.isfile(p):
            raise LifecycleError(f"evidence file not found: {ev}")
        response = {"decision": decision, "evidence": ev, "sha256": sha256_file(p),
                    "at": now_iso(), "reason": a.reason}
        sub["response"] = response
        doc["submission"] = sub
        upsert_evidence(doc, ev, response["sha256"], "platform-decision", "record:response")
        detail = {"decision": decision, "evidence": ev}
        appeal = doc.get("appeal") or {}
        if appeal.get("status") in ("DRAFTED", "SENT"):
            appeal["status"] = "RESOLVED"
            appeal["outcome"] = f"platform decision {decision} recorded {response['at']}"
            doc["appeal"] = appeal
            detail["appeal_resolved"] = True
        append_history(doc, "response_recorded", detail)
        # a platform decision is authoritative for the disposition; prior
        # outcomes stay in history
        doc["disposition"] = decision
        save_ledger(root, doc, body)
    rebuild_index_tolerant(root)
    disp = doc["disposition"]
    emit({"lines": [f"{a.id}: response {decision} recorded (revision {doc['revision']}); disposition={disp}"]},
          a.json)
    return EXIT_OK


def cmd_record_appeal(a) -> int:
    root = require_case(a)
    with CaseLock(root):
        doc, body = record_common(root, a)
        appeal = doc.get("appeal") or default_appeal_block()
        status = check_enum(a.status, APPEAL_STATES[1:], "--status")
        current = appeal.get("status", "NONE")
        order = {None: 0, "NONE": 0, "DRAFTED": 1, "SENT": 2, "RESOLVED": 3}
        if order[status] != order[current] + 1:
            raise LifecycleError(f"appeal transition {current} -> {status} is not sequential")
        detail = {"status": status}
        if status == "DRAFTED":
            if doc["disposition"] != "REJECTED":
                raise LifecycleError("appeals are drafted for REJECTED findings "
                                     f"(current disposition: {doc['disposition']})")
            materials = a.materials or []
            if not materials:
                raise LifecycleError("--materials required when drafting an appeal")
            entries = []
            for m in materials:
                p = safe_rel(root, m, "appeal material")
                if not os.path.isfile(p):
                    raise LifecycleError(f"appeal material not found: {m}")
                entries.append({"path": m, "sha256": sha256_file(p)})
                upsert_evidence(doc, m, entries[-1]["sha256"], "appeal-material", "record:appeal")
            appeal["materials"] = entries
            if a.deadline:
                appeal["deadline"] = str(parse_date(a.deadline, "--deadline"))
                detail["deadline"] = appeal["deadline"]
        elif status == "SENT":
            receipt = as_str(a.receipt, "--receipt (send receipt)")
            p = safe_rel(root, receipt, "appeal receipt")
            if not os.path.isfile(p):
                raise LifecycleError(f"appeal receipt not found: {receipt}")
            appeal["sent_receipt"] = {"path": receipt, "sha256": sha256_file(p)}
            upsert_evidence(doc, receipt, appeal["sent_receipt"]["sha256"], "appeal-receipt", "record:appeal")
            detail["receipt"] = receipt
        elif status == "RESOLVED":
            appeal["outcome"] = as_str(a.outcome, "--outcome")
            detail["outcome"] = appeal["outcome"]
        appeal["status"] = status
        doc["appeal"] = appeal
        append_history(doc, "appeal_updated", detail)
        save_ledger(root, doc, body)
    rebuild_index_tolerant(root)
    emit({"lines": [f"{a.id}: appeal {status} (revision {doc['revision']})"]}, a.json)
    return EXIT_OK


# ---------------------------------------------------------------------------
# init

def cmd_record_correction(a) -> int:
    """Tier-1 post-package document correction (contracts section 10).

    Wording/disclosure/narration fixes over the report or material field
    files: refresh manifest hashes, rebind PASSED-gate inputs and evidence,
    journal the correction. Technical changes (PoC, amounts, severity,
    targets) are rejected here — they are Tier 2 (reopen PACKAGED).
    """
    root = require_case(a)
    with CaseLock(root):
        doc, body = load_ledger(root, a.id)
        cas_check(doc, a.expected_revision)
        if doc["disposition"] != "OPEN":
            raise LifecycleError(f"{a.id} is closed ({doc['disposition']}); corrections need OPEN")
        cur = STAGES.index(doc["stage"])
        if cur < STAGES.index("PACKAGED"):
            raise LifecycleError(f"{a.id}: corrections apply from PACKAGED "
                                 f"(current stage {doc['stage']})")
        if doc["stage"] == "SUBMITTED":
            raise LifecycleError(f"{a.id}: submitted packages never change — "
                                 "reopen (Tier 2) instead")
        summary = as_str(a.summary, "--summary")
        if len(summary.strip()) < 20:
            raise LifecycleError("--summary must state what changed and why (>= 20 characters)")

        manifest_rel = f"packages/{a.id}/manifest.yaml"
        manifest = load_yaml_file(safe_rel(root, manifest_rel, "package manifest"),
                                  manifest_rel)
        pkg = as_dict(manifest.get("package") or {}, f"{manifest_rel}: package")
        materials = manifest.get("materials") or {}
        report_rel = (pkg.get("report") or {}).get("path")
        field_paths = {f_.get("path") for f_ in (materials.get("fields") or [])
                       if isinstance(f_, dict)}
        eligible = {p for p in ({report_rel} | field_paths)
                    if isinstance(p, str) and p.strip()}
        if not eligible:
            raise LifecycleError(f"{manifest_rel}: no report or material fields declared — "
                                 "nothing Tier-1 correctable")

        changed = [as_str(f, "--files entry") for f in (a.files or [])]
        if not changed:
            raise LifecycleError("--files required: list every document this batch changed")
        for rel in changed:
            if rel not in eligible:
                raise LifecycleError(
                    f"{rel}: not a Tier-1 surface (the report or a material field file). "
                    "A technical change (PoC, amounts, severity, targets, eligibility) is "
                    "Tier 2: reopen --affect-stage PACKAGED and build a new package version")
            if not os.path.isfile(safe_rel(root, rel, "correction file")):
                raise LifecycleError(f"correction file not found: {rel}")

        lint_rel = as_str(a.lint_log, "--lint-log (a saved lint log; see lint --save-log)")
        lint_p = safe_rel(root, lint_rel, "lint log")
        if not os.path.isfile(lint_p):
            raise LifecycleError(f"lint log not found: {lint_rel} — run "
                                 "`lifecycle.py lint --id … --save-log …` after the edits")
        with open(lint_p, encoding="utf-8", errors="ignore") as f:
            if "LINT: PASS" not in f.read():
                raise LifecycleError(f"lint log {lint_rel} does not carry 'LINT: PASS' — fix "
                                     "the BLOCK findings, re-run lint, then record the correction")

        targeted_rel = a.targeted_review
        if cur >= STAGES.index("SELF_REVIEWED"):
            targeted_rel = as_str(targeted_rel,
                                  "--targeted-review (required once SELF_REVIEWED): an "
                                  "independent sign-off covering exactly the changed passages")
        if targeted_rel:
            tp = safe_rel(root, targeted_rel, "targeted review")
            if not os.path.isfile(tp):
                raise LifecycleError(f"targeted review not found: {targeted_rel}")

        # dual-copy discipline: a changed doc that is a zip member forces a
        # zip rebuild in the same batch (loose docs and zip must never drift)
        zip_spec = as_dict(pkg.get("zip") or {}, f"{manifest_rel}: package.zip")
        zip_rel = as_str(zip_spec.get("path"), f"{manifest_rel}: package.zip.path")
        zip_p = safe_rel(root, zip_rel, "package zip")
        prefix = f"packages/{a.id}/"
        zip_members = set()
        if os.path.isfile(zip_p):
            try:
                with zipfile.ZipFile(zip_p) as zf:
                    zip_members = {n for n in zf.namelist() if not n.endswith("/")}
            except (zipfile.BadZipFile, OSError) as exc:
                raise LifecycleError(f"package zip unreadable: {zip_rel}: {exc}")
        for rel in changed:
            member = rel[len(prefix):] if rel.startswith(prefix) else rel
            if member in zip_members and not a.zip_refreshed:
                raise LifecycleError(
                    f"{rel} is a package-zip member; this correction must rebuild the zip "
                    "in the same batch — rebuild it, then pass --zip-refreshed")

        new_hashes = {rel: sha256_file(safe_rel(root, rel, "correction file"))
                      for rel in changed}
        for f_ in as_list(pkg.get("files") or [], f"{manifest_rel}: package.files"):
            if isinstance(f_, dict) and f_.get("path") in new_hashes:
                f_["sha256"] = new_hashes[f_["path"]]
        if isinstance(materials, dict):
            for f_ in as_list(materials.get("fields") or [], f"{manifest_rel}: materials.fields"):
                if isinstance(f_, dict) and f_.get("path") in new_hashes:
                    f_["sha256"] = new_hashes[f_["path"]]
        zip_refreshed = bool(a.zip_refreshed)
        if zip_refreshed:
            zip_spec["sha256"] = sha256_file(zip_p)
        with open(safe_rel(root, manifest_rel, "package manifest"), "w", encoding="utf-8") as f:
            yaml.safe_dump(manifest, f, sort_keys=False, allow_unicode=True, width=120)

        # rebind evidence entries and PASSED-gate input hashes; every rebind
        # is journaled in the correction + history event
        changed_paths = list(changed) + [manifest_rel]
        if zip_refreshed:
            changed_paths.append(zip_rel)
        purposes = {ev.get("path"): ev.get("purpose") for ev in doc.get("evidence", [])}
        for rel in changed_paths:
            digest = sha256_file(safe_rel(root, rel, "correction path"))
            upsert_evidence(doc, rel, digest,
                            purposes.get(rel) or "package-doc", "record:correction")
            for g in doc.get("gates", []):
                if g.get("status") != "PASSED":
                    continue
                for inp in g.get("inputs", []):
                    if inp.get("path") == rel:
                        inp["sha256"] = digest
        if targeted_rel:
            upsert_evidence(doc, targeted_rel,
                            sha256_file(safe_rel(root, targeted_rel, "targeted review")),
                            "correction-targeted-review", "record:correction")

        doc.setdefault("corrections", []).append({
            "at": now_iso(), "summary": summary, "files": list(changed),
            "lint_log": lint_rel, "zip_refreshed": zip_refreshed,
            "targeted_review": targeted_rel,
        })
        append_history(doc, "correction_recorded", {
            "summary": summary, "files": changed,
            "zip_refreshed": zip_refreshed, "lint_log": lint_rel,
            "targeted_review": targeted_rel,
        })
        save_ledger(root, doc, body)
    rebuild_index_tolerant(root)
    emit({"lines": [f"{a.id}: correction recorded (revision {doc['revision']}); "
                    f"{len(changed)} file(s) rebound, zip "
                    f"{'refreshed' if zip_refreshed else 'unchanged'}"]}, a.json)
    return EXIT_OK


def cmd_init(a) -> int:
    root = a.case_root
    os.makedirs(root, exist_ok=True)
    prog_path = os.path.join(root, "program.yaml")
    if os.path.exists(prog_path):
        raise LifecycleError(f"{prog_path} already exists; refusing to overwrite (no --force)")
    src = a.program_yaml or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "templates", "program.yaml")
    prog = load_yaml_file(src, "program template")
    prog = dict(prog)
    if a.program_id:
        prog["program"] = dict(prog.get("program") or {})
        prog["program"]["id"] = a.program_id
    if a.rules_snapshot:
        if not os.path.isfile(a.rules_snapshot):
            raise LifecycleError(f"--rules-snapshot not found: {a.rules_snapshot}")
        base = os.path.basename(a.rules_snapshot)
        shutil.copyfile(a.rules_snapshot, os.path.join(root, base))
        prog["program"] = dict(prog.get("program") or {})
        prog["program"]["snapshot"] = {"path": base, "sha256": sha256_file(a.rules_snapshot)}
    validate_program(prog)
    for d in ("findings", "evidence", "packages"):
        os.makedirs(os.path.join(root, d), exist_ok=True)
    with open(prog_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(prog, f, sort_keys=False, allow_unicode=True, default_flow_style=False, width=120)
    snap = (prog.get("program") or {}).get("snapshot") or {}
    lines = [
        f"initialized case root: {root}",
        f"program id: {prog['program']['id']}",
        f"rules snapshot: {snap.get('path')} sha256={snap.get('sha256')}",
    ]
    if snap.get("sha256") is None:
        lines.append("NOTE: snapshot sha256 is empty; fill it (sha256sum) before the TRIAGED gate")
    emit({"lines": lines}, a.json)
    return EXIT_OK


# ---------------------------------------------------------------------------
# plumbing

def require_case(a) -> str:
    root = a.case_root
    if not root or not os.path.isdir(root):
        raise LifecycleError(f"--case-root directory not found: {root!r}")
    return os.path.realpath(root)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="lifecycle.py",
                                description="finding lifecycle gate CLI (no --force; evidence gates cannot be skipped)")
    sub = p.add_subparsers(dest="command", required=True, metavar="command")

    sp = sub.add_parser("init", help="initialize a case root")
    sp.add_argument("--case-root", required=True)
    sp.add_argument("--program-yaml", help="program.yaml source (default: bundled template)")
    sp.add_argument("--program-id", help="override program id")
    sp.add_argument("--rules-snapshot", help="copy the rules snapshot into the root and freeze its hash")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_init)

    sp = sub.add_parser("ingest",
                        help="discover audit artifacts by name and scaffold finding-source drafts")
    sp.add_argument("--case-root", required=True)
    sp.add_argument("--scan-dir", help="directory to scan (default: current directory)")
    sp.add_argument("--pattern", default="audit",
                    help="name substring to match files/directories (default: audit)")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_ingest)

    sp = sub.add_parser("import-audit",
                        help="import a finalized audit-orchestrator handoff bundle")
    sp.add_argument("--case-root", required=True)
    sp.add_argument("--handoff", required=True,
                    help="path to the finalized handoff/manifest.yaml")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_import_audit)

    sp = sub.add_parser("register", help="register a finding from an original source")
    sp.add_argument("--case-root", required=True)
    sp.add_argument("--from", dest="src", required=True, help="finding-source.yaml")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_register)

    sp = sub.add_parser("check", help="read-only gate check for the next stage")
    sp.add_argument("--case-root", required=True)
    sp.add_argument("--id", required=True)
    sp.add_argument("--stage", help="must equal the next stage")
    sp.add_argument("--input", help="override the stage input path")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_check)

    sp = sub.add_parser("advance", help="validate and advance one stage")
    sp.add_argument("--case-root", required=True)
    sp.add_argument("--id", required=True)
    sp.add_argument("--reviewer", required=True)
    sp.add_argument("--reason", required=True, help="substantive review note citing artifacts")
    sp.add_argument("--input", help="override the stage input path")
    sp.add_argument("--expected-revision", type=int, required=True)
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_advance)

    sp = sub.add_parser(
        "lint",
        help="material lint: regression battery over the report + platform field files "
             "(run after EVERY edit batch; exit 1 on BLOCK findings)")
    sp.add_argument("--case-root", required=True)
    sp.add_argument("--id", required=True)
    sp.add_argument("--save-log", dest="save_log",
                    help="write the lint output plus a final 'LINT: PASS|FAIL' marker to "
                         "this case-root-relative file (consumed by record correction)")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_lint)

    sp = sub.add_parser("close", help="record a disposition")
    sp.add_argument("--case-root", required=True)
    sp.add_argument("--id", required=True)
    sp.add_argument("--disposition", required=True, choices=DISPOSITIONS)
    sp.add_argument("--into", help="surviving finding id (MERGED)")
    sp.add_argument("--reason")
    sp.add_argument("--evidence")
    sp.add_argument("--refutation-poc")
    sp.add_argument("--refutation-log")
    sp.add_argument("--boundary", help="refutation conclusion boundary (REFUTED)")
    sp.add_argument("--expected-revision", type=int, required=True)
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_close)

    sp = sub.add_parser("reopen", help="reopen a closed finding and invalidate gates")
    sp.add_argument("--case-root", required=True)
    sp.add_argument("--id", required=True)
    sp.add_argument("--reason", required=True)
    sp.add_argument("--affect-stage", required=True, choices=STAGES[1:])
    sp.add_argument("--evidence", help="new evidence justifying the reopen")
    sp.add_argument("--expected-revision", type=int, required=True)
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_reopen)

    sp = sub.add_parser("resume", help="validate state, output blockers and next steps")
    sp.add_argument("--case-root", required=True)
    sp.add_argument("--id")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_resume)

    sp = sub.add_parser("index", help="rebuild the derived index")
    sp.add_argument("--case-root", required=True)
    sp.set_defaults(func=cmd_index)

    sp = sub.add_parser(
        "export",
        help="assemble submission materials (Immunefi/HackenProof form fields) from packaged findings")
    sp.add_argument("--case-root", required=True)
    sp.add_argument("--id", dest="ids", action="append", required=True, metavar="F-…",
                    help="finding id; repeatable — order sets submission priority (01, 02, …)")
    sp.add_argument("--out",
                    help="output directory (default: <case-root>/submission)")
    sp.add_argument("--readme", action="store_true",
                    help="(re)generate the README.md index even if one exists")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_export)

    sp = sub.add_parser("record", help="record receipts / blockers / appeals")
    rsp = sp.add_subparsers(dest="record_command", required=True, metavar="record_command")

    q = rsp.add_parser("blocker")
    q.add_argument("--case-root", required=True)
    q.add_argument("--id", required=True)
    q.add_argument("--item", required=True)
    q.add_argument("--next-step", dest="next_step", required=True)
    q.add_argument("--expected-revision", type=int, required=True)
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_record_blocker)

    q = rsp.add_parser("resolve")
    q.add_argument("--case-root", required=True)
    q.add_argument("--id", required=True)
    q.add_argument("--index", type=int, required=True)
    q.add_argument("--expected-revision", type=int, required=True)
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_record_resolve)

    q = rsp.add_parser("correction",
                       help="record a Tier-1 post-package doc correction (wording/disclosure "
                            "only; technical changes reopen PACKAGED instead)")
    q.add_argument("--case-root", required=True)
    q.add_argument("--id", required=True)
    q.add_argument("--summary", required=True,
                   help="what changed and why (>= 20 characters)")
    q.add_argument("--files", nargs="+", required=True,
                   help="every changed doc: the report or material field files")
    q.add_argument("--lint-log", dest="lint_log", required=True,
                   help="saved lint log carrying 'LINT: PASS' (lint --save-log)")
    q.add_argument("--zip-refreshed", dest="zip_refreshed", action="store_true",
                   help="the package zip was rebuilt in this batch (mandatory when a "
                        "changed doc is a zip member)")
    q.add_argument("--targeted-review", dest="targeted_review",
                   help="independent sign-off on the changed passages (required once "
                        "SELF_REVIEWED)")
    q.add_argument("--expected-revision", type=int, required=True)
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_record_correction)

    q = rsp.add_parser("submission")
    q.add_argument("--case-root", required=True)
    q.add_argument("--id", required=True)
    q.add_argument("--input", help="submission.yaml path (default: evidence/<id>/submission.yaml)")
    q.add_argument("--expected-revision", type=int, required=True)
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_record_submission)

    q = rsp.add_parser("response")
    q.add_argument("--case-root", required=True)
    q.add_argument("--id", required=True)
    q.add_argument("--decision", required=True, choices=["ACCEPTED", "REJECTED"])
    q.add_argument("--evidence", required=True)
    q.add_argument("--reason")
    q.add_argument("--expected-revision", type=int, required=True)
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_record_response)

    q = rsp.add_parser("appeal")
    q.add_argument("--case-root", required=True)
    q.add_argument("--id", required=True)
    q.add_argument("--status", required=True, choices=APPEAL_STATES[1:])
    q.add_argument("--deadline")
    q.add_argument("--materials", nargs="+")
    q.add_argument("--receipt")
    q.add_argument("--outcome")
    q.add_argument("--expected-revision", type=int, required=True)
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_record_appeal)

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
    except LifecycleError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except BrokenPipeError:
        return EXIT_ERROR
    except Exception as exc:  # unexpected runtime failure -> defined exit code
        print(f"internal error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
