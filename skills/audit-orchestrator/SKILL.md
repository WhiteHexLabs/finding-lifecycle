---
name: audit-orchestrator
description: Orchestrates configured local smart-contract audit skills, enforces a standard execution/output contract, freezes each audit step's artifacts, aggregates findings by root cause, and emits a versioned handoff bundle. Use for audit-only work or before finding-lifecycle.
---

# audit-orchestrator

Runs the configured local audit skills in order against one target scope,
under a strict execution/output contract, and freezes every step's outputs
into canonical per-step artifacts. After all steps complete, the session
aggregates the reports semantically (root-cause clustering, dedup,
disagreement preservation) and `finalize` emits a versioned, hash-bound
handoff bundle that `finding-lifecycle` can import.

**Division of responsibility:** each audit Skill defines **how to audit**
(methodology, tools, internal layout — never overridden). The orchestrator
defines **how execution results are handed back** (target/scope, step
order, work dir, result contract, artifact freezing).

**Red lines (always):** never modify the audited target source · never
fabricate evidence or completion · there is no `--force` · missing or
ambiguous output BLOCKs instead of guessing · canonical artifacts are
immutable evidence once recorded · no secrets/RPC keys/KYC material in
audit work roots · zero findings never becomes "the protocol is safe".

## Quick start

```bash
A="python3 <skill-root>/scripts/audit.py"

cp <skill-root>/templates/audit-skills.yaml <work-root>/audit-skills.yaml  # fill in!
$A prepare --work-root <dir>     # batch the configured skills; writes per-step
                                 # execution-prompt.md + work/ dirs
#   per step: read steps/<N>/execution-prompt.md AND the skill's SKILL.md,
#   execute the audit, write result.yaml, then:
$A record  --work-root <dir> --step 1 --input result.yaml --expected-revision N
$A check   --work-root <dir>     # every step COMPLETED + artifacts fresh?
#   aggregate: write audits/<run-id>/analysis.md (+ candidates/A-001.yaml…)
$A finalize --work-root <dir> --expected-revision N
```

Exit codes: `0` ok · `1` gate failed · `2` input/runtime error. `--case-root`
is accepted as a deprecated alias for `--work-root`.

## Stages

```text
PREPARE → EXECUTE → RECORD/NORMALIZE → CHECK → AGGREGATE → FINALIZE
```

- **PREPARE** — validate `audit-skills.yaml` (strict schema; scope inside
  target_root; no duplicate skills; the orchestrator and finding-lifecycle
  themselves are rejected), fingerprint every in-scope file, create
  `audits/<run-id>/` with per-step `step.yaml`, `execution-prompt.md`, `work/`.
  Missing SKILL.md → that step is BLOCKED while the rest still runs.
- **EXECUTE** — the session reads the skill's SKILL.md and the generated
  execution prompt, then executes the audit itself (the CLI never executes
  skill content). Fixed-output skills run in their own directory and
  declare their real output paths in `result.yaml`.
- **RECORD/NORMALIZE** — `record` validates the result, verifies the target
  was not modified, copies every declared artifact into the step's canonical
  `attempts/<k>/artifacts/`, hashes files (SHA-256) and directories
  (deterministic tree hash), and writes `artifact-manifest.yaml` for the
  accepted COMPLETED attempt.
- **CHECK** — every step COMPLETED and every frozen artifact still hashes
  correctly; config/target/skill drift stales the batch.
- **AGGREGATE** — the session writes `audits/<run-id>/analysis.md`
  (semantic root-cause clustering, dedup, disagreement preservation — never
  report concatenation) and one `candidates/A-XXX.yaml` per consolidated
  root cause. The CLI validates both at finalize.
- **FINALIZE** — validates aggregation, hashes analysis + candidates, binds
  candidate sources to canonical manifests, writes the immutable
  `handoff/manifest.yaml` (`whitehexlabs.audit-handoff/v1`). Stop here for
  audit-only work, or hand the bundle to `finding-lifecycle import-audit`.

## Operating rules

- Steps record strictly in order; after the first pass only FAILED/BLOCKED
  steps may be rerun — in original order; COMPLETED steps are terminal
  within a batch; retries never overwrite prior attempts.
- Any drift (config, in-scope target file added/deleted/modified — including
  edits made by a sub-skill, skill entry) stales the batch → `prepare --new`
  (old runs stay on disk). A finalized batch plus its bound inputs is
  immutable; material new evidence requires a new run.
- COMPLETED means "the audit ran", never "no vulnerabilities" — zero
  findings still require a real report plus a coverage note, and the
  analysis must say so explicitly.
- `severity_hint` in candidates is advisory only; bounty severity is
  decided later by finding-lifecycle.
- Aggregation reads only `steps/*/artifact-manifest.yaml` and canonical
  artifacts — never the wider filesystem; deleting a skill's original
  output after `record` must not break check/aggregation/finalize.

## References

`references/workflow.md` (stage-by-stage manual) ·
`references/execution-contract.md` (execution prompt + result contract) ·
`references/artifact-contract.md` (normalization, hashing, manifests) ·
`references/handoff-contract.md` (finalize + handoff schema) ·
`templates/` (audit-skills.yaml, result.yaml, audit-candidate.yaml) ·
`tests/` (behavioral tests at the repository root).
