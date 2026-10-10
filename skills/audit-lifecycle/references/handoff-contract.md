# Handoff contract — finalize and the audit → lifecycle boundary

The boundary between the two halves of this skill. `audit.py finalize`
produces the bundle; `lifecycle.py import-audit` verifies it end to end
and copies it into the case root. It stays a file-based, hash-bound
contract — not an in-memory call — so the audit work-root stays
disposable and the case ledger stays independent of it.

## Finalization preconditions (all enforced, none skippable)

- a run exists and every required step is COMPLETED;
- the batch is fresh (config, target scope, skill entries unchanged);
- canonical artifact manifests exist and validate (legacy frozen copies
  are adapted, never fabricated);
- `analysis.md` exists, carries every required section heading and is
  substantive;
- candidate files validate against `whitehexlabs.audit-candidate/v1`;
- candidate ids are unique (`A-<digits>`, filename matches id);
- candidates reference only canonical run artifacts (their step's
  `artifact-manifest.yaml`, report by artifact id);
- all references resolve.

## Output

```text
audits/<run-id>/
├── analysis.md                  # hashed and bound
└── handoff/
    ├── manifest.yaml            # whitehexlabs.audit-handoff/v1
    └── candidates/A-001.yaml…   # exact copies, hashed and bound
```

## Handoff manifest schema

```yaml
schema: whitehexlabs.audit-handoff/v1
run_id: run-…
status: FINALIZED
created_at: "…"
target:
  scope: [...]                   # resolved scope paths (local run metadata)
  fingerprint_sha256: …
audit:
  config_sha256: …
  analysis: {path: ../analysis.md, sha256: …}
steps:
  - step: 1
    skill_name: …
    skill_sha256: …
    artifact_manifest: {path: ../steps/1/artifact-manifest.yaml, sha256: …}
candidates:
  - {id: A-001, path: candidates/A-001.yaml, sha256: …}
candidate_count: 1
```

Paths are relative to `handoff/`. The consumer never needs the skills'
original output locations.

## Audit candidate schema

`whitehexlabs.audit-candidate/v1` (template:
`templates/audit-candidate.yaml`): id/title/claim, `root_cause
{summary, mechanism}`, `sources[]` (each: step, skill_name,
original_finding_id, artifact_manifest, `report {artifact_id}`, locations,
note), preconditions/affected_code/disagreements/coverage_gaps lists, and
nullable `severity_hint`/`confidence_hint`. Severity hints are advisory
only — the lifecycle half independently determines scope eligibility,
known issue status, exploitability, victim impact and final bounty
severity.

## Immutability

Once finalized, changes to any bound input invalidate the finalization —
detected by `check` and by an attempted re-`finalize`:

- config, target scope, audit skill file
- canonical artifacts, artifact manifests
- analysis, candidates, the handoff manifest itself (hash-bound in
  `run.yaml`'s `finalization` block)

Finalized manifests are never silently rewritten. Materially new audit
evidence requires `prepare --new` and a new run. Re-running `finalize` on
an intact finalized batch is an idempotent read-only success.

## Consumer — what `import-audit` verifies (before copying anything)

```bash
lifecycle.py import-audit --case-root <dir> --work-root <audit work-root>
# or: --handoff <work-root>/audits/<run-id>/handoff/manifest.yaml
#     (--work-root auto-discovers the newest finalized handoff;
#      --run-id <id> selects a specific run)
```

- schema exactly `whitehexlabs.audit-handoff/v1`; status exactly FINALIZED;
- run_id well-formed; all paths relative and confined to the handoff run
  root (traversal/symlink escape rejected);
- analysis exists and hashes correctly;
- every step artifact manifest exists and hashes correctly;
- every canonical artifact those manifests bind exists on disk and matches
  its SHA-256 (files) or deterministic tree hash + count (directories);
- candidate count matches, ids unique, copies hash-match.

No `--force`. Any violation is a hard error (exit 2).

## Consumer — what gets copied (immutable, case-local)

```text
<case-root>/imports/audit/<run-id>/
├── manifest.yaml          # import key: the finalized manifest itself
├── analysis.md
├── candidates/A-001.yaml…
├── artifact-manifests/step-<N>.yaml
└── sources/step-<N>/<artifact path>   # every bound canonical artifact
```

After a successful import the case root is fully independent of the audit
workspace: it may be moved or deleted. The audited target source tree is
never copied at import time; later lifecycle stages collect exactly the
source evidence they need through the normal register/evidence mechanisms.

## Idempotency and collision rules

- Imports are keyed by the finalized manifest's SHA-256.
- Same manifest again → success, "already imported", zero changes.
- Same run id with a different manifest hash → fail closed.
- Previously imported evidence is never overwritten or mutated.

## Drafts (the only write into `ingest/`)

One `ingest/<run-id>/finding-source.A-XXX.yaml` per candidate with
provenance pre-filled (`auditor: audit-lifecycle`, `original_finding_id`,
`audit_round: <run-id>`, file references into `imports/…`) and all four
prescreen aspects UNKNOWN/TODO. Import never registers findings and never
guesses pre-screen answers — duplication PASS, scope, authority and
exclusion judgments are completed by hand before `register`, which rejects
unresolved TODO/UNKNOWN fields.

## Relationship to prior art

Root-cause deduplication inside the audit run already happened during audit
aggregation. The PRIOR_ART_CHECKED stage is a different, later check against
the project's published audit reports (docs site, program page, professional
reports) — importing a handoff never satisfies or skips it.
