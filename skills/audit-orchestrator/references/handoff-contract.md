# Handoff contract — finalize and the audit → lifecycle boundary

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
only — finding-lifecycle independently determines scope eligibility, known
issue status, exploitability, victim impact and final bounty severity.

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

## Consumer

`finding-lifecycle import-audit --case-root <dir> --handoff <manifest.yaml>`
verifies this bundle end to end (schema, FINALIZED status, analysis and
candidate hashes, artifact-manifest hashes, source artifact file/tree
hashes), copies the evidence immutably into the case root, and scaffolds
one finding-source draft per candidate — without registering or
pre-screening anything.
