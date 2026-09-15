# Handoff contract — the consumer side (audit-orchestrator → finding-lifecycle)

The producer contract lives in `audit-orchestrator/references/handoff-contract.md`;
this file describes what finding-lifecycle expects and enforces.

## What a handoff is

A finalized audit run's immutable bundle:

```text
<work-root>/audits/<run-id>/
├── analysis.md                  # consolidated semantic analysis
└── handoff/
    ├── manifest.yaml            # whitehexlabs.audit-handoff/v1, status FINALIZED
    └── candidates/A-001.yaml…   # whitehexlabs.audit-candidate/v1 copies
```

The manifest hash-binds the analysis, every step's canonical
`artifact-manifest.yaml`, and every candidate copy. The consumer needs no
access to the skills' original output locations.

## What `import-audit` verifies (before copying anything)

- schema exactly `whitehexlabs.audit-handoff/v1`; status exactly FINALIZED;
- run_id well-formed; all paths relative and confined to the handoff run
  root (traversal/symlink escape rejected);
- analysis exists and hashes correctly;
- every step artifact manifest exists and hashes correctly;
- every canonical artifact those manifests bind exists on disk and matches
  its SHA-256 (files) or deterministic tree hash + count (directories);
- candidate count matches, ids unique, copies hash-match.

No `--force`. Any violation is a hard error (exit 2).

## What gets copied (immutable, case-local)

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
provenance pre-filled (`auditor: audit-orchestrator`, `original_finding_id`,
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
