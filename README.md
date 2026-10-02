# finding-lifecycle (repository)

A three-Skill collection for smart-contract security work: assemble verified
targets from block explorers, run the audits, then track each finding to a
verified, privately submitted bounty report — with strict, hash-bound
evidence contracts at every boundary.

```text
skills/contract-fetch/       — transcribe bounty scope tables, fetch verified
                               sources from explorers, build a compilable
                               Foundry workspace, prove byte-identity, emit
                               a sources-manifest
skills/audit-orchestrator/   — run configured audit skills, freeze artifacts,
                               aggregate by root cause, emit a versioned handoff
skills/finding-lifecycle/    — import handoffs or arbitrary audit output and
                               drive findings to submission
```

## Which skill do I need?

```text
Need the target protocol's sources locally (pre-audit)?
→ skills/contract-fetch (init → validate → select → fetch → assemble → build
  → verify → manifest → check)

Only want an audit?
→ skills/audit-orchestrator (prepare → record → check → aggregate → finalize)

Already have an audit result / finding?
→ skills/finding-lifecycle (import-audit | ingest | register → advance → submit)

Want the complete flow?
→ skills/contract-fetch (verified Foundry workspace) — use its manifest src
  paths as the orchestrator's target_root
→ skills/audit-orchestrator → finalize
→ skills/finding-lifecycle import-audit --handoff <…>/handoff/manifest.yaml
```

## Workspace layout (one parent per program)

The audit work-root and the lifecycle case-root are **sibling directories
under one parent per target program** — never a single shared root:

```text
<program>/
├── audit/                        # audit-orchestrator --work-root
│   ├── audit-skills.yaml
│   └── audits/<run-id>/handoff/manifest.yaml
└── case/                         # finding-lifecycle --case-root
    ├── imports/audit/<run-id>/   # immutable copies written by import-audit
    ├── ingest/ · findings/ · evidence/ · packages/
    └── submission/               # `export` output: NN-<slug>-<SEVERITY>/ paste kits
```

Why siblings and not one root: `import-audit` copies the evidence, so the
case survives deleting or moving `audit/` afterwards; the work-root is
disposable (`prepare --new` batches accumulate there) while the case root is
the long-lived submission ledger. Orchestrator output always enters via
`import-audit` (0A) — do not run 0B `ingest` with a `--scan-dir` that covers
`audit/`: its name-based discovery would scaffold a duplicate draft.

## skills/contract-fetch

Pre-audit batch source fetching from block explorers (design doc:
`docs/contract-fetch-design.md`). Candidates come from vulnerability-platform
**Assets in Scope** tables — the Funds column ranks "large locked value", the
Added-on column filters "recently added"; transcription is the operator's
judgment, validation/ranking is the CLI's. One gated pipeline per target:
SELECTED → FETCHED → ASSEMBLED → BUILT → VERIFIED → READY.

```bash
CF="python3 skills/contract-fetch/scripts/fetch.py"
$CF init     --fetch-root <dir>            # scaffold + targets.yaml template
#   transcribe scope rows (references/discovery-sources.md), then:
$CF validate --fetch-root <dir>
$CF select   --fetch-root <dir> --sort funds --top 20 -o targets-selected.yaml
$CF fetch    --fetch-root <dir>            # ETHERSCAN_API_KEY from env, cache-first
$CF assemble --fetch-root <dir>            # byte-identical trees + foundry.toml
$CF build    --fetch-root <dir>            # FOUNDRY_PROFILE=<id> forge build
$CF verify   --fetch-root <dir>            # on-chain bytecode + source identity
$CF manifest --fetch-root <dir>            # sources-manifest.yaml (→ target_root)
$CF check    --fetch-root <dir>
```

Red lines: downloaded sources are immutable evidence (never edited; BUILD_FAIL
is recorded, not patched), fail-closed on unverified/Vyper/nightly/mismatch,
no `--force`, API keys only from the environment. Verification proves bytecode
equality (immutable-masked, metadata included) and per-file keccak identity —
metadata-hash equality is what makes local line numbers identical to the
explorer's code view.

Docs: `skills/contract-fetch/references/` (discovery-sources, explorer-api,
verification, workflow).

## skills/audit-orchestrator

Orchestrates configured local audit skills (`audit-skills.yaml`: target
tree, scope, ordered SKILL.md list). The audit methodology always belongs
to each audit skill; the orchestrator owns execution boundaries: per-step
execution prompts, the `result.yaml` contract
(`whitehexlabs.audit-result/v1`), artifact normalization/freezing
(`attempts/<k>/artifacts/` + `artifact-manifest.yaml`), root-cause
aggregation (`analysis.md` + `candidates/A-XXX.yaml`), and the immutable
finalized handoff (`whitehexlabs.audit-handoff/v1`). Audit-only work stops
at finalize — a first-class stopping point.

```bash
A="python3 skills/audit-orchestrator/scripts/audit.py"
$A prepare  --work-root <dir>          # also writes per-step execution-prompt.md
$A record  --work-root <dir> --step 1 --input result.yaml --expected-revision N
$A check   --work-root <dir>
#   write audits/<run-id>/analysis.md + candidates/, then:
$A finalize --work-root <dir> --expected-revision N
```

Docs: `skills/audit-orchestrator/references/` (workflow, execution
contract, artifact contract, handoff contract).

## skills/finding-lifecycle

Post-audit lifecycle with an enforced eight-stage state machine
(DISCOVERED → PRIOR_ART_CHECKED → CROSS_CHECKED → FORK_PROVEN → TRIAGED →
PACKAGED → SELF_REVIEWED → SUBMITTED), dispositions, blockers, reopen and
appeals. It never executes audit skills. Entry modes:

```bash
LC="python3 skills/finding-lifecycle/scripts/lifecycle.py"
$LC import-audit --case-root <dir> --handoff <…>/handoff/manifest.yaml   # 0A
$LC ingest    --case-root <dir>                                          # 0B
$LC register  --case-root <dir> --from finding-source.yaml               # 0C
$LC export    --case-root <dir> --id F-… [--id F-…]                      # materials
```

Each finding keeps its PoC as a locally runnable project under
`evidence/<id>/poc/` (re-verifiable with `forge test` even if never
submitted). Platform submission materials are format-gated: when
`program.yaml delivery.platform: immunefi`, PACKAGED also requires the
three-file form kit `packages/<id>/immunefi/{1-title,2-description,
3-poc}.txt` (required section headers enforced); with
`delivery.platform: hackenproof` it requires the four-field kit
`packages/<id>/hackenproof/fields/{1-title.txt,2-vulnerability-details.md,
3-validation-steps.md,4-supporting-files.txt}` plus the full write-up
`hackenproof/submission.md` (headers and the `Upload:` bundle line
enforced). `export` assembles `submission/NN-<slug>-<SEVERITY>/` (field
files + the attachment zip + declared attachments + README index with
per-package form targets and a not-exported ledger) in the given
submission-priority order — the HackenProof attachment is copied out as
`<slug>-poc-bundle.zip`.

Post-package quality loop (hardened after a real multi-round submission
cycle): self-review is a **bounded loop of independent rounds** — each later
round first landing-verifies the previous round's fixes, and the loop ends
only on a clean round. `lint` is the post-edit regression battery over the
report + form fields: address allowlist (wrong-address transcriptions have
survived three review rounds), recipient-visible file references, platform
form sections still present, and submission-facing voice (no review/process
narration). Post-review edits are two-tier: wording fixes are journaled
corrections (`record correction` — lint log, manifest hash refresh, gate
input rebind); technical changes reopen PACKAGED for a new package version
and a fresh independent review. Declaring "no published audits" in the
prior-art gate requires two discovery channels plus an independent
confirmation — absence is the most expensive claim to get wrong.

Docs: `skills/finding-lifecycle/references/` (workflow, contracts, handoff
contract). Demo: `demo/drive.py` (controlled local-chain exercise).

## Migration from the combined skill

| Old combined command | New owner |
|---|---|
| `audit prepare` | `audit-orchestrator` (`audit.py prepare --work-root`) |
| `audit record` | `audit-orchestrator` (`audit.py record`) |
| `audit check` | `audit-orchestrator` (`audit.py check`) |
| audit resume/recovery | `audit-orchestrator` (`audit.py prepare` recovers) |
| audit aggregation + finalization | `audit-orchestrator` (`audit.py finalize`, new) |
| `ingest` | `finding-lifecycle` (unchanged shape) |
| `register` | `finding-lifecycle` (no longer gated by an audit batch) |
| lifecycle `check/advance/close/reopen/record/resume/index` | `finding-lifecycle` (unchanged) |
| `import-audit` | `finding-lifecycle` (new) |

Compatibility: old unfinished audit batches resume under the new
orchestrator (the legacy result shape and legacy frozen artifacts are still
accepted; finalize adapts frozen copies into canonical manifests). A legacy
`audit-skills.yaml` in a lifecycle case root only warns.

## Repository layout

```text
skills/     the three independent Skills (no runtime imports between them;
            file-based contracts are the integration boundaries:
            sources-manifest → audit-orchestrator, handoff → finding-lifecycle)
tests/      audit_orchestrator/ · finding_lifecycle/ · contract_fetch/ · integration/
demo/       controlled local-chain exercise for the lifecycle pipeline
docs/       design documents (contract-fetch-design.md)
```

Tests: `python3 -m unittest discover -s tests` (requires PyYAML; the demo and
forge-build tests skip without Foundry; contract-fetch tests run fully offline
against a mock explorer/RPC server). Security rules on all sides: never modify
the audited target, never fabricate evidence, no `--force`, no secrets in work
roots, no public disclosure of private bounty findings.
