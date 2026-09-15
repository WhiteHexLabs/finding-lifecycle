# finding-lifecycle (repository)

A two-Skill collection for smart-contract security work: run the audits,
then track each finding to a verified, privately submitted bounty report —
with strict, hash-bound evidence contracts on both sides of the boundary.

```text
skills/audit-orchestrator/   — run configured audit skills, freeze artifacts,
                               aggregate by root cause, emit a versioned handoff
skills/finding-lifecycle/    — import handoffs or arbitrary audit output and
                               drive findings to submission
```

## Which skill do I need?

```text
Only want an audit?
→ skills/audit-orchestrator (prepare → record → check → aggregate → finalize)

Already have an audit result / finding?
→ skills/finding-lifecycle (import-audit | ingest | register → advance → submit)

Want the complete flow?
→ skills/audit-orchestrator → finalize
→ skills/finding-lifecycle import-audit --handoff <…>/handoff/manifest.yaml
```

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
```

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
skills/     the two independent Skills (no runtime imports between them;
            the file-based handoff bundle is the integration boundary)
tests/      audit_orchestrator/ · finding_lifecycle/ · integration/
demo/       controlled local-chain exercise for the lifecycle pipeline
```

Tests: `python3 -m unittest discover -s tests` (requires PyYAML; the demo
test skips without Foundry). Security rules on both sides: never modify the
audited target, never fabricate evidence, no `--force`, no secrets in work
roots, no public disclosure of private bounty findings.
