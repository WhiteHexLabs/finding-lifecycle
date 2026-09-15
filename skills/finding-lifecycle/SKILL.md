---
name: finding-lifecycle
description: Post-audit lifecycle for smart-contract vulnerability findings. Imports finalized audit handoffs, generic audit artifacts, or manual finding sources, then verifies prior art, cross-checks deployments, proves exploitability, triages severity and eligibility, packages evidence, independently reviews, and records private submission.
---

# finding-lifecycle

Eight-stage lifecycle for verified, submitted vulnerability findings (official-audit dedup comes right after registration, before any deep work). Markdown
ledger per finding is the single source of truth; a Python CLI enforces the
gates. Load `references/workflow.md` before operating a stage; the state
machine is specified in `references/contracts.md`.

This skill **never executes audit skills**. To run audits, use
`audit-orchestrator` and import its finalized handoff (entry 0A below).

**Red lines (always):** never modify target protocol code (fixes go into the
report's remediation attachment; PoCs use separate attack contracts) · never
disclose publicly (private repos / platform private attachments only; no secret
gists) · never fabricate passage — there is no `--force`.

## Entry modes — pick by what you already have

1. **0A — a finalized `audit-orchestrator` handoff** →
   `lifecycle.py import-audit --case-root <dir> --handoff <path/to/handoff/manifest.yaml>`:
   verifies the bundle, copies immutable evidence under
   `<root>/imports/audit/<run-id>/`, and scaffolds one TODO draft per audit
   candidate under `ingest/<run-id>/`. After import the case is independent
   of the original audit workspace.
2. **0B — arbitrary external audit output (no handoff)** →
   `ingest --case-root <dir>`: scans the current directory (override with
   `--pattern` / `--scan-dir`) for *audit*-named files/directories and
   scaffolds one TODO draft per bundle under `<root>/ingest/`. Idempotent;
   rerun on every pickup.
3. **0C — a manually structured finding** → hand-write `finding-source.yaml`
   and `register --from` it directly.

All three converge on `register`: complete every TODO in the draft (one file
per distinct root cause; fill each prescreen; duplication must be PASS), then
`register --from` each. A legacy `audit-skills.yaml` inside the case root only
produces a warning — it is no longer executed here.

## Quick start

```bash
LC="python3 <skill-root>/scripts/lifecycle.py"

$LC init --case-root <dir> --program-yaml <skill-root>/templates/program.yaml \
         --rules-snapshot rules.md            # 0. setup (fill program.yaml!)
$LC import-audit --case-root <dir> --handoff <audit-work-root>/audits/<run-id>/handoff/manifest.yaml
$LC ingest    --case-root <dir>               # 0B. no-handoff entry: *audit* files in CWD
$LC register  --case-root <dir> --from <root>/ingest/finding-source.xxx.yaml
$LC check    --case-root <dir> --id F-…       # preview the next gate (read-only)
$LC advance  --case-root <dir> --id F-… --reviewer <who> \
             --reason "<substantive note citing an evidence path>" \
             --expected-revision N            # one stage per call
$LC close|reopen|record|resume|index …        # dispositions, receipts, recovery
```

Exit codes: `0` ok · `1` gate failed · `2` input/runtime error. Mutating
commands require the current `--expected-revision` (lost-update protection).

## Stages & gates (one file each, exact schemas in workflow.md)

| # | Stage | Produce | Gate essence |
|---|-------|---------|--------------|
| 0 | DISCOVERED | finding-source.yaml + prescreen | traceable source; duplication resolved; pre-screen recorded |
| 1 | PRIOR_ART_CHECKED | prior-art.yaml + report copies | official docs site & program page searched; each audit report hashed locally + checked; MATCH ⇒ INELIGIBLE (or still_eligible with rule_ref); no audits must be declared |
| 2 | CROSS_CHECKED | cross-check.yaml + assessment.md | explicit affected deployment set (addr + runtime code hash); refutation attempts; damage ≠ profit |
| 3 | FORK_PROVEN | fork-proof.yaml + PoC + run.log | pinned fork; real addresses; assertions present in the log; PnL split (unknown stays unknown); cheatcodes justified |
| 4 | TRIAGED | triage.yaml | severity == matrix entry; every eligibility item PASS/NOT_APPLICABLE (FAIL ⇒ close INELIGIBLE); novelty recorded; rules snapshot frozen |
| 5 | PACKAGED | manifest.yaml + report.en.md + zip | clean-dir run `RESULT: PASS`; hashes; zip complete; secrets scan; pinned deps |
| 6 | SELF_REVIEWED | self-review.yaml | independent session/agent; bound to final package hash; zero unresolved objections |
| 7 | SUBMITTED | submission.yaml (record submission → advance) | receipt + PRIVATE channel + package hash + account limits |

Dispositions (independent of stage): `OPEN MERGED INELIGIBLE REFUTED ACCEPTED
REJECTED WITHDRAWN`; appeals: `NONE → DRAFTED → SENT → RESOLVED`.

## Operating rules

- Before cross-checking any finding, dedup it against the project's own audit
  reports (PRIOR_ART_CHECKED): docs site + program page → download → keyword
  search → record. Overlap closes as INELIGIBLE unless the rules pay for it.
  Cross-skill root-cause dedup inside an audit run is a different thing —
  that happened at audit aggregation; this gate checks the project's
  published prior art.
- Imported audit evidence (`imports/`) is immutable provenance; drafts
  scaffolded by `import-audit` pre-fill sources/auditor/audit_round and
  leave every prescreen UNKNOWN — the claim and the dedup judgment stay
  with you. `register` rejects unresolved TODO/UNKNOWN fields by design.
- One parent directory per target program: this case root (`case/`) sits
  beside the audit work-root (`audit/`) — siblings, never one shared root.
  `import-audit`'s copies exist precisely so the case survives deleting
  the audit workspace. Orchestrator output enters via 0A only — never
  0B-scan a directory that covers `audit/` (name-based discovery would
  scaffold a duplicate draft).
- Run `resume` first when picking up any case; it reports blockers, invalid
  gates and rebuilds a broken index. `check` before every `advance`.
- Modified PoC/report/targets/rules invalidate the affected gates and their
  successors → `reopen --affect-stage <stage>`, never hand-edits. Manual edits
  never grant passage.
- Infrastructure failure (RPC down, missing deps, unclear rules) ⇒ `record
  blocker`, stay open. REFUTED needs fork counter-evidence + a conclusion
  boundary; INELIGIBLE is not "not a bug".
- Report changes after review = new package version + new independent review;
  submitted packages are never overwritten. "Generated" ≠ "submitted".
- Case roots hold no credentials, RPC keys or KYC documents.

## Repository layout

`templates/` (program.yaml, finding, assessment, report.en, self-review,
appeal, poc/setup_and_run.sh) · `references/` (workflow, contracts,
handoff-contract) · `scripts/lifecycle.py` · `demo/` (controlled local-chain
exercise: success + refutation samples driven end to end via
`python3 demo/drive.py`) · `tests/` (behavioral tests at the repository
root). Skill install never carries finding data; each target program lives
in its own case root outside this repo. Audit execution lives in the sibling
skill `audit-orchestrator`.
