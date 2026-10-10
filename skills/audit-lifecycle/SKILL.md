---
name: audit-lifecycle
description: End-to-end smart-contract audit skill. The audit half orchestrates configured local audit skills under a strict execution/output contract, freezes artifacts, aggregates findings by root cause, and emits a versioned handoff bundle. The lifecycle half imports that handoff (or generic audit artifacts, or manual finding sources) and drives each finding through an eight-stage verified lifecycle to private submission. Use for audit-only work, the complete flow, or post-audit finding management.
---

# audit-lifecycle

Two halves, one skill, one continuous flow:

- **audit.py — audit orchestration.** Runs the configured local audit
  skills in order against one target scope, under a strict
  execution/output contract, freezing every step's outputs into canonical
  per-step artifacts. After all steps complete, the session aggregates the
  reports semantically (root-cause clustering, dedup, disagreement
  preservation) and `finalize` emits a versioned, hash-bound handoff
  bundle. Audit-only work stops here — a first-class stopping point.
- **lifecycle.py — finding lifecycle.** Imports the finalized handoff (or
  arbitrary audit output, or a manually structured finding), then verifies
  prior art, cross-checks deployments, proves exploitability, triages
  severity and eligibility, packages evidence, independently reviews, and
  records private submission.

The handoff bundle (`whitehexlabs.audit-handoff/v1`) remains the boundary
between the halves: hash-bound, machine-verified end to end by
`import-audit`, and the reason the disposable audit work-root and the
long-lived case ledger stay independent — the case survives deleting the
audit workspace after import.

**Division of responsibility (audit half):** each configured audit Skill
defines **how to audit** (methodology, tools, internal layout — never
overridden). The orchestrator defines **how execution results are handed
back** (target/scope, step order, work dir, result contract, artifact
freezing). lifecycle.py never executes audit skills.

**Red lines (always):** never modify the audited target source · never
fabricate evidence, completion or gate passage · there is no `--force` ·
missing or ambiguous output BLOCKs instead of guessing · canonical audit
artifacts are immutable evidence once recorded · zero findings never
becomes "the protocol is safe" · no secrets/RPC keys/KYC material in audit
work roots or case roots · never disclose findings publicly (private
repos / platform private attachments only; no secret gists).

## Quick start — the complete flow

```bash
S="<skill-root>/scripts"
A="python3 $S/audit.py"        # audit half (--work-root)
LC="python3 $S/lifecycle.py"   # lifecycle half (--case-root)

# 1. audit half — one disposable work-root per target program
cp <skill-root>/templates/audit-skills.yaml <work-root>/audit-skills.yaml  # fill in!
$A prepare  --work-root <dir>     # per-step execution-prompt.md + work/ dirs
#   per step: read steps/<N>/execution-prompt.md AND the audit skill's SKILL.md,
#   execute the audit, write result.yaml, then:
$A record  --work-root <dir> --step 1 --input result.yaml --expected-revision N
$A check   --work-root <dir>     # every step COMPLETED + artifacts fresh?
#   aggregate: write audits/<run-id>/analysis.md (+ candidates/A-001.yaml…)
$A finalize --work-root <dir> --expected-revision N
#   → audit-only work stops here

# 2. lifecycle half — the long-lived case ledger (sibling of the work-root)
$LC init --case-root <dir> --program-yaml <skill-root>/templates/program.yaml \
         --rules-snapshot rules.md            # only if not yet initialized
$LC import-audit --case-root <dir> --work-root <audit work-root>
#   auto-discovers the newest finalized handoff; one TODO draft per candidate
#   is scaffolded — complete every prescreen (duplication must be PASS), then:
$LC register --case-root <dir> --from <root>/ingest/<run-id>/finding-source.A-XXX.yaml
$LC check    --case-root <dir> --id F-…       # preview the next gate (read-only)
$LC advance  --case-root <dir> --id F-… --reviewer <who> \
             --reason "<substantive note citing an evidence path>" \
             --expected-revision N            # one stage per call
$LC lint     --case-root <dir> --id F-… --save-log evidence/<id>/lint-<date>.log
$LC close|reopen|record|resume|index …        # dispositions, receipts, recovery
$LC export   --case-root <dir> --id F-…       # assemble submission/NN-…-<SEV>/
```

`import-audit` also accepts an explicit `--handoff <path>` (a finalized
`handoff/manifest.yaml`) when the work-root is not at hand. Exit codes for
both CLIs: `0` ok · `1` gate failed · `2` input/runtime error. Mutating
lifecycle commands require the current `--expected-revision`.

## Part 1 — audit orchestration (audit.py)

```text
PREPARE → EXECUTE → RECORD/NORMALIZE → CHECK → AGGREGATE → FINALIZE
```

- **PREPARE** — validate `audit-skills.yaml` (strict schema; scope inside
  target_root; no duplicate skills; this skill itself is rejected),
  fingerprint every in-scope file, create `audits/<run-id>/` with per-step
  `step.yaml`, `execution-prompt.md`, `work/`. Missing SKILL.md → that
  step is BLOCKED while the rest still runs.
- **EXECUTE** — the session reads the audit skill's SKILL.md and the
  generated execution prompt, then executes the audit itself (the CLI
  never executes skill content). Fixed-output skills run in their own
  directory and declare their real output paths in `result.yaml`.
- **RECORD/NORMALIZE** — `record` validates the result, verifies the
  target was not modified, copies every declared artifact into the step's
  canonical `attempts/<k>/artifacts/`, hashes files (SHA-256) and
  directories (deterministic tree hash), and writes
  `artifact-manifest.yaml` for the accepted COMPLETED attempt.
- **CHECK** — every step COMPLETED and every frozen artifact still hashes
  correctly; config/target/skill drift stales the batch.
- **AGGREGATE** — the session writes `audits/<run-id>/analysis.md`
  (semantic root-cause clustering, dedup, disagreement preservation —
  never report concatenation) and one `candidates/A-XXX.yaml` per
  consolidated root cause. The CLI validates both at finalize.
- **FINALIZE** — validates aggregation, hashes analysis + candidates,
  binds candidate sources to canonical manifests, writes the immutable
  `handoff/manifest.yaml` (`whitehexlabs.audit-handoff/v1`).

Operating rules: steps record strictly in order; after the first pass
only FAILED/BLOCKED steps may be rerun — in original order; COMPLETED
steps are terminal within a batch; retries never overwrite prior
attempts. Any drift (config, in-scope target file added/deleted/modified
— including edits made by a sub-skill, skill entry) stales the batch →
`prepare --new` (old runs stay on disk); a finalized batch plus its bound
inputs is immutable — material new evidence requires a new run. COMPLETED
means "the audit ran", never "no vulnerabilities" — zero findings still
require a real report plus a coverage note, stated explicitly in the
analysis. `severity_hint` in candidates is advisory only; bounty severity
is decided by the lifecycle half. Aggregation reads only
`steps/*/artifact-manifest.yaml` and canonical artifacts — deleting a
skill's original output after `record` must not break
check/aggregation/finalize.

## Part 2 — finding lifecycle (lifecycle.py)

**Entry modes — pick by what you already have:**

1. **0A — a finalized handoff** → `import-audit --case-root <dir>
   --work-root <audit work-root>` (or `--handoff <path>`): verifies the
   bundle, copies immutable evidence under `<root>/imports/audit/<run-id>/`,
   and scaffolds one TODO draft per audit candidate under
   `ingest/<run-id>/`. After import the case is independent of the audit
   workspace.
2. **0B — arbitrary external audit output (no handoff)** → `ingest
   --case-root <dir>`: scans the current directory (override with
   `--pattern` / `--scan-dir`) for *audit*-named files/directories and
   scaffolds one TODO draft per bundle under `<root>/ingest/`. Idempotent;
   rerun on every pickup. Never 0B-scan a directory that covers the audit
   work-root (name-based discovery would scaffold a duplicate draft).
3. **0C — a manually structured finding** → hand-write
   `finding-source.yaml` and `register --from` it directly.

All three converge on `register`: complete every TODO in the draft (one
file per distinct root cause; fill each prescreen; duplication must be
PASS), then `register --from` each. A legacy `audit-skills.yaml` inside
the case root only produces a warning — audit execution never happens in
the lifecycle half.

**Stages & gates** (one file each, exact schemas in workflow.md):

| # | Stage | Produce | Gate essence |
|---|-------|---------|--------------|
| 0 | DISCOVERED | finding-source.yaml + prescreen | traceable source; duplication resolved; pre-screen recorded |
| 1 | PRIOR_ART_CHECKED | prior-art.yaml + report copies | official docs site & program page searched; each audit report hashed locally + checked; MATCH ⇒ INELIGIBLE (or still_eligible with rule_ref); declared "no audits" needs ≥2 channels + an independent confirmation |
| 2 | CROSS_CHECKED | cross-check.yaml + assessment.md | explicit affected deployment set (addr + runtime code hash); refutation attempts; damage ≠ profit |
| 3 | FORK_PROVEN | fork-proof.yaml + PoC + run.log | pinned fork; real addresses; assertions present in the log; PnL split (unknown stays unknown); cheatcodes justified |
| 4 | TRIAGED | triage.yaml | severity == matrix entry; every eligibility item PASS/NOT_APPLICABLE (FAIL ⇒ close INELIGIBLE); novelty recorded; rules snapshot frozen |
| 5 | PACKAGED | manifest.yaml + report.en.md + zip | clean-dir run `RESULT: PASS`; hashes; zip complete; secrets scan; pinned deps; platform materials when `delivery.platform` names one (Immunefi: `immunefi/{1-title,2-description,3-poc}.txt`; HackenProof: `hackenproof/fields/{1..4}` + `submission.md`; Code4rena/CodeHawks/Sherlock/Cantina: `1-title.txt` + one markdown body — see `references/platform-standards.md`) |
| 6 | SELF_REVIEWED | self-review.yaml | independent rounds until a clean round; next round landing-verifies the last; bound to final package hash; zero unresolved objections |
| 7 | SUBMITTED | submission.yaml (record submission → advance) | receipt + PRIVATE channel + package hash + account limits |

Dispositions (independent of stage): `OPEN MERGED INELIGIBLE REFUTED
ACCEPTED REJECTED WITHDRAWN`; appeals: `NONE → DRAFTED → SENT → RESOLVED`.

Operating rules: before cross-checking any finding, dedup it against the
project's own published audit reports (PRIOR_ART_CHECKED — docs site +
program page → download → keyword search → record; overlap closes as
INELIGIBLE unless the rules pay for it; cross-skill root-cause dedup
inside an audit run already happened at audit aggregation). Imported
audit evidence (`imports/`) is immutable provenance; drafts scaffolded by
`import-audit` pre-fill sources/auditor/audit_round and leave every
prescreen UNKNOWN — `register` rejects unresolved TODO/UNKNOWN fields by
design. Every finding keeps its PoC as a runnable project under
`evidence/<id>/poc/` (foundry.toml, verified-source src/, test/, vendored
lib/, run.log) — re-verifiable with `forge test` even when never
submitted; packaging copies that tree verbatim. Run `resume` first when
picking up any case; `check` before every `advance`. Modified
PoC/report/targets/rules invalidate the affected gates and their
successors → `reopen --affect-stage <stage>`, never hand-edits; the one
sanctioned exception is Tier-1 wording fixes via `record correction`
(lint log + rebind + journal) — anything technical is Tier 2 (reopen, new
package version, fresh review). Infrastructure failure ⇒ `record
blocker`, stay open; REFUTED needs fork counter-evidence; INELIGIBLE is
not "not a bug". After PACKAGED, run `lint` after **every** edit batch to
the report or form fields. Submitted packages are never overwritten;
"generated" ≠ "submitted".

## Workspace layout (one parent per program)

The audit work-root and the lifecycle case-root are **sibling directories
under one parent per target program** — never a single shared root:

```text
<program>/
├── audit/                        # audit.py --work-root (disposable)
│   ├── audit-skills.yaml
│   └── audits/<run-id>/handoff/manifest.yaml
└── case/                         # lifecycle.py --case-root (long-lived ledger)
    ├── imports/audit/<run-id>/   # immutable copies written by import-audit
    ├── ingest/ · findings/ · evidence/ · packages/
    └── submission/               # `export` output: NN-<slug>-<SEVERITY>/
```

`import-audit`'s copies exist precisely so the case survives deleting or
moving `audit/`; `prepare --new` batches accumulate in the work-root
while the case root stays the submission ledger.

## References

`references/audit-workflow.md` (audit stage-by-stage manual) ·
`references/execution-contract.md` (execution prompt + result contract) ·
`references/artifact-contract.md` (normalization, hashing, manifests) ·
`references/handoff-contract.md` (finalize + import — the internal
boundary contract, both sides) · `references/workflow.md` (lifecycle
stage-by-stage manual) · `references/contracts.md` (lifecycle state
machine spec) · `references/platform-standards.md` (submission material
formats, PoC bars, severity vocabularies) · `templates/` (audit-skills,
result, audit-candidate, program.yaml, finding, report.en, self-review,
appeal, poc, platform kits) · `demo/` (controlled local-chain exercise,
at the repository root) · `tests/` (behavioral tests at the repository
root). Skill install never carries finding data; each target program
lives in its own work/case roots outside this repo.
