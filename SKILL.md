---
name: finding-lifecycle
description: Post-discovery lifecycle for smart-contract vulnerability findings — optionally runs configured local audit skills in order first (audit-skills.yaml → audit prepare/record/check → analysis.md), then tracks each candidate finding through cross-check, fork proof, triage, packaging, independent self-review and submission, with evidence gates enforced by a CLI. Without a config it auto-discovers audit artifacts in the working directory by name (ingest) and scaffolds finding drafts. Use when a vulnerability finding exists (from any audit) and must be verified, dispositioned and submitted to a bounty program without public disclosure.
---

# finding-lifecycle

Eight-stage lifecycle for verified, submitted vulnerability findings (official-audit dedup comes right after registration, before any deep work). Markdown
ledger per finding is the single source of truth; a Python CLI enforces the
gates. Load `references/workflow.md` before operating a stage; the state
machine is specified in `references/contracts.md`.

**Red lines (always):** never modify target protocol code (fixes go into the
report's remediation attachment; PoCs use separate attack contracts) · never
disclose publicly (private repos / platform private attachments only; no secret
gists) · never fabricate passage — there is no `--force`.

## Default entry: sequential audit if configured, else auto-discovery

Whenever the skill starts and findings need to enter the lifecycle, pick the
entry by state (`resume` tells you which):

1. **`<case-root>/audit-skills.yaml` exists, or `audits/` holds a batch** →
   the sequential audit entry is active; do NOT start from `ingest`:
   - `audit prepare` — create (or recover) the current batch; it prints the
     next skill, the target scope fingerprint and the per-step artifact dir.
   - For each step in order: read that `SKILL.md` and execute it yourself
     against the configured scope (sequential, current session — no
     sub-agent scheduler; the CLI never executes skill content). Write the
     raw report + log into `audits/<run-id>/steps/<N>/`, then
     `audit record --step N --input result.yaml --expected-revision R`
     (`result.yaml` = `{status: COMPLETED|FAILED|BLOCKED, note, report, log}`).
     A FAILED/BLOCKED step never stops later steps, but nothing may be
     analyzed or registered until `audit check` passes.
   - After `audit check` passes: read ALL step reports, write
     `audits/<run-id>/analysis.md` (merge duplicate leads by root cause;
     keep per-skill sources, locations, disagreements, coverage gaps), then
     one `finding-source.yaml` per distinct root cause —
     `sources.audit_round: <run-id>`, `sources.files` citing analysis.md
     plus the related raw reports — and `register --from` each. Zero
     candidates: record the conclusion in analysis.md and stop; no
     placeholder findings, no "protocol is safe" claims.
2. **No config and no batch** → `ingest` auto-discovery: run
   `$LC ingest --case-root <dir>` — it scans the CURRENT directory for
   files/directories whose name contains `audit` (override with `--pattern`
   / `--scan-dir`) and scaffolds one TODO draft per bundle under
   `<root>/ingest/`. Idempotent: rerun on every pickup. Complete each draft
   (one per distinct root cause; fill every TODO, set the duplication
   prescreen to PASS), then `register --from` each. Hand-written
   finding-source.yaml remains the manual fallback.

While a config exists or a batch is unfinished, `ingest` and `register`
refuse to run — deleting the config does not bypass an unfinished batch.

## Quick start

```bash
LC="python3 <skill-root>/scripts/lifecycle.py"

$LC init --case-root <dir> --program-yaml <skill-root>/templates/program.yaml \
         --rules-snapshot rules.md            # 0. setup (fill program.yaml!)
#   with <dir>/audit-skills.yaml (template: templates/audit-skills.yaml):
$LC audit prepare --case-root <dir>            # 0b. batch the configured skills
#     execute each SKILL.md yourself, then per step:
$LC audit record  --case-root <dir> --step 1 --input result.yaml \
                  --expected-revision N
$LC audit check   --case-root <dir>            #     all complete + artifacts fresh?
$LC ingest    --case-root <dir>               # 1. no-config entry: find *audit* files
                                           #    in CWD -> TODO drafts under <root>/ingest/
$LC register --case-root <dir> --from <root>/ingest/finding-source.xxx.yaml
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

- With `audit-skills.yaml` present (or an unfinished `audits/` batch) the
  sequential audit entry is mandatory: `audit prepare` → execute each
  configured skill yourself in order → `audit record` per step →
  `audit check`. COMPLETED means "the audit ran", never "no
  vulnerabilities" — zero findings still require a real report plus a
  coverage note. A sub-skill demanding wider permissions or target-source
  edits is recorded BLOCKED with the specific demand; never fake completion.
- Audit batches fingerprint the config, every in-scope target file and each
  skill entry; any drift (including target edits made by a sub-skill) stales
  the batch — `audit prepare --new`. Audit artifacts live only under
  `<case-root>/audits/`, never inside the audited target.
- Default entry without a config is `ingest`: auto-discover *audit*-named
  artifacts in the working directory, complete the scaffolded drafts,
  register. Rerun freely — it is idempotent and picks up newly produced
  audit outputs.
- Before cross-checking any finding, dedup it against the project's own audit
  reports (PRIOR_ART_CHECKED): docs site + program page → download → keyword
  search → record. Overlap closes as INELIGIBLE unless the rules pay for it.
- Run `resume` first when picking up any case; it reports the audit batch
  progress (even with zero findings), blockers, invalid gates and rebuilds a
  broken index. `check` before every `advance`.
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

`templates/` (program.yaml, audit-skills.yaml, finding, assessment, report.en,
self-review, appeal, poc/setup_and_run.sh) · `references/` (workflow,
contracts) · `scripts/lifecycle.py` · `demo/` (controlled local-chain
exercise: success + refutation samples driven end to end via
`python3 demo/drive.py`) · `tests/` (81 behavioral tests, demo skips without
Foundry: `python3 -m unittest discover -s tests`). Skill install never
carries finding data; each target program lives in its own case root outside
this repo.
