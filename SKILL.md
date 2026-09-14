---
name: finding-lifecycle
description: Post-discovery lifecycle for smart-contract vulnerability findings — track each candidate finding from registration through cross-check, fork proof, triage, packaging, independent self-review and submission, with evidence gates enforced by a CLI. Use when a vulnerability finding exists (from any audit) and must be verified, dispositioned and submitted to a bounty program without public disclosure.
---

# finding-lifecycle

Seven-stage lifecycle for verified, submitted vulnerability findings. Markdown
ledger per finding is the single source of truth; a Python CLI enforces the
gates. Load `references/workflow.md` before operating a stage; the state
machine is specified in `references/contracts.md`.

**Red lines (always):** never modify target protocol code (fixes go into the
report's remediation attachment; PoCs use separate attack contracts) · never
disclose publicly (private repos / platform private attachments only; no secret
gists) · never fabricate passage — there is no `--force`.

## Quick start

```bash
LC="python3 <skill-root>/scripts/lifecycle.py"

$LC init --case-root <dir> --program-yaml <skill-root>/templates/program.yaml \
         --rules-snapshot rules.md            # 0. setup (fill program.yaml!)
$LC register --case-root <dir> --from finding-source.yaml
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
| 1 | CROSS_CHECKED | cross-check.yaml + assessment.md | explicit affected deployment set (addr + runtime code hash); refutation attempts; damage ≠ profit |
| 2 | FORK_PROVEN | fork-proof.yaml + PoC + run.log | pinned fork; real addresses; assertions present in the log; PnL split (unknown stays unknown); cheatcodes justified |
| 3 | TRIAGED | triage.yaml | severity == matrix entry; every eligibility item PASS/NOT_APPLICABLE (FAIL ⇒ close INELIGIBLE); novelty recorded; rules snapshot frozen |
| 4 | PACKAGED | manifest.yaml + report.en.md + zip | clean-dir run `RESULT: PASS`; hashes; zip complete; secrets scan; pinned deps |
| 5 | SELF_REVIEWED | self-review.yaml | independent session/agent; bound to final package hash; zero unresolved objections |
| 6 | SUBMITTED | submission.yaml (record submission → advance) | receipt + PRIVATE channel + package hash + account limits |

Dispositions (independent of stage): `OPEN MERGED INELIGIBLE REFUTED ACCEPTED
REJECTED WITHDRAWN`; appeals: `NONE → DRAFTED → SENT → RESOLVED`.

## Operating rules

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
appeal, poc/setup_and_run.sh) · `references/` (workflow, contracts) ·
`scripts/lifecycle.py` · `tests/` (32 behavioral tests: `python3 -m unittest
discover -s tests`). Skill install never carries finding data; each target
program lives in its own case root outside this repo.
