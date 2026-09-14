# Workflow — the seven stages in practice

Operating manual. State/gate contracts: references/contracts.md. Two red lines
apply at every stage: **never modify target protocol code** (fix ideas go into
the report's remediation attachment only; PoCs use separate attack contracts)
and **never disclose publicly** (controlled private channels only).

Conventions: `lc()` is `python3 <skill-root>/scripts/lifecycle.py`. Every
mutating command needs `--case-root` and `--expected-revision` (the current
`revision` in the ledger). Read the revision with `resume`/`index` or the
frontmatter. `check` before `advance` to preview a gate without writing.

## 0. Setup and registration (→ DISCOVERED)

```bash
lc init --case-root <dir> --program-yaml templates/program.yaml \
        --rules-snapshot <fetched-rules-file>
```

Fill `program.yaml` completely (scope, severity matrix verbatim from the rules,
exclusions, novelty sources, bounty/submission rules, KYC/SLA — null = unknown,
never guessed). `init` freezes the snapshot hash; keep the snapshot file
untouched afterwards, or re-`init` a fresh root.

Register each candidate finding from a `finding-source.yaml`:

```yaml
title: ...
claim: ...
sources: {auditor: ..., original_finding_id: ..., audit_round: ..., files: [{path: <original doc>, note: ...}]}
prescreen:
  - {aspect: scope,      status: PASS|FAIL|UNKNOWN|NOT_APPLICABLE, evidence: ..., explanation: ...}
  - {aspect: authority,  status: ..., ...}
  - {aspect: exclusion,  status: ..., ...}
  - {aspect: duplication, status: PASS, ...}   # must be PASS; merge instead otherwise
```

`register` copies source documents into `evidence/<id>/sources/` and renders the
ledger. Deduplicate against the index and era map first. Pre-screen FAILs print
a hint to `close --disposition INELIGIBLE --reason ... --evidence ...`; UNKNOWNs
become blockers — neither is a technical refutation.

## 1. Cross-check (→ CROSS_CHECKED)

Produce `evidence/<id>/assessment.md` (four pillars + adverse evidence,
templates/assessment.md) and `evidence/<id>/cross-check.yaml`:

```yaml
targets:
  - {chain_id: 1, address: 0x…, proxy_address: 0x…|null, implementation_address: 0x…|null,
     block: 19000000, code_sha256: 0x<runtime bytecode hash>}
root_cause: {claim: ..., variants: [...]}
refutation_attempts: [{attempt: ..., outcome: ...}]
damage_vs_profit: {victim_damage: ..., attacker_profit: ...}
assessment: evidence/<id>/assessment.md
uncovered_variants: [...]
```

Work items: enumerate deployment variants (proxy/implementation pairs, per-chain
deployments, upgraded versions); verify the audited source against on-chain
runtime bytecode; try to kill the claim on every variant; separate victim damage
from attacker profit. Uncovered variants must not be written up as affected.

```bash
lc check  --id F-…                 # preview
lc advance --id F-… --reviewer <you> \
  --reason "cross-checked variants; blocked paths per evidence/F-…/assessment.md" \
  --expected-revision N
```

## 2. Fork proof (→ FORK_PROVEN)

Pin the fork and reproduce end-to-end on the real addresses (Foundry mainnet
fork is the default). Write `evidence/<id>/fork-proof.yaml`:

```yaml
fork: {chain_id: 1, block_number: …, block_hash: 0x…, rpc_url_ref: env MAINNET_RPC_URL,
       tool_versions: {forge: 0.2.2}}
targets_checked: [0x…]
capabilities: [{name: deal|prank|warp|oracle_mock|other, used_for: ..., justification: ...}]
controls: [{control: pause|denylist|…, applicable: false, verified: "no pause exists"}]
poc: {test_file: evidence/<id>/Exploit.t.sol, run_log: evidence/<id>/run.log,
      expected_assertions: [ProfitWithdrawn], result: PASS}
pnl:
  currency: USDC
  attacker: [{item: gross_proceeds, amount: "123", known: true}, {item: gas, amount: unknown, known: false}]
  victim:   [{item: direct_loss, amount: "123", known: true}]
```

Rules: every cheatcode capability must be justified — powers a real attacker
cannot have cannot evidence exploitability. The run log must contain each named
assertion. PnL splits profit and damage; unknown costs are `unknown`, not zero.
RPC down? `record blocker --item "RPC unavailable" --next-step …` and stop —
never close on infrastructure failure. Name the tests after the assertions so
the log check is meaningful.

## 3. Triage (→ TRIAGED)

`evidence/<id>/triage.yaml`:

```yaml
severity: {final: HIGH, matrix_entry: S2, justification: "amounts in evidence/<id>/run.log match S2"}
eligibility:
  - {aspect: scope, rule_ref: rules-snapshot.md#scope, status: PASS,
     evidence: evidence/<id>/run.log, explanation: ...}
  - {aspect: "E1 privileged", rule_ref: rules-snapshot.md#E1, status: PASS, evidence: ..., explanation: ...}
novelty:
  sources_searched: [{source: prior-audits, result: ..., location: url|null}]
  known_issues_found: none
  missing_materials: [...]
program_snapshot: {sha256: <snapshot hash>}
```

UNKNOWN on any eligibility item blocks; FAIL means `close --disposition
INELIGIBLE --reason … --evidence …`. Novelty search must be recorded — claim
"no prior report found", never "provably novel". The snapshot hash must match
the frozen file.

## 4. Package (→ PACKAGED)

One English report per root cause (templates/report.en.md) into
`packages/<id>/`. Assemble: report, PoC sources, pinned dependencies
(embedded when distribution is legal), `setup_and_run.sh`
(templates/poc/setup_and_run.sh), `manifest.yaml`:

```yaml
package:
  report: {path: packages/<id>/report.en.md, language: en, root_cause_id: RC-1}
  files: [{path: ..., sha256: <64hex>, purpose: ...}, ...]   # includes the report
  zip: {path: packages/<id>/package.zip, sha256: <64hex>}     # zip members are package-dir-relative
  clean_run: {performed_in: /tmp/clean-…, log_path: evidence/<id>/clean-run.log, result: PASS}
  secrets_scan: {status: CLEAN|EXCEPTIONS, exceptions: [{file: ..., pattern_id: ..., reason: ...}]}
  dependencies: {pinned: [{name: foundry, version: 0.2.2}], external_prereqs: [foundry 0.2.2, archive RPC]}
  self_contained: true     # false requires limitations_note (declared external deps)
```

Procedure: unzip into an empty temp dir, run `setup_and_run.sh`, save the log
(it must end with `RESULT: PASS`), zip the package (report + files +
manifest.yaml at zip root), fill hashes. The gate re-runs the secrets scan;
exceptions must match actual findings (a legit tx hash will trip
`privkey_hex` — allowlist it with a reason). No floating branches, no
`curl | sh`, no keys inside the package.

## 5. Self-review (→ SELF_REVIEWED)

Spawn an **independent** session/agent (same model is fine; shared context is
not). Give it the frozen package + rules — not your draft answers. It reruns
the package in a clean directory, audits every number against artifacts,
re-checks preconditions for realistic attacker powers, flags overstated
wording, and writes `evidence/<id>/self-review.yaml`:

```yaml
reviewer: {identity: agent-2/session-xyz, kind: independent_agent}
package_sha256: 0x<zip hash>
checks:
  rerun: {performed: true, result: PASS, log_path: evidence/<id>/self-rerun.log}
  amounts: {status: VERIFIED, notes: ...}
  preconditions: {status: VERIFIED, notes: ...}
  wording: {changes: [...]}
adverse_facts: [...]
unresolved_objections: []    # must be empty; objections become blockers
```

Changed the report or PoC after review? That is a NEW package: bump it, redo
package verification and the independent review. Old review records never carry
over; old packages are never overwritten.

## 6. Submit & defend (→ SUBMITTED, then human-only follow-up)

Final checks: re-read the rules; re-verify the channel is private; count
submissions against the program's per-account limits using your own complete
manual log — when other programs' counts are unknown, mark "to confirm", never
"within limits". Pushing a report repo requires a live PRIVATE check first:

```bash
gh repo view <owner>/<repo> --json visibility   # must print "PRIVATE" or block the push
```

Submit manually; keep the receipt (export/screenshot reference stored as a
file). Then:

```bash
lc record submission --id F-… --expected-revision N   # reads evidence/<id>/submission.yaml
lc advance --id F-… --reviewer <you> \
  --reason "receipt verified, channel PRIVATE; see evidence/<id>/receipt.txt" \
  --expected-revision N
```

`submission.yaml` carries platform id, ISO time, channel (`privacy_check:
{performed: true, result: PRIVATE}`), package hash, receipt `{path, sha256}`,
`account_limits: {checked: true, result: ...}`, `kyc: {status: ...}`.

Follow-ups (all human-triggered):

```bash
lc record response --id F-… --decision REJECTED --evidence evidence/<id>/rejection.md --expected-revision N
lc record appeal   --id F-… --status DRAFTED --materials evidence/<id>/appeal.md --deadline 2026-09-30 --expected-revision N
lc record appeal   --id F-… --status SENT --receipt evidence/<id>/appeal-receipt.txt --expected-revision N
lc record response --id F-… --decision ACCEPTED --evidence evidence/<id>/award.md --expected-revision N
```

Appeals draft only against REJECTED findings and move strictly
DRAFTED→SENT→RESOLVED; a later `record response` resolves the appeal and
supersedes the disposition while history keeps both decisions. "Generated
material" is never "submitted"; if a send's outcome is unclear, verify on the
platform before re-sending.

## 7. When things change

New code, new rules, a broken premise, a botched PoC:

```bash
lc reopen --id F-… --reason "rules updated" --affect-stage TRIAGED \
          --evidence evidence/<id>/new-rules.md --expected-revision N
```

`reopen` returns the finding to the stage before `--affect-stage`, marks the
affected gate and everything after INVALID, keeps the old evidence and history,
and archives any submission/appeal state into history. Do not hand-edit
frontmatter to "fix" state: manual edits never grant passage, and drift is
detected as INVALID gates or consistency conflicts (`revision != len(history)`).
Routine inspection: `lc resume --case-root <dir>` (also rebuilds a broken index).

## 8. Boundaries of this version

EVM + Foundry fork only; entry-point agnostic (any audit output that yields a
claim + targets works). No database, no web UI, no auditor-plugin system, no
auto-submission service, no model routing, no secret gists — delivery goes
through private repositories and platform-private attachments only.
