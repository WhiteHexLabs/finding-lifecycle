# Workflow — the eight stages in practice

Operating manual. State/gate contracts: references/contracts.md; the audit
handoff interface: references/handoff-contract.md; per-platform formats,
PoC bars and rejection causes: references/platform-standards.md. Two red lines
apply at every stage: **never modify target protocol code** (fix ideas go into
the report's remediation attachment only; PoCs use separate attack contracts)
and **never disclose publicly** (controlled private channels only).
This skill never executes audit skills — use `audit-orchestrator` for that
(entry 0A consumes its output).

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

### Entry 0A — canonical audit handoff (`import-audit`)

When `audit-orchestrator` finished a run and finalized its handoff:

```bash
lc import-audit --case-root <dir> --handoff <work-root>/audits/<run-id>/handoff/manifest.yaml
```

The import verifies the bundle end to end (schema, FINALIZED status,
analysis/candidate/artifact-manifest hashes, source artifact file/tree
hashes; path traversal and symlink escapes rejected; duplicates detected by
manifest hash — same hash twice is an idempotent no-op, same run id with a
different hash fails closed), then copies immutable evidence into:

```text
<case-root>/imports/audit/<run-id>/
├── manifest.yaml        # the finalized handoff manifest (import key)
├── analysis.md          # consolidated audit analysis
├── candidates/          # audit candidates (A-001.yaml…)
├── artifact-manifests/  # per-step canonical manifests
└── sources/             # every canonical artifact the manifests bind
```

After import the case is independent of the original audit workspace —
moving or deleting it changes nothing here. The target source tree is not
copied. Recommended placement: one parent directory per target program,
the case root as `case/` beside the audit work-root `audit/` — siblings,
never one shared root; and never point 0B `ingest --scan-dir` at a
directory covering `audit/` (its name-based discovery would scaffold a
duplicate draft — orchestrator output enters here via 0A only). One TODO
draft per candidate is scaffolded at
`ingest/<run-id>/finding-source.A-001.yaml` with provenance pre-filled
(auditor `audit-orchestrator`, original id, audit round, imported files);
every prescreen stays UNKNOWN/TODO — imports never register or pre-screen.
Zero-candidate handoffs import fine (analysis preserved, no drafts).

### Entry 0B — generic artifact discovery (`ingest`)

Without a canonical handoff, `ingest` is the default entry move (run it on
every pickup; it is idempotent). It bridges arbitrary audit skills to the
register entry point by NAME only — it never parses contents, and it never
heuristically parses canonical handoffs (use 0A for those):

```bash
lc ingest --case-root <dir> [--scan-dir DIR] [--pattern audit] [--json]
```

It scans a directory (default: the current one) for files or directories whose
name contains the pattern, skipping hidden/junk dirs and the case root itself.
A matching directory becomes one bundle; a matching file is a standalone
source. Each bundle scaffolds a draft `ingest/finding-source.<slug>.yaml`
listing the source files (absolute paths, copied into evidence at register
time).

### Entry 0C — manual finding source

Hand-write the `finding-source.yaml` below and `register --from` it.

### Completing drafts and registering

Complete every TODO in whichever drafts you have — one file per distinct
root cause — resolve the duplication prescreen to PASS, then
`register --from` each. `register` rejects unresolved TODO fields by
design: discovery is mechanical, the claim and the dedup judgment stay
with you. Rerunning `ingest` is idempotent (existing drafts are skipped).
A legacy `audit-skills.yaml` in the case root only prints a warning.

## 1. Prior-art check (→ PRIOR_ART_CHECKED)

Dedup against the project's own published audits BEFORE investing in
cross-check and fork work. Procedure:

1. Collect audit-report links from the project's **official docs site**
   (`program.docs_url`) and the **bounty platform program page**
   (`program.bounty_page_url`). Record both channels with fetch dates.
2. Download every report into `evidence/<id>/prior-art/` (pdf/md/html) —
   the CLI never fetches; copies + hashes are your evidence.
3. Search each report for the root cause: function names, contract names,
   mechanism keywords. Record a result per report, with page/section.
4. Write `evidence/<id>/prior-art.yaml`:

```yaml
discovery:
  - {kind: docs_site, url: https://docs.example.com/security, fetched_at: "2026-09-14", note: audits section}
  - {kind: program_page, url: https://immunefi.com/example, fetched_at: "2026-09-14", note: audit links}
reports:
  - {title: "2025 audit", url: https://example.com/audit-2025.pdf, auditor: "Firm X",
     date: "2025-06-01", path: evidence/<id>/prior-art/audit-2025.pdf, sha256: <64hex>}
checks:
  - {report: "2025 audit", searched_for: [withdraw, reentrancy, state update],
     result: NO_MATCH, detail: "no finding shares this root cause", location: null}
  # MATCH/PARTIAL variant continuing despite the overlap (rules must allow it):
  # - {report: "...", searched_for: [...], result: PARTIAL, detail: "...", location: "p.12 §3.4",
  #     still_eligible: {rule_ref: "rules-snapshot.md#known-issues", explanation: "program pays for known-but-unfixed"}}
no_reports_found: false        # true only when BOTH channels yielded no audit links
no_reports_note: ...
no_reports_confirmation:       # required when no_reports_found: true — absence is the
  {by: agent-2/session-abc, at: "2026-09-14",   # highest-stakes claim in the gate and
   note: "re-searched docs site, program page and the repo's security dir; no audits"}  # needs a second pair of eyes
conclusion: NEW               # KNOWN means: do not advance, close instead
```

```bash
lc check   --id F-…
lc advance --id F-… --reviewer <you> \
  --reason "no audit overlap per evidence/F-…/prior-art/audit-2025.pdf" \
  --expected-revision N
```

Outcome handling:

- **MATCH / PARTIAL** — default: `close --disposition INELIGIBLE --reason
  "already reported in <audit>" --evidence <overlap-note.md>` (the overlap note
  plus the report copy are the evidence; INELIGIBLE keeps the "bug exists, not
  bounty-eligible" semantics). Continue only when the rules explicitly pay for
  known-but-unfixed issues, recorded via `still_eligible {rule_ref, explanation}`.
- **NOT_SEARCHABLE** (e.g. unparseable scan) — unresolved: `record blocker`
  and resolve it (OCR/manual read) before re-recording.
- **No published audits** — the absence claim is the most expensive thing to
  get wrong in this gate (a missed report can void the submission later), so
  it carries extra weight: `no_reports_found: true` requires both discovery
  channels recorded, a note naming them, AND an independent
  `no_reports_confirmation {by, at, note}` — a second session that re-ran the
  search before the gate passes. Without the confirmation, record a blocker
  and get the second pass; never advance on a single unchecked "found
  nothing".

## 2. Cross-check (→ CROSS_CHECKED)

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

## 3. Fork proof (→ FORK_PROVEN)

Pin the fork and reproduce end-to-end on the real addresses (Foundry mainnet
fork is the default). The PoC lives in its own directory
`evidence/<id>/poc/` — a self-contained, locally runnable Foundry project:

```text
evidence/<id>/poc/
├── foundry.toml         # pinned solc/evm settings matching the deployment
├── src/                 # explorer-verified target source copy
├── test/Exploit.t.sol   # the attack test (assertions named after themselves)
├── lib/                 # vendored, pinned dependencies
└── run.log              # the pinned evidence run
```

Keep the PoC runnable even for findings that are never submitted — anyone can
re-verify locally with `forge test --fork-url $RPC` at any time (`cache/` and
`out/` are build artifacts; ignore them in version control). Write
`evidence/<id>/fork-proof.yaml`:

```yaml
fork: {chain_id: 1, block_number: …, block_hash: 0x…, rpc_url_ref: env MAINNET_RPC_URL,
       tool_versions: {forge: 0.2.2}}
targets_checked: [0x…]
capabilities: [{name: deal|prank|warp|oracle_mock|other, used_for: ..., justification: ...}]
controls: [{control: pause|denylist|…, applicable: false, verified: "no pause exists"}]
poc: {test_file: evidence/<id>/poc/test/Exploit.t.sol, run_log: evidence/<id>/poc/run.log,
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

## 4. Triage (→ TRIAGED)

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

## 5. Package (→ PACKAGED)

One English report per root cause (templates/report.en.md) into
`packages/<id>/`. Assemble: report, the frozen PoC tree copied from
`evidence/<id>/poc/` to `packages/<id>/poc/` (foundry.toml, src/, test/, lib/
— runnable on its own), pinned dependencies (embedded when distribution is
legal), `setup_and_run.sh` (templates/poc/setup_and_run.sh), `manifest.yaml`:

**Report citation conventions** (manual discipline; `lint` covers the
mechanical classes): before citing `Contract.function :N-M`, first decide
whether the citation is a *function pointer* (span reaches the closing `}` of
the function) or a *statement pointer* (span ends at the last cited
statement) — then keep that convention identical for the same function across
every package of the program, and only cite line numbers from a source tree
whose parity with the deployed code you have actually verified
(`diff -rq packages/<id>/poc/src/ <canonical-source>/` before the first
citation).

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

### Platform materials — required when delivery.platform names one

When `program.yaml delivery.platform` names a material platform, the package
also carries the web-form field files the platform expects, and the PACKAGED
gate refuses to pass without them. Six formats are built in; per-platform
quality bars, severity vocabularies and rejection causes live in
references/platform-standards.md.

**Immunefi** (`delivery.platform: immunefi`) — three flat txt files, one per
form field (templates/immunefi/):

- `packages/<id>/immunefi/1-title.txt` — one impact-first line → Title field.
- `packages/<id>/immunefi/2-description.txt` — must contain the section
  headers `## Brief/Intro`, `## Vulnerability Details`, `## Impact Details`,
  `## References` → Details field.
- `packages/<id>/immunefi/3-poc.txt` — must contain `### Threat modeled`,
  `### Reproduce`, `### Expected output`, `### What the test proves` → PoC
  field. Reproduce points at the attached package.zip; any additionally
  hosted copy must satisfy the private-channel rule (no public/unlisted
  gists) and be recorded in submission.yaml.

**HackenProof** (`delivery.platform: hackenproof`) — four field files under
a `fields/` subdirectory plus the standalone full write-up
(templates/hackenproof/):

- `packages/<id>/hackenproof/fields/1-title.txt` — one impact-first line →
  Title field.
- `packages/<id>/hackenproof/fields/2-vulnerability-details.md` →
  Vulnerability details field. Opens with a `**Severity.**` / `**Location.**`
  / `**Type:**` lead paragraph, then must contain `## Root cause`,
  `## Precondition`, `## PoC`, `## Impact`, `## Fix`.
- `packages/<id>/hackenproof/fields/3-validation-steps.md` → Validation
  steps field. Must contain `## How to run`, `## Expected output` (the
  verbatim `forge test -vv` output, also attached as forge-test-output.txt
  inside the bundle), `## What each test proves` (one numbered entry per
  test, mapped to the states in Vulnerability details); a `## Harness
  fidelity` section (real vs mocked contracts) is recommended.
- `packages/<id>/hackenproof/fields/4-supporting-files.txt` → Supporting
  files field. Must open with an `Upload: <file>` line naming the bundle;
  then a bundle-contents list (test, mocks, vendored pinned target +
  dependencies with commit/version, foundry.toml/remappings, README,
  forge-test-output.txt) and the one-line run command.
- `packages/<id>/hackenproof/submission.md` — the full standalone write-up:
  the exact body of the vulnerability-details field, headed by
  `# Finding <n> - <title>`, plus a `## Reproduction` section (unzip the
  bundle, `forge test -vv`, captured output).

**Code4rena** (`delivery.platform: code4rena`) — two files
(templates/code4rena/); individual High/Medium findings only — QA and Gas
go into one consolidated report per warden, assembled outside export:

- `packages/<id>/code4rena/1-title.txt` — one impact-first line → Title.
- `packages/<id>/code4rena/2-finding.md` — the finding body; must contain
  `## Impact`, `## Proof of Concept` (the coded PoC: test diff, run
  command, verbatim output; a reverting PoC prints the exact revert
  error), `## Recommended Mitigation Steps`. `export` refuses severities
  outside high/medium.

**CodeHawks** (`delivery.platform: codehawks`) — two files
(templates/codehawks/); Medium/High are individual reports, Lows are
consolidated (export refuses them):

- `packages/<id>/codehawks/1-title.txt` — one impact-first line → Title.
- `packages/<id>/codehawks/2-finding.md` — the report body, verbatim
  template: `## Summary`, `## Vulnerability Details`, `## Impact`,
  `## Tools Used`, `## Recommended Mitigation`. PoC: executable test with
  line-by-line comments and explicit `// Attacker: / Victim: / Protocol:`
  roles, or the Initial State → steps → Outcome → Implications scenario.

**Sherlock** (`delivery.platform: sherlock`) — two files
(templates/sherlock/); one GitHub Issue per finding labeled Medium/High:

- `packages/<id>/sherlock/1-title.txt` — the issue title.
- `packages/<id>/sherlock/2-issue-body.md` — the Audit Item body; must
  contain `## Issue`, `## Impact`, `## Attack path`, `## PoC`, and every
  `github.com` reference must be a commit-pinned permalink
  (`/blob/<40-hex>/…#L…`) — the gate and `lint` both reject branch links
  (code references that can be altered after submission). Enumerate every
  trigger condition; likelihood never argues severity.

**Cantina** (`delivery.platform: cantina`) — two files (templates/cantina/):

- `packages/<id>/cantina/1-title.txt` — one concise line → Title; select
  the Severity in the form yourself.
- `packages/<id>/cantina/2-description.md` — the Description field; must
  contain `## Root cause`, `## PoC` (the coded PoC: test file, run
  command, actual vs expected output — H/M submissions without a
  compiling, impact-demonstrating PoC get downgraded or invalidated),
  `## Impact`.

They live beside `package.zip` (not inside it), and are declared in the same
`manifest.yaml` under a top-level `materials` block (hash-bound like
everything else — editing them after review invalidates the gate):

```yaml
materials:
  platform: hackenproof        # or immunefi | code4rena | codehawks | sherlock | cantina
  slug: fast-withdrawal-zero-signer   # short lowercase slug; names the export dir
  fields:
    - {field: title,               path: packages/<id>/hackenproof/fields/1-title.txt, sha256: <64hex>}
    - {field: vulnerability_details, path: packages/<id>/hackenproof/fields/2-vulnerability-details.md, sha256: <64hex>}
    - {field: validation_steps,    path: packages/<id>/hackenproof/fields/3-validation-steps.md, sha256: <64hex>}
    - {field: supporting_files,    path: packages/<id>/hackenproof/fields/4-supporting-files.txt, sha256: <64hex>}
    - {field: submission,          path: packages/<id>/hackenproof/submission.md, sha256: <64hex>}
  form_targets:                 # which contract to pick in each platform form
    - {field: "Impacted contract", address: 0x…,                   # dropdown/field name
       source: "PROVENANCE.md + live registry snapshot at block N"}  # where the address was verified
  attachments:                  # files uploaded beside the bundle zip
    - {path: packages/<id>/forge-test-output.txt, sha256: <64hex>,
       note: "verbatim forge output; also pasted in the validation-steps field"}
```

(Immunefi declares `title` / `description` / `poc` against
`packages/<id>/immunefi/{1-title,2-description,3-poc}.txt` instead.)

**Submission-facing voice and reference discipline** — the field files and
report are read by a triager who sees nothing else. Three rules, all enforced
by `lint` (§9 of the contracts):

1. **No process narration.** No internal finding ids, no review-round or
   correction vocabulary ("this review", "previous round", "corrected",
   "synchronized"), no statements about your workspace process ("verified
   before submission"). The document states findings, not its own history.
2. **Every file reference is recipient-visible.** Any file you name must be
   inside the bundle zip or declared in `materials.attachments` — never a
   local-only artifact (a package-verification JSON, a workspace log, a
   sibling file that will not travel with the submission).
3. **Universal claims carry citations.** "Not identified in any published
   audit" is only writable against the per-report NO_MATCH entries in
   prior-art.yaml; "never happened on-chain" only against recorded on-chain
   reads. Otherwise scope the sentence down.

`form_targets` exist because platform forms ask "which contract?" through a
dropdown that the scraped program page populates unreliably — labels pair
with the address printed *above* them, and twin contracts built from the same
source (e.g. an OUSG-style issuer beside its USDY twin) look identical in
name. Verify each form target against your cross-check `targets[]` plus an
authoritative source (deployment provenance doc, live registry read), record
that source, and let the export README carry the mapping.

## 6. Self-review (→ SELF_REVIEWED)

Self-review is a **bounded loop of independent rounds**, not a single pass.
Each round is run by an independent session/agent (same model is fine; shared
context is not) that receives the frozen package + rules — never your draft
answers — and reruns the package in a clean directory, audits every number
against artifacts, re-checks preconditions for realistic attacker powers, and
flags overstated wording. Three loop rules learned the hard way:

1. **A round ends clean or the loop continues.** Termination is a round that
   raises zero required changes (`clean_round: true`) — never "we've reviewed
   enough".
2. **Round N+1 starts by landing-verifying round N.** First action of every
   round after the first: confirm the previous round's declared fixes are
   actually present in the loose docs *and* the zip, and re-run
   `lc lint --id F-…`. A fix that never landed is the classic survivor.
3. **No ✅ inheritance.** Each round re-derives line numbers and assertions
   from the sources; a previous round's checkmarks are not evidence (two
   contradictory conventions have been marked correct in the same review
   before). Objections you decide not to act on are recorded as
   `kept_with_rationale` with the rationale — the "存疑未改" ledger.

```yaml
# evidence/<id>/self-review.yaml
reviewer: {identity: agent-2/session-xyz, kind: independent_agent}
package_sha256: 0x<zip hash>
rounds:
  - round: 1
    date: "2026-10-01"
    landing_check: {of_round: null, result: N_A}     # round 1 has nothing to verify
    objections:
      - {id: P1, verdict: kept_with_rationale, note: "protocol-level statement; precise cases listed in §Impact"}
      - {id: P2, verdict: fixed, note: "span corrected to closing brace"}
    clean_round: false
  - round: 2
    date: "2026-10-01"
    landing_check: {of_round: 1, result: PASS}       # round 1's fixes verified present
    objections: []
    clean_round: true                                 # final round must be clean
checks:                        # consolidated checks of the final state
  rerun: {performed: true, result: PASS, log_path: evidence/<id>/self-rerun.log}
  amounts: {status: VERIFIED, notes: ...}
  preconditions: {status: VERIFIED, notes: ...}
  wording: {changes: [...]}
adverse_facts: [...]
unresolved_objections: []    # must be empty; objections become blockers
```

(A flat legacy self-review without `rounds[]` still passes the gate as an
implicit single round; new reviews use the loop.)

### Fix batches — the regression battery after every edit

Review rounds and their fixes are themselves a defect source: a rewrite has
deleted the PoC run instructions out of a validation field, injected review
narration into a report, and pointed a supporting-files field at a local-only
file — all in one day. So **every edit batch to packaged docs** (from a
review round or your own polish) runs the same battery before anything is
considered landed:

```bash
lc lint --case-root <dir> --id F-… --save-log evidence/<id>/lint-2026-10-02-1.log
# BLOCK findings -> fix and re-run; only a "LINT: PASS" log proceeds
```

`lint` re-checks the platform form contract (required sections still
present), the address allowlist, recipient-visible references, and the
submission-facing voice — the four classes that regress under editing. With a
passing log, record the batch (see below), then the next review round
landing-verifies it.

### Changed something after review? Two tiers (contracts §10)

- **Tier 1 — wording/disclosure/narration fixes** (no address, amount, PoC,
  severity, target or eligibility change):

  ```bash
  # rebuild the zip if the changed doc is a zip member (the report is);
  # update manifest hashes for materials; then:
  lc record correction --case-root <dir> --id F-… \
      --summary "trim review narration from validation steps; wording only" \
      --files packages/<id>/hackenproof/fields/3-validation-steps.md \
      --lint-log evidence/<id>/lint-2026-10-02-1.log \
      --zip-refreshed \
      [--targeted-review evidence/<id>/targeted-review-2026-10-02.md] \
      --expected-revision N
  ```

  The command refreshes manifest hashes, rebinds the PASSED-gate inputs and
  journals the correction in `corrections` + `history`. Once the finding is
  SELF_REVIEWED, `--targeted-review` is mandatory: an independent reviewer's
  sign-off covering exactly the changed passages. Same-day batches each get
  their own lint log and correction entry — history is appended, never
  rewritten.
- **Tier 2 — any technical claim** (address, amount, PoC, severity, targets,
  eligibility, rules): `reopen --affect-stage PACKAGED`, new package version,
  full independent review. Old review records never carry over; old packages
  are never overwritten. After SUBMITTED, every change is Tier 2 by
  definition.

## 7. Submit & defend (→ SUBMITTED, then human-only follow-up)

**Submit/withhold decision first.** Before polishing any package further,
make the go/no-go call per finding: acceptance odds against the payout table
(is the severity worth the slot?), known-issue rejection risk from prior
art, and per-account submission budget. Withholding a weak finding after
three review rounds is late — the decision belongs before round one. Record
the call in the ledger: withhold via `close --disposition WITHDRAWN --reason
"acceptance odds vs budget; see assessment"` or proceed to submit. Two
honesty rules that override everything else:

- Disclosure timelines (e.g. "report within 24h of discovery") are
  **eligibility criteria, not deadlines to satisfy** — state the true
  discovery/verification times; "unknown stays unknown". Never rewrite a
  timeline to fit a rule; a wrong date is a rejectable misrepresentation.
- Severity claims match the narrowed impact actually proven, not the widest
  reading of the mechanism.

Final checks: re-read the rules; re-verify the channel is private; count
submissions against the program's per-account limits using your own complete
manual log — when other programs' counts are unknown, mark "to confirm", never
"within limits". Pushing a report repo requires a live PRIVATE check first:

```bash
gh repo view <owner>/<repo> --json visibility   # must print "PRIVATE" or block the push
```

For material platforms, assemble the paste-ready submission directory first —
order of `--id` is the submission priority (01, 02, …):

```bash
lc export --case-root <dir> --id F-… --id F-…        # → <case-root>/submission/
lc export --case-root <dir> --id F-… --out <dir>     # elsewhere (e.g. a private repo)
```

Each `submission/NN-<slug>-<SEVERITY>/` gets the field files in their
platform layout (Immunefi: the three txt files flat; HackenProof:
`fields/{1..4}` plus `submission.md`; Code4rena/CodeHawks: `1-title.txt` +
`2-finding.md`; Sherlock: `1-title.txt` + `2-issue-body.md`; Cantina:
`1-title.txt` + `2-description.md`) with hashes re-verified against the
frozen manifest — drifted materials abort the export; reopen PACKAGED
instead — plus the attachment zip (Immunefi: `package.zip`; HackenProof:
copied out as `<slug>-poc-bundle.zip`, the name the Supporting files field's
`Upload:` line quotes; the four contest platforms: `<slug>-poc.zip`) and any
declared `materials.attachments`. Platforms with an individual-submission
severity vocabulary refuse out-of-vocabulary severities (e.g. a QA-level
finding on Code4rena) — consolidated QA/Gas/Low reports are assembled by
hand from the findings `export` leaves out. A `README.md`
index is written once (`--readme` regenerates): per-package form targets
(which contract to select in each form field, from `materials.form_targets`),
zip hashes, and a "not exported" section listing every TRIAGED+ finding left
out of this run with its disposition — the removed-findings ledger. Reordering
findings aborts on the stale numbered dir — remove it or keep the previous
order.

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

## 8. When things change

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

## 9. Boundaries of this version

EVM + Foundry fork only; entry-point agnostic (any audit output that yields a
claim + targets works). This skill never executes audits — the sibling
`audit-orchestrator` skill runs configured audit skills and hands over a
finalized bundle (§0A). Material platforms are built in with fixed form
formats — Immunefi's three-file kit (`delivery.platform: immunefi`),
HackenProof's fields/ four-field kit plus full write-up
(`delivery.platform: hackenproof`), and the four contest platforms
Code4rena / CodeHawks / Sherlock / Cantina (title + one markdown body each;
individual High/Medium findings only); per-platform standards live in
references/platform-standards.md; other platforms use free-format
delivery. Consolidated QA/Gas/Low reports (C4/Sherlock/CodeHawks) and
Remedy/Hats formats are documented boundaries of this version — assembled
by hand, not by export. No database, no web UI, no auditor-plugin system,
no auto-submission service, no secret gists — delivery goes
through private repositories and platform-private attachments only.
