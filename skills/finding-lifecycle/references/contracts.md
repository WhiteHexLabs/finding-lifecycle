# Contracts — state, gates, CLI

Normative reference for `scripts/lifecycle.py`. Files are authoritative; the
CLI only performs validated, locked, atomic, revision-checked transitions.
This skill never executes audit skills (see references/handoff-contract.md
for the audit-orchestrator boundary).

## 1. Case root layout

```text
<case-root>/
├── program.yaml          # program configuration (validated at init / load)
├── audit-skills.yaml     # legacy: no longer executed here; warning only
├── rules-snapshot.md     # frozen rules snapshot (hash recorded in program.yaml)
├── lint-allowlist.yaml   # optional: justified lint exceptions (see §9)
├── findings/F-<uuid>.md  # one ledger per finding (single source of truth)
├── evidence/F-<uuid>/    # source copies, stage input docs, logs, receipts
├── packages/F-<uuid>/    # frozen report + PoC package (+ manifest, zip)
├── imports/audit/<run-id>/  # immutable imported audit evidence (see §8)
├── ingest/               # scaffolded finding-source drafts (entries 0A/0B)
├── index.md              # derived; rebuildable; never a source of truth
└── .lifecycle.lock       # transient write lock
```

Credentials, RPC keys and KYC material never enter these directories.

## 2. Ledger contract

Markdown file: YAML frontmatter (checkable fields) + body (narrative).
Unknown frontmatter keys are rejected on load. The invariant
`revision == len(history)` holds for every CLI-written ledger; a mismatch is a
consistency conflict and blocks all mutations until repaired.

| Field | Contract |
|---|---|
| `id` | `F-<32 hex>`; assigned at registration; never encodes severity |
| `stage` | last **passed** stage; one of the eight below |
| `disposition` | closure outcome, independent of stage |
| `revision` | +1 on every CLI write; the basis of compare-and-swap |
| `sources` | auditor / original finding id / round / copied source docs with hashes |
| `targets` | set at CROSS_CHECKED; chain, address, proxy, implementation, block, runtime code hash |
| `root_cause` | claim + variants; merged from cross-check input |
| `duplicate_of` | surviving finding; set only by `close MERGED` |
| `severity` | candidate (inherited) / final + matrix_entry + justification (set at TRIAGED) |
| `program_snapshot` | frozen rules snapshot hash + check time |
| `prior_art` | set at PRIOR_ART_CHECKED: `{checked_at, conclusion, discovery[], reports[]}` — the project's own audit reports checked and their local copies |
| `evidence` | `{path, sha256, purpose, produced_by, recorded_at}`; upserted by path |
| `gates` | `{id, stage, status: PASSED\|INVALID, at, reviewer, reason, inputs[]}` |
| `blockers` | `{item, next_step, raised_at, resolved_at}` |
| `submission` | receipt block; gates SUBMITTED; holds `response` after platform decision |
| `appeal` | `NONE → DRAFTED → SENT → RESOLVED` (+deadline, materials, receipt, outcome) |
| `corrections` | Tier-1 post-package corrections (§10): `{at, summary, files[], lint_log, zip_refreshed, targeted_review}` |
| `history` | append-only; exactly one event per revision |

### States

Stages (one direction only; regress via `reopen`):

```text
DISCOVERED → PRIOR_ART_CHECKED → CROSS_CHECKED → FORK_PROVEN
          → TRIAGED → PACKAGED → SELF_REVIEWED → SUBMITTED
```

Dispositions: `OPEN, MERGED, INELIGIBLE, REFUTED, ACCEPTED, REJECTED, WITHDRAWN`.

- `MERGED` must point to an existing finding; self-reference and cycles rejected.
- `INELIGIBLE` means "not eligible for bounty", never "the bug is not real".
- `REFUTED` requires stage ≥ FORK_PROVEN plus a refutation PoC + run log
  containing a `RESULT:` marker and an explicit conclusion boundary. Static
  doubt without a fork attempt stays a blocker.
- RPC unavailability, unclear rules and missing dependencies are blockers, never closures.
- Platform accept/reject reflects the platform outcome only; it does not rewrite
  the technical record, and a new platform decision (e.g. after an appeal) may
  supersede it — prior outcomes stay in `history`.

Compatibility: findings recorded before the PRIOR_ART_CHECKED stage was
introduced keep their stage; the new gate applies to findings at DISCOVERED.
Older ledgers without a `prior_art` key remain valid.

## 3. Gate contract

`advance` moves exactly one stage. Before evaluating the target stage it
re-verifies **integrity**: every recorded evidence hash and every PASSED gate's
input hashes (files and hashed ledger fields). Any drift fails immediately with
`[invalid] gate ... INVALID` and requires `reopen` — there is no `--force`.

Every gate needs both (a) machine-checked artifacts and (b) a substantive
review record: `--reviewer` plus `--reason` of at least 30 characters citing at
least one artifact consumed by the gate. Hash validity alone proves only that
files are unchanged.

Stage input documents (default paths, overridable with `--input`):

| Target stage | Input | Machine-checked essentials |
|---|---|---|
| PRIOR_ART_CHECKED | `evidence/<id>/prior-art.yaml` | discovery channels recorded (docs site / program page); every audit report present as a local copy with matching hash; one check per report (NO_MATCH with keywords+detail; MATCH/PARTIAL ⇒ close INELIGIBLE or `still_eligible {rule_ref, explanation}`; NOT_SEARCHABLE ⇒ blocker); `no_reports_found` requires ≥2 distinct discovery channels, an explicit note and an independent `no_reports_confirmation {by, at, note}`; conclusion must be NEW |
| CROSS_CHECKED | `evidence/<id>/cross-check.yaml` | targets (addr + runtime code hash + chain), root_cause.claim, ≥1 refutation attempt, damage≠profit stated, assessment file |
| FORK_PROVEN | `evidence/<id>/fork-proof.yaml` | fork pinning (chain, block, hash, tool versions, rpc ref), targets covered, cheatcode capabilities each justified, controls (pause/denylist) verified or marked N/A, PoC test+log files, `result: PASS`, every expected assertion present in the log, PnL per side (unknown ⇒ `"unknown"`, never 0) |
| TRIAGED | `evidence/<id>/triage.yaml` | severity.final == matrix entry level, justification cites a recorded evidence path, every eligibility item PASS/NOT_APPLICABLE with evidence file (UNKNOWN blocks; FAIL ⇒ close INELIGIBLE), novelty search recorded, snapshot hash frozen and matching |
| PACKAGED | `packages/<id>/manifest.yaml` | English report listed+hashed, all files hashed, zip hash + zip contains every listed file, clean-run log with `RESULT: PASS`, secrets scan re-run with justified exceptions exactly matching findings, `self_contained` (false ⇒ limitations note) |
| SELF_REVIEWED | `evidence/<id>/self-review.yaml` | independent reviewer, `package_sha256` == current zip, rerun PASS with log, amounts+preconditions VERIFIED, `unresolved_objections: []`; when `rounds[]` is present (multi-round loop, workflow §6): ≥1 round, the final round `clean_round: true`, every round's landing check PASS or N/A, every `kept_with_rationale` objection carries a note. A flat legacy self-review (no `rounds[]`) remains valid as an implicit single round |
| SUBMITTED | (recorded submission block) | platform id, ISO time, channel privacy check `PRIVATE`, package hash == current zip, receipt file hash, account limits checked, KYC status enum |

Gate inputs record hashes of consumed files and hashed ledger fields, so later
modification of the PoC, report, targets, severity or rules snapshot invalidates
the depending gates and everything after them. The one sanctioned exception is
`record correction` (§10), which rebinds recorded hashes for Tier-1 document
changes and journals every rebind in `history`.

## 4. CLI reference

All commands take `--case-root`. Finding commands take `--id`. Mutating
commands take `--expected-revision` (compare-and-swap against the ledger).

```text
init       --case-root D [--program-yaml P] [--program-id X] [--rules-snapshot F]
import-audit --case-root D --handoff manifest.yaml [--json]
           verify a finalized audit-orchestrator handoff (schema, hashes,
           path confinement), copy immutable evidence under imports/audit/,
           scaffold one TODO draft per candidate; never registers anything
ingest     --case-root D [--scan-dir DIR] [--pattern audit] [--json]
           name-based discovery of audit artifacts -> TODO drafts under <root>/ingest/;
           no content parsing; `register` rejects unresolved TODO fields
register   --case-root D --from finding-source.yaml [--json]
check      --case-root D --id F [--stage S] [--input P] [--json]
advance    --case-root D --id F --reviewer R --reason T [--input P] --expected-revision N
lint       --case-root D --id F [--save-log P] [--json]
           material lint over the packaged report + platform field files
           (§9): five defect-class checks with BLOCK/WARN severities; exit 1
           on any BLOCK; --save-log writes the output plus a final
           "LINT: PASS|FAIL" marker for record correction
close      --case-root D --id F --disposition X [--into F2] [--reason T] [--evidence P]
           [--refutation-poc P] [--refutation-log P] [--boundary T] --expected-revision N
reopen     --case-root D --id F --reason T --affect-stage S [--evidence P] --expected-revision N
resume     --case-root D [--id F] [--json]
index      --case-root D
record blocker  --id F --item T --next-step T --expected-revision N
record resolve  --id F --index N --expected-revision N
record correction --id F --summary T --files P... --lint-log P [--zip-refreshed]
                  [--targeted-review P] --expected-revision N
                  Tier-1 post-package doc correction (§10): refreshes manifest
                  hashes for the changed docs, rebinds gate inputs, appends a
                  corrections entry + history event
record submission --id F [--input P] --expected-revision N
record response  --id F --decision ACCEPTED|REJECTED --evidence P [--reason T] --expected-revision N
record appeal    --id F --status DRAFTED|SENT|RESOLVED [--deadline D] [--materials P...]
                  [--receipt P] [--outcome T] --expected-revision N
export     --case-root D --id F [--id F ...] [--out DIR] [--readme]
           read-only assembly of the paste-ready submission/ dir from PACKAGED
           findings of a material platform: one NN-<slug>-<SEVERITY>/ per
           finding (--id order = submission priority), field files in the
           platform layout, the bundle zip under the platform's export name,
           declared attachments, and a README index (form targets, hashes,
           withheld TRIAGED+ findings). Material and zip hashes are re-verified
           against the frozen manifest — drift aborts. Platforms with an
           individual-submission severity vocabulary (code4rena, codehawks,
           sherlock, cantina) refuse out-of-vocabulary severities; consolidated
           QA/Gas/Low reports are assembled outside export.
```

Exit codes: `0` success · `1` gate not passed · `2` input/runtime error
(malformed YAML, illegal fields/enums, path escapes, revision or lock
conflicts, unreadable ledger). There is no `--force` anywhere.

`check`/`resume` emit human-readable summaries and `--json` payloads with gate
id/status, missing artifacts, hash mismatches, incomplete judgments and next steps.

## 5. Write path, locking, recovery

Every mutation: acquire `.lifecycle.lock` (O_EXCL; stale after 10 min or dead
pid) → compare `--expected-revision` → re-verify gates/evidence → write ledger
via temp file + `os.replace` → rebuild `index.md` → release lock.

If the ledger write succeeds but the index rebuild fails, the command still
exits 0 with "ledger saved, index needs repair"; `index` or `resume` rebuilds
it without re-applying any transition (transitions are never replayed — the
ledger already contains exactly one history event for them).

`resume` re-validates every finding (parse, evidence hashes, gate inputs,
revision invariant), rebuilds the index, reports blockers/pending follow-ups
(appeal deadlines, SLA — unknown stays unknown) and exits 1 on structural
damage only.

## 6. program.yaml contract

Validated at `init` and on every load: `program.id` non-empty; snapshot digest
well-formed; `scope.chains`/`scope.targets` (valid addresses) non-empty;
`severity_matrix` ids unique with levels; `exclusions`/`novelty_sources` lists
present. The TRIAGED gate re-hashes the snapshot file against the recorded
digest. The CLI checks structure and references only — natural-language
exclusion interpretation stays with the reviewer, recorded per eligibility item.

## 7. Security boundaries

- The mechanism guards against operational mistakes and lost updates, not
  against a deliberate writer with file access (plan §2.3).
- Ledger paths must stay inside the case root; absolute paths and escapes are
  rejected. Arbitrary Python/shell expressions are never evaluated from config.
- Secrets never belong in evidence/packages; the PACKAGED gate re-runs a
  pattern scan over package files (justified exceptions must match actual hits).
- No auto-submission, auto-appeal or background polling exists in this version;
  sending is human-only through private channels (workflow.md §8).

## 8. Audit import contract (`import-audit`)

This skill never executes audit skills. A legacy `audit-skills.yaml` found
in the case root only produces a warning on entry commands — nothing is
gated, blocked or executed because of it; audit execution belongs to the
sibling `audit-orchestrator` skill.

`import-audit --case-root D --handoff <manifest.yaml>` consumes one
FINALIZED handoff bundle (schema `whitehexlabs.audit-handoff/v1`; producer
side: audit-orchestrator's references/handoff-contract.md). Verification
before any copying — no `--force`, any violation is exit 2:

1. schema is exactly supported;
2. status is FINALIZED;
3. analysis exists and its hash matches;
4. all step artifact manifests exist;
5. artifact manifest hashes match;
6. canonical artifacts referenced by candidates exist;
7. candidate count matches the manifest;
8. candidate ids are unique;
9. candidate hashes match;
10. source artifact file hashes / directory tree hashes match;
11. path traversal is rejected (all paths resolve inside the handoff run root);
12. symlink escape is rejected;
13. duplicate imports are detected by finalized manifest hash.

Imported evidence lands in `<case-root>/imports/audit/<run-id>/`
(`manifest.yaml`, `analysis.md`, `candidates/`, `artifact-manifests/`,
`sources/`) and is immutable: the same manifest imported twice succeeds
without changes; the same run id with a different manifest hash fails
closed; previously imported evidence is never overwritten. After import,
deleting the original audit workspace changes nothing here. The target
source tree is not copied.

For each audit candidate exactly one draft is scaffolded at
`ingest/<run-id>/finding-source.A-XXX.yaml`: provenance pre-filled
(auditor `audit-orchestrator`, original finding id, audit round, imported
file references) and every prescreen aspect left UNKNOWN with TODO
evidence/explanation — no bounty pre-screen answers are guessed. Nothing is
registered automatically; the existing `register` gates reject unresolved
TODO/UNKNOWN fields exactly as for hand-written sources. A valid
zero-candidate handoff imports successfully: analysis and provenance are
preserved, no drafts, no findings.

## 9. Material lint (`lint`)

`lint --case-root D --id F` runs read-only, any time after PACKAGED, over the
submission-facing surfaces: the packaged report (`manifest.package.report`)
and every platform field file (`manifest.materials.fields[]`). It is the
regression battery of the fix-batch protocol (workflow §6a) — run it after
EVERY edit to those files, not only at gate time. Findings carry a severity:

- **BLOCK** — exit 1. Defect classes: wrong address, dangling reference,
  missing form section, internal voice.
- **WARN** — exit 0. Universal-claim phrasing that must carry a citation;
  review and either support or reword.

Checks:

| id | severity | catches |
|---|---|---|
| `addr` | BLOCK | every `0x…` 40-hex address in the texts must be a cross-check target (`targets[].address/proxy_address/implementation_address`), a program scope target, a declared `materials.form_targets[].address`, or allowlisted with a reason |
| `attachment` | BLOCK | every file-like reference (`.txt .md .log .json .zip .pdf .sh .toml .yaml .yml .sol`) must resolve into the attachment set: package-zip members, `materials.attachments[]` entries, the exported bundle name, or the material files themselves |
| `sections` | BLOCK | every platform-required section header and the `Upload:` line still present in the field files (the "rewrite deleted the run instructions" regression); on platforms with `permalink_fields` (Sherlock), every github.com reference still a commit-pinned permalink (`/blob/<40-hex>/…#L…`) — branch links can be altered after submission |
| `voice` | BLOCK | internal/process vocabulary in submission-facing text: internal finding ids (`F-<32hex>`), review-round/correction narration ("this review", "previous round", "corrected", "synchronized"), workspace-local phrasing |
| `universal` | WARN | universal claims ("never happened", "not identified in any", "in all production", "every withdrawal") that must cite the per-report prior-art NO_MATCH entries or a source-derivation |

Justified exceptions live in `<case-root>/lint-allowlist.yaml`, one line per
suppressed finding — same discipline as secrets-scan exceptions:

```yaml
allow:
  - {check: addr,        pattern: "0x123…def", reason: "attacker helper contract, mentioned only"}
  - {check: attachment,  pattern: "forge-test-output.txt", reason: "attached separately in the platform form"}
  - {check: voice,       pattern: "synchronized", file: "packages/F-…/immunefi/2-description.txt", reason: "…"}
```

`pattern` is a literal substring (case-insensitive for `voice`); `file` scopes
the exception to one surface. An allowlist entry that matches nothing is
reported as WARN (stale exceptions rot into noise).

`--save-log P` writes the full output plus a final `LINT: PASS` (no BLOCK
findings) or `LINT: FAIL` marker line; `record correction` requires a log
carrying `LINT: PASS`.

## 10. Post-review changes — two tiers

The freeze rule ("report changed after review ⇒ new package version + new
independent review") was too heavy for the reality of multi-round fixes and
got bypassed wholesale. It is now explicit about weight:

- **Tier 1 — `record correction`** (wording/disclosure/narration fixes that do
  not touch a technical claim): allowed while `stage ∈ {PACKAGED,
  SELF_REVIEWED}` and disposition OPEN. Requires a lint log containing
  `LINT: PASS`, a substantive `--summary`, and — once `stage ≥ SELF_REVIEWED`
  — a `--targeted-review` note in which an independent reviewer signs off on
  exactly the changed passages. Eligible paths are mechanically bounded: the
  manifest-declared report and material field files only. The command
  refreshes their hashes in `manifest.yaml` (plus the zip hash when
  `--zip-refreshed`), rebinds the corresponding PASSED-gate input hashes and
  evidence entries, and appends `{at, summary, files, lint_log, zip_refreshed,
  targeted_review}` to `corrections` and one `correction_recorded` history
  event. Every rebind is journaled; nothing is silently rewritten.
- **Tier 2 — reopen** (anything technical): address, amount, PoC, severity,
  targets, eligibility, rules. `record correction` rejects any path outside
  the Tier-1 set with a pointer to `reopen --affect-stage PACKAGED`, which
  invalidates the affected gates as before and requires a full new package
  version plus a fresh independent review.

Packages at SUBMITTED never change; corrections after submission are Tier 2
by definition (reopen archives the submission state).

Materials blocks may additionally declare (hash-bound like everything else):

```yaml
materials:
  form_targets:                                  # which contract to pick in each platform form field
    - {field: "Impacted contract", address: 0x…, source: "PROVENANCE.md + registry snapshot at block N"}
  attachments:                                   # files uploaded beside the bundle zip
    - {path: packages/<id>/forge-test-output.txt, sha256: <64hex>, note: "verbatim forge output, also pasted in the validation field"}
```

`form_targets` answers the form-dropdown question at export time (the export
README lists them per package); `attachments` extend the lint attachment set
and are copied into the export directory alongside the bundle zip.

Six platforms have built-in material specs — immunefi, hackenproof,
code4rena, codehawks, sherlock, cantina (formats, per-platform PoC bars and
severity vocabularies: references/platform-standards.md). Two platform rules
are enforced mechanically in addition to headers/paths: Sherlock's
`permalink_fields` (every github.com reference in the issue body must be a
commit-pinned permalink) and the contest platforms' `severity_levels`
(`export` refuses a `severity.final` that is not an individual-submission
level — consolidated QA/Gas/Low reports live outside export).
