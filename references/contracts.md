# Contracts — state, gates, CLI

Normative reference for `scripts/lifecycle.py`. Files are authoritative; the
CLI only performs validated, locked, atomic, revision-checked transitions.

## 1. Case root layout

```text
<case-root>/
├── program.yaml          # program configuration (validated at init / load)
├── audit-skills.yaml     # optional: sequential audit entry config (see §8)
├── rules-snapshot.md     # frozen rules snapshot (hash recorded in program.yaml)
├── findings/F-<uuid>.md  # one ledger per finding (single source of truth)
├── evidence/F-<uuid>/    # source copies, stage input docs, logs, receipts
├── packages/F-<uuid>/    # frozen report + PoC package (+ manifest, zip)
├── audits/run-…/         # audit batches: run.yaml + steps/<N>/ + analysis.md
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
| PRIOR_ART_CHECKED | `evidence/<id>/prior-art.yaml` | discovery channels recorded (docs site / program page); every audit report present as a local copy with matching hash; one check per report (NO_MATCH with keywords+detail; MATCH/PARTIAL ⇒ close INELIGIBLE or `still_eligible {rule_ref, explanation}`; NOT_SEARCHABLE ⇒ blocker); `no_reports_found` requires an explicit note; conclusion must be NEW |
| CROSS_CHECKED | `evidence/<id>/cross-check.yaml` | targets (addr + runtime code hash + chain), root_cause.claim, ≥1 refutation attempt, damage≠profit stated, assessment file |
| FORK_PROVEN | `evidence/<id>/fork-proof.yaml` | fork pinning (chain, block, hash, tool versions, rpc ref), targets covered, cheatcode capabilities each justified, controls (pause/denylist) verified or marked N/A, PoC test+log files, `result: PASS`, every expected assertion present in the log, PnL per side (unknown ⇒ `"unknown"`, never 0) |
| TRIAGED | `evidence/<id>/triage.yaml` | severity.final == matrix entry level, justification cites a recorded evidence path, every eligibility item PASS/NOT_APPLICABLE with evidence file (UNKNOWN blocks; FAIL ⇒ close INELIGIBLE), novelty search recorded, snapshot hash frozen and matching |
| PACKAGED | `packages/<id>/manifest.yaml` | English report listed+hashed, all files hashed, zip hash + zip contains every listed file, clean-run log with `RESULT: PASS`, secrets scan re-run with justified exceptions exactly matching findings, `self_contained` (false ⇒ limitations note) |
| SELF_REVIEWED | `evidence/<id>/self-review.yaml` | independent reviewer, `package_sha256` == current zip, rerun PASS with log, amounts+preconditions VERIFIED, `unresolved_objections: []` |
| SUBMITTED | (recorded submission block) | platform id, ISO time, channel privacy check `PRIVATE`, package hash == current zip, receipt file hash, account limits checked, KYC status enum |

Gate inputs record hashes of consumed files and hashed ledger fields, so later
modification of the PoC, report, targets, severity or rules snapshot invalidates
the depending gates and everything after them.

## 4. CLI reference

All commands take `--case-root`. Finding commands take `--id`. Mutating
commands take `--expected-revision` (compare-and-swap against the ledger).

```text
init       --case-root D [--program-yaml P] [--program-id X] [--rules-snapshot F]
ingest     --case-root D [--scan-dir DIR] [--pattern audit] [--json]
           name-based discovery of audit artifacts -> TODO drafts under <root>/ingest/;
           no content parsing; `register` rejects unresolved TODO fields;
           gated while an audit config/batch is active (see §8)
audit prepare --case-root D [--new] [--json]
           create or recover the current sequential-audit batch
audit record  --case-root D --step N --input result.yaml --expected-revision N [--json]
           record one skill-execution result (COMPLETED|FAILED|BLOCKED + note + artifacts)
audit check   --case-root D [--json]
           PASS only when every step is COMPLETED and all frozen artifacts hash-match
register   --case-root D --from finding-source.yaml [--json]
check      --case-root D --id F [--stage S] [--input P] [--json]
advance    --case-root D --id F --reviewer R --reason T [--input P] --expected-revision N
close      --case-root D --id F --disposition X [--into F2] [--reason T] [--evidence P]
           [--refutation-poc P] [--refutation-log P] [--boundary T] --expected-revision N
reopen     --case-root D --id F --reason T --affect-stage S [--evidence P] --expected-revision N
resume     --case-root D [--id F] [--json]
index      --case-root D
record blocker  --id F --item T --next-step T --expected-revision N
record resolve  --id F --index N --expected-revision N
record submission --id F [--input P] --expected-revision N
record response  --id F --decision ACCEPTED|REJECTED --evidence P [--reason T] --expected-revision N
record appeal    --id F --status DRAFTED|SENT|RESOLVED [--deadline D] [--materials P...]
                  [--receipt P] [--outcome T] --expected-revision N
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

## 8. Audit batch contract

`audit-skills.yaml` (template in `templates/`) names `target_root` (an
existing directory; paths resolve relative to the config file — absolute and
`~` allowed), a non-empty `scope` of existing files/dirs that must stay inside
`target_root`, and a non-empty `skills` list of local SKILL.md paths in
execution order. Duplicate skill paths, finding-lifecycle itself, unknown
keys, empty `scope` and empty `skills` are config errors (exit 2) — an empty
configured audit never falls back to the report-import entry. The CLI never
executes skill content: it manages config, state, artifacts and order only;
the current session reads each SKILL.md and follows it, sequentially.

Each batch lives in `audits/<run-id>/` (run ids sort by creation time; the
newest is current) with `run.yaml` as the state source: config snapshot +
hash, scope file manifest + hashes, per-step skill entry hashes, and per-step
status `PENDING/COMPLETED/FAILED/BLOCKED` with attempts
`{at, status, note, report, log}` — report/log are frozen as copies under
`steps/<N>/attempt-<k>-report|log…` so retries append, never overwrite.
`revision == len(history)` holds as in ledgers; `record` is compare-and-swap
via `--expected-revision`. A skill missing at prepare blocks its step while
the rest of the batch stays executable, but such a step can never record
COMPLETED (its entry was never fingerprinted).

Ordering: a step may be recorded only after every earlier step has an
execution result; after the first pass only FAILED/BLOCKED steps may be
rerun, in original order; COMPLETED steps are terminal within a batch.
COMPLETED means "the audit ran", never "no findings" — a completed step
requires a real report, a log and a substantive note.

`audit check` passes only when every step is COMPLETED and every frozen
artifact still hashes correctly. The batch is stale — requiring
`audit prepare --new` — when the config, any in-scope target file (content
or file set) or any skill entry changes. Audit artifacts are written only
under the case root, never into the audited target.

Gating: while a config exists or a batch is present and not fresh-and-
complete, `ingest` and `register` fail (exit 1); deleting the config does not
bypass an unfinished batch. Registering under a complete batch additionally
requires `sources.audit_round == <run-id>`, a written
`audits/<run-id>/analysis.md`, and `sources.files` citing that analysis plus
at least one raw step report (copied into evidence by the normal mechanism).
`resume` reports batch progress, blocked steps and the next move even when
no findings exist.
