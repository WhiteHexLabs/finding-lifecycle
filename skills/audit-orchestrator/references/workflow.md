# Workflow — audit orchestration in practice

Operating manual for `scripts/audit.py`. Contracts:
`execution-contract.md` (prompts + results), `artifact-contract.md`
(normalization + manifests), `handoff-contract.md` (finalize + handoff).

Conventions: `audit()` is `python3 <skill-root>/scripts/audit.py`. Mutating
commands (`record`, `finalize`) need `--expected-revision` (compare-and-swap
against `run.yaml`). `--case-root` is a deprecated alias for `--work-root`.

## Stage layout

```text
<work-root>/
├── audit-skills.yaml          # strict config: target_root, scope, ordered skills
└── audits/
    └── <run-id>/              # run ids sort by creation time; newest is current
        ├── run.yaml           # state source of truth (revision == len(history))
        ├── analysis.md        # authored at AGGREGATE; validated at FINALIZE
        ├── candidates/        # authored A-001.yaml…; validated + copied at FINALIZE
        ├── handoff/           # FINALIZE output: manifest.yaml + candidates/
        └── steps/<N>/
            ├── step.yaml           # static step metadata (written at PREPARE)
            ├── execution-prompt.md # orchestration overlay for this step
            ├── work/               # preferred work directory for the skill
            ├── result.yaml         # latest attempt's declared result (copy)
            ├── attempts/<k>/
            │   ├── result.yaml     # the declared result, archived per attempt
            │   └── artifacts/      # canonical frozen copies (immutable)
            └── artifact-manifest.yaml  # manifest of the accepted COMPLETED attempt
```

Recommended placement: one parent directory per target program, with this
work-root as `audit/` beside the lifecycle case root `case/` — sibling
directories, never one shared root (the work-root is disposable after
finalize + import-audit; the case root is a long-lived ledger).

## 1. PREPARE

```bash
audit prepare --work-root <dir> [--new]
```

Validates the config (strict schema, unknown keys rejected, scope must stay
inside `target_root`, duplicate skills rejected, the orchestrator itself and
finding-lifecycle rejected as skill entries, empty skills/scope are errors —
an empty configured audit never falls back to report import), hashes every
in-scope target file, and creates the batch with one step per configured
skill. Each step gets `step.yaml`, `execution-prompt.md` and `work/`. A
missing SKILL.md blocks its step at prepare while the rest stay executable,
and such a step can never record COMPLETED.

Re-running `prepare` recovers the current batch (never re-executes
completed steps) and prints the next step, its execution prompt and its
work dir. `--new` starts a fresh batch, keeping old runs on disk.

## 2. EXECUTE

The session — not the CLI — executes each step:

1. read `steps/<N>/execution-prompt.md` **and** the skill's own `SKILL.md`;
2. obey the skill's audit methodology (it owns **how to audit**);
3. obey the execution contract (it owns **how results come back**);
4. run the audit against the configured scope.

Two output modes are supported:

- **Mode A — configurable output directory (preferred):** if the skill
  accepts an output/work dir (`--output-dir`, env var, prompted workspace,
  …), point it at `steps/<N>/work/`.
- **Mode B — fixed/native output directory:** if the skill requires its own
  location (e.g. `<target>/.evm-auditor-work/` or `./reports/`), do NOT
  break the skill to force relocation — run it normally and declare the
  actual output paths in `result.yaml`. `record` copies them into the
  canonical step directory; the original location becomes disposable.

The audited target source must never be modified — that drift stales the
whole batch (§CHECK) and must be investigated, not papered over.

## 3. RECORD / NORMALIZE

```bash
audit record --work-root <dir> --step N --input result.yaml --expected-revision R
```

`result.yaml` (v1 schema, legacy flat shape accepted — see
execution-contract.md) declares status, note, the primary report/log and
optional supporting artifacts. `record` then:

1. validates status/note/schema and the declared source paths (existence,
   not inside the audited target, no symlinks, no key/credential material);
2. re-fingerprints the target scope — drift fails the gate before anything
   is frozen;
3. copies artifacts into `steps/<N>/attempts/<k>/artifacts/` (deterministic
   collision suffixes; retries never overwrite prior attempts);
4. hashes files (SHA-256) and directories (deterministic tree hash);
5. writes `steps/<N>/artifact-manifest.yaml` for the accepted COMPLETED
   attempt;
6. archives the result declaration and bumps the revision.

Ordering: a step may be recorded only after every earlier step has a first
result; after the first pass only FAILED/BLOCKED steps may be rerun, in
original order; COMPLETED steps are terminal within a batch.

## 4. CHECK

```bash
audit check --work-root <dir>
```

PASS requires: every step COMPLETED; every canonical artifact manifest
valid (schema, run/step/attempt binding, per-artifact file hash or
directory tree hash); config/target/skills unchanged since prepare. After
finalization, the handoff bundle is verified too — any bound input that
changed invalidates it.

## 5. AGGREGATE (session work; CLI validates)

Read every step's report through `steps/*/artifact-manifest.yaml` — never
the wider filesystem, never the skills' original output locations.
Prioritize `type: findings` structured outputs, then the primary `report`;
use poc/trace/coverage evidence when needed; logs are provenance. Perform
semantic consolidation — never report concatenation:

```text
finding extraction → normalization → root-cause clustering
→ cross-skill deduplication → disagreement preservation → candidates
```

Write `audits/<run-id>/analysis.md` with the required sections (Audit Run,
Target and Scope, Audit Skills Executed, Coverage Summary, Consolidated
Findings, Duplicate / Overlapping Leads, Disagreements Between Auditors,
Coverage Gaps and Limitations, Zero-Finding Statement). Zero findings is
valid: say "No candidate findings were identified within the executed audit
scope and methods." — never "the protocol is safe".

Then author one `candidates/A-XXX.yaml` per consolidated root cause
(schema `whitehexlabs.audit-candidate/v1`; sources reference the canonical
artifact manifests by relative path and artifact ID). Cross-skill
root-cause dedup here is NOT bounty prior-art eligibility — that check
lives in finding-lifecycle against the project's published audits.

## 6. FINALIZE

```bash
audit finalize --work-root <dir> --expected-revision R
```

Preconditions: fresh batch, every step COMPLETED, valid canonical
manifests (legacy batches: frozen copies are exposed as manifest entries —
missing artifacts are never fabricated), substantive analysis.md, valid
unique candidates referencing only canonical run artifacts. Output:
`handoff/manifest.yaml` (`whitehexlabs.audit-handoff/v1`) + hashed
candidate copies. Finalization is idempotent and afterwards immutable:

```text
Audit complete.
Aggregated report: <analysis.md path>
Finalized handoff: <manifest.yaml path>
You can stop here or import the handoff into finding-lifecycle.
```

Do not automatically invoke finding-lifecycle — stopping here is a
first-class workflow.

## 7. When things change

Config, target content/file set, or a skill entry drifted → every command
refuses until `prepare --new` (old runs stay on disk for history). A skill
that cannot run (missing tool, refused permissions, demands target edits)
records its step BLOCKED with the specific demand — never fake completion.
A step whose primary report is ambiguous records BLOCKED naming the
candidate files. Infrastructure failure is never a refutation of anything.
