# Workflow — operating the pipeline stage by stage

Load this before operating any stage. The CLI is
`python3 <skill-root>/scripts/fetch.py` (`fetch.py` below). Exit codes:
`0` ok · `1` gate failed · `2` input/runtime error.

## 0. Scaffold + transcribe (entry 0A)

```bash
fetch.py init --fetch-root <dir>
```

Creates `targets.yaml` from the template, `fetch-cache/`, `projects/`,
`verification/`, `state.yaml`. Then transcribe the platform's Assets in Scope
rows (see `discovery-sources.md`) and run `validate` until it passes. Typical
selection:

```bash
fetch.py validate --fetch-root <dir>
fetch.py select   --fetch-root <dir> --sort funds --min-added-on 2026-08-28 --top 20 \
                  -o targets-selected.yaml
```

Downstream stages prefer `targets-selected.yaml` when it exists.

## 1. Fetch

```bash
export ETHERSCAN_API_KEY=…          # only needed on cache miss
fetch.py fetch --fetch-root <dir>   # add --rpc-url for a reliable endpoint
```

Freezes the batch id (`YYYYMMDD-<sha8 of the targets file>`) in `state.yaml`.
**The targets file is frozen from here on** — a changed file fails closed
(exit 2): start a new fetch root for a new selection. Failures land as
`FAILED:FETCH` with next steps; a proxy's implementation becomes a derived
`<id>--impl` target automatically. Everything after this stage is offline.

## 2. Assemble

```bash
fetch.py assemble --fetch-root <dir>            # add --rebuild <id> to force a tree
```

Reconstructs `projects/<batch>/targets/<id>/src/…` byte-identically, writes
`target.yaml` (per-file keccak/sha256/lines), `artifacts/input.json`
(verbatim for standard-json), and regenerates `foundry.toml` with one profile
per target (settings from the verification record; remappings derived from
bare import prefixes). Sources are never edited — a dangling import or an
exotic path fails the row (`FAILED:ASSEMBLE`).

## 3. Build

```bash
fetch.py build --fetch-root <dir>               # requires forge on PATH
```

Runs `FOUNDRY_PROFILE=<id> forge build --force` per target (forge installs
the pinned solc itself) and writes `projects/<batch>/build-report.yaml`
(forge version, durations, error excerpts). BUILD_FAIL rows keep their
verified sources untouched — exclude them with a reason or report the case.

## 4. Verify

```bash
fetch.py verify --fetch-root <dir>              # optional: export CF_SOLC_PATH=…
```

See `verification.md` for the ladder. With a matching solc on the machine the
report's `build_cross_check` is `PASS`; without one it is honestly `SKIPPED`
and the bytecode verdict degrades to `MATCH_CODE_ONLY` (metadata linkage
unproven — still recorded, still source-identity-checked).

## 5. Manifest + gate

```bash
fetch.py manifest --fetch-root <dir>
fetch.py check   --fetch-root <dir>
```

`sources-manifest.yaml` lists every target with build/verification verdicts
(failures included, honestly). `check` exits 0 only when every non-excluded
target is READY. Resolve blockers by excluding the row in the targets file
**with an `exclude_reason`** (excluded rows never fetch and never block) or
fixing the row — never by editing evidence.

## 6. Hand off to audit-orchestrator

One work-root per READY target (keeps the orchestrator's target-modification
guard scoped, and its `audit-skills.yaml` needs a single `target_root`):

```yaml
# <audit-work-root>/audit-skills.yaml
target_root: <absolute fetch-root>/projects/<batch>/targets/<id>/src
scope:
  - .
skills: [ … your audit pipeline, unchanged … ]
```

The manifest's `src` entries are exactly those paths. Record the manifest
hash alongside the audit run so the audited tree stays attributable.

## Resume semantics (entry 0B)

Every stage processes only targets in its entering state (`SELECTED` /
`FETCHED` / `ASSEMBLED` / `BUILT`, plus same-stage `FAILED:*` retries) and is
idempotent otherwise — safe to re-run after any interruption. `check` prints
each blocking target and its recorded next steps.
