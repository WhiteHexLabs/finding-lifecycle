---
name: contract-fetch
description: Pre-audit batch source fetching from block explorers. Transcribes bounty-platform Assets-in-Scope rows into a validated target list, fetches verified sources via Etherscan V2, reconstructs a compilable Foundry workspace, and proves local code byte-identical to the explorer's verified code (runtime bytecode equality plus source-identity hashes), emitting a sources-manifest for audit-orchestrator.
---

# contract-fetch

Turns bounty-platform scope tables into a verified, compilable Foundry
workspace. A Python CLI enforces the pipeline gates
(`docs/contract-fetch-design.md` is the spec; load
`references/workflow.md` before operating a stage).

This skill **never audits and never modifies downloaded sources**. It produces
target workspaces for `audit-orchestrator`; findings belong to
`finding-lifecycle`.

**Red lines (always):** never edit a reconstructed `.sol` file (compilation is
steered only through generated foundry.toml/remappings; a tree that does not
compile is recorded as BUILD_FAIL) · never claim a match without evidence —
there is no `--force`; unverified/Vyper/nightly/mismatching targets fail closed
· never write the Etherscan API key into any artifact (env `ETHERSCAN_API_KEY`
only) · never scrape platform pages from the CLI (transcription is the
operator's judgment; the CLI only validates and processes).

## Entry modes — pick by what you already have

1. **0A — an empty directory** → `init`, transcribe scope rows into
   `targets.yaml` (guide + worked example in `references/discovery-sources.md`),
   then run the pipeline left to right (Quick start below).
2. **0B — a partially advanced fetch root** → re-run the failed stage; every
   stage is idempotent and `state.yaml` records where each target stands
   (`check` prints the blocking targets and their next steps).

## Quick start

```bash
CF="python3 <skill-root>/scripts/fetch.py"

$CF init     --fetch-root <dir>                  # 0. scaffold + targets.yaml template
#   …transcribe Assets-in-Scope rows into targets.yaml, then:
$CF validate --fetch-root <dir>                  # schema + semantic checks (exit 1 = row issues)
$CF select   --fetch-root <dir> --sort funds --min-added-on <date> --top 20 \
             -o targets-selected.yaml            # deterministic ranking by Funds column
$CF fetch    --fetch-root <dir>                  # needs ETHERSCAN_API_KEY on cache miss
$CF assemble --fetch-root <dir>                  # byte-identical trees + foundry.toml
$CF build    --fetch-root <dir>                  # forge per profile (needs forge)
$CF verify   --fetch-root <dir>                  # bytecode + source identity
$CF manifest --fetch-root <dir>                  # sources-manifest.yaml, READY
$CF check    --fetch-root <dir>                  # gate: every non-excluded target READY
```

Exit codes: `0` ok · `1` gate failed · `2` input/runtime error. Stage commands
exit `1` when any target failed that stage (successful targets still advance);
`check` is the batch gate.

## Stages & gates (per target, one state.yaml entry each)

| # | Stage | Produce | Gate essence |
|---|-------|---------|--------------|
| 0 | SELECTED | targets.yaml row | schema valid; funds_raw verbatim + parsed; chain from explorer domain whitelist; (chain,address) unique |
| 1 | FETCHED | fetch-cache/{getsourcecode,getcode}.json | verified Solidity source (standard-json/multi-file/flattened); solc not vyper/nightly; on-chain code non-empty at a recorded block; proxy ⇒ implementation derived as `<id>--impl` |
| 2 | ASSEMBLED | targets/<id>/src + target.yaml + artifacts/input.json | byte-identical reconstruction (per-file keccak/sha256); no dangling imports; remappings generated, never source edits |
| 3 | BUILT | forge artifact + build-report.yaml | `FOUNDRY_PROFILE=<id> forge build --force` passes with the verification settings |
| 4 | VERIFIED | verification/<id>.yaml | exact-input recompile == on-chain runtime (immutable-masked, metadata included ⇒ line numbers identical); tree-build code equal modulo metadata; disk keccak unchanged |
| 5 | READY | sources-manifest.yaml entry | manifest lists build + verification verdicts; audit_recommended = both PASS |

## Operating rules

- Discovery is judgment: browse the platform's **Assets in Scope** table and
  transcribe Funds / address / Added-on / description **verbatim**
  (`references/discovery-sources.md`); ranking is the CLI's `select`.
- After `fetch` starts a batch, the targets file is frozen by hash; changing
  the selection means starting a new fetch root (fail-closed, exit 2).
- Cache-first: everything after a successful `fetch` works offline;
  `--refresh <address>` busts a single stale entry.
- On any FAILED target: exclude it in targets.yaml **with a reason** or fix the
  row; the manifest records failures honestly, `check` blocks until resolved.
- Hand off to audit-orchestrator with one work-root per READY target:
  `target_root: <fetch-root>/<manifest src path>` (see `references/workflow.md`).

## Repository layout

`scripts/fetch.py` (single-file CLI) · `references/` (discovery-sources,
explorer-api, verification, workflow) · `templates/targets.yaml` · repo
`tests/contract_fetch/` · design doc `docs/contract-fetch-design.md`. Install
by symlinking this directory into `~/.zcode/skills/contract-fetch`.
