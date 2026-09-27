# contract-fetch — Pre-Audit Batch Source Fetching From Block Explorers

## Objective

Before a formal audit starts, an operator needs a local, compilable, provably
faithful copy of the target protocol's verified on-chain sources. Today that
work is manual: open the bounty platform page, click each address, copy code
out of the explorer, hand-stitch a Foundry project, and hope nothing drifted.

This document specifies a third skill for this repository, `contract-fetch`,
which turns that into a gated pipeline:

1. **Source download** — pick candidates from vulnerability-platform **Assets
   in Scope** tables (recently-added rows and large-funds rows), fetch every
   verified contract from block explorers, and assemble a Foundry workspace.
2. **Compilable** — the assembled workspace must pass `forge build`.
3. **Consistency** — local code must be identical to the explorer's verified
   code: on-chain bytecode equality **and** source-line correspondence.

The skill produces a `sources-manifest` that `audit-orchestrator` consumes
directly. Pipeline position:

```
contract-fetch  (targets → verified Foundry workspace)
      │  sources-manifest.yaml
      ▼
audit-orchestrator  (--work-root, runs the audit skills)
      │  finalized handoff
      ▼
finding-lifecycle   (per-finding ledger)
```

Design language follows the two existing skills: one single-file Python CLI
enforces deterministic gates; judgment work (browsing platform pages) stays
with the operator/agent; every artifact is hashed; nothing is ever forced.

---

# 1. Non-negotiable design principles

## 1.1 Discovery is judgment, fetching is mechanics

Reading an Immunefi scope page, deciding "this program is worth auditing", and
transcribing the table are judgment calls that break every time a platform
redesigns. Scraping is therefore **not** CLI functionality. The agent browses
platform pages with its web tools and transcribes scope rows into
`targets.yaml`; the CLI validates, ranks, fetches, assembles, builds, and
verifies. Same split as `finding-lifecycle`'s "the CLI never fetches; copies +
hashes are your evidence" — except that here, once targets are structured, the
fetching itself is deterministic and therefore belongs in the CLI.

## 1.2 Downloaded sources are immutable evidence

The reconstructed `.sol` files are byte-copies of what the explorer verified.
They are **never edited** — not to fix imports, not to silence warnings, not to
make a build pass. If a tree does not compile as-is, the build gate records a
failure and the operator decides. Compilation is steered exclusively through
generated configuration (`foundry.toml` profiles, `remappings`), never through
source edits. This mirrors the orchestrator's target-modification guard and is
what makes requirement 3 provable.

## 1.3 Fail closed

Unverified contract, Vyper contract, unresolvable proxy, dangling import,
nightly compiler version, bytecode mismatch — every one is a hard failure with
a categorized issue and `next_steps`. There is no `--force` and no
silent-skip. A batch proceeds to the manifest only when every selected target
is READY or the operator explicitly excluded a target in `targets.yaml` with a
reason.

## 1.4 No secrets in artifacts

The Etherscan API key is read from the environment (`ETHERSCAN_API_KEY`) and is
never written into any file under the fetch root, cache, reports, or manifest.

## 1.5 Independence

`contract-fetch` is a self-contained skill: single Python file, stdlib +
PyYAML, no runtime imports from the sibling skills, no new third-party
dependencies. Integration with `audit-orchestrator` is a file contract (the
manifest), nothing else.

---

# 2. Candidate discovery — Assets in Scope tables

Both selection signals come from the **same** table on the vulnerability
platform's project page. Worked example (Immunefi):

| Funds | Address | Description | Added on |
|---|---|---|---|
| $35.8M | [0x5376…](https://etherscan.io/address/0x…) | LiquidETH - boring_vault | 30 March 2026 |
| $7.1M | [0x9c18…](https://etherscan.io/address/0x…) | LiquidUSD - boring_vault | 30 March 2026 |
| $474.3K | [0x0ecb…](https://arbiscan.io/address/0x…) | LiquidBTC - boring_vault | 30 March 2026 |

- **"刚加入审计" (recently added)** → the **Added on** column.
- **"锁仓量大" (large funds)** → the **Funds** column (funds at risk as stated
  by the project). Sorting by this column replaces any external TVL lookup —
  no DefiLlama integration; the platform's own numbers are the ranking input.

## 2.1 Transcription rules (operator side)

The agent fills `targets.yaml` (template provided) with one entry per scope
row, transcribing **verbatim**:

- `funds_raw`: the Funds cell exactly as shown (`"$35.8M"`, `"$474.3K"`,
  `"$1,200,000"`, `"N/A"`).
- `address` + `chain`: the address and the explorer domain of its hyperlink.
  The chain is derived from the domain (table in §2.2), not guessed from the
  project's marketing.
- `added_on`: the Added-on cell as a date (normalize to `YYYY-MM-DD`).
- `description`: the scope-table description cell verbatim (it usually names
  the contract role — useful later when the operator picks what to audit).
- `source_url`: the platform project page URL; `platform`: e.g. `immunefi`.

The worked example above is codified in
`references/discovery-sources.md` so the transcription step is repeatable.
Other platforms (hats.finance, HackenProof, contest listings) can be added to
that reference later without touching the CLI.

## 2.2 Explorer-domain → chain map (v1 whitelist)

| Domain | Chain | Etherscan V2 `chainid` |
|---|---|---|
| etherscan.io | Ethereum | 1 |
| bscscan.com | BNB Smart Chain | 56 |
| polygonscan.com | Polygon PoS | 137 |
| optimistic.etherscan.io | OP Mainnet | 10 |
| basescan.org | Base | 8453 |
| arbiscan.io | Arbitrum One | 42161 |
| snowtrace.io | Avalanche C-Chain | 43114 |
| ftmscan.com | Fantom Opera | 250 |

Chains whose verified bytecode is not plain solc output (zkSync Era: zksolc /
eraVM) are **excluded from v1** — a solc recompile can never match there (see
§14).

Unknown domain ⇒ `validate` fails with the row referenced (extend the map in
one place). The whitelist is deliberately short in v1; it is data in
`fetch.py`, not a config surface.

## 2.3 Funds parsing (CLI side)

`validate` parses `funds_raw` into `funds_usd` and rejects rows where the two
disagree:

```
"$35.8M"  → 35_800_000      "$474.3K" → 474_300
"$1.2B"   → 1_200_000_000   "$1,200,000" → 1_200_000
"N/A" / empty → funds_usd omitted (row stays eligible; sorts last)
```

Both the verbatim string and the number are kept — the string is evidence of
what the page said, the number is the sort key.

---

# 3. `targets.yaml` — schema `whitehexlabs.targets/v1`

```yaml
schema: whitehexlabs.targets/v1
batch_note: "Liquid Finance, Immunefi, transcribed 2026-09-27"   # free text
rpc:                                      # OPTIONAL per-chain override
  1: https://eth-mainnet.g.alchemy.com/v1/<key>   # key from env is preferred
targets:
  - id: liquideth-boring-vault            # slug, unique
    project: Liquid Finance
    platform: immunefi
    source_url: https://immunefi.com/boost/liquid-finance-boost-detail
    chain: 1                              # Etherscan V2 chainid
    address: "0x5376A20dC3b9165E3d38e5A4B0f7e4c5…"
    funds_raw: "$35.8M"
    funds_usd: 35800000                   # optional; validate cross-checks
    added_on: 2026-03-30
    description: "LiquidETH - boring_vault"
    excluded: false                       # true requires exclude_reason
    exclude_reason: ""                    # mandatory when excluded
    notes: ""
```

Validation rules (`validate` subcommand, exit 1 with one issue per problem
row):

- `schema` string exact; `targets` non-empty list.
- `id` unique slug; `address` is 20-byte hex (checksum form accepted,
  normalized to lowercase internally; a bad EIP-55 checksum is an error).
- `chain` in the whitelist; `(chain, address)` pairs unique (the same address
  on two chains is fine — two rows for one address on one chain is an error).
- `added_on` a real date; `funds_usd` (when present) consistent with
  `funds_raw`.
- `excluded: true` requires non-empty `exclude_reason`.

## 3.1 `select` — deterministic ranking

```bash
fetch.py select --fetch-root R \
  [--targets targets.yaml] \
  [--sort funds|added_on|id] [--min-funds 1000000] \
  [--min-added-on 2026-08-01] [--top 20] \
  -o targets-selected.yaml
```

Filters, sorts (stable; secondary key always `id`; missing `funds_usd` sorts
last), writes a pruned file carrying the same schema plus a provenance header
(`selected_from: <sha256 of parent>`, filter flags recorded). Downstream
subcommands read `targets-selected.yaml` when present, else `targets.yaml`.

---

# 4. Fetch root layout

```
<fetch-root>/
  targets.yaml                    # transcribed scope rows
  targets-selected.yaml           # optional pruned view (from select)
  fetch-cache/
    <chainid>/<address>.getsourcecode.json   # raw Etherscan V2 response
    <chainid>/<address>.getcode.json         # raw eth_getCode JSON-RPC + block number
  projects/<batch>/
    foundry.toml                  # one profile per target (§6)
    targets/<target-id>/
      target.yaml                 # immutable record (§6.2)
      src/…                       # reconstructed byte-identical tree
      artifacts/{explorer.json, input.json, output.json}
      out/                        # forge artifacts (generated)
  verification/<target-id>.yaml   # per-target consistency verdict (§7)
  sources-manifest.yaml           # batch summary → audit-orchestrator (§8)
  state.yaml                      # per-target pipeline state (§4.1)
```

`batch` id = `YYYYMMDD-<sha8(targets file actually used)>`, recorded in
`state.yaml`. Re-creating the same selection yields the same batch id
(idempotent); changing the selection creates a new batch directory and never
touches previous ones.

## 4.1 Per-target state machine

```
SELECTED → FETCHED → ASSEMBLED → BUILT → VERIFIED → READY
     any stage may record  FAILED:<stage> + issues + next_steps (terminal)
```

Each subcommand advances only targets whose current state is the immediately
preceding one (or re-verify the recorded artifacts and no-op when already
advanced — every stage is idempotent). `state.yaml` is a plain ledger: target
id, state, timestamps, artifact hashes. No revision counters: a fetch root is
single-operator scratch until the manifest is produced (unlike a lifecycle
case root, there is no long-lived multi-session ledger to protect).

---

# 5. `fetch` — explorer + chain state

## 5.1 Etherscan V2

```
GET https://api.etherscan.io/v2/api
    ?chainid=<chain>&module=contract&action=getsourcecode
    &address=<addr>&apikey=<ETHERSCAN_API_KEY>
```

- Key from env only; missing key ⇒ exit 2 with the exact export line in the
  message.
- Rate limit 5 req/s (configurable `--rps`), exponential backoff on
  `"Max rate limit reached"` / HTTP 429 (max 3 retries, then fail).
- The raw response is cached verbatim at
  `fetch-cache/<chainid>/<address>.getsourcecode.json` together with its
  sha256. Cached-and-parseable ⇒ skip the network (`--refresh` busts one
  address or `--refresh-all`). After the first successful run, every later
  stage works fully offline.

## 5.2 Chain state via RPC

`eth_getCode(address, "latest")` + `eth_blockNumber`, both recorded (the block
number anchors reproducibility: "on-chain code as of block N"). RPC selection
order: `--rpc-url` flag > `targets.yaml` `rpc:` map > built-in public endpoint
per chain. Public endpoints are a default, not a promise — the reference doc
says so and suggests paid RPC for large batches.

## 5.3 Response parsing — three verification formats

`result[0].SourceCode` is inspected:

1. **Standard JSON** (field starts `{{`, ends `}}`): strip one brace layer →
   the full solc standard-JSON input the deployer submitted: `language`,
   `settings` (optimizer, runs, viaIR, evmVersion, remappings, libraries),
   `sources{path: {content}}`. Gold standard — `input.json` is this payload
   verbatim.
2. **Multi-file** (starts `{`): object with `sources{path: content}` (older
   format, settings taken from the sibling `CompilerVersion` /
   `OptimizationUsed` / `Runs` / `EVMVersion` fields instead).
3. **Single file** (anything else): one flattened Solidity source. Recorded
   with `format: single-file-flattened` — see §7.4.

Fail-closed rows (recorded as `FAILED:FETCH` with next_steps):

- `SourceCode` empty / `ABI == "Contract source code not verified"` — target
  unverified. Nothing can be claimed about its code.
- `CompilerVersion` starting `vyper` — Vyper is out of scope in v1.
- Nightly solc (`0.8.x-nightly…`) — not reproducible via forge's solc
  management.
- `Proxy == "1"` — the implementation address is fetched and **appended to the
  batch as a derived target** (`id: <parent-id>--impl`, `derived_from:
  <parent-id>`); if the implementation is itself unverified, both rows fail
  with next_steps. EIP-1967 implementation-slot read via RPC is the fallback
  when the explorer reports no implementation.

---

# 6. `assemble` + `build` — the Foundry workspace (requirement 2)

## 6.1 Tree reconstruction

For standard-JSON and multi-file formats, every source is written at its
original path under `targets/<id>/src/`, normalized only in path shape (strip
leading `/`, reject `..` traversal and absolute paths outside the tree — same
hardening as `import-audit`'s bundle resolver). For single-file format the one
file becomes `src/<ContractName>.sol`.

Per file, `assemble` records `keccak256` and `sha256` of the explorer content
and asserts disk == explorer byte-for-byte before moving on.

## 6.2 `target.yaml` — the immutable per-target record

```yaml
schema: whitehexlabs.target/v1
id: liquideth-boring-vault
chain: 1
address: "0x5376…"
contract_name: BoringVault
compiler:
  version: 0.8.25            # from CompilerVersion, leading 'v' stripped
  optimizer: true
  runs: 200
  via_ir: false
  evm_version: cancun        # omitted ⇒ compiler default (recorded as such)
  libraries: {}              # from settings.libraries when present
format: standard-json        # standard-json | multi-file | single-file-flattened
proxy: {parent: null, implementation: null}
fetch:
  getsourcecode_sha256: …
  getcode_sha256: …
  block_number: 12345678
files:                       # ordered by path
  - path: src/BoringVault.sol
    keccak256: 0x…
    sha256: …
    lines: 412
```

## 6.3 foundry.toml — one profile per target

```toml
# [profile.default] intentionally minimal; every real target gets its own profile

[profile.liquideth-boring-vault]
src = "targets/liquideth-boring-vault/src"
out = "targets/liquideth-boring-vault/out"
solc = "0.8.25"
optimizer = true
optimizer_runs = 200
via_ir = false               # emitted only when the explorer said so
evm_version = "cancun"       # emitted only when the explorer said so
remappings = ["@openzeppelin/=targets/liquideth-boring-vault/src/@openzeppelin/"]
extra_output = ["evm.deployedBytecode.immutableReferences"]
```

Builds are invoked as `FOUNDRY_PROFILE=<id> forge build --force` (forge 1.x
selects profiles through the environment, not a CLI flag); the immutable
reference table lands in the artifact at
`deployedBytecode.immutableReferences`.

Settings come from the verification record, never from guesswork. Profile ids
are the target ids (slugs are already validated safe for TOML keys).

## 6.4 Remappings generation (deterministic)

1. Collect every import string in the target's sources.
2. Relative imports (`./`, `../`) resolve naturally in the reconstructed tree
   — nothing to emit.
3. For each non-relative import, take its first path segment (e.g.
   `@openzeppelin` from `@openzeppelin/contracts/token/ERC20.sol`), verify
   `src/<segment>/` exists in the tree, and emit
   `"<segment>/=targets/<id>/src/<segment>/"`.
4. Any import that still resolves to nothing (the verifier's input was
   self-contained, so this indicates a parsing bug or an exotic layout) ⇒
   `FAILED:ASSEMBLE` listing the dangling import and file. No fallback
   remapping is invented, no source is edited.

`artifacts/input.json` is the exact standard-JSON input (for format 1: the
payload verbatim; formats 2–3: synthesized from the parsed fields, and marked
`input_exact: false` — see §7.2).

## 6.5 `build` gate

Per target: `forge build --profile <id>` in `projects/<batch>/` with a
timeout. `forge --version` is recorded in `build-report.yaml`; solc versions
are installed by forge's own solc management. Verdict per target:
`BUILD_PASS` / `BUILD_FAIL` (with the compiler error excerpt). The build is
run with `--force` on re-runs so stale artifacts never mask a regression.

---

# 7. `verify` — consistency (requirement 3)

Two independent comparisons, both required. Per target the verdict lands in
`verification/<target-id>.yaml`.

## 7.1 Bytecode equality

Compare the locally compiled **runtime** bytecode against on-chain
`eth_getCode`:

1. Local bytecode source of truth: the exact-input compilation — compile
   `artifacts/input.json` with the pinned solc via `solc --standard-json`
   (binary resolution: `CF_SOLC_PATH` env > `~/.svm/<v>/solc-<v>` > PATH `solc`
   with a matching version; decided in M4 — this forge version has no
   `build --stdin`). Only the exact input reproduces the verification-time
   unit paths, and the metadata hash commits to source **paths**, so the
   forge tree build's metadata can never equal on-chain — by design, not by
   defect (see the cross-check below).
2. Mask nothing yet. Equal → `MATCH_EXACT`.
3. Not equal → mask the `immutableReferences` byte ranges **on both sides**
   (immutables are deployment-specific values baked at construction; the
   explorer-verified compilation has zeros, on-chain has live values) and
   compare again → `MATCH_AFTER_IMMUTABLE_MASK`. The metadata tail (§7.3) is
   **outside** every immutable range and stays in the comparison.
4. **No matching solc binary anywhere** → the forge tree-build artifact
   becomes the primary local bytecode, and a further fallback is allowed:
   mask each side's **own** CBOR metadata tail and compare →
   `MATCH_CODE_ONLY` (recorded with `metadata_masked: true`; the executable
   code is proven equal, the metadata linkage is not — covered instead by
   §7.2's direct source identity plus the explorer's own verification).
5. Still not equal → `MISMATCH` (fail-closed). Diagnostics: metadata tail
   bytes of both sides, first differing offset, and a hint table (metadata
   differs ⇒ sources/settings differ; only code differs ⇒ settings such as
   optimizer/via_ir/evm_version differ).

The exact-input run is authoritative for **all** formats when a solc resolves
(formats 2–3 use the synthesized input, whose source keys are the original
explorer paths — that is what matters to the metadata). Independently, the
forge tree-build runtime is compared against the exact-input runtime with
**both metadata tails masked** (paths legitimately differ between the two
compilations): equal → `build_cross_check: PASS`; not equal →
`RECONSTRUCTION_SUSPECT` — an `assemble` defect to investigate, not a target
defect. This cross-check is what guards against remapping/reconstruction
bugs while tolerating the path-dependent metadata hash.

## 7.2 Source identity (line-number correspondence)

For every file in the tree, re-read from disk and record `keccak256`,
`sha256`, line count; assert disk keccak == the keccak recorded at assemble
time (catches post-fetch tampering or accidental edits — requirement 1.2's
enforcement).

## 7.3 Why bytecode equality ⇒ identical line numbers

solc appends to the runtime bytecode a CBOR blob whose payload is the
metadata hash (`bzzr1`/`ipfs`). That hash is computed over a metadata JSON
that commits to **every** source file's path and `keccak256(content)`, plus
the settings. Therefore:

```
local runtime bytecode == on-chain runtime bytecode (both incl. metadata)
  ⟹ metadata hashes equal
  ⟹ for every file: path + keccak256(content) identical
  ⟹ every local file is byte-identical to the explorer-verified source
  ⟹ line N of a local file == line N shown in the explorer's code viewer
```

The per-file hash table in the verification report is the human-checkable
form of that argument (and the audit report's file:line citations stay valid
against the explorer view). `MATCH_AFTER_IMMUTABLE_MASK` preserves the claim:
masked ranges cover only immutable values, never the metadata tail.

## 7.4 Flattened-single-file caveat

If the deployer verified a flattened single file, "the explorer's code" **is**
that flattened file, and line numbers are consistent against it by
construction. The verification report carries
`format: single-file-flattened` so report authors know file:line citations
refer to the flattened unit, not the project's repo layout. (Fidelity to the
explorer view is the requirement; repo-layout fidelity is explicitly a
non-goal.)

## 7.5 Verdict file

```yaml
schema: whitehexlabs.verification/v1
target: liquideth-boring-vault
block_number: 12345678
onchain_runtime_sha256: …
local_runtime_sha256: …       # exact-input compile output (primary)
tree_runtime_sha256: …        # forge tree-build artifact
bytecode: MATCH_EXACT         # | MATCH_AFTER_IMMUTABLE_MASK | MATCH_CODE_ONLY | MISMATCH
metadata_masked: false        # true only for MATCH_CODE_ONLY
immutable_mask: {ranges: 3, ast_ids: [...]}
source_identity: PASS         # disk keccak == assemble keccak, all files
metadata_tail: "0x…"          # CBOR tail of the primary local runtime
format: standard-json
input_exact: true
build_cross_check: PASS       # | RECONSTRUCTION | SKIPPED (+reason)
verdict: PASS                 # PASS requires bytecode MATCH + source PASS
```

---

# 8. `manifest` + `check` — batch gate and handoff

## 8.1 `sources-manifest.yaml` — schema `whitehexlabs.sources-manifest/v1`

```yaml
schema: whitehexlabs.sources-manifest/v1
batch: 20260927-a1b2c3d4
created: 2026-09-27T…Z
targets:
  - id: liquideth-boring-vault
    project: Liquid Finance
    platform: immunefi
    source_url: https://immunefi.com/…
    chain: 1
    address: "0x5376…"
    funds_raw: "$35.8M"
    added_on: 2026-03-30
    src: projects/20260927-a1b2c3d4/targets/liquideth-boring-vault/src
    compiler: {version: 0.8.25, optimizer: true, runs: 200}
    build: BUILD_PASS
    verification: MATCH_EXACT
    audit_recommended: true    # build PASS + verification PASS/EXACT|MASK
    verification_report: verification/liquideth-boring-vault.yaml
```

Excluded and failed targets appear in the manifest with their verdicts and
reasons — the manifest is the honest batch record, not just the happy path.

## 8.2 Handoff to audit-orchestrator

Recommended wiring (one work-root per target, keeps the orchestrator's target
modification guard scoped to one tree):

```yaml
# <work-root>/audit-skills.yaml
target_root: <fetch-root>/projects/<batch>/targets/<id>/src
scope:
  - .
skills: [ …unchanged… ]
```

The manifest's `src` paths are exactly those `target_root`s. A single
orchestrator run over the whole batch (target_root = `projects/<batch>`,
scope = per-target dirs) is possible but couples protocols; the reference doc
recommends per-target runs.

## 8.3 `check`

Exit 0 iff every non-excluded target is READY. Otherwise exit 1 with
categorized issues + next_steps (e.g. "target X FAILED:FETCH — unverified;
exclude it in targets.yaml with a reason or replace the address"). `--json`
emits the same machine-readably.

---

# 9. CLI surface

```
fetch.py init     --fetch-root D                       # scaffold from template
fetch.py validate --fetch-root D [--targets F]
fetch.py select   --fetch-root D [filters] -o F
fetch.py fetch    --fetch-root D [--targets F] [--refresh|--refresh-all] [--rps N]
fetch.py assemble --fetch-root D
fetch.py build    --fetch-root D
fetch.py verify   --fetch-root D
fetch.py manifest --fetch-root D
fetch.py check    --fetch-root D
```

- Global: `--fetch-root`, `--json`; exit codes `0` ok / `1` gate failed /
  `2` input/runtime error — identical semantics to the sibling CLIs.
- Gate failures print categorized issues + `next_steps` (GateFailure style);
  runtime errors print `error: …` (exit 2).
- Style contract from the sibling scripts carries over unchanged: constants
  block, custom exceptions, atomic writes via tempfile, SHA-256 everywhere,
  `--json` mirrors the human output.

Script: `skills/contract-fetch/scripts/fetch.py`. The name `fetch.py` matches
the sibling convention of one noun-verb script per skill (`audit.py`,
`lifecycle.py`).

---

# 10. Skill package layout

```
skills/contract-fetch/
  SKILL.md                     # same skeleton as siblings (§10.1)
  scripts/fetch.py
  references/
    discovery-sources.md       # scope-table transcription guide + domain→chain map + worked Immunefi example
    explorer-api.md            # V2 endpoint, response formats, cache layout, rate limits
    verification.md            # §7 in depth: masking algorithm, metadata argument, diagnostics
    workflow.md                # stage-by-stage operating procedure for the agent
  templates/
    targets.yaml               # §3 example as a fill-in template
```

## 10.1 SKILL.md skeleton

Mirrors the siblings: thesis paragraph + boundary statement ("this skill never
audits and never modifies downloaded sources; it produces verified target
workspaces for `audit-orchestrator`"), **Red lines (always)** (§1.2–1.4),
**Entry modes** (0A empty dir → full pipeline; 0B resume a partially advanced
fetch root), **Quick start** bash block, **Stages & gates** table
(SELECTED→READY with Produce/Gate essence per stage), **Operating rules**,
**Repository layout** pointer. Installation stays manual-symlink like the
siblings: `~/.zcode/skills/contract-fetch → skills/contract-fetch`.

---

# 11. Test plan

`tests/contract_fetch/`, stdlib `unittest`, subprocess-driven against the real
CLI in temp dirs — same harness as the existing suites. All network is faked:
a thread-local `http.server` serves canned explorer/RPC JSON; the CLI's
endpoints are overridable (`--api-base`, `--rpc-url`) for exactly this.

- `test_validate.py` — schema accept/reject; funds parsing table (§2.3);
  checksum address handling; chain whitelist; `(chain,address)` dedup;
  excluded-requires-reason.
- `test_select.py` — each filter, sort orders + stability, provenance header,
  missing `funds_usd` sorts last.
- `test_fetch.py` — three source formats parse correctly; unverified / vyper /
  nightly / proxy-derivation fixtures; 429 backoff (server counts requests);
  cache idempotency; `--refresh`; missing env key → exit 2; raw-response
  sha256 recorded.
- `test_assemble.py` — byte-fidelity of reconstruction; path normalization +
  traversal rejection; remapping generation (relative / `@scope` / dangling);
  proxy child rows; `target.yaml` hashes.
- `test_build.py` — skip without forge (mirrors `test_demo.py`); with forge: a
  tiny real fixture builds; a deliberately broken fixture reports BUILD_FAIL
  without editing anything.
- `test_verify.py` — fixtures with immutables (masking correctness); metadata
  tamper (flip one source byte → MISMATCH + diagnostics); disk-tamper after
  assemble → source_identity FAIL; flattened-format caveat recorded.
- `test_manifest_check.py` — aggregation incl. failed/excluded rows; `check`
  exit codes; handoff paths exist and point inside the batch.
- `test_state.py` — idempotent re-runs; resume from each intermediate state;
  new selection → new batch id, old batch untouched.

Forge-dependent tests self-skip when `forge` is absent so `python3 -m unittest
discover -s tests` stays green on any machine. Target: ~60 tests.

---

# 12. Non-goals (v1)

- No page scraping in the CLI (platform pages are agent territory).
- No DefiLlama / external TVL — ranking uses the platform's own Funds column.
- No Vyper, no decompilation, no unverified-contract recovery.
- No creation-bytecode comparison (constructor args are deployment-specific;
  runtime equality is the auditable claim).
- No source modification of any kind, including "harmless" import fixes.
- No finding/ PoC/ lifecycle functionality — downstream skills own those.

---

# 13. Implementation milestones

- **M1** — CLI skeleton, `init`/`validate`/`select` + `test_validate`/
  `test_select`.
- **M2** — `fetch` + cache + mock-server fixtures (+ tests).
- **M3** — `assemble` + `build` (+ tests; forge-skip pattern).
- **M4** — `verify` (+ tests); pin down the exact-input compile route
  (`forge build --stdin` availability in the pinned foundry vs svm `solc
  --standard-json`).
- **M5** — `manifest`/`check`, SKILL.md + references + templates, README
  three-skill overview, symlink install note.

Each milestone leaves `python3 -m unittest discover -s tests` green.

---

# 14. Open questions

1. ~~**Exact-input compile route**~~ — **resolved in M4**: `solc
   --standard-json` with binary resolution `CF_SOLC_PATH` >
   `~/.svm/<v>/solc-<v>` > PATH-solc-with-matching-version; this forge
   version has no `build --stdin`, and the tree build is only ever a
   modulo-metadata cross-check (paths enter the metadata hash). Recorded in
   `references/verification.md`.
2. **Public RPC defaults** — which free endpoints per chain are reliable
   enough to ship as defaults (llamarpc / ankr / publicnode); paid RPC via
   `rpc:` map is the documented escape hatch.
3. **Batch → orchestrator granularity** — per-target work roots (recommended)
   vs one run per batch; revisit after the first real batch.
4. **Whitelist growth** — process for adding chains/domains (data-table edit +
   test fixtures; keep it boring). zkSync-era-style chains (non-solc
   compilers, non-EVM bytecode) stay out until verify can handle their
   toolchains explicitly.
