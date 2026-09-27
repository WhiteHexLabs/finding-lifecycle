# Verification — bytecode equality and line-number correspondence

`verify` produces `verification/<target-id>.yaml` per target. Two independent
claims must both hold; there is no `--force`.

## Which local bytecode is authoritative

The **exact-input compilation** — `solc --standard-json < artifacts/input.json`
— whenever a matching solc binary resolves:

1. `CF_SOLC_PATH` env (version must match), else
2. `~/.svm/<version>/solc-<version>` (forge's solc management), else
3. `solc` on PATH (version must match), else → no exact-input run.

Only the exact-input compile reproduces the **verification-time unit paths**
(and therefore the metadata hash) of the on-chain bytecode. The forge tree
build compiles the same sources under project paths
(`targets/<id>/src/...`), so its metadata hash differs **by design** — the
metadata commits to source paths.

## Bytecode ladder

Against the on-chain `eth_getCode` (cached, at the recorded block):

1. `MATCH_EXACT` — byte-identical, metadata included.
2. `MATCH_AFTER_IMMUTABLE_MASK` — equal after zeroing the
   `immutableReferences` byte ranges (per ast id, from the solc output) on
   **both** sides. Immutables are deployment-specific constructor values;
   the metadata tail sits outside every immutable range, so metadata equality
   still holds.
3. `MATCH_CODE_ONLY` — fallback **only when no matching solc binary exists**:
   equal after additionally masking each side's own CBOR metadata tail.
   Executable code is proven equal; the metadata linkage is not, and the
   report records `metadata_masked: true` + `build_cross_check: SKIPPED`.
4. `MISMATCH` — fail-closed. Diagnostics: whether the metadata tails are
   equal, the first differing byte offset, and the reading
   (metadata differs ⇒ sources/settings differ; metadata equal but code
   differs ⇒ optimizer/via_ir/evm_version differ).

Tree cross-check (when the exact-input run exists): the forge artifact's
runtime vs the exact-input runtime with **both metadata tails masked** —
`PASS`, or `RECONSTRUCTION` (the reconstructed tree is suspect; rerun
`assemble --rebuild <id>`).

## Why bytecode equality ⇒ identical line numbers

solc appends a CBOR blob to the runtime bytecode whose payload is the metadata
hash; the hash commits to every source file's **path + keccak256(content)**
plus settings. Therefore:

```
local runtime == on-chain runtime (metadata included)
  ⟹ metadata hashes equal
  ⟹ every file's path + keccak256 identical
  ⟹ every local file is byte-identical to the explorer-verified source
  ⟹ line N locally == line N in the explorer's code viewer
```

`MATCH_AFTER_IMMUTABLE_MASK` preserves the claim (mask ranges exclude the
metadata tail). `MATCH_CODE_ONLY` does **not** make this claim via metadata;
it is covered instead by the direct source-identity check below, plus the
explorer's own act of verification.

## Source identity (always, no solc needed)

Every file listed in `target.yaml` is re-read from disk and its keccak256 must
equal the one recorded at assemble time (which was asserted equal to the
explorer payload). Any drift (edits, deletions) ⇒ `SOURCE_TAMPER` — rerun
`assemble --rebuild <id>` to restore the tree from cache.

## Notes and gotchas

- solc `--standard-json` emits `deployedBytecode.object` **without** an `0x`
  prefix; forge artifacts carry it **with** the prefix (and `deployedBytecode`
  is a dict `{object, immutableReferences, linkReferences}` — immutable refs
  live inside that dict only when the profile sets
  `extra_output = ["evm.deployedBytecode.immutableReferences"]`, which the
  generated foundry.toml does).
- Unlinked library placeholders (`__$…$__`) in the artifact ⇒
  `LIBRARY_UNLINKED` (a verified input normally carries
  `settings.libraries` and links cleanly).
- Flattened-single-file targets: line numbers correspond to the flattened
  unit by construction; the report carries
  `format: single-file-flattened` so report authors cite accordingly.
- Creation bytecode is never compared: constructor arguments are
  deployment-specific; runtime equality is the auditable claim.
- Verdict file schema: `whitehexlabs.verification/v1` — see the design doc
  §7.5 for the field list.
