# Explorer API + chain state — request behavior, cache, failure policy

## Etherscan V2 (getsourcecode)

```
GET {api_base}/v2/api?chainid=<id>&module=contract&action=getsourcecode
                    &address=<addr>&apikey=<ETHERSCAN_API_KEY>
```

- Default `api_base` is `https://api.etherscan.io`; `--api-base` overrides it
  (used by the test suite's local mock server).
- The key comes **only** from the environment (`ETHERSCAN_API_KEY`). A run
  where every needed response is already cached needs no key — the whole
  pipeline is offline after a successful first fetch.
- Rate limit: default 5 req/s (`--rps`), plus exponential backoff (3 retries)
  on HTTP 429/5xx, network errors, and the 200-body
  `"Max rate limit reached"` response. Backoff base is 1s;
  `CF_BACKOFF_BASE` overrides it (tests set 0.01).
- Raw responses are cached verbatim at
  `fetch-cache/<chainid>/<address>.getsourcecode.json` (sha256 recorded in
  state). `--refresh <address>` busts one address (also re-runs it regardless
  of pipeline state); `--refresh-all` busts everything.

## Response parsing

`result[0]` fields used: `SourceCode`, `ABI`, `ContractName`,
`CompilerVersion`, `OptimizationUsed`, `Runs`, `EVMVersion`, `Proxy`,
`Implementation`.

Three `SourceCode` shapes:

1. **standard-json** — starts `{{` ends `}}`: one brace layer wraps the exact
   solc standard-JSON input the deployer submitted (settings + sources with
   inline content). Stored verbatim as `artifacts/input.json`
   (`input_exact: true`). Gold standard.
2. **multi-file** — starts `{`: a `{"sources": {path: {content}}}` object;
   settings come from the sibling fields; the input is synthesized
   (`input_exact: false`).
3. **single-file-flattened** — plain Solidity text: one file
   `src/<ContractName>.sol`; line numbers refer to the flattened unit (the
   explorer's view — that is the fidelity target).

Source paths are normalized (leading `/` stripped, `..` rejected, collisions
rejected). `settings` resolution order for standard-json: the payload's own
`settings` (optimizer.enabled/runs, viaIR, evmVersion, libraries, remappings),
falling back to the top-level fields for the other formats.

## Fail-closed rows (recorded as `FAILED:FETCH` + next_steps)

| Category | Trigger |
|---|---|
| UNVERIFIED | empty `SourceCode` / "Contract source code not verified" ABI |
| VYPER | `CompilerVersion` starts `vyper` (out of scope v1) |
| NIGHTLY | compiler version contains `nightly` (not reproducible) |
| SOLC | version doesn't parse as `x.y.z` |
| PARSE | payload has no inline sources (keccak-only entries) or bad JSON |
| EXPLORER | API error after retries |
| RPC | eth_getCode failed / returned empty code (EOA or wrong chain) |

Proxies: `Proxy == "1"` ⇒ the `Implementation` address is appended to the
batch as a derived target `<parent-id>--impl` (same chain, funds inherited
from the parent row, `derived_from` recorded). A proxy whose implementation is
itself unverified fails on its own row.

## Chain state (RPC)

Per address: `eth_getCode(addr, "latest")` + `eth_blockNumber`, cached at
`fetch-cache/<chainid>/<address>.getcode.json` together with the block number
(anchors the comparison: "on-chain code as of block N").

RPC selection order: `--rpc-url` flag → `rpc:` map in the targets file
(keys may be ints or strings) → built-in public endpoint per chain
(llamarpc / bnbchain / polygon-rpc / optimism / base.org / arbitrum / avax /
ftm.tools). Public endpoints are a default, not a promise — for large batches
put a paid RPC in the `rpc:` map.
