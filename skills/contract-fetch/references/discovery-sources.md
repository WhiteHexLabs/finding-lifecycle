# Discovery sources — transcribing Assets in Scope

The CLI never scrapes platform pages. Discovery is the operator's judgment:
browse the platform's project page, transcribe the scope table into
`targets.yaml` verbatim, and let `validate`/`select` do the mechanical work.

Both selection signals live in the **same** table — no external TVL feed is
used; the platform's own numbers rank the batch.

## Worked example (Immunefi)

A program detail page's "Assets in Scope" section looks like:

| Funds | Address | Description | Added on |
|---|---|---|---|
| $35.8M | [0x5376…](https://etherscan.io/address/0x…) | LiquidETH - boring_vault | 30 March 2026 |
| $7.1M | [0x9c18…](https://etherscan.io/address/0x…) | LiquidUSD - boring_vault | 30 March 2026 |
| $474.3K | [0x0ecb…](https://arbiscan.io/address/0x…) | LiquidBTC - boring_vault | 30 March 2026 |

Transcription rules, one `targets.yaml` row per table row:

- **`funds_raw`** — the Funds cell **verbatim**: `"$35.8M"`, `"$474.3K"`,
  `"$1,200,000"`, `"N/A"`. The string is evidence of what the page said;
  `validate` cross-checks the optional numeric `funds_usd` against it
  (`$35.8M` → 35800000, `$474.3K` → 474300, `$1.2B` → 1200000000; `N/A` and
  empty → no number, the row sorts last).
- **`chain`** — derived from the explorer domain of the address hyperlink, not
  from the project's marketing (table below). An unknown domain fails
  `validate` with the row referenced — extend the whitelist in `fetch.py`
  (single data table) only together with an RPC default and a test fixture.
- **`address`** — the address as shown; mixed-case must be a valid EIP-55
  checksum, lowercase is accepted and normalized internally.
- **`added_on`** — the "Added on" cell normalized to `YYYY-MM-DD`.
- **`description`** — verbatim; it usually names the contract's role.
- **`source_url`** — the program page you are reading; `platform` — e.g.
  `immunefi`.

## Domain → chain whitelist (v1)

| Domain | Chain | chainid |
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
eraVM) are excluded — a solc recompile can never match there.

## Selection strategy

- "Recently added to audit" → `select --min-added-on <today-30d>` (or your
  window) over the transcribed rows.
- "Large funds at risk" → `select --sort funds --top N` / `--min-funds`.
- Both → combine the flags; the CLI's sort is deterministic (missing funds
  last, stable by id).
- De-duplicate across programs by `(chain, address)` before writing the file
  (validate rejects duplicates within one file; the same address legitimately
  appears on two chains).

## Other platforms

The same transcription applies to any platform that lists per-asset funds and
addresses (hats.finance, HackenProof asset pages, contest repos that publish
in-scope addresses). Record `platform` accordingly; only Immunefi's layout is
codified here because it is the worked example. New platforms = new
transcription guidance here, never CLI scraping.
