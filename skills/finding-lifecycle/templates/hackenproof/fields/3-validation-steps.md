## How to run

(One short paragraph: the attached `<slug>-poc-bundle.zip` unzips to a
self-contained Foundry project — `src/`, the verified target source and
pinned dependencies are inside, no clone or install needed. The tests execute
the live deployed protocol on a fork pinned at block <N> (<ISO timestamp>).
State the RPC requirement up front, plus the one-line alternative:)

```
export <PROVIDER>_API_KEY=<key>
unzip <slug>-poc-bundle.zip && cd <project-dir>
./setup_and_run.sh     # equivalent: forge test --match-contract <ExactContractName> -vv
```

(Any archive endpoint serving state at block <N> works after a one-line edit
of the fork URL in `setUp`. `foundry.toml` pins solc <version> to match the
target build; forge downloads it on first run if missing.)

## Expected output

(Verbatim output of the pinned evidence run — every [PASS] line with its
named test and gas, and the per-suite result line. If the output is also
attached as a separate file, say so in one clause naming that attachment;)

```
Ran <N> tests for test/<PoC>.t.sol:<ContractName>
[PASS] test_<name_describing_the_scenario>() (gas: <gas>)
Suite result: ok. <N> passed; 0 failed; 0 skipped
```

(The attached project also passes from a fresh extraction of the archive,
with identical gas at the pinned fork block.)

## What each test proves

(Numbered, one per test, mapped to the states named in Vulnerability details.
One sentence each: the configuration the test builds, the call made, what is
asserted — nothing the test does not check.)

1. `test_<name>` — <what it sets up; which path it exercises; what it asserts>.
2. …

## Harness fidelity and test-only preparations

(List every test-only preparation explicitly and say why it is not a
production assumption: Foundry `deal` writes token-balance storage in the
fork (`forge-std/src/StdCheats.sol`); `vm.prank` voices a real on-chain role
read from the fork — it grants no key and no unprivileged way to acquire the
role; `vm.warp` sets the clock; any stand-in contracts in `src/mocks/` and
why no assertion depends on their internal accounting. State the evidence
boundary: report text governs; test comments may use broader shorthand.)

## Supporting on-chain evidence

(Optional, when on-chain reads back the claim — zero-event histories, registry
snapshots: name the evidence file in the attachment and what it shows.)
