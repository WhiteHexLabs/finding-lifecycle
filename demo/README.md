# Demo — controlled local-chain exercise

Implements plan.md §5: "另用受控测试合约在本地链上构造成功与反证样例,验证完整流程".
This validates the **workflow** end to end; it does not replace mainnet fork
forensics on a real target (that trial happens when onboarding the first real
program).

## Contents

| File | Role |
|---|---|
| `src/VulnerableVault.sol` | deliberately vulnerable target (withdraw sends before clearing state), seeded with 10 ETH victim funds |
| `src/GuardedVault.sol` | hardened variant (CEI + reentrancy guard) — the refutation target |
| `src/Attacker.sol` | reentrancy attacker shared by both PoCs |
| `test/ExploitVault.t.sol` | success PoC; named assertion `ProfitWithdrawn` |
| `test/RefuteGuarded.t.sol` | refutation PoC; states `RESULT: REFUTED` + the blocking mechanism |
| `script/Deploy.s.sol` | deploys both targets with victim seed on the local chain |
| `drive.py` | driver: anvil → deploy → pin block → run PoCs on the pinned fork → walk the lifecycle CLI through all eight gates |

## Run

```bash
python3 demo/drive.py                 # case root defaults to demo/run/case
python3 demo/drive.py --case-root /tmp/my-case --rpc-port 8645
```

Requires Foundry (`forge`, `anvil`, `cast`). The pinned `forge-std` is
installed on first run (`--no-git`, no submodule). Everything the driver does
is the real procedure: real chain, real pinned fork, real CLI gates — no mocks.

Expected outcome:

- finding A (`Reentrancy in VulnerableVault…`) advances
  DISCOVERED → … → SUBMITTED, including a clean-directory run of the frozen
  package (report + vendored deps + zip + manifest);
- finding B (`Claimed reentrancy in GuardedVault…`) closes **REFUTED** with
  fork counter-evidence (profit zero, funds intact) and an explicit conclusion
  boundary — the same attack that drains A is *completed* on B and shown to
  extract nothing, rather than merely reverting.

`demo/run/` holds generated artifacts (case root, logs, anvil output) and is
gitignored.
