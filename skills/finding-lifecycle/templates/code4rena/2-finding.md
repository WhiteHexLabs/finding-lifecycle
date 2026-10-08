(Opening paragraphs before the first header: the vulnerability itself.
Name the contract and its role, state the violated invariant in one
sentence, then the line-anchored code block of the faulty code. C4 judges
apply a burden-of-proof test — identification AND demonstration of the root
cause and of the MAXIMUM achievable impact; missing maximal impact yields
partial scoring or a downgrade, so state and prove the biggest loss the
path allows, not a representative one. No hand-wavy hypotheticals: assets =
funds, NFTs, data, authorization, private info.)

## Impact

(Numbered impacts, most specific first. Map to C4's severity definitions
directly: High = assets can be stolen/lost/compromised directly (or
indirectly with a valid attack path); Medium = value leaks or function/
availability is affected, but no direct asset loss. Note the platform caps:
unmatured-yield loss caps at Medium, dust losses are QA. Quantify from the
run.log — loss formula, real repetition bounds; unknown stays unknown.)

## Proof of Concept

(C4 requires a runnable, coded PoC for High/Medium by default (the contest
README can waive it). The PoC is built against the contest repo test suite:
which test file was added/modified, pasted here as a diff, then the exact
run command and the verbatim forge output from the evidence run. Every
assertion names itself; if the exploit demonstrates a revert condition, the
test prints the exact revert error string. One line on fidelity: fork pin
(block number/hash) and that no source contract was modified.)

```diff
(the test diff — attack steps numbered and commented // Attacker / Victim /
Protocol where the roles matter)
```

```bash
forge test --match-test test_exploit_<name> -vvv
```

```
(verbatim [PASS] lines with named assertions and gas, and the suite-result
line — copied from evidence/<id>/poc/run.log, never retyped)
```

## Recommended Mitigation Steps

(The concrete fix: a code sketch of the corrected check and why it holds
under the same storage/upgradeability constraints, plus the policy-level
fix when relevant, plus what a narrower fix would leave broken.)
