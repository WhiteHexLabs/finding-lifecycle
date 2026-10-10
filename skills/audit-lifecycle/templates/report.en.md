# <Short impact-oriented title>

**Program:** <program id / name>
**Severity claimed:** <LEVEL> (matrix entry <Sx>)
**Targets:** <chain id> <address(es), proxy -> implementation>
**Pinned block:** <number> (block hash 0x…)
**Report version:** <n> (each revision is a new frozen package; never edit a submitted package)

## Summary

Two to five sentences: what an attacker achieves, against whom, under which
preconditions, and the quantified impact. No dramatization; the triager reads
this first.

## Root cause

The exact defect: file, function, lines (against the verified source), and the
invariant that is violated. One report per root cause; related variants listed
explicitly.

## Preconditions

Every condition the attack relies on, each with its real-world availability:

| # | Precondition | Realistically available? | Evidence |
|---|--------------|--------------------------|----------|
| 1 | e.g. flashloan-sized capital | yes / no / cost bound | run log ref |

Attack paths that depend on powers an attacker cannot obtain (admin keys,
unrealistic oracle moves) must be labeled as such or removed.

## Attack path

Step-by-step transaction sequence from entry to exit, with the fork test that
reproduces each step.

## Impact

- Victim damage: <quantified, separately stated>
- Attacker profit: <gross proceeds, costs, gas; unknown components marked unknown>
- Scope of victims and realistic repetition bounds.

## Proof of concept

The attached package contains the self-contained PoC:

- `setup_and_run.sh` — pinned toolchain, declared prerequisites, terminates with
  `RESULT: PASS`.
- `test/Exploit.t.sol` — the attack test with named assertions
  (<AssertionName> must appear in the run log).
- `run.log` — the executed log from the pinned block.
- `manifest.yaml` — file list with hashes, dependency pins, clean-run record.

External prerequisites: (declared toolchain + archive RPC; nothing else).

## Limitations

What this PoC does NOT prove: variants not covered, costs not modeled,
assumptions that remain assumptions. State them plainly.

## Remediation (attachment, optional)

Suggested fix directions. This section is advisory only; no target code was
modified to produce any result in this report.
