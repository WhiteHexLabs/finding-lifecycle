# Self-review — <finding id>

Independent review of the FROZEN package, run as a **bounded loop of rounds**
(workflow §6). Each round comes from an independent session or agent that
receives the package and the rules — never the author's draft answers. This
document describes the loop; the gate input is `evidence/<id>/self-review.yaml`
with the shape at the bottom.

## Loop rules

1. A round ends clean or the loop continues — termination is a round that
   raises zero required changes (`clean_round: true`), never "reviewed
   enough".
2. Round N+1 starts by **landing-verifying** round N: every fix the previous
   round declared is actually present in the loose documents *and* the zip,
   and `lifecycle.py lint --id <id>` passes. A declared-but-never-landed fix
   is the classic survivor.
3. No ✅ inheritance: each round re-derives line numbers, addresses and
   amounts from the sources. A previous round's checkmarks are not evidence.

Per round: rerun the package from a clean directory, audit every number
against run artifacts, re-check preconditions for realistic attacker powers,
re-justify every cheatcode, and list objections. Objections you decide not to
act on are recorded `kept_with_rationale` with the rationale — that is the
"raised but not changed" ledger the later rounds and any appeal can lean on.

Fixes between rounds run the fix-batch battery (workflow §6a): edit → lint
`--save-log` → `record correction` → next round landing-verifies.

## self-review.yaml shape

```yaml
reviewer: {identity: <session/agent id>, kind: independent_session|independent_agent}
package_sha256: 0x<final zip hash>
rounds:
  - round: 1
    date: <iso>
    landing_check: {of_round: null, result: N_A}
    objections:
      - {id: P1, verdict: kept_with_rationale, note: <why it stands, with evidence ref>}
      - {id: P2, verdict: fixed, note: <what was fixed>}
    clean_round: false
  - round: 2                      # starts with the round-1 landing check
    date: <iso>
    landing_check: {of_round: 1, result: PASS}
    objections: []
    clean_round: true              # final round must be clean
checks:                           # consolidated checks of the final state
  rerun: {performed: true, result: PASS, log_path: evidence/<id>/self-rerun.log}
  amounts: {status: VERIFIED, notes: <every number traced to an artifact>}
  preconditions: {status: VERIFIED, notes: <realistic attacker powers; cheatcodes re-justified>}
  wording: {changes: [...]}
adverse_facts: [...]              # stated honestly in the report
unresolved_objections: []         # must be empty; objections become blockers
```

(A flat legacy self-review without `rounds[]` still passes the gate as an
implicit single round; new reviews use the loop.)
