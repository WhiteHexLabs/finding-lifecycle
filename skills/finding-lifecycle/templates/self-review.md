# Self-review — <finding id>

Independent review of the FROZEN package. The reviewer must come from an
independent session or agent, receives the package and the rules, and does NOT
see the author's pre-filled answers. This document is produced by the reviewer.

- Package reviewed: <path> sha256 <0x…> (must equal the final package zip hash)
- Reviewer: <identity> (<independent_session | independent_agent>)
- Date: <iso>

## Rerun

- Performed from the frozen package in a clean directory: yes/no
- Result: PASS/FAIL; log saved at: <path>

## Amounts audit

Every number in the report traced back to run artifacts:

| Report claim | Artifact & line | Agreement |
|--------------|-----------------|-----------|
| (e.g. profit 123 USDC) | run.log:ProfitWithdrawn | yes/no |

Discrepancies:

## Preconditions audit

Each precondition re-checked for realistic availability; cheatcode usage
re-examined (would a real attacker have this power?).

## Wording audit

Claims that overstate the evidence, hedged or missing limitations, terminology
mismatches with the program rules. List the required changes.

## Adverse facts check

Are the adverse facts from the assessment reflected honestly in the report?

## Triage-readiness

Anticipated triager objections and the prepared answers:

- Q: <likely objection> — A: <answer with evidence reference>

## Unresolved objections

MUST be empty to pass the SELF_REVIEWED gate. Anything unresolved goes to
blockers instead.
