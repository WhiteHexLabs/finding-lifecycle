(CodeHawks marks a report insufficient when "a judge needs to invest
additional time in research or coding to verify the claims" — every section
below must be self-sufficient. Gas, QA and informational submissions are
not accepted; Low findings are consolidated into one separate report per
auditor and do not use this template.)

## Summary

(2-4 sentences: the contract's role, the violated invariant in one
sentence, the trigger, and who is left holding the loss.)

## Vulnerability Details

(The exact defect against the verified source: a line-anchored code block
of the faulty check, then each precondition as a bullet — internal state
first, then external/market conditions, each with who can create it.
Impact x Likelihood drives the severity on CodeHawks: state both sides
explicitly so the community judge can fill the matrix without guessing.
Close every escape hatch: each role/path that cannot fix or bypass the
condition and why.)

## Impact

(Numbered impacts, most specific first, quantified from the run.log — loss
formula, repetition bounds, funds-at-risk amount. High impact = funds
directly or nearly directly at risk or severe protocol disruption; Medium =
funds indirectly at risk with functional disruption; Low = no funds at
risk but incorrect behavior.)

## Tools Used

(Short list — e.g. Foundry fork tests at the pinned block, manual source
review. No narration.)

## Recommended Mitigation

(The concrete fix: code sketch of the corrected check, why it fits the
storage/upgradeability constraints, and what a narrower fix would leave
broken. Attach or inline the PoC test here — CodeHawks expects an
executable test with line-by-line comments and explicit actors marked
// Attacker: / // Victim: / // Protocol:; when a test is genuinely
impractical, replace it with the exploit scenario written as Initial State
-> numbered steps -> Outcome -> Implications.)
