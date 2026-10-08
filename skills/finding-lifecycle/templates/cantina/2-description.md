(The Description field: cause, effects, and the PoC/supporting material in
one document. All High and Medium submissions must carry a coded PoC that
compiles and demonstrates the impact — a PoC that fails to compile, does
not show the claimed impact, or rests on unrealistic assumptions is the
single most common cause of downgrade/invalidation on Cantina. Severity on
Cantina weighs Impact x Likelihood; speculative future-integration
findings are invalid. Select the matching Severity (and optionally
Likelihood/Impact ratings) in the form.)

## Root cause

(The defect against the verified source: a line-anchored code block of the
faulty check, then the invariant break as bullets with file:line anchors —
which side is maintained where, written by which function, and why nothing
cross-constrains them. State internal and external preconditions and who
can create each; close every escape hatch: each role/path that cannot fix
or bypass the condition and why.)

## PoC

(The coded PoC: which test file in the attached <slug>-poc.zip, the run
command against the audit branch, and the actual vs expected output shown
side by side —

```bash
forge test --match-test test_exploit_<name> -vvv
```

```
(verbatim output from evidence/<id>/poc/run.log: the [PASS] lines with
named assertions and the concrete before/after balances — never retyped)
```

Expected: <the invariant holds / the balances are unchanged>; Actual:
<the measured loss, quantified>.)

## Impact

(Numbered impacts, most specific first, quantified from the run.log — loss
formula, funds-at-risk, repetition bounds. High impact = funds can be
lost; name the victim class ("who is left holding the loss"). Front-end-
fixable user errors are informational; do not inflate them.)
