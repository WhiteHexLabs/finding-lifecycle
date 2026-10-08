(The Audit Item issue body. The four headers below are the house contract —
the live contest's Audit Item template wins if it differs; keep every
required section when adapting. Three Sherlock judging rules shape this
document: (1) every code reference must be a commit-pinned permalink —
branch links are treated as attempts to alter source under the judge; (2)
likelihood is NOT considered — argue severity purely through loss size and
constraints; (3) admins are trusted and README invariants beat code
comments — do not submit admin-misuse or design-choice findings.)

## Issue

(The defect as a permalink-anchored walkthrough: one sentence on the
contract's role, the violated invariant, then the pinned code block with
github.com/<org>/<repo>/blob/<commit>/…#L… anchors. Enumerate EVERY
trigger condition as a bullet — internal state, external/market
conditions, timing windows; a report whose trigger list is incomplete can
be invalidated when the judge finds a missing constraint. Note front-
running claims: on chains with private mempools the issue must work via
unintentional front-running or it downgrades High to Medium.)

## Impact

(The loss stated against Sherlock's bars: High = direct loss of funds
without extensive external conditions (users lose >1% and >$10 of
principal/yield, or protocol loses >1% and >$10 of fees; a replayable
small loss aggregates); Medium = loss requires specific external
conditions or is highly constrained, OR core contract functionality breaks
without direct loss. Funds locked >1 week or time-sensitive functions
disrupted = Medium; both = High. Quantify from the run.log; unknown stays
unknown.)

## Attack path

(Numbered steps with concrete actors and amounts: 1. attacker does X with
N tokens; 2. state changes to Y; …; final step names who is left holding
the loss. Each step that touches contract code carries its permalink.)

## PoC

(The PoC inline as a Foundry test (inline PoC code is acceptable on
Sherlock) or a pointer to the attached <slug>-poc.zip with the run command
and verbatim output from the evidence run. A report without a PoC is
considered invalid if the issue cannot be clearly understood without one —
default to including it.)
