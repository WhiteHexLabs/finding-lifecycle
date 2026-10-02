# Finding <N> - <the one-line title from fields/1-title.txt>

(The full standalone write-up: the exact body of fields/2-vulnerability-
details.md — the **Severity.** / **Location.** / **Type:** lead and the
## Root cause / ## Precondition / ## PoC / ## Impact / ## Fix sections,
unchanged — followed by the Reproduction section below. This file is
hash-bound as a material: whenever the details field changes, regenerate
this copy.)

## Reproduction

(One short paragraph: the attached `<slug>-poc-bundle.zip` is a
self-contained Foundry project. After `unzip <slug>-poc-bundle.zip && cd
<project-dir>`, run `forge test -vv`. All <N> tests pass on solc <version>;
the captured output is `forge-test-output.txt` — the step-by-step mapping
lives in the Validation steps field.)
