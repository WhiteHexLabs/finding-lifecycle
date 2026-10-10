# Platform standards — formats, PoC bars, and what gets reports rejected

Normative companion to workflow §5 (platform materials) and §7 (submit) for
every `delivery.platform` value. Researched against the platforms' own docs
(October 2026); the live program/contest page always overrides this file —
record divergences in the case root. Sources per platform are listed at the
end.

Two things every platform shares, stated once:

- **Duplicates are judged by root cause.** Fixing the root cause (in a
  reasonable manner) must make the reported exploit impossible — that is
  the grouping rule on every platform below. Our PRIOR_ART_CHECKED /
  MERGED machinery encodes the same rule: one root cause, one report.
  Never split one root cause into multiple submissions (HackenProof closes
  every split with reputation penalties).
- **Local fork testing only.** Immunefi v2.3 prohibits testing on mainnet
  or public testnets, testing pricing oracles or third-party contracts,
  and DoS attacks; every other platform assumes the same posture. All PoC
  work happens on pinned local forks (`evidence/<id>/poc/`), never against
  live deployments.

## Severity vocabulary per platform

Internal severity is program-defined (`program.yaml severity_matrix`,
levels copied verbatim from the program/contest rules). The platform
columns are the individual-submission levels `export` enforces
(`severity_levels` in `scripts/lifecycle.py MATERIAL_SPECS`):

| platform | individual levels | consolidated (outside export) | notes |
|---|---|---|---|
| immunefi | Critical/High/Medium/Low | — | v2.3 impact tables; no platform-wide coded-PoC mandate but direct-loss demonstration expected |
| hackenproof | Critical/High/Medium/Low | — | PoC mandatory at submission; Dual Defence pays Critical only; mislabeled severity costs reputation |
| code4rena | high/medium | QA (one report), Gas (one report) | coded PoC required for H/M by default (README can waive; signal ≥ 0.4 exempt) |
| codehawks | high/medium | low (one report) | Gas/QA/Informational not accepted since 2023-08 |
| sherlock | high/medium | QA (one report) | issue label Medium/High IS the severity claim |
| cantina | critical/high/medium/low | — | coded PoC hard-required for H/M (rep ≥ 80 exempt); Impact × Likelihood |

Export refuses a `severity.final` outside the platform's individual set
(e.g. a QA-level finding on code4rena) with a pointer here: consolidated
reports are assembled by hand from the TRIAGED findings the export README
lists under "Not exported this run". The consolidated-report model (one
markdown doc per warden, numbered L-01…/C-01…/QA entries) is a deliberate
boundary of this version.

## Immunefi (`delivery.platform: immunefi`)

- **Mechanics:** private dashboard web form, one report per finding;
  program listings flag "PoC required", KYC, Safe Harbor per program.
- **Materials:** `immunefi/{1-title.txt, 2-description.txt, 3-poc.txt}`
  (templates/immunefi/); `package.zip` attached privately.
- **Report shape:** Title / Vulnerability details / Attack scenario / PoC /
  Impact / Mitigation — the three-file kit encodes this; anchor Impact
  wording in the program's own impact table (v2.3: Critical = direct theft
  of user funds, permanent freezing; High = theft/freezing of unclaimed
  yield, royalties, temporary freezing of funds; Medium = griefing, gas
  theft, block stuffing; Low = promised returns not delivered).
- **PoC bar:** demonstrate the direct, realistic loss — findings needing
  elevated privileges or unusual user interaction get downgraded or
  rejected; hand-waving impact is the top rejection cause.
- **After submission:** triage (program or Immunefi) → escalation per the
  Responsible Publication Policy (publication generally permitted if
  unresolved 90 days after escalation + 21-day notice) → `record response`
  / `record appeal`. Disclosure per program setting, usually post-fix.
- **Commonly burned by:** default exclusions ignored (oracle data errors,
  Sybil, phishing-based impact, missing headers without demonstrated
  impact); automated-scan output; misreading the frozen/unclaimed-yield
  line that separates Critical from High.

## HackenProof (`delivery.platform: hackenproof`)

- **Mechanics:** web form; mandatory sections Overview / Description / POC
  / Recommendation.
- **Materials:** `hackenproof/fields/{1..4}` + `submission.md`
  (templates/hackenproof/); the supporting-files field's `Upload:` line
  names `<slug>-poc-bundle.zip`.
- **PoC bar:** working PoC at submission time — "POCs submitted later via
  comments will not be accepted"; submissions without one are closed and
  cost reputation points. Only the originally reported issue counts.
- **After submission:** first validation ~2 h; severity triage; duplicates
  by root cause close extra reports with reputation penalties; payout on
  acceptance. Dual Defence programs pay Critical only.
- **Commonly burned by:** severity overstatement (a Medium labeled
  Critical can be closed without reward); late PoCs in comments; splitting
  one root cause.

## Code4rena (`delivery.platform: code4rena`)

- **Mechanics:** website submission form; each High/Medium finding is an
  individual submission; all Low-risk + Governance/Centralization items go
  into ONE consolidated QA report (graded A/B/C, top 3 paid); Gas is a
  separate consolidated report. Short edit/withdraw window after
  submitting.
- **Materials:** `code4rena/{1-title.txt, 2-finding.md}`
  (templates/code4rena/); `2-finding.md` must carry `## Impact`,
  `## Proof of Concept`, `## Recommended Mitigation Steps` (+ optional
  `## Tools Used` / `## Assessed type` appended after them).
- **PoC bar:** runnable coded PoC required for H/M by default (contest
  README can waive; signal ≥ 0.4 exempt), built against the contest repo
  test suite as a diff; a reverting PoC must print the exact revert error.
  Burden of proof: demonstrate root cause AND maximum achievable impact —
  missing maximal impact means partial credit or downgrade.
- **Severity:** High = assets (funds/NFTs/data/authorization/private info)
  stolen or compromised directly, or indirectly via a valid attack path,
  free of hypotheticals; Medium = value leaks or function/availability
  affected with hypothetical-but-stated assumptions. Caps: unmatured-yield
  loss ≤ Medium; dust and unused-view-function issues are QA.
- **After submission:** judging (validity + quality) → duplicate grouping
  by root cause → post-judging QA (PJQA) public challenge window → report
  published. Repeated low-quality/spam submissions can invalidate ALL of a
  warden's findings.
- **Commonly burned by:** skipping the coded PoC; overstated severity
  (quality penalty); non-standard tokens (out of scope unless the contest
  supports them, USDT excepted); approve front-running (informational).

## Sherlock (`delivery.platform: sherlock`)

Note: Sherlock migrated contests to the Audit Engine; classic-contest
judging rules below still define submission quality. Check the live
contest's Audit Item template — the house headers (`## Issue`, `## Impact`,
`## Attack path`, `## PoC`) are our completeness floor, not a claim about
the live template.

- **Mechanics:** one GitHub Issue per finding in your private contest repo,
  labeled Medium or High; QA items go into one separate QA report.
- **Materials:** `sherlock/{1-title.txt, 2-issue-body.md}`
  (templates/sherlock/); `<slug>-poc.zip` referenced from the body (inline
  PoC code also acceptable).
- **Hard rule enforced by the gate:** every `github.com` code reference in
  the issue body must be a commit-pinned permalink
  (`github.com/<org>/<repo>/blob/<40-hex>/…#L…`) — branch links read as
  attempts to alter source under the judge. Enforced at the PACKAGED gate
  and re-checked by `lint` (`sections`).
- **PoC bar:** a report without a PoC is invalid "if the issue cannot be
  clearly understood without one" — complex paths, non-trivial input
  constraints, precision loss, reentrancy, revert-related attacks: include
  it. Enumerate ALL trigger conditions.
- **Severity:** likelihood explicitly NOT considered. High = direct loss
  without extensive external conditions (>1% and >$10 for users, or
  replayable small loss aggregated); Medium = constrained loss or core
  functionality breaking; funds locked >1 week or time-sensitive functions
  disrupted = Medium, both = High. Invalid-list: zero-address checks, event
  values, admin misconfiguration (admins trusted by default), stale-price
  recommendations (pull-based oracles like Pyth excepted), accidental
  direct transfers. README invariants beat code comments.
- **After submission:** real-time judging + dedup → Lead Judge phase →
  24-hour escalation window (escalations cost Signal Score; invalid
  escalations waste it) → final judgments. Fix review by a Lead Senior
  Watson; payout ~2 weeks.
- **Commonly burned by:** non-permalink references; missing trigger
  conditions; admin-trust/design-decision submissions; front-running
  claims not shown to work via unintentional front-running (High→Medium on
  private-mempool chains).

## Cantina (`delivery.platform: cantina`)

- **Mechanics:** web form — Severity (dropdown), optional Likelihood/Impact
  ratings, Title, Description (+ structured template option).
- **Materials:** `cantina/{1-title.txt, 2-description.md}`
  (templates/cantina/); `2-description.md` must carry `## Root cause`,
  `## PoC`, `## Impact`.
- **PoC bar:** H/M submissions MUST carry a coded PoC that compiles and
  demonstrates the impact, submitted before the competition ends (rep ≥ 80
  and dedicated researchers exempt). State the test file, confirm it runs
  on the audit branch, contrast actual vs expected output. "Incorrect PoC"
  → downgrade or invalidation.
- **Severity:** Impact × Likelihood; High impact = funds can be lost, High
  likelihood = any participant can trigger. Caps: admin-only ≤ Low;
  weird-ERC20 and rounding/dust ≤ Low; approval race conditions invalid;
  front-end-fixable user errors informational.
- **After submission:** judge dedup (root cause + Medium impact + valid
  attack path) → preliminary → final decisions; escalations possible but
  invalid escalations carry penalties. Unvalidated AI-generated finding
  dumps risk disqualification or a permanent ban.
- **Commonly burned by:** H/M without a compiling, impact-demonstrating
  PoC; speculative future-integration findings; re-escalating without new
  arguments.

## CodeHawks (`delivery.platform: codehawks`)

- **Mechanics:** web form; template verbatim `## Summary / ## Vulnerability
  Details / ## Impact / ## Tools Used / ## Recommended Mitigation`; M/H
  individual, all Lows consolidated into one report per auditor.
- **Materials:** `codehawks/{1-title.txt, 2-finding.md}`
  (templates/codehawks/).
- **PoC bar:** reports lack sufficient proof "when a judge needs to invest
  additional time in research or coding to verify the claims" —
  self-validate before submitting. Expected form: a working, executable
  test with line-by-line comments and explicit Actors (Attacker / Victim /
  Protocol), or — when genuinely impractical — an exploit scenario written
  as Initial State → steps → Outcome → Implications. Computationally
  infeasible claims (key guessing etc.) must be proven feasible by the
  submitter.
- **Severity:** Impact × Likelihood (High = funds directly/nearly directly
  at risk or severe disruption; Medium = indirect risk + disruption; Low =
  no funds at risk, incorrect behavior). Gas/QA/Informational not accepted
  since 2023-08.
- **After submission:** Cyfrin judging + community judging phases; public
  leaderboard; disqualification for plagiarism/spam; findings disclosed
  after resolution.
- **Commonly burned by:** bundling M/H into one report; missing coded PoC;
  infeasible-attack claims.

## Documented, no material spec (use `delivery.platform: other`)

- **Remedy (r.xyz):** web form — Assets, Severity (RVSS calculator, a
  CVSS-style score), Title, rich-text Markdown content, ≤5 attachments.
  PoC must be working executable code ("screenshots of code are not
  acceptable"), mainnet-fork based, with dependencies/env documented, each
  attack step printed, and a funds-at-risk assessment (tokens × price at
  submission). No public testnet/mainnet testing; no post-submit edits.
- **Hats Finance:** on-chain vault submissions (the tx fee is the spam
  filter); per-vault committee adjudication; Low/Medium/High template
  (no Critical tier), protocol-configured.

## PoC enhancement playbook (applies to every platform)

The PoC artifact itself lives at `evidence/<id>/poc/` (workflow §4) and is
frozen into `packages/<id>/poc/`; every submission-facing PoC section below
is EXTRACTED from its `run.log` — never retyped, never "expected".

1. **Sketch before code.** Before writing `Exploit.t.sol`, write the
   exploit sketch (borrowed from the security-auditor convention; keep it
   in `evidence/<id>/` as design notes for the fork-proof): `attacker`
   (profile + real powers), `capabilities`, `preconditions` (internal +
   external; `None` = strongest), `tx_sequence` (one line per call with
   concrete args), `state_deltas` (which storage moves where),
   `broken_invariant`, `numeric_example` (concrete numbers end to end),
   `same_fix_test` (the single change that would kill the exploit — the
   dedup anchor). A sketch that cannot fill every field is a LEAD, not a
   finding.
2. **Named actors.** Mark roles in the test and the report — `// Attacker:`
   / `// Victim:` / `// Protocol:` (CodeHawks judges look for this
   verbatim); "no attacker at all" is a valid answer — then name the
   honest actors whose documented job triggers the condition.
3. **Numbers, twice.** Log before/after balances with concrete amounts and
   the funds-at-risk figure (tokens × price at the pin, source stated);
   unknown stays unknown. Every assertion names itself in the log.
4. **Actual vs expected.** State both, side by side (Cantina requires it
   explicitly); a reverting-path PoC prints the exact revert error string
   (C4).
5. **Fidelity statement.** One line per report: fork pin (block + hash +
   timestamp), no source contract modified, every cheatcode justified
   (`vm.prank` voices real on-chain roles; `deal` only writes balances the
   participant already holds) — this is the `3-poc.txt` Threat-modeled
   discipline, reused by all templates.
6. **Fork-only, always.** Pinned local fork against the live deployment's
   runtime bytecode; never mainnet, never public testnets (Immunefi v2.3
   prohibited activities; Remedy hard rule).

## Report enhancement playbook (applies to every platform)

1. **Root cause + maximal impact, both demonstrated** (C4 burden of proof,
   mirrored by every judge): show the missing-or-wrong operation AND the
   largest loss the path allows — partial credit otherwise.
2. **Trigger conditions fully enumerated** (Sherlock): each internal state
   requirement, external/market condition, and timing window, with who can
   create each; a judge finding a missing constraint can invalidate.
3. **Impact wording anchored in the program's own tables** (Immunefi v2.3
   most literally): quote the in-scope impact text and map to it; keep
   severity claims at the narrowed impact actually proven.
4. **Trust boundaries stated, not assumed**: admins trusted (Sherlock/
   Cantina cap or invalidate admin-only findings), default exclusions
   (oracles, Sybil, non-standard tokens, front-running) checked against
   the contest README before the go/no-go call.
5. **SELF_REVIEWED round check:** re-read the report against this file's
   per-platform "Commonly burned by" list — that is the cheapest rejection
   insurance in the loop.

## Sources

- Immunefi: Severity Classification v2.3 (immunefi.com), bug-report
  guidance, reports.immunefi.com.
- HackenProof: General Guidelines (docs.hackenproof.com).
- Code4rena: Submission guidelines, Judging criteria, Severity
  categorization (docs.code4rena.com).
- Sherlock: Watsons, Judging, Criteria for Issue Validity
  (docs.sherlock.xyz, contest-era pages referenced by the Audit Engine
  docs).
- Cantina: Submission guidelines, Severity, Judging (docs.cantina.security).
- CodeHawks: How to Write and Submit a Finding, PoC and Severity guides
  (docs.codehawks.com).
- Remedy: Bug Submitting, How to Write a PoC, RVSS (r-xyz.gitbook.io).
- Hats Finance: Evaluating the Severity of Submissions (docs.hats.finance).
