---
# Canonical ledger shape, shown for reference. `register` generates the real
# file; state changes go through the CLI only. Field semantics: references/contracts.md
id: F-00000000000000000000000000000000
title: (one-line claim; IDs never encode severity)
program_id: example-program
created_at: "2026-01-01T00:00:00+00:00"
updated_at: "2026-01-01T00:00:00+00:00"
stage: DISCOVERED          # last passed stage
disposition: OPEN          # closure outcome, independent of stage
revision: 1                # bumped by every CLI write; equals len(history)

sources:                   # traceable origin of the claim
  auditor: (who found it)
  original_finding_id: (their id)
  audit_round: (scan/round name)
  files:                   # copies preserved under evidence/<id>/sources/
    - path: evidence/<id>/sources/original.md
      sha256: (64-hex)
      note: (what this document is)

targets: []                # filled at CROSS_CHECKED: chain/address/proxy/impl/block/code hash

root_cause:
  claim: (single sentence holding on the real deployments)
  variants: []             # related code paths sharing the root cause

duplicate_of: null         # set by close --disposition MERGED

severity:
  candidate: (auditor's level, if any)
  final: null              # set at TRIAGED; must equal the matrix entry level
  matrix_entry: null        # severity_matrix id in program.yaml
  justification: null       # must cite a recorded evidence path

program_snapshot:
  sha256: null             # frozen rules snapshot hash at TRIAGED
  checked_at: null

prior_art: null            # set at PRIOR_ART_CHECKED: {checked_at, conclusion, discovery[], reports[]}

evidence: []               # {path, sha256, purpose, produced_by, recorded_at}
gates: []                  # {id, stage, status, at, reviewer, reason, inputs[]}

blockers: []               # {item, next_step, raised_at, resolved_at}

submission:                # filled by `record submission`; gates SUBMITTED
  platform_id: null
  submitted_at: null
  channel: null            # {kind, detail, privacy_check}
  package_sha256: null
  receipt: null            # {path, sha256}
  account_limits: null
  kyc: null
  response: null           # {decision, evidence, sha256, at, reason}

appeal:                    # NONE -> DRAFTED -> SENT -> RESOLVED
  status: NONE
  deadline: null
  materials: []
  sent_receipt: null
  outcome: null

history: []                # append-only; one event per revision
---

# (title)

## Claim

(What is asserted, on which deployments, under which preconditions.)

## Preconditions

| controller | realistically reachable? | cost | duration | how the fork satisfies it | exclusion reference |
|-----------|--------------------------|------|----------|---------------------------|---------------------|
| (e.g. none / LP / governance) | | | | | |

## Refutation attempts

(Each attempt to break the claim and its outcome. "Attack script reverted" alone
is NOT sufficient refutation — name the blocking mechanism.)

## Impact

(Victim damage and attacker profit stated separately; unknown components stay
"unknown", never zero.)

## Evidence log

(The frontmatter `evidence` list is authoritative; narrate here what each
artifact proves.)

## Next steps

(Immediate next actions and blockers.)
