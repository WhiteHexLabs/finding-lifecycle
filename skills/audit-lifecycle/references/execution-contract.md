# Execution contract — prompts, boundaries, result declaration

What the orchestrator imposes on each audit step, and what each step must
hand back. The audit skill's own `SKILL.md` always governs **how to audit**;
this contract governs **how execution results are handed back**.

## Execution prompt (overlay, not a replacement)

At PREPARE every step gets `audits/<run-id>/steps/<N>/execution-prompt.md`,
regenerated on recovery for the next pending step. It is local run metadata
and may contain absolute paths. The executing session must:

1. read the selected audit skill's `SKILL.md`;
2. obey its audit methodology;
3. also obey the generated execution contract below.

The prompt contains at least: run id, step number, audit skill path, target
root, scope, preferred work directory, the required primary report
contract, the result contract, the artifact declaration contract, the
target-modification prohibition, and instructions for fixed-output skills.

## Boundaries per step (owned by the orchestrator)

- target root and scope (fingerprinted before and after execution)
- step number and run id
- preferred work directory: `audits/<run-id>/steps/<N>/work/`
- required primary artifact: one `report` (log recommended)
- permitted artifact declaration format (see below)
- prohibition on modifying target source
- expected output contract (result.yaml)

## Output modes

- **Configurable output directory** — if the skill supports `--output-dir`,
  `--work-dir`, `--report-dir`, an env var or a prompted workspace, direct
  it at the preferred work directory.
- **Fixed/native output directory** — do not break the skill to force
  relocation. Run it normally, then declare the actual output paths in
  `result.yaml`; `record` freezes copies into the canonical step
  directory and the original location becomes disposable.

## Result discovery policy

The CLI never performs filesystem discovery. Resolution order:

1. explicit configured work/output directory (`steps/<N>/work/`);
2. explicit output paths observed during execution ("Report written to …"),
   recorded by the executing agent in `result.yaml`;
3. restricted fallback — only if the output location genuinely cannot be
   determined, the agent may look inside `steps/<N>/work/`, the skill's
   documented output directory, and the execution current directory.

The agent — never the CLI — selects and declares the primary report.
**Ambiguity BLOCKs the step** (record BLOCKED with a note naming the
candidates); the CLI must not guess which arbitrary Markdown file is the
report. Never scan `/`, `$HOME` recursively, unrelated repositories or
previous runs.

## result.yaml (Skill → Orchestrator interface)

```yaml
schema: whitehexlabs.audit-result/v1
status: COMPLETED            # COMPLETED | FAILED | BLOCKED
note: >-                     # substantive (>= 20 chars): what ran, covered, why
  ...
primary:
  report: <path>             # required for COMPLETED; the ONE primary report
  log: <path>                # recommended
artifacts:
  - path: <file or directory>
    type: report|log|findings|poc|trace|coverage|subagent-results|analysis|other
    note: ...
```

The legacy flat shape is still accepted and normalized internally:

```yaml
status: COMPLETED
note: ...
report: <path>
log: <path>
```

Validation on `record`: strict key sets; status enum; note substance;
`primary.report` required for COMPLETED (zero findings still need the real
report); declared paths exist, are not inside the audited target, contain
no symlinks, and carry no key/credential material. Unknown artifact types
are rejected — use `type: other`.
