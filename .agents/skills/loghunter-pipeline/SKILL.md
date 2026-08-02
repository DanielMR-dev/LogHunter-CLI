---
name: loghunter-pipeline
description: Run the LogHunter multi-agent development pipeline from orchestrator-owned planning through implementation, review, correction, and verified delivery. Use for features, bug fixes, refactors, tests, packaging, CI, or public behavior changes.
license: MIT
metadata:
  project: loghunter-cli
  workflow: orchestrate-plan-implement-review
---

# LogHunter Multi-Agent Pipeline

Use this skill whenever a task changes source code, tests, fixtures, packaging, CI, documentation tied to behavior, or the public CLI contract.

The primary `loghunter-orchestrator` is also the project planner. Planning must remain inside the orchestrator's context and must not be delegated to a separate Planner agent.

## Pipeline

```text
Orchestrator: inspect and plan
  -> Developer: implement and verify
  -> Reviewer: audit
  -> Developer: fix critical/high findings when required
  -> Reviewer: re-audit
  -> Orchestrator: deliver verified outcome
```

## 1. Intake and classification

The Orchestrator must:

1. Read `AGENTS.md`.
2. Inspect the actual repository state.
3. Classify the task.
4. Identify the active milestone.
5. Define explicit non-goals.
6. Select only the relevant domain skills.
7. Resolve ambiguity in public behavior, detection semantics, file formats, or compatibility before implementation.

Do not begin implementation from a vague request.

## 2. Orchestrator planning phase

The Orchestrator creates the complete bounded plan directly.

The plan must include:

- Objective.
- Current state.
- Scope and non-goals.
- Contracts and invariants.
- File changes.
- Test-first sequence.
- Verification commands.
- Risks and mitigations.
- Completion criteria.

The Orchestrator must inspect relevant source, tests, fixtures, configuration, documentation, CLI behavior, and current diff before finalizing the plan.

Reject or refine plans that:

- Add unrelated features.
- Put business logic in `cli.py`.
- Combine parser, analyzer, detector, output, and export responsibilities.
- Skip malformed-input, negative, or boundary tests.
- Add dependencies without justification.
- Change public contracts without compatibility and documentation analysis.
- Depend on real production logs, network access, or the current clock.
- Introduce active response, shell execution, telemetry, or network lookups.

## 3. Developer invocation

Invoke `loghunter-developer` with:

- Original request.
- Complete orchestrator-authored plan.
- Current branch or diff context.
- Relevant skills.
- Exact verification commands.

Require the Developer to:

- Read `AGENTS.md`.
- Load only relevant skills.
- Write failing tests first for parser and detector changes.
- Implement the smallest complete change.
- Avoid unrelated refactors.
- Preserve public and architectural contracts.
- Run focused checks before the full relevant gate.
- Report exact command outcomes and blockers.

## 4. Reviewer invocation

Invoke `loghunter-reviewer` with:

- Original request.
- Orchestrator-authored plan.
- Complete diff or changed files.
- Developer verification report.

The Reviewer audits:

- Scope and plan compliance.
- Correctness.
- Untrusted-input safety.
- Regex behavior.
- Detection boundaries.
- Typing and architecture.
- CLI and export compatibility.
- Tests, fixtures, packaging, and documentation.

## 5. Correction loop

For every CRITICAL or HIGH finding:

1. Send the finding unchanged to the Developer.
2. Require a focused correction.
3. Require a regression test when behavior was incorrect.
4. Require relevant checks to run again.
5. Reinvoke the Reviewer with the corrected diff.

Do not deliver while CRITICAL or HIGH findings remain.

MEDIUM and LOW findings may remain only when they are outside scope, explicitly documented, and do not invalidate correctness, security, or public compatibility.

## 6. Verification matrix

Choose checks based on the change.

### Documentation only

```bash
git diff --check
```

### Python logic

```bash
uv run ruff format --check .
uv run ruff check .
uv run pyright
uv run pytest
```

### Parser work

```bash
uv run pytest tests/unit/test_parser.py
uv run pytest --cov=loghunter --cov-report=term-missing
```

### Detector work

```bash
uv run pytest tests/unit/test_detector.py
uv run pytest --cov=loghunter --cov-report=term-missing
```

### CLI or packaging

```bash
uv run pytest tests/test_cli.py
uv run loghunter --help
uv run loghunter --version
uv run python -m loghunter --help
uv build
```

Only report checks that were actually run.

## 7. Delivery format

The Orchestrator reports:

```markdown
## Outcome

## Changed files

## Behavior

## Tests

## Verification

## Reviewer verdict

## Remaining limitations
```

Keep the report concise, factual, and traceable to actual changes and command results.