---
name: cli-contract
description: Design and review LogHunter Typer commands, options, Rich presentation, stdout/stderr behavior, no-color support, machine output, exit codes, and compatibility.
license: MIT
metadata:
  project: loghunter-cli
  interface: cli
---

# CLI Contract

## Principles

The CLI must be:

- Predictable.
- Scriptable.
- Accessible without color.
- Clear for expected user errors.
- Stable once a command is released.
- Thin over application logic.

## Current root contract

```bash
loghunter --help
loghunter --version
python -m loghunter --help
```

These commands must remain fast and side-effect free.

## Planned commands

```text
loghunter analyze PATH
loghunter top-ips PATH
loghunter validate PATH
loghunter export PATH
```

Do not expose a command until its behavior and tests are complete.

## Thin command handlers

Command functions may:

- Receive Typer arguments and options.
- Validate simple option relationships.
- Call application functions.
- Catch expected application exceptions.
- Select terminal or machine output.
- Exit with a defined code.

Command functions must not:

- Contain regex patterns.
- Parse log lines.
- Implement sliding windows.
- Build summary statistics.
- Reimplement serializers.

## Output streams

Use stdout for:

- Successful human-readable results.
- Machine-readable JSON or CSV when explicitly requested on stdout.
- Version output.

Use stderr for:

- Expected errors.
- Warnings that must not corrupt machine-readable stdout.
- Diagnostic information in verbose or debug modes.

## Rich output

- Keep Rich rendering inside `output.py` or dedicated presentation helpers.
- Respect `--no-color`.
- Do not use decorative terminal output in JSON or CSV.
- Avoid relying on color alone to convey severity.
- Include textual severity labels.
- Keep tables usable in narrow terminals where practical.

## Exit codes

Target contract:

| Code | Meaning |
|---:|---|
| 0 | Success |
| 1 | Detection found when `--fail-on-detection` is active |
| 2 | Invalid CLI usage |
| 3 | Invalid or unreadable input |
| 4 | No supported records recognized |
| 5 | Export failure |
| 10 | Unexpected internal failure |

Do not use exit code 1 for ordinary findings unless the user explicitly requests automation failure behavior.

## Option validation

Validate:

- `--threshold >= 1`.
- `--window >= 1`.
- `--top >= 1`.
- Year belongs to an accepted range.
- Export format is supported.
- Output path rules are explicit.

Prefer Typer validation for simple values and application errors for domain validation.

## File behavior

- Input must exist and be a regular readable file.
- Output files must not overwrite existing data silently unless an explicit force policy is accepted.
- Parent directory errors must be clear.
- Source input must never be modified.

## Compatibility

A public CLI change includes:

- Command names.
- Argument positions.
- Option names and defaults.
- Exit codes.
- stdout/stderr behavior.
- JSON keys.
- CSV columns.

Such changes require tests and documentation.

## Required CLI tests

- Root help.
- Version.
- No arguments behavior.
- Missing input path.
- Directory passed as input.
- Empty file.
- Invalid numeric options.
- No supported records.
- Detection with and without `--fail-on-detection`.
- `--no-color` output.
- JSON or CSV output not contaminated by decorative text.
- Export failure mapping.

Use Typer's `CliRunner` for command tests and `tmp_path` for files.

## Review checklist

- [ ] CLI handlers remain thin.
- [ ] Expected errors avoid tracebacks.
- [ ] stdout and stderr are appropriate.
- [ ] Exit codes match the contract.
- [ ] Machine output is clean.
- [ ] `--no-color` is tested.
- [ ] Public changes are documented.