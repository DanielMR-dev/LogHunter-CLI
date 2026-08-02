---
name: testing-quality
description: Apply LogHunter test-first development, pytest structure, coverage targets, Ruff, Pyright, build checks, deterministic fixtures, and CI expectations.
license: MIT
compatibility: opencode
metadata:
  project: loghunter-cli
  quality: testing-ci
---

# Testing and Quality

## Test-first rule

Parser and detector changes follow:

```text
Failing test
  -> minimal implementation
  -> refactor
  -> focused verification
  -> full verification
```

A behavior-changing patch without a regression or feature test is incomplete unless the behavior cannot reasonably be automated and the limitation is documented.

## Test structure

Recommended layout:

```text
tests/
├── conftest.py
├── fixtures/
│   └── logs/
├── unit/
│   ├── test_models.py
│   ├── test_parser.py
│   ├── test_analyzer.py
│   ├── test_detector.py
│   └── test_exporters.py
├── integration/
│   ├── test_analyze_command.py
│   ├── test_validate_command.py
│   └── test_export_command.py
└── test_cli.py
```

Use the smallest appropriate layer. Pure parser logic belongs in unit tests; complete command behavior belongs in integration tests.

## Fixtures

- Use synthetic log records.
- Never commit real private authentication logs.
- Keep each fixture focused.
- Prefer inline strings for one-line parser cases.
- Use fixture files for multi-line and end-to-end scenarios.
- Use `tmp_path` for temporary input and output files.

## Determinism

Tests must not depend on:

- Network access.
- The developer's real system logs.
- Local timezone unless explicitly fixed.
- The current year unless injected.
- File iteration order.
- Random values without a fixed seed.
- Terminal width unless configured in the test.

## Parser tests

For every supported event family include:

- Canonical line.
- Valid variation.
- Malformed line.
- Unrelated line.
- IPv4 or IPv6.
- Correct line number.
- Correct enum and fields.

## Detector tests

Include:

- Below threshold.
- At threshold.
- Above threshold.
- Exact time boundary.
- Outside time boundary.
- Independent source addresses.
- Severity transitions.
- Duplicate suppression.
- Invalid configuration.

## CLI tests

Use:

```python
from typer.testing import CliRunner
```

Test:

- Exit code.
- stdout.
- stderr when relevant.
- Created files.
- Machine-readable output validity.
- Absence of tracebacks for expected errors.

## Coverage

Targets:

- Overall: at least 85 percent.
- Parser: at least 90 percent.
- Detector: at least 90 percent.

Coverage is a guardrail, not a replacement for meaningful boundary assertions.

## Static quality

Run:

```bash
uv run ruff format --check .
uv run ruff check .
uv run pyright
```

Do not silence rules broadly to make checks pass. Prefer a local, justified suppression when necessary.

## Test commands

Focused:

```bash
uv run pytest tests/unit/test_parser.py
uv run pytest tests/unit/test_detector.py
uv run pytest tests/test_cli.py
```

Full:

```bash
uv run pytest
uv run pytest --cov=loghunter --cov-report=term-missing
```

Packaging:

```bash
uv build
uv run loghunter --help
uv run python -m loghunter --help
```

## CI expectations

The eventual CI matrix should cover Python 3.12, 3.13, and 3.14.

Jobs should verify:

- Locked dependency installation.
- Ruff formatting.
- Ruff linting.
- Pyright strict mode.
- Pytest with coverage.
- Package build.
- Installed CLI smoke test.

## Review checklist

- [ ] New behavior has a failing-first test or clear regression test.
- [ ] Boundaries are asserted.
- [ ] Fixtures are synthetic.
- [ ] Tests are deterministic.
- [ ] Error behavior is tested.
- [ ] Public output is tested.
- [ ] Reported commands were actually run.