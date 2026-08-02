---
name: python-project-standards
description: Apply LogHunter's Python architecture, typing, dependency, packaging, error-handling, and code-quality standards. Use for any source-code or pyproject change.
license: MIT
metadata:
  project: loghunter-cli
  language: python
---

# Python Project Standards

## Supported runtime

- Python 3.12 through 3.14.
- Use syntax and standard-library APIs available in Python 3.12.
- Do not target beta or free-threaded-only behavior.

## Project management

Use `uv` for all operations:

```bash
uv sync --locked --dev
uv add PACKAGE
uv add --dev PACKAGE
uv run COMMAND
uv build
```

Commit `uv.lock` when dependency metadata changes.

## Package layout

```text
src/loghunter/
tests/
pyproject.toml
uv.lock
```

The distribution name is `loghunter-cli` and the import package is `loghunter`.

The console entry point remains:

```toml
[project.scripts]
loghunter = "loghunter.cli:run"
```

## Module boundaries

- `cli.py`: arguments, options, orchestration, error-to-exit translation.
- `models.py`: typed immutable contracts.
- `parser.py`: raw line to normalized event.
- `analyzer.py`: deterministic aggregations.
- `detector.py`: detection rules.
- `exporters.py`: serialization.
- `output.py`: terminal rendering.
- `exceptions.py`: expected application errors.
- `constants.py`: defaults and stable codes.

Do not create a generic `utils.py`. Put behavior in the module that owns the concept.

## Typing

- Annotate all public functions and methods.
- Prefer concrete domain types over `dict[str, Any]`.
- Avoid `Any`; when unavoidable, isolate and explain it.
- Prefer `Sequence[T]` for read-only inputs when list semantics are unnecessary.
- Prefer `Iterator[T]` or `Iterable[T]` for streaming APIs.
- Use `Path` for filesystem paths.
- Use `IPv4Address | IPv6Address` for validated addresses.
- Use `datetime` for timestamps.
- Use `StrEnum` for stable values.

## Domain models

Preferred pattern:

```python
from dataclasses import dataclass

@dataclass(frozen=True, slots=True)
class Example:
    value: str
```

Rules:

- Keep models immutable after construction.
- Avoid hidden I/O in model methods.
- Keep serialization separate from core models when possible.
- Use tuples for immutable final collections.

## Error handling

- Define expected application errors in `exceptions.py`.
- Translate standard-library errors at meaningful boundaries.
- Preserve cause chains:

```python
raise InputFileError(path) from error
```

- Do not use broad exception handling inside pure logic.
- A broad catch is acceptable only at the outer CLI boundary to map unexpected failures to a stable exit code.
- Expected user errors must not print a traceback by default.

## Dependency policy

Production dependencies are intentionally small:

- Typer.
- Rich.

Before adding another production dependency, document:

1. Required capability.
2. Why the standard library is insufficient.
3. Maintenance and security implications.
4. Package size and transitive dependencies.
5. Test strategy.

Do not add pandas, NumPy, Pydantic, SQLAlchemy, HTTP clients, or asynchronous frameworks without an accepted requirement.

## Code style

- Line length: 100.
- Double quotes through Ruff formatting.
- Descriptive names.
- Small focused functions.
- No mutable default arguments.
- No hidden global mutable state.
- Constants use uppercase names.
- Private helpers begin with `_`.
- Docstrings explain public contracts and non-obvious security decisions, not every line.

## Performance

- Process log files incrementally.
- Avoid retaining raw lines unless explicitly required.
- Use counters and bounded deques for aggregation.
- Avoid repeated regex compilation.
- Do not optimize without measurements, but do not introduce obvious whole-file memory growth.

## Required checks

```bash
uv run ruff format --check .
uv run ruff check .
uv run pyright
uv run pytest
```

When packaging changes:

```bash
uv build
uv run loghunter --help
uv run python -m loghunter --help
```