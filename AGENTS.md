# AGENTS.md — LogHunter CLI Project Intelligence

This file is the canonical project reference for AI agents and human contributors working on LogHunter CLI. It defines the current state, target architecture, non-negotiable rules, verification commands, and agentic workflow.

Agents must read this file before planning, implementing, reviewing, or documenting changes.

## 1. Project identity

LogHunter CLI is a local, offline-first Python command-line application for analyzing OpenSSH authentication logs and detecting suspicious authentication behavior.

Primary users:

- SOC analysts and trainees.
- Blue Team practitioners.
- Linux administrators.
- Developers learning typed Python and security engineering.

Primary technical goals:

- Parse untrusted OpenSSH authentication records safely.
- Normalize supported records into immutable domain objects.
- Compute deterministic statistics.
- Detect repeated failures using bounded time windows.
- Present and export reproducible results.

## 2. Current repository state

At the time this file is introduced, the project foundation exists:

```text
src/loghunter/
├── __init__.py
├── __main__.py
└── cli.py
```

Current behavior:

- `loghunter --help`
- `loghunter --version`
- `python -m loghunter`

Current tooling:

- Python `>=3.12,<3.15`
- uv
- Typer
- Rich
- pytest
- pytest-cov
- Ruff
- Pyright strict mode
- uv build backend

Do not claim parser, analyzer, detector, or export functionality is implemented until the corresponding code and tests exist.

## 3. Product boundaries

### In scope for 1.0

- Local regular files containing OpenSSH authentication logs.
- Streaming line-by-line processing.
- Traditional syslog-style timestamps with an explicit or inferred year.
- Failed password events.
- Invalid-user events.
- Accepted password and public-key events.
- IPv4 and IPv6 source addresses.
- Summary statistics.
- Top source addresses.
- Sliding-window brute-force findings.
- JSON and CSV output.
- Parser validation metrics.
- Stable exit codes.

### Out of scope for 1.0

- Live endpoint agents.
- Automatic firewall changes.
- IP blocking.
- Network calls or threat-intelligence enrichment.
- SIEM ingestion.
- Packet capture analysis.
- Machine learning.
- Arbitrary code plugins.
- Web or desktop interfaces.
- Windows Event Log parsing.
- Apache, Nginx, firewall, or cloud-provider formats.

Any proposal that expands scope must explain why it belongs to the active milestone. Otherwise defer it to the roadmap.

## 4. Architecture

The project uses a small layered design.

```text
Typer CLI
   |
   v
Input validation and orchestration
   |
   v
OpenSSH parser
   |
   v
AuthEvent domain stream
   |
   +------------------+
   |                  |
   v                  v
Analyzer           Detector
   |                  |
   +---------+--------+
             |
             v
      Summary and findings
             |
      +------+------+
      |             |
      v             v
Rich output     JSON/CSV export
```

Planned modules:

| Module | Responsibility |
|---|---|
| `cli.py` | Commands, arguments, options, expected error translation |
| `models.py` | Immutable dataclasses, enums, result contracts |
| `parser.py` | Parse one line and stream files into normalized events |
| `analyzer.py` | Counts, grouping, rankings, time ranges, coverage |
| `detector.py` | Sliding windows, findings, severity, duplicate suppression |
| `exporters.py` | Stable JSON and CSV schemas |
| `output.py` | Rich tables, summaries, warnings, no-color behavior |
| `exceptions.py` | Expected application exceptions |
| `constants.py` | Defaults, exit codes, supported formats |

### Dependency direction

Allowed direction:

```text
cli -> parser/analyzer/detector/exporters/output
parser/analyzer/detector/exporters -> models
output -> models
models -> standard library only
```

Forbidden direction examples:

- `models` importing Typer or Rich.
- `parser` rendering terminal output.
- `detector` reading files directly.
- `exporters` reparsing raw log lines.
- `cli` containing regular expressions or detection algorithms.

## 5. Domain model rules

Domain models should use the standard library unless a clearly justified requirement cannot be met.

Preferred patterns:

- `@dataclass(frozen=True, slots=True)` for immutable records.
- `StrEnum` for stable string-valued enums.
- `datetime` for timestamps.
- `IPv4Address | IPv6Address` for source addresses.
- Tuples for immutable collections in final findings.
- Explicit `None` for absent optional data.

Public data contracts must be typed. Avoid dictionaries with undocumented arbitrary keys inside the domain layer.

## 6. OpenSSH parser contract

The parser treats every input line as untrusted.

A single-line parser should have a contract equivalent to:

```python
def parse_line(line: str, *, line_number: int, year: int) -> AuthEvent | None:
    ...
```

Rules:

1. Return a normalized event for supported lines.
2. Return `None` for unsupported lines.
3. Raise a documented application error only when the caller supplied invalid configuration, not for ordinary unmatched text.
4. Preserve the input line number for traceability.
5. Validate source addresses with `ipaddress.ip_address`.
6. Validate ports as integers in the range 1-65535 when present.
7. Never execute, import, or evaluate data found in a log line.
8. Avoid regex designs with nested ambiguous repetition.
9. Compile stable regex patterns once at module import time.
10. Add a positive, variation, and negative test for every supported shape.

Target event families:

```text
Failed password for USER from IP port PORT ssh2
Failed password for invalid user USER from IP port PORT ssh2
Invalid user USER from IP port PORT
Accepted password for USER from IP port PORT ssh2
Accepted publickey for USER from IP port PORT ssh2
```

Traditional syslog records omit the year. The caller supplies a year or uses a documented inference policy. Reports must record when the year was inferred.

## 7. File-processing rules

- Read input incrementally.
- Do not use `Path.read_text()` for potentially large logs.
- Open text files explicitly with a documented encoding and error policy.
- Do not modify the source file.
- Do not follow application-controlled shell commands or subprocesses.
- Report missing, unreadable, empty, and non-file paths using expected errors.
- Use `tmp_path` in tests rather than machine-specific paths.
- Never read real system authentication logs during automated tests.

## 8. Analysis contract

The analyzer operates on normalized events, not raw lines.

Minimum summary fields:

- Total lines.
- Parsed lines.
- Ignored lines.
- Parser coverage percentage.
- Failed logins.
- Successful logins.
- Invalid-user events.
- Unique source addresses.
- First observed event.
- Last observed event.
- Number of findings.

Ordering must be deterministic. Rankings require explicit tie-breaking.

Recommended top-source tie-break order:

1. Descending failed-attempt count.
2. Descending last-seen timestamp.
3. Ascending normalized IP text.

## 9. Detection contract

The first detector identifies repeated failures from one source address within a time window.

Default configuration:

```text
threshold = 5
window_seconds = 60
```

Algorithm requirements:

- Group by normalized source address.
- Process timestamps in chronological order or explicitly sort a bounded collection before detection.
- Use a deque or equivalent sliding-window structure.
- Remove events older than the configured window.
- Do not combine different source addresses.
- Define boundary behavior in tests.
- Suppress duplicate findings for the same active sequence.
- Keep detection deterministic.

Severity policy for the initial milestone:

| Attempts in active window | Severity |
|---|---|
| At least threshold | Medium |
| At least two times threshold | High |
| At least three times threshold | Critical |

This is a LogHunter prioritization level, not CVSS.

## 10. CLI contract

The command-line interface uses Typer and Rich.

Planned commands:

```text
loghunter analyze PATH
loghunter top-ips PATH
loghunter validate PATH
loghunter export PATH
```

Global behavior:

- `--help` must remain fast and side-effect free.
- `--version` must read the installed package version.
- Expected user errors must not print tracebacks.
- Human output goes to the terminal through the presentation layer.
- Machine-readable output must remain stable and free of decorative text.
- `--no-color` must disable ANSI styling.
- `--fail-on-detection` must change the exit status only when explicitly requested.

Planned exit codes:

| Code | Meaning |
|---:|---|
| 0 | Successful execution |
| 1 | Finding detected with `--fail-on-detection` |
| 2 | Invalid CLI usage |
| 3 | Missing, invalid, or unreadable input path |
| 4 | No supported records recognized |
| 5 | Export failure |
| 10 | Unexpected internal failure |

Changing an established command, option, JSON field, CSV column, or exit code requires an explicit compatibility note.

## 11. Security rules

The following rules are non-negotiable:

- No `eval` or `exec`.
- No shell execution derived from log content.
- No automatic network access in analysis paths.
- No telemetry.
- No modification of source logs.
- No automatic response or blocking.
- No secrets committed to the repository.
- No test fixtures copied from private production logs.
- No raw traceback for expected failures.
- No unconstrained regex backtracking.
- No silent swallowing of unexpected exceptions.

Expected errors should be converted into concise user-facing messages. Unexpected failures may be chained internally while protecting sensitive path or environment details in normal output.

## 12. Python standards

- Support Python 3.12 through 3.14.
- Use modern type syntax supported by Python 3.12.
- All public functions require parameter and return annotations.
- Prefer pure functions for parser, analyzer, and detector logic.
- Avoid mutable default arguments.
- Avoid broad `except Exception` unless at the outer CLI boundary, where it must preserve diagnostic context and return a defined exit code.
- Use `pathlib.Path` instead of string path manipulation.
- Use `collections.Counter`, `defaultdict`, and `deque` where they improve clarity.
- Do not add dependencies for functionality available clearly in the standard library.
- Production dependency additions require a written justification.

## 13. Testing standards

Development for parser and detector behavior follows this sequence:

```text
Write failing test
  -> implement smallest correct behavior
  -> refactor without changing behavior
  -> run focused tests
  -> run full quality gate
```

Required test layers:

- Unit tests for models and pure logic.
- Parser tests for each supported record.
- Boundary tests for timestamps and thresholds.
- CLI tests with `CliRunner`.
- Export schema tests.
- At least one end-to-end file analysis test.

Required quality targets:

- Overall coverage at least 85 percent.
- Parser and detector coverage at least 90 percent.
- Strict Pyright success.
- Ruff format and lint success.
- No network-dependent tests.
- No tests that rely on the current clock unless the clock is injected or fixed.
- No tests that read the developer's actual `/var/log` files.

## 14. Verification commands

Use `uv` for every project command.

Focused development:

```bash
uv run pytest tests/unit/test_parser.py
uv run pytest tests/unit/test_detector.py
uv run ruff check src tests
uv run pyright
```

Full local gate:

```bash
uv sync --locked --dev
uv run ruff format --check .
uv run ruff check .
uv run pyright
uv run pytest --cov=loghunter --cov-report=term-missing
uv build
```

Package smoke test:

```bash
uv run loghunter --help
uv run loghunter --version
uv run python -m loghunter --help
```

Agents must report which commands were actually run. Never claim a check passed when it was not executed.

## 15. Git workflow

Branch prefixes:

```text
feat/
fix/
test/
docs/
refactor/
chore/
ci/
```

Commit format:

```text
type(scope): imperative summary
```

Examples:

```text
feat(parser): parse failed password events
fix(detector): handle exact window boundary
test(export): verify deterministic JSON schema
docs(readme): clarify current project status
ci: test supported Python versions
```

Rules:

- One coherent concern per commit.
- No unrelated formatting or refactors.
- Do not commit `.venv`, caches, coverage artifacts, build outputs, secrets, or private logs.
- Update `uv.lock` when dependency metadata changes.
- Public behavior changes require tests and documentation.

## 16. Definition of done

A task is complete only when:

1. The implementation matches the orchestrator-authored plan.
2. Tests cover success, failure, and relevant boundaries.
3. Ruff format passes.
4. Ruff lint passes.
5. Pyright strict mode passes.
6. Relevant pytest tests pass.
7. Full tests pass when feasible.
8. Build succeeds when packaging is affected.
9. Documentation reflects user-visible changes.
10. The reviewer reports no unresolved critical or high findings.
11. Changed files and commands run are reported accurately.

## 17. Agentic workflow

The project uses three OpenCode agents. The primary Orchestrator also owns architecture inspection and planning:

```text
loghunter-orchestrator
├── loghunter-developer
└── loghunter-reviewer
```

Standard pipeline:

1. Orchestrator reads this file, inspects the actual repository, classifies the request, and creates a bounded plan.
2. Developer loads applicable skills, writes tests first, implements the orchestrator-authored plan, and runs checks.
3. Reviewer audits the diff for correctness, security, typing, tests, compatibility, and scope.
4. Critical or high findings return to Developer.
5. Reviewer rechecks fixes.
6. Orchestrator reports the final state without claiming unrun checks.

Agents must load only the skills relevant to the task. They must not perform broad repository rewrites when a focused change is sufficient.

## 18. Skills map

| Task | Required skill |
|---|---|
| Any multi-agent implementation | `loghunter-pipeline` |
| Python modules, typing, dependencies | `python-project-standards` |
| OpenSSH parsing | `openssh-log-parsing` |
| Brute-force or correlation logic | `detection-engineering` |
| Typer commands, output, exit codes | `cli-contract` |
| Tests, coverage, CI, packaging checks | `testing-quality` |
| Input safety or security audit | `security-review` |

## 19. Output discipline for agents

Plans should include:

- Scope.
- Files to inspect or change.
- Contracts and invariants.
- Test cases.
- Verification commands.
- Explicit non-goals.

Implementation reports should include:

- Changed files.
- Important behavior decisions.
- Commands run and exact results.
- Remaining blockers or limitations.

Reviews should include:

- Severity.
- File and line or symbol.
- Why the issue matters.
- Minimal correction.
- Approval status.

Do not produce filler, repeat the entire request, or invent repository state.