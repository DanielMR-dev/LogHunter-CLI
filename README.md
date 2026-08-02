# LogHunter CLI

[![Python](https://img.shields.io/badge/Python-3.12--3.14-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Package manager](https://img.shields.io/badge/package%20manager-uv-261230)](https://docs.astral.sh/uv/)
[![CLI](https://img.shields.io/badge/CLI-Typer-009485)](https://typer.tiangolo.com/)
[![Terminal output](https://img.shields.io/badge/output-Rich-000000)](https://rich.readthedocs.io/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-pre--alpha-orange)](#project-status)

LogHunter CLI is a local, offline-first command-line tool for analyzing OpenSSH authentication logs and identifying suspicious authentication behavior.

The project is designed as a focused Python security engineering exercise with professional software-development standards. Its first stable release will parse OpenSSH authentication events, calculate useful operational statistics, identify possible brute-force activity, and export deterministic reports for further analysis.

LogHunter is intended for defensive security work, SOC training, Linux administration, incident triage, and reproducible analysis of authorized log data.

## Project status

LogHunter is currently in the foundation stage.

Implemented:

- Installable Python package using a `src/` layout.
- Command-line entry point named `loghunter`.
- `--help` and `--version` support.
- Dependency management and locking with `uv`.
- Static analysis with Ruff and Pyright.
- Test tooling with pytest and pytest-cov.
- Multi-agent OpenCode workflow definitions.

Planned for the first stable release:

- Streaming analysis of local OpenSSH authentication logs.
- Parsing of failed and successful SSH authentication events.
- IPv4 and IPv6 source-address support.
- Statistics grouped by source IP and username.
- Configurable brute-force detection using time windows and thresholds.
- JSON and CSV export.
- Parser validation and coverage reporting.
- Deterministic exit codes for local use and automation.

The README distinguishes implemented functionality from planned functionality so that the repository never presents unfinished capabilities as production-ready.

## Goals

LogHunter has four primary goals:

1. Provide a small, understandable OpenSSH log-analysis tool.
2. Demonstrate modern, typed, tested Python development.
3. Apply defensive security concepts without modifying the analyzed system.
4. Create a maintainable foundation for future detection-engineering experiments.

## Non-goals

The initial project does not attempt to become a SIEM, an endpoint agent, an intrusion prevention system, or an automated response platform.

The first stable version will not:

- Block IP addresses.
- Change firewall rules.
- Modify analyzed logs.
- Execute shell commands based on log contents.
- Send logs to external services.
- Perform threat-intelligence lookups.
- Analyze packet captures.
- Support arbitrary log formats through an unrestricted plugin system.
- Use machine learning or generative AI for detections.

Keeping these boundaries explicit protects the learning objective and limits unnecessary complexity.

## Planned command-line interface

The following commands describe the target interface for the first stable release. Commands marked as planned may not yet be available on the current branch.

### Current commands

```bash
uv run loghunter --help
uv run loghunter --version
uv run python -m loghunter --help
```

### Planned: analyze a log file

```bash
loghunter analyze /var/log/auth.log --year 2026
```

Expected responsibilities:

- Validate the input path.
- Read the file incrementally.
- Parse supported OpenSSH authentication events.
- Calculate summary statistics.
- Detect suspicious failure sequences.
- Render a terminal report.

Planned options:

```text
--year INTEGER
--threshold INTEGER
--window INTEGER
--top INTEGER
--verbose
--no-color
--fail-on-detection
```

### Planned: list top source addresses

```bash
loghunter top-ips ./samples/auth_bruteforce.log --limit 10 --year 2026
```

### Planned: validate parser coverage

```bash
loghunter validate ./samples/auth_mixed.log --year 2026
```

### Planned: export results

```bash
loghunter export ./samples/auth_bruteforce.log \
  --format json \
  --output ./reports/loghunter-report.json \
  --year 2026
```

## Supported event scope

The first parser milestone is limited to OpenSSH authentication messages in traditional syslog-style records.

Target examples include:

```text
Jul 30 18:14:22 server01 sshd[4128]: Failed password for root from 192.168.1.50 port 54321 ssh2
Jul 30 18:15:03 server01 sshd[4132]: Failed password for invalid user administrator from 192.168.1.50 port 54322 ssh2
Jul 30 18:15:02 server01 sshd[4132]: Invalid user administrator from 192.168.1.50 port 54322
Jul 30 18:20:15 server01 sshd[4200]: Accepted publickey for daniel from 192.168.1.25 port 50931 ssh2
```

Unknown or unsupported lines must not terminate analysis. They will be counted as ignored input and may be surfaced through validation output.

Traditional syslog timestamps do not contain a year. LogHunter therefore plans to accept an explicit `--year` option and to document any inferred year in the resulting report.

## Planned detection model

The first detection rule identifies repeated authentication failures from the same source address within a configurable time window.

Default values:

```text
threshold: 5 failed attempts
window: 60 seconds
```

The detector will use a sliding-window algorithm per source IP. Events from different addresses will never be combined. Detection output will include the source address, event count, first and last observation, targeted users, and LogHunter severity.

This severity is a local classification for prioritization. It is not CVSS.

## Architecture

LogHunter follows a small, layered architecture that keeps parsing, analysis, detection, presentation, and export concerns independent.

```text
CLI arguments
     |
     v
Input validation
     |
     v
OpenSSH parser -----> ignored-line accounting
     |
     v
Normalized AuthEvent stream
     |
     +-------------> analysis engine
     |
     +-------------> detection engine
                         |
                         v
                findings and summary
                         |
              +----------+----------+
              |                     |
              v                     v
        Rich terminal output   JSON/CSV exporters
```

Planned module responsibilities:

```text
src/loghunter/
├── __init__.py       Package version
├── __main__.py       python -m loghunter entry point
├── cli.py            Typer commands and option handling
├── models.py         Immutable domain models and enums
├── parser.py         OpenSSH line parsing and normalization
├── analyzer.py       Statistics and aggregations
├── detector.py       Time-window detection logic
├── exporters.py      JSON and CSV serialization
├── output.py         Rich terminal presentation
├── exceptions.py     Expected application errors
└── constants.py      Stable defaults and exit codes
```

The CLI module must remain thin. It coordinates application services but must not contain regular expressions, detection algorithms, or export-format internals.

## Technology stack

| Area | Technology | Purpose |
|---|---|---|
| Runtime | Python 3.12-3.14 | Supported interpreter range |
| Project management | uv | Environments, dependencies, lockfile, builds |
| CLI | Typer | Typed commands, arguments, and options |
| Terminal output | Rich | Tables, panels, and readable diagnostics |
| Tests | pytest | Unit and integration testing |
| Coverage | pytest-cov | Branch and statement coverage |
| Linting and formatting | Ruff | Consistent style and static checks |
| Type checking | Pyright | Strict static typing |
| Packaging | uv build backend | Wheel and source distribution |

Production dependencies are intentionally limited. Core parsing, date handling, IP validation, JSON, CSV, collections, and filesystem operations should use the Python standard library where practical.

## Requirements

- Python 3.12, 3.13, or 3.14.
- `uv` installed.
- Git for source control.

## Installation for development

Clone the repository:

```bash
git clone https://github.com/DanielMR-dev/LogHunter-CLI.git
cd LogHunter-CLI
```

Install locked dependencies:

```bash
uv sync --dev
```

Verify the application:

```bash
uv run loghunter --help
uv run loghunter --version
```

## Install the local CLI

Install the current project as a local tool:

```bash
uv tool install .
```

Then run:

```bash
loghunter --help
```

To reinstall after local changes:

```bash
uv tool install --force .
```

## Development workflow

Create a branch from an updated `main`:

```bash
git switch main
git pull --ff-only
git switch -c feat/short-description
```

Run focused checks while developing:

```bash
uv run ruff format .
uv run ruff check .
uv run pyright
uv run pytest
```

Run the full verification gate before opening a pull request:

```bash
uv run ruff format --check .
uv run ruff check .
uv run pyright
uv run pytest --cov=loghunter --cov-report=term-missing
uv build
```

## Testing standards

The project uses test-first development for parsing and detection behavior.

Required test categories:

- Parser unit tests for every supported log shape.
- Negative tests for malformed and unrelated records.
- IPv4 and IPv6 cases.
- Boundary tests for time windows and thresholds.
- CLI tests using Typer's `CliRunner`.
- Export schema tests.
- End-to-end tests from file input to rendered or serialized result.

Quality targets:

- Overall coverage of at least 85 percent.
- Parser and detector coverage of at least 90 percent.
- Strict Pyright checks.
- No Ruff violations.
- Deterministic tests that do not depend on network access or the current machine's authentication logs.

## Security model

Log files are untrusted input.

The implementation must follow these rules:

- Never use `eval`, `exec`, or dynamic imports derived from input.
- Never pass log content to a shell.
- Never execute commands based on parsed values.
- Avoid regular expressions with unsafe catastrophic backtracking behavior.
- Validate IP addresses with the standard `ipaddress` module.
- Treat paths carefully and report permission errors without exposing unnecessary internals.
- Do not modify the source file.
- Do not perform network requests in the core analysis path.
- Do not collect telemetry.
- Do not print tracebacks for expected user errors unless an explicit debug mode is enabled.

Security issues should be reported according to [SECURITY.md](SECURITY.md) when that policy file is available.

## Agentic development with OpenCode

This repository includes project-specific instructions, agents, skills, and commands for a controlled agentic workflow.

```text
AGENTS.md
.opencode/
    └── agents/
        ├── loghunter-orchestrator.md
        ├── loghunter-developer.md
        └── loghunter-reviewer.md

.agents/
    └── skills/
        ├── loghunter-pipeline/
        ├── python-project-standards/
        ├── openssh-log-parsing/
        ├── detection-engineering/
        ├── cli-contract/
        ├── testing-quality/
        └── security-review/
```

The default workflow is:

```text
Request
  -> Orchestrator inspects the repository and creates a bounded implementation plan
  -> Developer implements tests and code
  -> Reviewer audits correctness, security, typing, and scope
  -> Developer fixes critical or high findings
  -> Reviewer verifies the corrected diff
  -> Orchestrator reports final checks and changed files
```

Read [AGENTS.md](AGENTS.md) for the canonical project rules.

## Roadmap

### 0.1.x: project foundation

- Package and CLI entry point.
- Quality tooling.
- Initial tests.
- Agentic development configuration.

### 0.2.x: OpenSSH parser

- Immutable authentication-event models.
- Failed password parsing.
- Invalid-user parsing.
- Successful password and public-key parsing.
- IPv4 and IPv6 support.
- Parser coverage reporting.

### 0.3.x: analysis engine

- Summary statistics.
- Grouping by source address and username.
- Top-source ranking.
- First-seen and last-seen timestamps.

### 0.4.x: detection engine

- Sliding-window brute-force detection.
- Configurable thresholds and windows.
- Deterministic severity assignment.
- Duplicate suppression.

### 0.5.x: CLI reports and exports

- `analyze` command.
- `top-ips` command.
- `validate` command.
- JSON and CSV export.
- Stable exit codes.

### 1.0.0: stable local analyzer

- Complete documented MVP.
- Cross-version CI.
- Build verification.
- Reproducible sample logs.
- Security and contribution policies.

## Contributing

Contributions should be small, scoped, tested, and documented.

Before opening a pull request:

1. Confirm the change belongs to the current milestone.
2. Add or update tests.
3. Run all quality gates.
4. Update documentation when behavior or public contracts change.
5. Avoid unrelated refactors.

Commit examples:

```text
feat(parser): parse failed password events
fix(detector): correct sliding-window boundary handling
test(cli): cover unreadable input file
docs(readme): document parser limitations
refactor(analyzer): extract source aggregation
ci: test Python 3.12 through 3.14
```

## Ethical use

LogHunter is intended for defensive analysis of systems and log files that the user owns or is authorized to investigate.

The software must not be presented as a tool for unauthorized access, credential attacks, evasion, or disruption. Detection examples and sample data should remain synthetic or explicitly authorized.

## License

LogHunter CLI is licensed under the MIT License. See [LICENSE](LICENSE) for details.