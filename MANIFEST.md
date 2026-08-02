# LogHunter Agentic Pack Manifest

This package contains project documentation and OpenCode configuration for LogHunter CLI.

## Root files

- `README.md`: professional public-facing project documentation.
- `AGENTS.md`: canonical project intelligence and engineering rules.
- `opencode.json`: project-level OpenCode instruction and skill configuration.

## Agents

The Orchestrator also performs repository inspection and implementation planning.

- `.opencode/agents/loghunter-orchestrator.md`
- `.opencode/agents/loghunter-developer.md`
- `.opencode/agents/loghunter-reviewer.md`

## Skills

- `.opencode/skills/loghunter-pipeline/SKILL.md`
- `.opencode/skills/python-project-standards/SKILL.md`
- `.opencode/skills/openssh-log-parsing/SKILL.md`
- `.opencode/skills/detection-engineering/SKILL.md`
- `.opencode/skills/cli-contract/SKILL.md`
- `.opencode/skills/testing-quality/SKILL.md`
- `.opencode/skills/security-review/SKILL.md`

## Commands

- `.opencode/commands/feature.md`
- `.opencode/commands/bugfix.md`
- `.opencode/commands/review.md`
- `.opencode/commands/verify.md`

## Installation

Copy the package contents into the root of the local LogHunter repository, review the diff, and commit on a dedicated documentation or tooling branch.

```bash
cp -a /path/to/loghunter-agentic-pack/. /home/danielmr-dev/Dev/LogHunter-CLI/
cd /home/danielmr-dev/Dev/LogHunter-CLI
git status
git diff -- README.md AGENTS.md opencode.json .opencode
```