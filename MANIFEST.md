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

- `.agents/skills/loghunter-pipeline/SKILL.md`
- `.agents/skills/python-project-standards/SKILL.md`
- `.agents/skills/openssh-log-parsing/SKILL.md`
- `.agents/skills/detection-engineering/SKILL.md`
- `.agents/skills/cli-contract/SKILL.md`
- `.agents/skills/testing-quality/SKILL.md`
- `.agents/skills/security-review/SKILL.md`

## Installation

Copy the package contents into the root of the local LogHunter repository, review the diff, and commit on a dedicated documentation or tooling branch.

```bash
cp -a /path/to/loghunter-agentic-pack/. /home/danielmr-dev/Dev/LogHunter-CLI/
cd /home/danielmr-dev/Dev/LogHunter-CLI
git status
git diff -- README.md AGENTS.md opencode.json .opencode
```