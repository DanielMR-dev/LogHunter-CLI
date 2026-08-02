---
name: security-review
description: Audit LogHunter for untrusted-log handling, regex denial of service, unsafe path behavior, command execution, information disclosure, dependency risk, and defensive-only scope.
license: MIT
metadata:
  project: loghunter-cli
  domain: application-security
---

# Security Review

## Threat model

LogHunter processes attacker-influenced text from authentication logs. A malicious record may contain:

- Extremely long fields.
- Unexpected Unicode.
- Invalid IP addresses.
- Oversized numeric values.
- Crafted text intended to trigger expensive regex behavior.
- Terminal control sequences.
- Misleading usernames or hostnames.

Input files and output paths may also be invalid, inaccessible, or intentionally confusing.

## Non-negotiable rules

- No `eval`.
- No `exec`.
- No dynamic import from input.
- No shell command built from log data.
- No subprocess execution in the core analyzer.
- No automatic firewall or account changes.
- No network enrichment in the offline analysis path.
- No telemetry.
- No modification of source logs.
- No secrets or private production logs in fixtures.

## Regex denial-of-service review

Inspect every regex for:

- Nested quantifiers.
- Ambiguous `.*` followed by overlapping alternatives.
- Repetition around optional groups.
- Patterns built dynamically from input.
- Missing anchors where the format is known.
- Unbounded capture of fields that can be tokenized explicitly.

Prefer named groups and explicit separators.

Stable patterns should be compiled once.

Where a pattern remains permissive, add a test with a long non-matching line and measure that execution remains reasonable.

## Terminal safety

Log fields may contain escape sequences.

- Do not render untrusted content as Rich markup unless escaped or markup is disabled for that value.
- Avoid allowing log text to alter terminal formatting.
- Limit or truncate raw ignored-line samples.
- Use textual labels in addition to color.

## Path safety

- Use `Path`.
- Validate that input is a regular file.
- Handle symlink policy explicitly if it becomes security relevant.
- Do not overwrite output without an accepted policy.
- Avoid exposing unnecessary absolute paths in ordinary errors.
- Preserve useful diagnostic context internally.
- Never delete or modify the input file.

## Resource exhaustion

Review:

- Whole-file reads.
- Retention of every raw line.
- Unbounded ignored-line samples.
- Per-source state that never expires.
- Extremely large usernames or hostnames retained in findings.
- Repeated sorting of large collections.

Prefer streaming, bounded deques, bounded samples, and explicit truncation in presentation.

## Parsing integrity

- Validate IPs with `ipaddress`.
- Range-check ports.
- Reject impossible timestamps.
- Do not fabricate values when fields are absent.
- Keep unsupported input distinct from valid events.
- Preserve line numbers for traceability.

## Error handling

Expected failures:

- Missing file.
- Permission denied.
- Empty file.
- Unsupported records.
- Invalid configuration.
- Export path failure.

These should produce concise messages and stable exit codes, not raw tracebacks.

Unexpected failures must not be swallowed. A debug mode may expose chained diagnostics, but normal output should avoid leaking environment details unnecessarily.

## Dependency review

For every new production dependency verify:

- It is necessary.
- It is maintained.
- Its transitive footprint is acceptable.
- It does not add network behavior unexpectedly.
- It is pinned through the lockfile.
- The security benefit outweighs added attack surface.

## Defensive scope

Reject changes that turn LogHunter into:

- A credential attack tool.
- An evasion tool.
- An automatic blocking or retaliation system.
- A data-exfiltration mechanism.
- A remote collection agent without an explicit new product decision.

## Required security tests

- Long unrelated line.
- Escape-sequence-containing username or hostname presentation.
- Invalid IP and port.
- Truncated input.
- Unreadable file.
- Output path failure.
- No traceback for expected errors.
- Bounded ignored-line samples.
- No network calls in standard tests.

## Review output

Security findings must state:

- Severity.
- Exploitable or failure scenario.
- Exact code location.
- Minimal safe correction.
- Regression test required.