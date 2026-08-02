---
name: openssh-log-parsing
description: Design, implement, and review safe OpenSSH authentication-log parsing for LogHunter, including syslog timestamps, IPv4/IPv6, invalid users, malformed records, and parser coverage.
license: MIT
metadata:
  project: loghunter-cli
  domain: openssh-logs
---

# OpenSSH Log Parsing

## Scope

The first parser supports traditional syslog-style OpenSSH authentication messages.

Target families:

```text
Jul 30 18:14:22 server01 sshd[4128]: Failed password for root from 192.168.1.50 port 54321 ssh2
Jul 30 18:15:03 server01 sshd[4132]: Failed password for invalid user administrator from 192.168.1.50 port 54322 ssh2
Jul 30 18:15:02 server01 sshd[4132]: Invalid user administrator from 192.168.1.50 port 54322
Jul 30 18:20:15 server01 sshd[4200]: Accepted password for daniel from 192.168.1.25 port 50930 ssh2
Jul 30 18:20:15 server01 sshd[4200]: Accepted publickey for daniel from 2001:db8::25 port 50931 ssh2
```

Do not generalize to unrelated daemons or arbitrary formats during this milestone.

## Parser layers

Prefer two conceptual stages:

1. Parse the common syslog envelope:
   - Month.
   - Day.
   - Time.
   - Hostname.
   - Service.
   - Optional PID.
   - Message body.
2. Parse supported OpenSSH message bodies.

This keeps timestamp and host parsing separate from event-specific patterns.

## Contract

A single-line parser should return:

```python
AuthEvent | None
```

Return `None` when:

- The line is unrelated.
- The event is not yet supported.
- A malformed line cannot be normalized safely.

Do not crash the full file analysis for an ordinary unmatched line.

Invalid caller configuration, such as an impossible year, may raise a documented application error.

## Timestamp rules

Traditional syslog timestamps omit a year.

- Accept the year from the caller.
- Validate the year before processing.
- Build a timezone-naive timestamp unless the input contains an explicit zone and a future contract supports it.
- Record whether the year was inferred at the report layer.
- Do not silently guess cross-year rollover in the first implementation.
- Add tests for single-digit days and leap-day validity when relevant.

## Address and port validation

Use:

```python
ipaddress.ip_address(value)
```

Do not validate addresses only with regex.

Port rules:

- Parse as integer.
- Accept 1 through 65535.
- Treat invalid values as unmatched or malformed according to the agreed parser contract.

## Username handling

- Preserve the username text captured from supported messages.
- Distinguish an invalid-user event from a failure for an existing user.
- Do not normalize case unless a product requirement defines it.
- Do not execute or interpolate usernames into shell commands.
- Include tests for hyphens, underscores, dots, and unexpected whitespace where supported by the pattern.

## Regex safety

- Compile patterns once at module import time.
- Anchor patterns where practical.
- Avoid nested ambiguous quantifiers such as `(.*)+`.
- Prefer explicit tokens and non-greedy bounded groups.
- Never build regex source directly from log content.
- Keep patterns readable through named groups.
- Benchmark or stress-test unusually permissive patterns.

## File streaming

Recommended shape:

```python
def iter_events(path: Path, *, year: int) -> Iterator[AuthEvent]:
    ...
```

The file layer should also account for:

- Total lines.
- Parsed lines.
- Ignored lines.
- Optional bounded samples of ignored lines.

Do not retain every ignored raw line.

## Required tests per event family

1. Canonical supported line.
2. Valid variation.
3. IPv4 or IPv6 as applicable.
4. Malformed source address.
5. Invalid or missing port.
6. Unrelated service.
7. Truncated input.
8. Empty line.
9. Stable line number.
10. Correct event type and authentication method.

## Negative behavior

Unknown lines:

- Do not produce fabricated fields.
- Do not default unknown IPs to a placeholder address.
- Do not default missing users to an empty string when `None` is the contract.
- Do not emit terminal output from the parser.

## Review checklist

- [ ] Common envelope and event message concerns are separated.
- [ ] Stable patterns are compiled once.
- [ ] IPs use `ipaddress` validation.
- [ ] Ports are range checked.
- [ ] Unsupported lines return `None`.
- [ ] Year behavior is explicit.
- [ ] IPv4 and IPv6 are tested.
- [ ] Malformed and unrelated lines are tested.
- [ ] No unsafe regex construction exists.
- [ ] No real private logs are committed.