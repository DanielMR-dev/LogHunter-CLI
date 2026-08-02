---
name: detection-engineering
description: Implement and review deterministic LogHunter detection rules, especially source-based sliding-window brute-force detection, severity assignment, duplicate suppression, and boundary tests.
license: MIT
metadata:
  project: loghunter-cli
  domain: detection
---

# Detection Engineering

## Initial rule

Detect repeated failed OpenSSH authentication events from the same source address within a configured window.

Defaults:

```text
threshold = 5
window_seconds = 60
```

## Inputs

The detector consumes normalized authentication events. It must not parse raw log lines or open files.

Only relevant failed events participate in the initial rule. Successful logins and unrelated event types do not increment the failure window unless a later accepted rule defines that behavior.

## Sliding-window algorithm

For each source address:

1. Process events in chronological order.
2. Maintain a deque of relevant timestamps.
3. Add the current timestamp.
4. Remove timestamps outside the active window.
5. Compare the remaining count with the threshold.
6. Emit or update a finding according to duplicate-suppression policy.

Define the boundary explicitly.

Recommended first contract:

```text
current_timestamp - oldest_timestamp <= window
```

Under that contract, events exactly 60 seconds apart remain in a 60-second window. Tests must lock this behavior.

## Configuration validation

Reject:

- Threshold less than 1.
- Window less than 1 second.
- Unsupported event sets when the public API requires a specific model.

Use a documented application error or constructor validation. Do not silently replace invalid values with defaults.

## Grouping

- Group by normalized IP address objects or their canonical text.
- Never combine IPv4 and IPv6 values.
- Never combine different addresses.
- Track targeted usernames separately within each finding.

## Severity

Initial policy:

| Count | Severity |
|---|---|
| `threshold <= count < 2 * threshold` | Medium |
| `2 * threshold <= count < 3 * threshold` | High |
| `count >= 3 * threshold` | Critical |

The finding must make clear that this is LogHunter severity, not CVSS.

## Duplicate suppression

The implementation must define when repeated qualifying events create:

- One evolving finding.
- Multiple findings for distinct bursts.

For the first version, prefer one finding per source and active sequence rather than emitting a new duplicate on every event after the threshold.

A new sequence may begin after the active window is empty or after a clearly documented cooldown rule.

Do not invent a cooldown without tests and documentation.

## Determinism

- Sort events by timestamp when input order is not guaranteed.
- Define tie behavior for identical timestamps.
- Sort targeted users in output.
- Sort findings by severity, count, timestamp, and address using documented keys.
- Keep JSON and CSV output stable across runs.

## Memory

For streaming detection:

- Keep only timestamps inside each active window.
- Remove inactive address state when safe.
- Do not retain raw log lines.

For an initial bounded event collection, document the memory trade-off.

## Required tests

- Four failures in 60 seconds with threshold five: no finding.
- Five failures in 60 seconds: finding.
- Five failures exactly on the boundary: behavior matches the contract.
- Five failures outside the boundary: no finding.
- Two source addresses: independent windows.
- IPv4 and IPv6: independent and valid.
- Ten failures: High.
- Fifteen failures: Critical.
- Duplicate qualifying events: no unintended duplicate findings.
- Unsorted events: deterministic result if supported.
- Successful events: do not increment the initial rule.
- Invalid threshold and window: rejected.

## Review checklist

- [ ] Detector consumes normalized events only.
- [ ] Boundary semantics are documented and tested.
- [ ] Sources are isolated.
- [ ] Duplicate policy is explicit.
- [ ] Severity transitions are tested.
- [ ] Ordering is deterministic.
- [ ] State is bounded by the active window where practical.
- [ ] No automatic response action exists.