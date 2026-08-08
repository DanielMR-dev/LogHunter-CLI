---
name: analysis-engine
description: Design, implement, and review the single-pass loghunter analysis engine, including aggregation counts, deterministic sorting, source tracking, username tracking, and domain model generation.
---

# Analysis Engine Skill

When working on the LogHunter analysis engine (`src/loghunter/analyzer.py` and related analyzer tests/models), apply these rules:

1. **Single Pass:** The analyzer must consume the event stream in a single pass (`O(n)` with `O(s + u)` memory footprint for `s` unique sources and `u` unique users).
2. **Deterministic Rankings:** Always tie-break explicitly.
   - For `SourceStats`: Sort descending by `failed_logins`, then descending by `last_observed` timestamp, then ascending by canonical IP string.
   - For `UsernameStats`: Sort ascending by username.
3. **Immutability:** Produce an immutable `AnalysisSummary` populated with immutable `SourceStats` and `UsernameStats`.
4. **No Layer Leakage:** The analyzer must NOT read files, perform detection (no sliding windows here), run regexes, call the CLI, or format terminal output.
5. **Exact Counting semantics:**
   - A standalone `INVALID_USER` event increments `invalid_user_events`.
   - A `LOGIN_FAILED` event (even if it's for an invalid user) increments `failed_logins` but DOES NOT increment `invalid_user_events`.
   - Both password and public key successes increment `successful_logins`.
6. **Invariants validation:** The `AnalysisSummary` model MUST validate that global counts match the sum of component counts in `SourceStats` and `UsernameStats`.
