"""Core analysis engine for extracting intelligence from OpenSSH authentication events."""

from collections.abc import Iterable
from typing import Any

from loghunter.models import AnalysisSummary, AuthEvent, AuthEventType, ParseStats


def analyze_events(
    events: Iterable[AuthEvent],
    *,
    parse_stats: ParseStats,
) -> AnalysisSummary:
    """
    Produce a deterministic summary from a single-pass stream of authentication events.

    The function aggregates primary event counts, dynamically determines the
    first and last observed timestamps, and calculates source-address cardinality
    without modifying the input sequence or duplicating the underlying parser statistics.

    Args:
        events: A one-pass iterable yielding immutable AuthEvent instances.
        parse_stats: The exact statistics returned by the parser for this file block.

    Returns:
        An immutable AnalysisSummary containing mathematically validated aggregation.

    Raises:
        ValueError: If the number of consumed events does not exactly match
                    the parsed_lines metric indicated by parse_stats.
    """
    failed_logins = 0
    successful_logins = 0
    invalid_user_events = 0
    unique_ips = set[Any]()
    first_observed = None
    last_observed = None
    actual_events = 0

    for event in events:
        actual_events += 1

        # Aggregate semantic counts
        if event.event_type is AuthEventType.LOGIN_FAILED:
            failed_logins += 1
        elif event.event_type is AuthEventType.LOGIN_SUCCEEDED:
            successful_logins += 1
        elif event.event_type is AuthEventType.INVALID_USER:
            invalid_user_events += 1

        # Collect cardinality keys
        unique_ips.add(event.source_ip)

        # Track timestamp boundaries incrementally
        if first_observed is None or event.timestamp < first_observed:
            first_observed = event.timestamp

        if last_observed is None or event.timestamp > last_observed:
            last_observed = event.timestamp

    if actual_events != parse_stats.parsed_lines:
        raise ValueError(
            f"event count mismatch: parse_stats claims {parse_stats.parsed_lines} "
            f"parsed lines but the analyzer consumed {actual_events}"
        )

    return AnalysisSummary(
        parse_stats=parse_stats,
        failed_logins=failed_logins,
        successful_logins=successful_logins,
        invalid_user_events=invalid_user_events,
        unique_source_addresses=len(unique_ips),
        first_observed=first_observed,
        last_observed=last_observed,
    )


__all__ = ["analyze_events"]
