from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from loghunter.models import (
    AnalysisSummary,
    AuthEvent,
    AuthEventType,
    ParseStats,
    SourceStats,
    UsernameStats,
)


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

    @dataclass(slots=True)
    class SourceAccumulator:
        failed: int = 0
        successful: int = 0
        invalid: int = 0
        first: datetime | None = None
        last: datetime | None = None

    @dataclass(slots=True)
    class UserAccumulator:
        failed: int = 0
        successful: int = 0
        invalid: int = 0
        first: datetime | None = None
        last: datetime | None = None

    source_accs: dict[Any, SourceAccumulator] = {}
    user_accs: dict[str, UserAccumulator] = {}

    first_observed = None
    last_observed = None
    actual_events = 0

    for event in events:
        actual_events += 1

        is_failure = False
        is_success = False
        is_invalid = False

        if event.event_type is AuthEventType.LOGIN_FAILED:
            failed_logins += 1
            is_failure = True
        elif event.event_type is AuthEventType.LOGIN_SUCCEEDED:
            successful_logins += 1
            is_success = True
        elif event.event_type is AuthEventType.INVALID_USER:
            invalid_user_events += 1
            is_invalid = True

        # Aggregate source
        s_acc = source_accs.setdefault(event.source_ip, SourceAccumulator())
        if is_failure:
            s_acc.failed += 1
        if is_success:
            s_acc.successful += 1
        if is_invalid:
            s_acc.invalid += 1

        if s_acc.first is None or event.timestamp < s_acc.first:
            s_acc.first = event.timestamp
        if s_acc.last is None or event.timestamp > s_acc.last:
            s_acc.last = event.timestamp

        # Aggregate user
        u_acc = user_accs.setdefault(event.username, UserAccumulator())
        if is_failure:
            u_acc.failed += 1
        if is_success:
            u_acc.successful += 1
        if is_invalid:
            u_acc.invalid += 1

        if u_acc.first is None or event.timestamp < u_acc.first:
            u_acc.first = event.timestamp
        if u_acc.last is None or event.timestamp > u_acc.last:
            u_acc.last = event.timestamp

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

    source_stats_list: list[SourceStats] = []
    for ip, acc in source_accs.items():
        assert acc.first is not None and acc.last is not None
        source_stats_list.append(
            SourceStats(
                source_ip=ip,
                failed_logins=acc.failed,
                successful_logins=acc.successful,
                invalid_user_events=acc.invalid,
                first_observed=acc.first,
                last_observed=acc.last,
            )
        )

    source_stats_list.sort(
        key=lambda s: (-s.failed_logins, -s.last_observed.timestamp(), str(s.source_ip))
    )

    user_stats_list: list[UsernameStats] = []
    for user, acc in user_accs.items():
        assert acc.first is not None and acc.last is not None
        user_stats_list.append(
            UsernameStats(
                username=user,
                failed_logins=acc.failed,
                successful_logins=acc.successful,
                invalid_user_events=acc.invalid,
                first_observed=acc.first,
                last_observed=acc.last,
            )
        )

    user_stats_list.sort(key=lambda u: u.username)

    return AnalysisSummary(
        parse_stats=parse_stats,
        failed_logins=failed_logins,
        successful_logins=successful_logins,
        invalid_user_events=invalid_user_events,
        unique_source_addresses=len(source_accs),
        first_observed=first_observed,
        last_observed=last_observed,
        source_stats=tuple(source_stats_list),
        username_stats=tuple(user_stats_list),
    )


__all__ = ["analyze_events"]
