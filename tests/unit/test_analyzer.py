"""Unit tests for the core analyzer layer."""

from collections.abc import Iterable
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Any

import pytest

from loghunter.analyzer import analyze_events
from loghunter.models import AuthEvent, AuthEventType, AuthMethod, ParseStats


def make_test_event(
    *,
    timestamp: datetime | None = None,
    event_type: AuthEventType = AuthEventType.LOGIN_FAILED,
    source_ip: Any = None,
    username: str = "root",
    invalid_user: bool = False,
    auth_method: AuthMethod | None = AuthMethod.PASSWORD,
) -> AuthEvent:
    """Helper to generate minimal synthetic events for testing."""
    if timestamp is None:
        timestamp = datetime(2026, 7, 30, 18, 14, 22)
    if source_ip is None:
        source_ip = IPv4Address("192.168.1.50")
    return AuthEvent(
        timestamp=timestamp,
        hostname="server01",
        process_id=4128,
        event_type=event_type,
        username=username,
        source_ip=source_ip,
        source_port=22,
        auth_method=auth_method,
        line_number=1,
        invalid_user=invalid_user,
    )


def test_mixed_event_summary() -> None:
    """A mixed stream must aggregate semantic counts and IP cardinality perfectly."""
    events = [
        make_test_event(
            event_type=AuthEventType.LOGIN_FAILED, source_ip=IPv4Address("192.168.1.50")
        ),
        make_test_event(
            event_type=AuthEventType.LOGIN_FAILED, source_ip=IPv4Address("192.168.1.51")
        ),
        make_test_event(
            event_type=AuthEventType.LOGIN_SUCCEEDED, source_ip=IPv6Address("2001:db8::1")
        ),
        make_test_event(
            event_type=AuthEventType.LOGIN_SUCCEEDED, source_ip=IPv6Address("2001:db8::1")
        ),
        make_test_event(
            event_type=AuthEventType.INVALID_USER,
            source_ip=IPv4Address("192.168.1.50"),
            auth_method=None,
            invalid_user=True,
        ),
    ]

    stats = ParseStats(total_lines=8, parsed_lines=5, ignored_lines=3)
    summary = analyze_events(events, parse_stats=stats)

    assert summary.failed_logins == 2
    assert summary.successful_logins == 2
    assert summary.invalid_user_events == 1
    assert summary.unique_source_addresses == 3  # 192.168.1.50, .51, 2001:db8::1

    assert len(summary.source_stats) == 3
    assert len(summary.username_stats) == 1

    # Assert properties delegate to stats properly
    assert summary.total_lines == 8
    assert summary.parsed_lines == 5
    assert summary.ignored_lines == 3
    assert summary.parser_coverage_percentage == 62.5


def test_failed_password_invalid_user() -> None:
    """A failed password for an invalid user must NOT increment invalid_user_events."""
    events = [
        make_test_event(
            event_type=AuthEventType.LOGIN_FAILED,
            invalid_user=True,
            auth_method=AuthMethod.PASSWORD,
        )
    ]

    stats = ParseStats(total_lines=1, parsed_lines=1, ignored_lines=0)
    summary = analyze_events(events, parse_stats=stats)

    assert summary.failed_logins == 1
    assert summary.invalid_user_events == 0

    assert summary.source_stats[0].failed_logins == 1
    assert summary.source_stats[0].invalid_user_events == 0
    assert summary.username_stats[0].failed_logins == 1
    assert summary.username_stats[0].invalid_user_events == 0


def test_standalone_invalid_user() -> None:
    """A standalone invalid user must NOT increment failed_logins."""
    events = [
        make_test_event(
            event_type=AuthEventType.INVALID_USER,
            invalid_user=True,
            auth_method=None,
        )
    ]

    stats = ParseStats(total_lines=1, parsed_lines=1, ignored_lines=0)
    summary = analyze_events(events, parse_stats=stats)

    assert summary.invalid_user_events == 1
    assert summary.failed_logins == 0

    assert summary.source_stats[0].invalid_user_events == 1
    assert summary.source_stats[0].failed_logins == 0
    assert summary.username_stats[0].invalid_user_events == 1
    assert summary.username_stats[0].failed_logins == 0


def test_both_success_methods() -> None:
    """Both password and public key successes must increment successful_logins."""
    events = [
        make_test_event(
            event_type=AuthEventType.LOGIN_SUCCEEDED,
            auth_method=AuthMethod.PASSWORD,
        ),
        make_test_event(
            event_type=AuthEventType.LOGIN_SUCCEEDED,
            auth_method=AuthMethod.PUBLIC_KEY,
        ),
    ]

    stats = ParseStats(total_lines=2, parsed_lines=2, ignored_lines=0)
    summary = analyze_events(events, parse_stats=stats)

    assert summary.successful_logins == 2


def test_empty_parsed_stream() -> None:
    """An empty stream must produce zeros and Nones without raising an exception."""
    stats = ParseStats(total_lines=5, parsed_lines=0, ignored_lines=5)
    summary = analyze_events([], parse_stats=stats)

    assert summary.failed_logins == 0
    assert summary.successful_logins == 0
    assert summary.invalid_user_events == 0
    assert summary.unique_source_addresses == 0
    assert summary.first_observed is None
    assert summary.last_observed is None
    assert summary.source_stats == ()
    assert summary.username_stats == ()


def test_timestamp_min_max() -> None:
    """first_observed and last_observed represent true extremes, independent of order."""
    events = [
        make_test_event(timestamp=datetime(2026, 7, 30, 18, 20)),
        make_test_event(timestamp=datetime(2026, 7, 30, 18, 10)),  # True Min
        make_test_event(timestamp=datetime(2026, 7, 30, 18, 30)),  # True Max
        make_test_event(timestamp=datetime(2026, 7, 30, 18, 15)),
    ]

    stats = ParseStats(total_lines=4, parsed_lines=4, ignored_lines=0)
    summary = analyze_events(events, parse_stats=stats)

    assert summary.first_observed == datetime(2026, 7, 30, 18, 10)
    assert summary.last_observed == datetime(2026, 7, 30, 18, 30)


def test_unique_addresses() -> None:
    """IPv4 and IPv6 must participate cleanly in uniqueness."""
    events = [
        make_test_event(source_ip=IPv4Address("192.168.1.10")),
        make_test_event(source_ip=IPv4Address("192.168.1.10")),
        make_test_event(source_ip=IPv6Address("2001:db8::10")),
        make_test_event(source_ip=IPv6Address("2001:db8::10")),
        make_test_event(source_ip=IPv4Address("10.0.0.5")),
    ]

    stats = ParseStats(total_lines=5, parsed_lines=5, ignored_lines=0)
    summary = analyze_events(events, parse_stats=stats)

    assert summary.unique_source_addresses == 3


def test_duplicate_events_count() -> None:
    """Identical events must not be deduplicated."""
    event = make_test_event()
    events = [event, event]

    stats = ParseStats(total_lines=2, parsed_lines=2, ignored_lines=0)
    summary = analyze_events(events, parse_stats=stats)

    assert summary.failed_logins == 2
    assert summary.unique_source_addresses == 1


def test_generator_support() -> None:
    """analyze_events must seamlessly support generator objects without lengths."""

    def event_generator() -> Iterable[AuthEvent]:
        yield make_test_event()
        yield make_test_event()

    stats = ParseStats(total_lines=2, parsed_lines=2, ignored_lines=0)
    summary = analyze_events(event_generator(), parse_stats=stats)

    assert summary.failed_logins == 2


class SinglePassIterable:
    """A custom iterable that violently explodes if iterated more than once."""

    def __init__(self, events: list[AuthEvent]) -> None:
        self._events = events
        self._iterated = False

    def __iter__(self) -> Any:
        if self._iterated:
            raise RuntimeError("SinglePassIterable iterated multiple times!")
        self._iterated = True
        yield from self._events


def test_single_pass_iterable_behavior() -> None:
    """analyze_events must genuinely process the iterable only once."""
    events = SinglePassIterable([make_test_event()])

    stats = ParseStats(total_lines=1, parsed_lines=1, ignored_lines=0)
    summary = analyze_events(events, parse_stats=stats)  # Must not raise RuntimeError

    assert summary.failed_logins == 1


@pytest.mark.parametrize(
    ("parsed_lines", "actual_events_count"),
    [
        (2, 1),
        (1, 2),
    ],
)
def test_parse_stats_mismatch(parsed_lines: int, actual_events_count: int) -> None:
    """A mismatch between parsed_lines and the actual iterator count must raise ValueError."""
    events = [make_test_event() for _ in range(actual_events_count)]
    stats = ParseStats(total_lines=10, parsed_lines=parsed_lines, ignored_lines=10 - parsed_lines)

    with pytest.raises(ValueError, match="event count mismatch"):
        analyze_events(events, parse_stats=stats)


def test_source_stats_chronological_min_max() -> None:
    """SourceStats should record the true min/max timestamp independent of iter order."""
    ip = IPv4Address("192.168.1.10")
    events = [
        make_test_event(timestamp=datetime(2026, 7, 30, 18, 20), source_ip=ip),
        make_test_event(timestamp=datetime(2026, 7, 30, 18, 10), source_ip=ip),
        make_test_event(timestamp=datetime(2026, 7, 30, 18, 30), source_ip=ip),
    ]

    stats = ParseStats(total_lines=3, parsed_lines=3, ignored_lines=0)
    summary = analyze_events(events, parse_stats=stats)

    assert summary.source_stats[0].first_observed == datetime(2026, 7, 30, 18, 10)
    assert summary.source_stats[0].last_observed == datetime(2026, 7, 30, 18, 30)


def test_username_stats_chronological_min_max() -> None:
    """UsernameStats should record the true min/max timestamp independent of iter order."""
    events = [
        make_test_event(timestamp=datetime(2026, 7, 30, 18, 20), username="admin"),
        make_test_event(timestamp=datetime(2026, 7, 30, 18, 10), username="admin"),
        make_test_event(timestamp=datetime(2026, 7, 30, 18, 30), username="admin"),
    ]
    # Set the username explicitly directly on the events, bypassing the make_test_event default
    for event in events:
        object.__setattr__(event, "username", "admin")

    stats = ParseStats(total_lines=3, parsed_lines=3, ignored_lines=0)
    summary = analyze_events(events, parse_stats=stats)

    assert summary.username_stats[0].first_observed == datetime(2026, 7, 30, 18, 10)
    assert summary.username_stats[0].last_observed == datetime(2026, 7, 30, 18, 30)


def test_source_ranking_priority_failures() -> None:
    """Sources must be ranked primarily by failure count descending."""
    ip1 = IPv4Address("192.168.1.1")
    ip2 = IPv4Address("192.168.1.2")
    events = [
        make_test_event(source_ip=ip2, event_type=AuthEventType.LOGIN_FAILED),
        make_test_event(source_ip=ip2, event_type=AuthEventType.LOGIN_FAILED),
        make_test_event(source_ip=ip1, event_type=AuthEventType.LOGIN_FAILED),
    ]
    stats = ParseStats(total_lines=3, parsed_lines=3, ignored_lines=0)
    summary = analyze_events(events, parse_stats=stats)

    assert summary.source_stats[0].source_ip == ip2
    assert summary.source_stats[1].source_ip == ip1


def test_source_ranking_priority_last_observed() -> None:
    """Sources tying on failures rank by last_observed descending."""
    ip1 = IPv4Address("192.168.1.1")
    ip2 = IPv4Address("192.168.1.2")
    events = [
        make_test_event(
            source_ip=ip1,
            event_type=AuthEventType.LOGIN_FAILED,
            timestamp=datetime(2026, 7, 30, 18, 10),
        ),
        make_test_event(
            source_ip=ip2,
            event_type=AuthEventType.LOGIN_FAILED,
            timestamp=datetime(2026, 7, 30, 18, 20),
        ),
    ]
    stats = ParseStats(total_lines=2, parsed_lines=2, ignored_lines=0)
    summary = analyze_events(events, parse_stats=stats)

    assert summary.source_stats[0].source_ip == ip2
    assert summary.source_stats[1].source_ip == ip1


def test_source_ranking_priority_canonical_ip() -> None:
    """Sources tying on failures and last_observed rank by canonical IP text ascending."""
    ip1 = IPv4Address("192.168.1.5")
    ip2 = IPv4Address("192.168.1.9")
    t = datetime(2026, 7, 30, 18, 10)
    # Give them events out of order to ensure sort handles it
    events = [
        make_test_event(source_ip=ip2, event_type=AuthEventType.LOGIN_FAILED, timestamp=t),
        make_test_event(source_ip=ip1, event_type=AuthEventType.LOGIN_FAILED, timestamp=t),
    ]
    stats = ParseStats(total_lines=2, parsed_lines=2, ignored_lines=0)
    summary = analyze_events(events, parse_stats=stats)

    assert summary.source_stats[0].source_ip == ip1
    assert summary.source_stats[1].source_ip == ip2


def test_username_sorting_is_alphabetical() -> None:
    """Usernames must be ranked alphabetically, not by counts."""
    events = [
        make_test_event(username="root"),
        make_test_event(username="admin"),
        make_test_event(username="daniel"),
    ]
    for i, user in enumerate(["root", "admin", "daniel"]):
        object.__setattr__(events[i], "username", user)

    stats = ParseStats(total_lines=3, parsed_lines=3, ignored_lines=0)
    summary = analyze_events(events, parse_stats=stats)

    assert summary.username_stats[0].username == "admin"
    assert summary.username_stats[1].username == "daniel"
    assert summary.username_stats[2].username == "root"
